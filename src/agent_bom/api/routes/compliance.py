"""Compliance and posture API routes.

Endpoints:
    GET  /v1/compliance                      15-framework compliance posture + AISVS benchmark
    GET  /v1/compliance/summary              aggregate compliance summary
    GET  /v1/compliance/aisvs                OWASP AISVS benchmark posture
    GET  /v1/compliance/narrative            full compliance narrative (all frameworks)
    GET  /v1/compliance/narrative/{framework} single-framework narrative
    GET  /v1/compliance/nist-800-53          NIST 800-53 catalog drill (per-control + ISO-by-id)
    GET  /v1/compliance/{framework}          single framework (must be after /narrative)
    GET  /v1/compliance/{framework}/report   signed evidence bundle for auditors
    GET  /v1/posture                         enterprise posture scorecard
    GET  /v1/posture/counts                  severity counts for nav badges
    GET  /v1/posture/credentials             credential risk ranking
    GET  /v1/posture/incidents               agent-centric incident correlation
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import os
import secrets
from collections.abc import AsyncIterator
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING, Annotated, Any, cast

import anyio.to_thread
from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.responses import JSONResponse, PlainTextResponse, StreamingResponse

from agent_bom.api.credential_rotation import build_credential_rotation_governance
from agent_bom.api.finding_list_envelope import HUB_LIST_OFFSET_CEILING as _HUB_LIST_OFFSET_CEILING
from agent_bom.api.models import ComplianceReportBundle, JobStatus
from agent_bom.api.stores import (
    _get_analytics_store,
    _get_credential_ref_store,
    _get_fleet_store,
    _get_policy_store,
    _get_store,
)
from agent_bom.api.tenancy import require_request_tenant_id
from agent_bom.backpressure import BackpressureRejectedError, adaptive_backpressure
from agent_bom.compliance_nist_catalog import (
    build_nist_800_53_catalog_line,
    build_nist_800_53_drill,
)
from agent_bom.compliance_nist_catalog import (
    evaluated_control_status as _evaluated_control_status,
)
from agent_bom.evidence import EvidenceTier, redact_for_persistence
from agent_bom.evidence.control_modes import (
    DETECTIVE_CONTROLS,
    MODE_CORRECTIVE,
    MODE_DETECTIVE,
    detective_control_status,
)
from agent_bom.evidence.scoring import score_compliance
from agent_bom.rbac import require_authenticated_permission
from agent_bom.security import sanitize_error, sanitize_text

if TYPE_CHECKING:
    from agent_bom.output.compliance_narrative import ComplianceNarrative


def _dep(permission: str) -> Any:
    return cast(Any, require_authenticated_permission(permission))


router = APIRouter(dependencies=[_dep("read")])
_logger = logging.getLogger(__name__)

# Cap on audit entries pulled into a single signed evidence bundle. When the
# window holds more than this the bundle marks itself truncated (honest partial
# evidence) rather than silently presenting the capped set as the complete
# window; consumers paginate the full trail via /v1/audit.
_AUDIT_EVIDENCE_FETCH_LIMIT = 10_000

_CLUSTER_SCAN_SOURCES = {"gpu_infra", "k8s"}
_CI_CD_SCAN_SOURCES = {"github_actions"}
_REGISTRY_SCAN_SOURCES = {"external_scan", "image", "sbom"}
_LOCAL_SCAN_SOURCES = {
    "agent_discovery",
    "ast_analysis",
    "browser_extensions",
    "dataset_cards",
    "external_scan",
    "filesystem",
    "image",
    "jupyter",
    "sbom",
    "secret_scan",
    "terraform",
    "training_pipelines",
}
_CLUSTER_ENVIRONMENTS = {"aks", "cluster", "eks", "gke", "k8s", "kubernetes"}


def _tenant_id(request: Request) -> str:
    return require_request_tenant_id(request)


def _tenant_jobs(request: Request) -> list:
    return cast(list, _get_store().list_all(tenant_id=_tenant_id(request)))


def _credential_rotation_governance(tenant_id: str) -> dict[str, Any]:
    try:
        credentials = _get_credential_ref_store().list_all(tenant_id=tenant_id)
    except RuntimeError:
        credentials = []
    return build_credential_rotation_governance(credentials, tenant_id=tenant_id)


def _normalize_csv_filter(value: str | None) -> set[str]:
    if not value:
        return set()
    return {item.strip().lower() for item in value.split(",") if item.strip()}


def _aisvs_summary(benchmark: dict[str, Any]) -> dict[str, int | float]:
    checks_value = benchmark.get("checks")
    checks: list[Any] = checks_value if isinstance(checks_value, list) else []
    status_counts = {"pass": 0, "fail": 0, "error": 0, "not_applicable": 0}
    for check in checks:
        if not isinstance(check, dict):
            continue
        status = str(check.get("status") or "").lower()
        if status in status_counts:
            status_counts[status] += 1

    if not checks:
        status_counts["pass"] = int(benchmark.get("passed") or 0)
        status_counts["fail"] = int(benchmark.get("failed") or 0)

    total = int(benchmark.get("total") or len(checks) or sum(status_counts.values()))
    score = float(benchmark.get("pass_rate") or benchmark.get("overall_score") or 0.0)
    return {
        "pass": status_counts["pass"],
        "fail": status_counts["fail"],
        "error": status_counts["error"],
        "not_applicable": status_counts["not_applicable"],
        "total": total,
        "score": round(score, 1),
    }


def _empty_aisvs_benchmark() -> dict[str, Any]:
    return {
        "benchmark": "OWASP AI Security Verification Standard",
        "benchmark_version": "1.0",
        "passed": 0,
        "failed": 0,
        "total": 0,
        "pass_rate": 0.0,
        "checks": [],
        "metadata": {},
    }


def _build_aisvs_payload(
    benchmark: dict[str, Any] | None,
    *,
    scan_id: str | None = None,
    measured_at: str | None = None,
) -> dict[str, Any]:
    normalized = _empty_aisvs_benchmark()
    if isinstance(benchmark, dict):
        normalized.update(benchmark)
        if not isinstance(normalized.get("checks"), list):
            normalized["checks"] = []
        if not isinstance(normalized.get("metadata"), dict):
            normalized["metadata"] = {}

    summary = _aisvs_summary(normalized)
    return {
        "framework": "aisvs",
        "framework_key": "aisvs_benchmark",
        "framework_label": normalized.get("benchmark") or "OWASP AI Security Verification Standard",
        "source": "scan_jobs",
        "scan_id": scan_id,
        "measured_at": measured_at,
        "summary": summary,
        "score": summary["score"],
        "representation": "benchmark",
        "benchmark": normalized,
    }


def _latest_aisvs_benchmark_from_jobs(jobs: list[Any]) -> dict[str, Any]:
    latest: tuple[str, str, dict[str, Any]] | None = None
    for job in jobs:
        if job.status != JobStatus.DONE or not isinstance(getattr(job, "result", None), dict):
            continue
        result = cast(dict[str, Any], job.result)
        benchmark = result.get("aisvs_benchmark") or result.get("aisvs_benchmark_data")
        if not isinstance(benchmark, dict):
            continue
        measured_at = str(getattr(job, "completed_at", None) or getattr(job, "created_at", None) or "")
        scan_id = str(result.get("scan_id") or getattr(job, "job_id", ""))
        if latest is None or measured_at >= latest[0]:
            latest = (measured_at, scan_id, benchmark)

    if latest is None:
        return _build_aisvs_payload(None)
    latest_measured_at, latest_scan_id, benchmark = latest
    return _build_aisvs_payload(benchmark, scan_id=latest_scan_id, measured_at=latest_measured_at or None)


def _result_has_runtime_signals(result: dict[str, Any]) -> bool:
    return bool(
        result.get("runtime_correlation")
        or result.get("runtime_session_graph")
        or result.get("introspection")
        or result.get("introspection_data")
        or result.get("health_check")
        or result.get("health_check_data")
    )


def _tenant_has_proxy_alerts(tenant_id: str) -> bool:
    """Return True when the in-process proxy-alert ring buffer holds any
    alerts for ``tenant_id``.

    Proxy alerts ingested via ``/v1/proxy/audit`` land in
    ``agent_bom.api.routes.proxy._proxy_alerts`` — a bounded deque that is
    independent of the scan-job result store and the gateway policy_store.
    The ingestion path tags each record with ``tenant_id`` so this helper
    can scope correctly on multi-tenant deployments. Older records that
    pre-date the tagging carry no ``tenant_id``; for those we fall back to
    a fleet-wide signal so a recently-ingested alert still surfaces in
    posture even if its tenant attribution was lost on restart.
    """
    try:
        from agent_bom.api.routes.proxy import _proxy_alerts
    except ImportError:  # pragma: no cover — defensive
        return False
    if not _proxy_alerts:
        return False
    for alert in _proxy_alerts:
        alert_tenant = alert.get("tenant_id")
        if alert_tenant is None or alert_tenant == tenant_id:
            return True
    return False


def _derive_deployment_context(request: Request, jobs: list[Any]) -> dict[str, Any]:
    tenant_id = _tenant_id(request)
    scan_sources: set[str] = set()
    has_mcp_context = False
    has_agent_context = False
    has_runtime_signals = False
    scan_count = 0

    for job in jobs:
        if job.status != JobStatus.DONE or not job.result:
            continue
        scan_count += 1
        result = cast(dict[str, Any], job.result)
        has_mcp_context = has_mcp_context or bool(result.get("has_mcp_context"))
        has_agent_context = has_agent_context or bool(result.get("has_agent_context"))
        scan_sources.update(str(src) for src in result.get("scan_sources", []) if src)
        has_runtime_signals = has_runtime_signals or _result_has_runtime_signals(result)

    fleet_agents = _get_fleet_store().list_by_tenant(tenant_id)
    has_fleet_ingest = len(fleet_agents) > 0
    has_cluster_scan = bool(scan_sources & _CLUSTER_SCAN_SOURCES) or any(
        str(getattr(agent, "environment", "") or "").strip().lower() in _CLUSTER_ENVIRONMENTS for agent in fleet_agents
    )
    has_ci_cd_scan = bool(scan_sources & _CI_CD_SCAN_SOURCES)
    has_local_scan = (
        bool(scan_sources & _LOCAL_SCAN_SOURCES)
        or has_agent_context
        or has_mcp_context
        or (scan_count > 0 and not has_cluster_scan and not has_ci_cd_scan)
    )
    has_registry = bool(scan_sources & _REGISTRY_SCAN_SOURCES)

    policy_store = _get_policy_store()
    policies = policy_store.list_policies(tenant_id=tenant_id)
    policy_audit = policy_store.list_audit_entries(limit=1, tenant_id=tenant_id)
    has_gateway = bool(policies)

    # has_proxy must also flip when a runtime proxy has reported alerts — the
    # /v1/proxy/audit ingestion path lands in an in-process ring buffer that's
    # independent of scan-result correlations and policy_store entries. Without
    # this signal, sites that ingest proxy alerts via the dedicated endpoint
    # see "no proxy data" on the dashboard even when alerts are sitting in
    # /v1/proxy/status. (audit P1-B)
    has_proxy_alerts = _tenant_has_proxy_alerts(tenant_id)

    has_proxy = bool(policy_audit) or has_runtime_signals or has_proxy_alerts
    has_traces = bool(policy_audit) or has_runtime_signals or has_proxy_alerts
    has_mesh = (
        has_fleet_ingest
        or bool(scan_count and has_agent_context and has_mcp_context)
        or bool(has_runtime_signals and (has_agent_context or has_fleet_ingest))
    )

    active_modes = sum((has_local_scan, has_fleet_ingest, has_cluster_scan))
    if active_modes > 1:
        deployment_mode = "hybrid"
    elif has_cluster_scan:
        deployment_mode = "cluster"
    elif has_fleet_ingest:
        deployment_mode = "fleet"
    else:
        deployment_mode = "local"

    return {
        "deployment_mode": deployment_mode,
        "has_local_scan": has_local_scan,
        "has_fleet_ingest": has_fleet_ingest,
        "has_cluster_scan": has_cluster_scan,
        "has_ci_cd_scan": has_ci_cd_scan,
        "has_mesh": has_mesh,
        "has_gateway": has_gateway,
        "has_proxy": has_proxy,
        "has_traces": has_traces,
        "has_registry": has_registry,
        "has_mcp_context": has_mcp_context,
        "has_agent_context": has_agent_context,
        "scan_sources": sorted(scan_sources),
        "scan_count": scan_count,
    }


def _aggregate_cis_foundations_checks(jobs: list[Any]) -> dict[str, Any]:
    """Deduped CIS Foundations Benchmark status rollup across a tenant's scans.

    Reuses ``build_cis_benchmark_check_rows`` + the same latest-per-(cloud,
    check_id) dedup as ``/v1/cis/checks`` so the scorecard's benchmark line
    reconciles with that endpoint by construction.

    This is the CIS *Foundations Benchmark* taxonomy (``CIS-2.1.1`` …), a
    different standard from the CVE-driven CIS Controls v8 line (safeguard
    ``CIS-02.1`` …) built elsewhere in :func:`get_compliance`. The two never
    share identifiers, so no control is counted in both lines.
    """
    from agent_bom.analytics_contract import build_cis_benchmark_check_rows

    all_rows: list[dict[str, Any]] = []
    for job in jobs:
        if job.status != JobStatus.DONE or not isinstance(getattr(job, "result", None), dict):
            continue
        all_rows.extend(
            build_cis_benchmark_check_rows(
                job.result,
                str(job.result.get("scan_id") or job.job_id),
                measured_at=getattr(job, "completed_at", None) or getattr(job, "created_at", None),
            )
        )
    # Newest measurement per logical (cloud, check_id) wins — identical dedup to
    # the /v1/cis/checks scan_jobs fallback so the two surfaces agree.
    all_rows.sort(key=lambda row: (str(row.get("measured_at") or ""), -int(row.get("priority") or 0)), reverse=True)
    seen: set[tuple[str, str]] = set()
    counts = {"pass": 0, "fail": 0, "error": 0, "not_applicable": 0, "other": 0}
    providers: dict[str, dict[str, int]] = {}
    # Deduped latest status per logical (cloud, check_id) — consumed by the NIST
    # 800-53 catalog line to map a CIS Foundations check to the NIST controls it
    # evidences (framework_mapping.nist_controls_for_cis_check).
    statuses: dict[tuple[str, str], str] = {}
    for row in all_rows:
        key = (str(row.get("cloud") or ""), str(row.get("check_id") or ""))
        if key in seen:
            continue
        seen.add(key)
        status = str(row.get("status") or "").lower()
        bucket = status if status in ("pass", "fail", "error", "not_applicable") else "other"
        counts[bucket] += 1
        statuses[key] = status
        cloud = str(row.get("cloud") or "unknown")
        prov = providers.setdefault(cloud, {"pass": 0, "fail": 0, "error": 0, "not_applicable": 0, "other": 0})
        prov[bucket] += 1
    return {"counts": counts, "providers": providers, "total_checks": len(seen), "statuses": statuses}


def _build_cis_foundations_line(agg: dict[str, Any]) -> dict[str, Any]:
    """Shape the benchmark-backed CIS Foundations scorecard line.

    Denominator is honest: ``evaluated = pass + fail + error`` (NOT_APPLICABLE
    checks are excluded from the score). ERROR is an explicit bucket — an
    unevaluable control (permission-denied / unreadable, which the eval layer
    correctly refuses to PASS) is neither pass nor fail, and never inflates the
    numerator.
    """
    counts = agg["counts"]
    passed = int(counts["pass"])
    failed = int(counts["fail"])
    errored = int(counts["error"])
    not_applicable = int(counts["not_applicable"])
    evaluated = passed + failed + errored
    score = round((passed / evaluated) * 100, 1) if evaluated > 0 else 0.0

    if not agg["total_checks"]:
        status = "no_data"
    elif failed > 0:
        status = "fail"
    elif errored > 0:
        # Everything evaluable passed, but some controls were unevaluable — not a
        # clean pass. Surface as warning so the reader knows coverage is partial.
        status = "warning"
    elif evaluated > 0:
        status = "pass"
    else:
        status = "no_data"  # only NOT_APPLICABLE checks — nothing was evaluated

    return {
        "framework": "cis-foundations",
        "framework_key": "cis_foundations_benchmark",
        "framework_label": "CIS Foundations Benchmark",
        "representation": "benchmark",
        "source": "cis_benchmark_data",
        "status": status,
        "score": score,
        "summary": {
            "pass": passed,
            "fail": failed,
            "error": errored,
            "not_applicable": not_applicable,
            "evaluated": evaluated,
            "score": score,
        },
        "providers": agg["providers"],
    }


@router.get("/compliance", tags=["compliance"])
async def get_compliance(
    request: Request,
    scan_id: Annotated[str | None, Query(max_length=200)] = None,
) -> dict:
    """Aggregate OWASP LLM Top 10, OWASP MCP Top 10, MITRE ATLAS, NIST AI RMF,
    OWASP Agentic Top 10, and EU AI Act compliance posture across all completed scans.

    Returns scored control posture plus applicability-only risk/technique
    catalogs and an overall score derived only from the scored frameworks.
    """
    from agent_bom.compliance_coverage import TAG_MAPPED_FRAMEWORKS, control_key_for_tag

    tenant_jobs = _tenant_jobs(request)
    if scan_id:
        matching_jobs = []
        for job in tenant_jobs:
            result_scan_id = str(job.result.get("scan_id") or "") if job.result else ""
            if job.job_id == scan_id or result_scan_id == scan_id:
                matching_jobs.append(job)
        tenant_jobs = matching_jobs

    # Collect blast_radius entries from all completed scans
    all_blast: list[dict] = []
    latest_scan: str | None = None
    scan_count = 0
    has_mcp_context = False
    has_agent_context = False
    all_scan_sources: set[str] = set()

    for job in tenant_jobs:
        if job.status != JobStatus.DONE or not job.result:
            continue
        scan_count += 1
        br_list = job.result.get("blast_radius", [])
        all_blast.extend(br_list)
        if latest_scan is None or (job.completed_at and job.completed_at > latest_scan):
            latest_scan = job.completed_at
        # Detect scan context from result metadata
        if job.result.get("has_mcp_context"):
            has_mcp_context = True
        if job.result.get("has_agent_context"):
            has_agent_context = True
        for src in job.result.get("scan_sources", []):
            all_scan_sources.add(src)

    def _build_controls(
        catalog: dict[str, str],
        tag_field: str,
        id_key: str,
        *,
        scored: bool = True,
    ) -> list[dict]:
        """Build per-control compliance entries from blast_radius data.

        Three evaluation modes decide what a scan result means for a control
        (see :mod:`agent_bom.evidence.control_modes`):

        * ``detective`` — the scan IS the control operating. A fresh completed
          scan is ``pass``; stale evidence is ``fail``; no scan is
          ``not_assessed``. Findings never fail a detective control.
        * ``corrective`` — attested by the ABSENCE of an open finding. An open
          finding fails/warns by worst severity; no mapped finding stays
          ``not_evaluated`` (absence of a CVE is not proof of implementation).
        * ``overlay`` (``scored=False``) — not a control at all. Entries are
          ``applicable`` / ``not_applicable`` and never touch the score.
        """
        detective_ids = DETECTIVE_CONTROLS.get(tag_field, frozenset())
        controls = []
        for code, name in sorted(catalog.items()):
            sev_breakdown = {"critical": 0, "high": 0, "medium": 0, "low": 0}
            affected_pkgs: set[str] = set()
            affected_agents: set[str] = set()
            findings = 0

            for br in all_blast:
                tags = br.get(tag_field, [])
                if any(control_key_for_tag(str(tag), catalog) == code for tag in tags):
                    findings += 1
                    sev = (br.get("severity") or "").lower()
                    if sev in sev_breakdown:
                        sev_breakdown[sev] += 1
                    pkg = br.get("package")
                    if pkg:
                        affected_pkgs.add(pkg)
                    for agent in br.get("affected_agents", []):
                        affected_agents.add(agent)

            if not scored:
                # Applicability overlay (MITRE ATT&CK): a technique is made
                # applicable by an observed weakness, or it is not. It is never
                # a control the estate passed or failed, so it never enters the
                # score. Presenting it as "fail" asserted dozens of unevidenced
                # control failures per CVE.
                mode = "overlay"
                reason = "technique_observed" if findings else "no_observed_signal"
                status = "applicable" if findings else "not_applicable"
            elif code in detective_ids:
                # The scan itself is the evidence this control operates —
                # producing this scan and this SBOM IS the implementation of
                # "monitor and scan for vulnerabilities" / "maintain a component
                # inventory". Findings mapped here would be proof it works, so
                # the status comes from evidence freshness, not from findings.
                mode = MODE_DETECTIVE
                status, reason = detective_control_status(scan_count=scan_count, latest_scan=latest_scan)
            elif scan_count == 0:
                # No completed scans means no evidence was gathered for this
                # control. Rendering "pass" here reads as a clean audit when in
                # fact nothing was measured, so surface an explicit not_assessed
                # status per control (mirrors the aggregate no_data top-line).
                mode = MODE_CORRECTIVE
                status, reason = "not_assessed", "no_completed_scan"
            elif findings == 0:
                # Scan ran but nothing maps to this control — no
                # vulnerability-derived evidence, so it is not_evaluated, never a
                # silent pass. Counting these as pass inflated overall_score
                # toward 100 and contradicted the narrative + CLI export; all
                # three surfaces now agree.
                mode = MODE_CORRECTIVE
                status, reason = "not_evaluated", "no_mapped_finding"
            else:
                mode = MODE_CORRECTIVE
                status = _evaluated_control_status(sev_breakdown)
                reason = "open_finding" if status != "not_evaluated" else "unrated_severity_finding"

            controls.append(
                {
                    id_key: code,
                    "control_id": code,
                    "name": name,
                    "tags": [code],
                    "findings": findings,
                    "status": status,
                    "evaluation_mode": mode,
                    "evidence_reason": reason,
                    "severity_breakdown": sev_breakdown,
                    "affected_packages": sorted(affected_pkgs),
                    "affected_agents": sorted(affected_agents),
                }
            )
        return controls

    framework_controls = {
        metadata.output_key: _build_controls(
            dict(metadata.catalog),
            metadata.tag_field,
            "code",
            scored=metadata.scored,
        )
        for metadata in TAG_MAPPED_FRAMEWORKS
    }

    def _count_statuses(controls: list[dict]) -> tuple[int, int, int]:
        p = sum(1 for c in controls if c["status"] == "pass")
        w = sum(1 for c in controls if c["status"] == "warning")
        f = sum(1 for c in controls if c["status"] == "fail")
        return p, w, f

    # Overlay frameworks are excluded from every aggregate: they carry no
    # pass/warning/fail at all, so folding them in would only ever add noise.
    all_frameworks = [framework_controls[m.output_key] for m in TAG_MAPPED_FRAMEWORKS if m.scored]
    status_totals = [_count_statuses(fw) for fw in all_frameworks]
    total_pass = sum(s[0] for s in status_totals)
    total_warn = sum(s[1] for s in status_totals)
    total_fail = sum(s[2] for s in status_totals)

    # Wire the CIS Foundations Benchmark posture (report.cis_benchmark_data + the
    # azure/gcp/snowflake/databricks siblings) into the aggregate. Previously the
    # scorecard derived every status ONLY from CVE-tag data, so a cloud account
    # failing CIS controls read green/no_data. The benchmark is a DIFFERENT
    # taxonomy than the CVE-driven CIS Controls v8 line, kept as its own labeled
    # line below; here we only fold its pass/fail/error into the top-line so a
    # failing CIS account can't read as compliant. ERROR is unevaluable — counted
    # toward the evaluated denominator (drags the score down) but never the
    # numerator.
    cis_foundations_agg = _aggregate_cis_foundations_checks(tenant_jobs)
    aisvs = _latest_aisvs_benchmark_from_jobs(tenant_jobs)
    aisvs_summary = aisvs["summary"]

    # AISVS folds in on exactly the same grounds as CIS Foundations: both are
    # DIRECTLY EVALUATED checks, not CVE-tag inferences, so both are real
    # evidence about the estate. Leaving AISVS out was invisible only while
    # ``pass`` was unreachable and every such estate read ``no_data`` anyway;
    # once a scan can legitimately pass its detective controls, an excluded
    # failing AISVS check buys a "100% Compliant" headline over a known
    # failure. AISVS is not in TAG_MAPPED_FRAMEWORKS, so this cannot
    # double-count.
    bench_pass = int(cis_foundations_agg["counts"]["pass"]) + int(aisvs_summary["pass"])
    bench_fail = int(cis_foundations_agg["counts"]["fail"]) + int(aisvs_summary["fail"])
    bench_error = int(cis_foundations_agg["counts"]["error"]) + int(aisvs_summary["error"])

    # Score over EVALUATED controls/checks only (CVE controls with mapped
    # findings + benchmark pass/fail/error). A CVE control with no findings is
    # not_evaluated, never a silent pass — otherwise every never-triggered bundled
    # control inflates the score toward 100. Matches the narrative so a
    # benign/empty estate can't read as "fully compliant".
    aggregate_pass = total_pass + bench_pass
    aggregate_fail = total_fail + bench_fail

    # A score over EVALUATED controls is only honest next to its coverage: a
    # scan that touched 8 of 931 controls and passed all 8 is "100%" of a very
    # small denominator, and a bare percentage hides that. Every surface that
    # renders overall_score MUST render these alongside it.
    total_controls = (
        sum(m.control_count for m in TAG_MAPPED_FRAMEWORKS if m.scored)
        + int(
            cis_foundations_agg["counts"]["pass"]
            + cis_foundations_agg["counts"]["fail"]
            + cis_foundations_agg["counts"]["error"]
            + cis_foundations_agg["counts"].get("not_applicable", 0)
        )
        + int(aisvs_summary["total"])
    )
    # A detective pass only establishes that we scan — it is evidence about the
    # monitoring program, not about whether the estate meets a framework. An
    # estate whose ONLY passing evidence is "a scan ran" has not been shown to
    # be compliant, so it reports no_data rather than a green headline. Without
    # this, a fresh scan over an estate with nothing gradeable rendered
    # "100% / Compliant" — the same false green that pinning the score at 0 was
    # originally (wrongly) papering over.
    detective_passes = sum(
        1 for controls_list in all_frameworks for c in controls_list if c.get("evaluation_mode") == MODE_DETECTIVE and c["status"] == "pass"
    )

    # ONE derivation of status + score, shared with the per-framework route, the
    # MCP tool, the HTML report and the evidence bundle. Deriving the two
    # separately here is exactly how overall_status="no_data" came to sit beside
    # overall_score=100.0: the score was aggregate_pass/evaluated (all detective
    # passes) while only the status consulted substantive_evaluated. With zero
    # completed scans nothing is measurable at all, which ``has_evidence``
    # carries.
    verdict = score_compliance(
        passed=aggregate_pass,
        warned=total_warn,
        failed=aggregate_fail,
        errored=bench_error,
        detective_passes=detective_passes,
        has_evidence=scan_count > 0,
    )
    overall_status = verdict.status
    overall_score = verdict.score
    evaluated_controls = verdict.evaluated
    coverage_pct = round((evaluated_controls / total_controls) * 100, 2) if total_controls > 0 else 0.0

    summary: dict[str, int | float] = {}
    for metadata in TAG_MAPPED_FRAMEWORKS:
        controls_list = framework_controls[metadata.output_key]
        if not metadata.scored:
            # An overlay has no pass/warn/fail to report. Emitting zeroed
            # ``*_pass``/``*_fail`` keys would read as "0 passing controls" for
            # something that has no controls at all, so report applicability.
            applicable = sum(1 for c in controls_list if c["status"] == "applicable")
            summary[f"{metadata.summary_prefix}_applicable"] = applicable
            summary[f"{metadata.summary_prefix}_not_applicable"] = len(controls_list) - applicable
            continue
        passed, warned, failed = _count_statuses(controls_list)
        summary[f"{metadata.summary_prefix}_pass"] = passed
        summary[f"{metadata.summary_prefix}_warn"] = warned
        summary[f"{metadata.summary_prefix}_fail"] = failed
        # Controls with no mapped findings are not_evaluated (not_assessed on a
        # zero-scan estate) — surface the count so consumers can tell an
        # unevaluated control apart from a passing one.
        not_evaluated = len(controls_list) - passed - warned - failed
        if not_evaluated:
            summary[f"{metadata.summary_prefix}_not_evaluated"] = not_evaluated
    cis_foundations_line = _build_cis_foundations_line(cis_foundations_agg)
    # PR3: catalog-backed NIST 800-53 line, scored INDEPENDENTLY over evaluated
    # controls only (curated check -> control map). Deliberately NOT folded into
    # overall_score/overall_status — the same CVE/CIS evidence already drives the
    # existing per-framework lines, so folding would double-count.
    nist_800_53_catalog_line = build_nist_800_53_catalog_line(
        all_blast,
        cis_foundations_agg.get("statuses", {}),
        scan_count,
    )
    summary.update(
        {
            "aisvs_pass": aisvs_summary["pass"],
            "aisvs_fail": aisvs_summary["fail"],
            "aisvs_error": aisvs_summary["error"],
            "aisvs_not_applicable": aisvs_summary["not_applicable"],
            "cis_foundations_pass": cis_foundations_line["summary"]["pass"],
            "cis_foundations_fail": cis_foundations_line["summary"]["fail"],
            "cis_foundations_error": cis_foundations_line["summary"]["error"],
            "cis_foundations_not_applicable": cis_foundations_line["summary"]["not_applicable"],
            "cis_foundations_evaluated": cis_foundations_line["summary"]["evaluated"],
            "nist_800_53_catalog_pass": nist_800_53_catalog_line["summary"]["pass"],
            "nist_800_53_catalog_fail": nist_800_53_catalog_line["summary"]["fail"],
            "nist_800_53_catalog_warning": nist_800_53_catalog_line["summary"]["warning"],
            "nist_800_53_catalog_error": nist_800_53_catalog_line["summary"]["error"],
            "nist_800_53_catalog_evaluated": nist_800_53_catalog_line["summary"]["evaluated"],
            "nist_800_53_catalog_not_evaluated": nist_800_53_catalog_line["summary"]["not_evaluated"],
        }
    )

    response: dict[str, Any] = {
        "overall_score": overall_score,
        "overall_status": overall_status,
        # Denominator context for overall_score — never render the percentage
        # without it (see the comment where these are computed).
        "evaluated_controls": evaluated_controls,
        "total_controls": total_controls,
        "coverage_pct": coverage_pct,
        "scan_count": scan_count,
        "latest_scan": latest_scan,
        "has_mcp_context": has_mcp_context,
        "has_agent_context": has_agent_context,
        "scan_sources": sorted(all_scan_sources),
        # Serialized measurement contract for every framework. Consumers must
        # not infer this from labels: OWASP risk catalogs and MITRE technique
        # catalogs are applicability overlays, never pass/fail controls.
        "framework_kinds": {metadata.output_key: ("scored" if metadata.scored else "applicability") for metadata in TAG_MAPPED_FRAMEWORKS},
        "aisvs_benchmark": aisvs,
        "cis_foundations_benchmark": cis_foundations_line,
        "nist_800_53_catalog": nist_800_53_catalog_line,
        "summary": summary,
    }
    for metadata in TAG_MAPPED_FRAMEWORKS:
        response[metadata.output_key] = framework_controls[metadata.output_key]
    return response


@router.get("/cis/checks", tags=["compliance"])
async def list_cis_benchmark_checks(
    request: Request,
    cloud: str | None = None,
    status: str | None = None,
    priority: int | None = None,
    limit: int = 100,
    offset: int = 0,
) -> dict:
    """List tenant-scoped CIS benchmark checks with indexed filters where available.

    The synchronous store reads (columnar/analytics queries plus the in-memory
    scan-job fallback) run in a worker thread under adaptive backpressure so a
    deep listing cannot block the event loop; under saturation the endpoint
    sheds with ``429 + Retry-After``.
    """
    try:
        async with adaptive_backpressure("compliance"):
            return await anyio.to_thread.run_sync(_list_cis_benchmark_checks_impl, request, cloud, status, priority, limit, offset)
    except BackpressureRejectedError as exc:
        raise HTTPException(
            status_code=429,
            detail=exc.to_dict(),
            headers={"Retry-After": str(exc.retry_after_seconds)},
        ) from exc


def _list_cis_benchmark_checks_impl(
    request: Request,
    cloud: str | None,
    status: str | None,
    priority: int | None,
    limit: int,
    offset: int,
) -> dict:
    tenant_id = _tenant_id(request)
    safe_limit = max(1, min(int(limit), 500))
    safe_offset = max(0, int(offset))
    cloud_filter = _normalize_csv_filter(cloud)
    status_filter = _normalize_csv_filter(status)
    if priority is not None and priority < 0:
        raise HTTPException(status_code=400, detail="priority must be >= 0")

    job_store = _get_store()
    store_query = getattr(job_store, "query_cis_benchmark_checks", None)
    if callable(store_query) and len(cloud_filter) <= 1 and len(status_filter) <= 1:
        rows = store_query(
            tenant_id,
            cloud=next(iter(cloud_filter), None),
            status=next(iter(status_filter), None),
            priority=priority,
            limit=safe_limit,
            offset=safe_offset,
        )
        if rows:
            return {"checks": [_coerce_cis_row(row) for row in rows], "count": len(rows), "source": "columnar"}

    analytics_store = _get_analytics_store()
    query_fn = getattr(analytics_store, "query_cis_benchmark_checks", None)
    if callable(query_fn) and len(cloud_filter) <= 1 and len(status_filter) <= 1:
        try:
            rows = query_fn(
                cloud=next(iter(cloud_filter), None),
                status=next(iter(status_filter), None),
                priority=priority,
                limit=safe_limit,
                offset=safe_offset,
                tenant_id=tenant_id,
            )
            if rows:
                return {"checks": [_coerce_cis_row(row) for row in rows], "count": len(rows), "source": "analytics"}
        except Exception:
            pass

    from agent_bom.analytics_contract import build_cis_benchmark_check_rows

    all_rows: list[dict[str, Any]] = []
    for job in _tenant_jobs(request):
        if job.status != JobStatus.DONE or not isinstance(getattr(job, "result", None), dict):
            continue
        all_rows.extend(
            build_cis_benchmark_check_rows(
                job.result,
                str(job.result.get("scan_id") or job.job_id),
                measured_at=getattr(job, "completed_at", None) or getattr(job, "created_at", None),
            )
        )
    filtered = [
        row
        for row in all_rows
        if (not cloud_filter or row["cloud"].lower() in cloud_filter)
        and (not status_filter or row["status"].lower() in status_filter)
        and (priority is None or int(row["priority"]) == priority)
    ]
    filtered.sort(key=lambda row: (str(row.get("measured_at") or ""), -int(row.get("priority") or 0)), reverse=True)
    # Collapse to the latest measurement per logical (cloud, check_id) so this
    # in-memory fallback matches the columnar store's DISTINCT ON dedup: without
    # it, N scans of the same cloud would stack N copies of each check. Rows are
    # already sorted newest-first, so the first occurrence wins.
    deduped: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for row in filtered:
        key = (str(row.get("cloud") or ""), str(row.get("check_id") or ""))
        if key in seen:
            continue
        seen.add(key)
        deduped.append(row)
    return {"checks": deduped[safe_offset : safe_offset + safe_limit], "count": len(deduped), "source": "scan_jobs"}


def _coerce_cis_row(row: dict[str, Any]) -> dict[str, Any]:
    from agent_bom.cloud.cis_remediation import fail_closed_remediation_payload

    coerced = dict(row)
    remediation = coerced.get("remediation")
    if isinstance(remediation, str):
        try:
            remediation = json.loads(remediation)
        except json.JSONDecodeError:
            remediation = {}
    remediation = fail_closed_remediation_payload(
        remediation,
        cloud=str(coerced.get("cloud") or ""),
        benchmark_version=str(coerced.get("benchmark_version") or ""),
        check_id=str(coerced.get("check_id") or ""),
        title=str(coerced.get("title") or ""),
        cis_section=str(coerced.get("cis_section") or ""),
    )
    coerced["remediation"] = remediation
    coerced["fix_cli"] = str(remediation.get("fix_cli") or "")
    coerced["fix_console"] = str(remediation.get("fix_console") or coerced.get("fix_console") or "")
    coerced["effort"] = str(remediation.get("effort") or "manual")
    coerced["requires_human_review"] = True
    return coerced


# ─── CIS Benchmark Trend / Drilldown (#1832) ──────────────────────────────


@router.get("/cis/trends", tags=["compliance"], deprecated=True)
async def cis_benchmark_trends(
    request: Request,
    days: int = 30,
    bucket: str = "day",
    cloud: str | None = None,
    section: str | None = None,
    status: str | None = None,
    severity: str | None = None,
) -> dict:
    """Time-bucketed CIS finding counts for trend / drilldown surfaces.

    Resolves to the columnar store (Postgres ``cis_benchmark_checks`` →
    ClickHouse) when available; otherwise reconstructs the aggregation
    in-memory from the tenant's recent scan results so single-node and
    SQLite-only deployments still return data.

    Soft-deprecated: no UI/CLI/MCP product consumer (#3666 Phase 2).

    Query parameters:
    - ``days`` (1–366, default 30): rolling window size.
    - ``bucket`` (``hour`` | ``day`` | ``week``, default ``day``): bucket
      width. Anything else falls back to ``day``.
    - ``cloud`` / ``section`` / ``status`` / ``severity``: optional
      single-value filters narrowing the slice before aggregation.

    The synchronous aggregation (columnar/analytics stores plus the in-memory
    scan-job fallback) runs in a worker thread under adaptive backpressure so
    it never blocks the event loop; under saturation the endpoint sheds with
    ``429 + Retry-After``.
    """
    try:
        async with adaptive_backpressure("compliance"):
            return await anyio.to_thread.run_sync(_cis_benchmark_trends_impl, request, days, bucket, cloud, section, status, severity)
    except BackpressureRejectedError as exc:
        raise HTTPException(
            status_code=429,
            detail=exc.to_dict(),
            headers={"Retry-After": str(exc.retry_after_seconds)},
        ) from exc


def _cis_benchmark_trends_impl(
    request: Request,
    days: int,
    bucket: str,
    cloud: str | None,
    section: str | None,
    status: str | None,
    severity: str | None,
) -> dict:
    tenant_id = _tenant_id(request)
    bucket_unit = bucket if bucket in {"hour", "day", "week"} else "day"
    days_clamped = max(1, min(int(days), 366))

    job_store = _get_store()
    aggregate_fn = getattr(job_store, "aggregate_cis_benchmark_checks", None)
    if callable(aggregate_fn):
        try:
            buckets = aggregate_fn(
                tenant_id,
                days=days_clamped,
                cloud=cloud,
                section=section,
                status=status,
                severity=severity,
                bucket=bucket_unit,
            )
            if buckets:
                return {
                    "buckets": buckets,
                    "count": len(buckets),
                    "source": "columnar",
                    "bucket": bucket_unit,
                    "days": days_clamped,
                }
        except Exception as exc:  # noqa: BLE001
            _logger.warning("Postgres CIS aggregation failed; trying analytics store: %s", sanitize_text(exc))

    analytics_store = _get_analytics_store()
    analytics_aggregate = getattr(analytics_store, "aggregate_cis_benchmark_checks", None)
    if callable(analytics_aggregate):
        try:
            buckets = analytics_aggregate(
                days=days_clamped,
                cloud=cloud,
                section=section,
                status=status,
                severity=severity,
                bucket=bucket_unit,
                tenant_id=tenant_id,
            )
            if buckets:
                return {
                    "buckets": buckets,
                    "count": len(buckets),
                    "source": "analytics",
                    "bucket": bucket_unit,
                    "days": days_clamped,
                }
        except Exception as exc:  # noqa: BLE001
            _logger.warning("ClickHouse CIS aggregation failed: %s", sanitize_text(exc))

    # In-memory fallback: aggregate the tenant's recent scan results
    # locally so even single-node and SQLite-only deployments answer.
    from agent_bom.analytics_contract import build_cis_benchmark_check_rows

    cutoff_isoformat = (datetime.now(timezone.utc) - timedelta(days=days_clamped)).isoformat()
    counts: dict[tuple[str, str, str, str, str], int] = {}
    for job in _tenant_jobs(request):
        if job.status != JobStatus.DONE or not isinstance(getattr(job, "result", None), dict):
            continue
        measured_at = getattr(job, "completed_at", None) or getattr(job, "created_at", None)
        if measured_at and str(measured_at) < cutoff_isoformat:
            continue
        rows = build_cis_benchmark_check_rows(
            job.result,
            str(job.result.get("scan_id") or job.job_id),
            measured_at=measured_at,
        )
        for row in rows:
            if cloud and row.get("cloud", "").lower() != cloud.lower():
                continue
            if section and row.get("cis_section", "") != section:
                continue
            if status and row.get("status", "").lower() != status.lower():
                continue
            if severity and row.get("severity", "").lower() != severity.lower():
                continue
            bucket_key = _bucket_for(str(row.get("measured_at") or ""), bucket_unit)
            key = (
                bucket_key,
                row.get("cloud", ""),
                row.get("cis_section", ""),
                row.get("status", ""),
                row.get("severity", ""),
            )
            counts[key] = counts.get(key, 0) + 1

    buckets_payload = [
        {
            "bucket": bucket_value,
            "cloud": cloud_value,
            "cis_section": section_value,
            "status": status_value,
            "severity": severity_value,
            "count": count,
        }
        for (bucket_value, cloud_value, section_value, status_value, severity_value), count in sorted(counts.items(), reverse=True)
    ]
    return {
        "buckets": buckets_payload,
        "count": len(buckets_payload),
        "source": "scan_jobs",
        "bucket": bucket_unit,
        "days": days_clamped,
    }


def _bucket_for(measured_at_iso: str, unit: str) -> str:
    """Truncate ``measured_at_iso`` to the given bucket granularity for the in-memory fallback."""
    if not measured_at_iso:
        return ""
    try:
        moment = datetime.fromisoformat(measured_at_iso.replace("Z", "+00:00"))
    except ValueError:
        return measured_at_iso
    if unit == "hour":
        moment = moment.replace(minute=0, second=0, microsecond=0)
    elif unit == "week":
        moment = moment - timedelta(days=moment.weekday())
        moment = moment.replace(hour=0, minute=0, second=0, microsecond=0)
    else:
        moment = moment.replace(hour=0, minute=0, second=0, microsecond=0)
    return moment.isoformat()


# ─── Compliance Narrative ─────────────────────────────────────────────────


def _current_narrative_evidence(request: Request) -> dict[str, Any] | None:
    """Return the same persisted current finding snapshot the queue exposes."""
    from agent_bom.api.routes.scan import current_findings_snapshot

    snapshot = current_findings_snapshot(request)
    if not snapshot["findings"] and not snapshot["completed_scan_count"]:
        return None
    return snapshot


def _narrative_to_dict(narrative: "ComplianceNarrative", *, evidence: dict[str, Any] | None = None) -> dict:
    """Serialise a ComplianceNarrative dataclass to a JSON-safe dict."""
    payload: dict[str, Any] = {
        "executive_summary": narrative.executive_summary,
        "risk_narrative": narrative.risk_narrative,
        "generated_at": narrative.generated_at,
        "claim_boundary": narrative.claim_boundary,
        "framework_narratives": [
            {
                "framework": fn.framework,
                "slug": fn.slug,
                "status": fn.status,
                "score": fn.score,
                "narrative": fn.narrative,
                "recommendations": fn.recommendations,
                "failing_controls": [
                    {
                        "control_id": cn.control_id,
                        "title": cn.title,
                        "status": cn.status,
                        "narrative": cn.narrative,
                        "affected_packages": cn.affected_packages,
                        "affected_agents": cn.affected_agents,
                        "affected_findings": cn.affected_findings,
                        "remediation_steps": cn.remediation_steps,
                    }
                    for cn in fn.failing_controls
                ],
            }
            for fn in narrative.framework_narratives
        ],
        "remediation_impact": [
            {
                "package": ri.package,
                "current_version": ri.current_version,
                "fix_version": ri.fix_version,
                "controls_fixed": ri.controls_fixed,
                "frameworks_impacted": ri.frameworks_impacted,
                "narrative": ri.narrative,
            }
            for ri in narrative.remediation_impact
        ],
    }
    if evidence is not None:
        payload["evidence_snapshot"] = {
            "schema_version": evidence.get("schema_version"),
            "source": "scan_and_current_ingest_findings",
            "tenant_id": evidence.get("tenant_id"),
            "scan_ids": evidence.get("scan_ids", []),
            "completed_scan_count": evidence.get("completed_scan_count", 0),
            "returned": evidence.get("count", 0),
            "total": evidence.get("total"),
            "completeness": evidence.get("completeness"),
            "count_metadata": evidence.get("count_metadata", {}),
            "warnings": evidence.get("warnings", []),
        }
    return payload


@router.get("/compliance/narrative", tags=["compliance"])
async def get_compliance_narrative(request: Request) -> dict:
    """Generate a review-ready compliance narrative from current tenant evidence.

    Produces human-readable stories for all supported framework mappings, a
    cross-framework executive summary, and a remediation-compliance bridge
    showing which package upgrades resolve which controls.

    No LLM is required — narratives are generated from template strings and
    the canonical current finding queue used by the REST/CLI/UI surfaces.
    """
    from agent_bom.output.compliance_narrative import COMPLIANCE_CLAIM_BOUNDARY

    evidence = _current_narrative_evidence(request)
    if evidence is None:
        return {
            "executive_summary": "No completed scans available. Run agent-bom scan first.",
            "framework_narratives": [],
            "remediation_impact": [],
            "risk_narrative": "No scan data available.",
            "generated_at": "",
            "claim_boundary": COMPLIANCE_CLAIM_BOUNDARY,
        }

    from agent_bom.output.compliance_narrative import generate_compliance_narrative_from_findings

    narrative: ComplianceNarrative = generate_compliance_narrative_from_findings(
        evidence["findings"],
        total_agents=evidence["total_agents"],
        total_packages=evidence["total_packages"],
        generated_at=evidence["generated_at"],
    )
    return _narrative_to_dict(narrative, evidence=evidence)


@router.get("/compliance/narrative/{framework}", tags=["compliance"])
async def get_compliance_narrative_by_framework(request: Request, framework: str) -> dict:
    """Generate a single-framework compliance narrative.

    Supported framework slugs: owasp-llm, owasp-mcp, atlas, nist,
    owasp-agentic, eu-ai-act, nist-csf, iso-27001, soc2, cis, cmmc.

    Returns the same structure as GET /v1/compliance/narrative but scoped
    to a single framework's controls.
    """
    from agent_bom.compliance_coverage import normalize_framework_slug
    from agent_bom.output.compliance_narrative import (
        ALL_FRAMEWORK_SLUGS,
        COMPLIANCE_CLAIM_BOUNDARY,
    )

    canonical = normalize_framework_slug(framework)
    if canonical not in ALL_FRAMEWORK_SLUGS:
        raise HTTPException(
            status_code=400,
            detail=(f"Unknown framework '{framework}'. Supported: {', '.join(ALL_FRAMEWORK_SLUGS)}"),
        )

    evidence = _current_narrative_evidence(request)
    if evidence is None:
        return {
            "executive_summary": "No completed scans available. Run agent-bom scan first.",
            "framework_narratives": [],
            "remediation_impact": [],
            "risk_narrative": "No scan data available.",
            "generated_at": "",
            "claim_boundary": COMPLIANCE_CLAIM_BOUNDARY,
        }

    from agent_bom.output.compliance_narrative import generate_compliance_narrative_from_findings

    narrative: ComplianceNarrative = generate_compliance_narrative_from_findings(
        evidence["findings"],
        total_agents=evidence["total_agents"],
        total_packages=evidence["total_packages"],
        generated_at=evidence["generated_at"],
        framework=canonical,
    )
    return _narrative_to_dict(narrative, evidence=evidence)


@router.get("/compliance/verification-key", tags=["compliance"])
async def get_compliance_verification_key(request: Request) -> dict:
    """Return the key material — and the verifiability posture — for evidence bundles.

    Safe to expose: the only key it can return is a public key. Auditors and
    external SIEM systems use this endpoint to fetch the verification key
    without operator hand-off.

    It answers "can I verify a bundle from this deployment?", not just "which
    algorithm was used". By default ``agent-bom serve`` has no
    ``AGENT_BOM_AUDIT_HMAC_KEY``, so the HMAC key is generated per-process and
    never leaves it — bundles signed with it are unverifiable by anyone, and
    reporting only ``algorithm: HMAC-SHA256`` sent auditors after a key that
    does not exist.

    Response shape:
      - ``algorithm``: "Ed25519" when asymmetric signing is configured, else "HMAC-SHA256"
      - ``signature_verifiable``: whether ANY verifier can check a bundle from this deployment
      - ``persists_across_restart``: whether the signing key survives a restart
      - ``verification_status``: verifiable_public_key | verifiable_shared_secret | unverifiable_ephemeral_key
      - ``remediation``: operator action to make evidence verifiable, or null when it already is
      - ``key_id``: stable 16-hex prefix of SHA-256(DER public key) — identifies the key across rotations
      - ``public_key_pem``: PEM-encoded public key (Ed25519 only)
      - ``key_distribution``: guidance for verifiers
    """
    from agent_bom.api.compliance_signing import describe_signer_disclosure

    disclosure = describe_signer_disclosure()
    return {
        "algorithm": disclosure.algorithm,
        "key_id": disclosure.key_id,
        "public_key_pem": disclosure.public_key_pem,
        "signature_verifiable": disclosure.signature_verifiable,
        "persists_across_restart": disclosure.persists_across_restart,
        "verification_status": disclosure.verification_status,
        "remediation": disclosure.remediation,
        "key_distribution": disclosure.verification_guidance,
    }


@router.get("/compliance/aisvs", tags=["compliance"])
async def get_aisvs_compliance(request: Request) -> dict:
    """Return the latest tenant-scoped OWASP AISVS benchmark result from completed scans."""
    return _latest_aisvs_benchmark_from_jobs(_tenant_jobs(request))


@router.get("/compliance/summary", tags=["compliance"])
async def get_compliance_summary(request: Request) -> dict:
    """Return aggregate compliance score and per-framework status counts.

    Keep this literal route above /v1/compliance/{framework}; otherwise FastAPI
    correctly treats "summary" as a framework slug.
    """
    full = await get_compliance(request)
    summary_keys = {
        "overall_score",
        "overall_status",
        # overall_score is a percentage of EVALUATED controls, so its
        # denominator travels with it on every surface that renders it (see the
        # comment where these are computed in get_compliance). Omitting them
        # here left the Overview rendering a bare percentage it could not
        # qualify.
        "evaluated_controls",
        "total_controls",
        "scan_count",
        "latest_scan",
        "has_mcp_context",
        "has_agent_context",
        "scan_sources",
        "summary",
    }
    response = {key: full.get(key) for key in summary_keys if key in full}

    # With zero completed scans nothing was evaluated: every control trivially
    # lacks findings, so the per-control "pass" statuses and the *_pass counts
    # from get_compliance would read as all-pass / fully compliant. That is the
    # same false assurance /v1/compliance guards against with overall_status=
    # "no_data" — so mirror it here and report not_evaluated instead of pass.
    no_data = int(full.get("scan_count") or 0) == 0

    from agent_bom.compliance_coverage import TAG_MAPPED_FRAMEWORKS

    overlay_keys = {metadata.output_key for metadata in TAG_MAPPED_FRAMEWORKS if not metadata.scored}

    def _control_status_counts(value: list[object]) -> tuple[int, int, int, int] | None:
        controls = [item for item in value if isinstance(item, dict) and isinstance(item.get("status"), str)]
        if not controls:
            return None
        pass_count = sum(1 for item in controls if item.get("status") == "pass")
        warn_count = sum(1 for item in controls if item.get("status") == "warning")
        fail_count = sum(1 for item in controls if item.get("status") == "fail")
        return len(controls), pass_count, warn_count, fail_count

    framework_summary: dict[str, dict[str, int | None]] = {}
    for key, value in full.items():
        if isinstance(value, list):
            counts = _control_status_counts(value)
            if counts is None:
                continue
            controls, pass_count, warn_count, fail_count = counts
            if key in overlay_keys:
                # An applicability overlay has no pass/warn/fail. Emitting zeros
                # would read as "0 of N passing"; report applicability instead.
                applicable = sum(1 for item in value if isinstance(item, dict) and item.get("status") == "applicable")
                framework_summary[key] = {
                    "controls": controls,
                    "scored": False,
                    "applicable": 0 if no_data else applicable,
                    "not_applicable": controls if no_data else controls - applicable,
                }
                continue
            if no_data:
                pass_count = warn_count = fail_count = 0
            framework_summary[key] = {
                "controls": controls,
                "scored": True,
                "pass": pass_count,
                "warning": warn_count,
                "fail": fail_count,
                "not_evaluated": controls - pass_count - warn_count - fail_count,
            }
    response["frameworks"] = framework_summary

    # When no_data the aggregate (get_compliance) already emits 0 pass/warn/fail
    # and a per-framework *_not_evaluated count equal to the catalogue size, so
    # the pass-through summary above is already honest — no reinterpretation
    # needed here.

    return response


@router.get("/compliance/nist-800-53", tags=["compliance"])
async def get_compliance_nist_800_53(
    request: Request,
    status: str | None = None,
    include_not_evaluated: bool = False,
) -> dict:
    """Drill the catalog-backed NIST SP 800-53 Rev 5 line.

    Returns per-control status (pass / fail / error / not_evaluated), the
    vendor-asserted evidencing checks behind each evaluated control, a family
    rollup for scale-aware navigation, and the ISO/IEC 27001 attribution derived
    BY ID from NIST's official SP 800-53 → ISO crosswalk (identifiers only; no
    copyrighted ISO title text).

    The headline ``summary``/``score``/``status`` are the SAME values the
    ``/v1/compliance`` ``nist_800_53_catalog`` line reports (one source of
    truth). By default only EVALUATED controls are listed — the ~1000-control
    ``not_evaluated`` remainder is a count, not a mile-long tower. Pass
    ``include_not_evaluated=true`` to enumerate the full catalog; ``status=``
    (comma-separated) filters the displayed control list WITHOUT changing the
    counts. Declared before ``/compliance/{framework}`` so FastAPI does not treat
    ``nist-800-53`` as a tag-mapped framework slug.
    """
    full = await get_compliance(request)
    return build_nist_800_53_drill(
        full["nist_800_53_catalog"],
        status=status,
        include_not_evaluated=include_not_evaluated,
    )


@router.get("/compliance/{framework}", tags=["compliance"])
async def get_compliance_by_framework(request: Request, framework: str) -> dict:
    """Get compliance posture for a single framework.

    Supported frameworks: owasp-llm, owasp-mcp, atlas, nist, owasp-agentic, eu-ai-act,
    nist-csf, iso-27001, soc2, cis, cmmc, aisvs
    """
    if framework.lower() == "aisvs":
        return await get_aisvs_compliance(request)

    full = await get_compliance(request)

    from agent_bom.compliance_coverage import framework_output_key_by_slug, normalize_framework_slug

    framework_map = framework_output_key_by_slug()

    canonical = normalize_framework_slug(framework)
    key = framework_map.get(canonical)
    if not key:
        supported = [*framework_map.keys(), "aisvs"]
        raise HTTPException(
            status_code=400,
            detail=f"Unknown framework '{framework}'. Supported: {', '.join(supported)}",
        )

    controls = full.get(key, [])
    # With zero completed scans every control trivially "passes" (no findings map
    # to it), so reporting score 100 / "fully compliant" is compliance theater.
    # Detect it from the aggregate's scan_count — the same no_data signal the
    # summary endpoint uses — and surface an explicit no_data status instead.
    no_data = int(full.get("scan_count") or 0) == 0
    pass_count = sum(1 for c in controls if c["status"] == "pass")
    warn_count = sum(1 for c in controls if c["status"] == "warning")
    fail_count = sum(1 for c in controls if c["status"] == "fail")

    if no_data or not controls:
        pass_count = warn_count = fail_count = 0

    # Same scorer as the aggregate. The hand-rolled chain this replaces —
    # ``"fail" if fail_count else "warning" if warn_count else "pass"`` — fell
    # through to "pass" whenever all three counts were 0, so a framework that
    # was never evaluated (SOC 2 on a zero-finding estate: pass 0, warning 0,
    # fail 0) reported a passing status, and a framework whose only passes were
    # detective (CSF, CIS) reported a pass with a real score.
    detective_passes = sum(1 for c in controls if c.get("evaluation_mode") == MODE_DETECTIVE and c["status"] == "pass")
    verdict = score_compliance(
        passed=pass_count,
        warned=warn_count,
        failed=fail_count,
        detective_passes=0 if no_data or not controls else detective_passes,
        has_evidence=not no_data and bool(controls),
    )

    return {
        "framework": framework,
        "status": verdict.status,
        "controls": controls,
        "summary": {"pass": pass_count, "warning": warn_count, "fail": fail_count},
        "score": verdict.score,
        # The score is a percentage of EVALUATED controls, never of the whole
        # catalogue — it does not travel without its denominator.
        "evaluated_controls": verdict.evaluated,
        "total_controls": len(controls),
    }


# ─── Signed evidence bundle ────────────────────────────────────────────────


def _parse_iso_or_default(value: str | None, default: datetime) -> datetime:
    """Parse an ISO-8601 timestamp; fall back to ``default`` on missing/invalid."""
    if not value:
        return default
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as exc:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid timestamp '{value}'. Use ISO-8601 with timezone.",
        ) from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def _evidence_for_control(
    control: dict,
    blast_radii_by_tag: dict[str, list[dict]],
) -> list[dict]:
    """Map a control's tags onto the matching blast-radius findings."""
    seen_finding_ids: set[str] = set()
    evidence: list[dict] = []
    tags = list(control.get("tags", []) or [])
    fallback_tag = control.get("control_id") or control.get("code") or control.get("id")
    if fallback_tag and fallback_tag not in tags:
        tags.append(str(fallback_tag))
    for tag in tags:
        for br in blast_radii_by_tag.get(tag, []):
            finding_id = br.get("finding_id") or f"{br.get('vulnerability_id', '')}@{br.get('package', '')}"
            if finding_id in seen_finding_ids:
                continue
            seen_finding_ids.add(finding_id)
            evidence.append(
                {
                    "finding_id": finding_id,
                    "control_tag": tag,
                    "vulnerability_id": br.get("vulnerability_id"),
                    "package": br.get("package"),
                    "severity": br.get("severity"),
                    "scan_id": br.get("scan_id"),
                    "scan_input": br.get("scan_input") or {},
                    "scanner_version": br.get("scanner_version"),
                    "scan_started_at": br.get("scan_started_at"),
                    "scan_completed_at": br.get("scan_completed_at"),
                    "policy_decisions": br.get("policy_decisions") or [],
                    "provenance": br.get("provenance") or {},
                    "fixed_version": br.get("fixed_version"),
                    "agents_at_risk": br.get("affected_agents") or [],
                }
            )
    return evidence


def _scan_request_payload(job: Any) -> dict:
    request = getattr(job, "request", None)
    if request is None:
        return {}
    if hasattr(request, "model_dump"):
        return cast(dict, request.model_dump(exclude_none=True))
    if hasattr(request, "dict"):
        return cast(dict, request.dict(exclude_none=True))
    if isinstance(request, dict):
        return {k: v for k, v in request.items() if v is not None}
    return {}


def _index_blast_radii_by_tag(jobs: list) -> dict[str, list[dict]]:
    """Build a flat tag → list[blast-radius] index across all completed scans."""
    from agent_bom.compliance_coverage import COMPLIANCE_TAG_FIELDS

    by_tag: dict[str, list[dict]] = {}
    for job in jobs:
        if job.status != JobStatus.DONE or not job.result:
            continue
        scan_id = job.result.get("scan_id") or job.job_id
        scan_context = {
            "scan_id": scan_id,
            "scan_input": _scan_request_payload(job),
            "scanner_version": job.result.get("scanner_version") or job.result.get("agent_bom_version"),
            "scan_started_at": getattr(job, "created_at", None),
            "scan_completed_at": getattr(job, "completed_at", None),
            "policy_decisions": job.result.get("policy_decisions") or [],
            "provenance": job.result.get("provenance") or job.result.get("scan_provenance") or {},
        }
        for br in job.result.get("blast_radius", []):
            br_with_scan = {**br, **scan_context}
            for tag_field in COMPLIANCE_TAG_FIELDS:
                for tag in br.get(tag_field, []) or []:
                    by_tag.setdefault(tag, []).append(br_with_scan)
    return by_tag


def _bundle_control_status(
    source_status: str,
    evidence: list[dict],
    *,
    has_completed_scans: bool,
    evaluation_mode: str | None = None,
) -> tuple[str, str]:
    """Map an API control status onto its bundle status + evidence state.

    The bundle is the auditor's copy of what the API reports, so it must not
    invent a different verdict. Two statuses previously had no mapping and fell
    through to ``not_evaluated``/``incomplete``, making the signed artifact
    contradict the live API:

    * A **detective** control (RA-5, CM-8, CIS-07.1 …) passes because a
      completed, in-window scan IS the control operating. The taggers
      deliberately never map findings onto it, so demanding finding evidence
      downgraded every detective pass to ``incomplete`` — a bar it could not
      ever clear. Its evidence is the scan, recorded as ``scan_evidence``.
    * **Applicability-overlay** statuses (MITRE ATT&CK ``applicable`` /
      ``not_applicable``) are not pass/fail claims at all and pass through
      unchanged, so the overlay's counters stop reading 0.
    """
    status = (source_status or "unknown").lower()
    if not has_completed_scans:
        return "not_evaluated", "missing_scan"
    if status in {"applicable", "not_applicable"}:
        return status, "complete" if evidence else status
    if status == "pass" and evaluation_mode == MODE_DETECTIVE:
        return "pass", "scan_evidence"
    if status in {"pass", "warning", "fail"} and not evidence:
        return "incomplete", "missing_control_evidence"
    if evidence:
        return status, "complete"
    if status in {"not_evaluated", "incomplete", "not_assessed"}:
        return status, status
    return "not_evaluated", "missing_control_evidence"


def _detective_pass_count(controls: list[dict], ceiling: int | None = None) -> int:
    """How many of ``controls`` pass ONLY because a scan ran.

    ``score_compliance`` subtracts these to decide whether anything substantive
    was measured. ``ceiling`` clamps the result to the caller's own pass count,
    which can be lower when a control's bundle status differs from its API
    status (an overlay entry, or a pass without finding evidence).
    """
    count = sum(1 for c in controls if c.get("evaluation_mode") == MODE_DETECTIVE and str(c.get("status", "")).lower() == "pass")
    return min(count, ceiling) if ceiling is not None else count


def _verify_audit_entries(entries: list) -> tuple[int, int]:
    """Verify only the entries included in the exported bundle."""
    verified = 0
    tampered = 0
    for entry in entries:
        if entry.verify():
            verified += 1
        else:
            tampered += 1
    return verified, tampered


def _enrich_controls_with_evidence(
    controls: list[dict],
    blast_by_tag: dict[str, list[dict]],
    *,
    completed_scan_count: int,
) -> tuple[list[dict], int, set[str], dict[str, int]]:
    """Pair each control with its blast-radius evidence and roll up bundle-status counts.

    Shared by the single-framework report bundle and the multi-framework
    evidence pack so both surfaces map controls to findings identically.

    Returns ``(controls, evidence_row_count, distinct_finding_ids, status_counts)``.
    A finding maps to many controls, so the row count is always >= the number of
    distinct findings. Reporting rows as a "finding count" made a 25-finding
    tenant read as 1342 findings in a document handed to an auditor; the two are
    now counted and named separately.
    """
    enriched_controls: list[dict] = []
    evidence_row_count = 0
    distinct_finding_ids: set[str] = set()
    for control in controls:
        evidence = _evidence_for_control(control, blast_by_tag)
        evidence_row_count += len(evidence)
        distinct_finding_ids.update(str(row.get("finding_id")) for row in evidence if row.get("finding_id"))
        source_status = str(control.get("status", "unknown")).lower()
        bundle_status, evidence_state = _bundle_control_status(
            source_status,
            evidence,
            has_completed_scans=completed_scan_count > 0,
            evaluation_mode=control.get("evaluation_mode"),
        )
        enriched_controls.append(
            {
                "control_id": control.get("control_id") or control.get("id"),
                "control_name": control.get("name") or control.get("title"),
                "status": bundle_status,
                "source_status": source_status,
                "evidence_state": evidence_state,
                "finding_count": len(evidence),
                "evidence": evidence,
            }
        )
    counts = {
        "pass": sum(1 for c in enriched_controls if c.get("status") == "pass"),
        "warning": sum(1 for c in enriched_controls if c.get("status") == "warning"),
        "fail": sum(1 for c in enriched_controls if c.get("status") == "fail"),
        "incomplete": sum(1 for c in enriched_controls if c.get("status") == "incomplete"),
        "not_evaluated": sum(1 for c in enriched_controls if c.get("status") == "not_evaluated"),
        # Applicability-overlay entries (MITRE ATT&CK) are not controls the
        # estate passed or failed; they are counted, never scored.
        "applicable": sum(1 for c in enriched_controls if c.get("status") == "applicable"),
        "not_applicable": sum(1 for c in enriched_controls if c.get("status") == "not_applicable"),
    }
    return enriched_controls, evidence_row_count, distinct_finding_ids, counts


@router.get("/compliance/{framework}/report", tags=["compliance"], response_model=ComplianceReportBundle)
async def export_compliance_report(
    request: Request,
    framework: str,
    since: str | None = None,
    until: str | None = None,
    format: str = "json",
) -> JSONResponse | PlainTextResponse | StreamingResponse:
    """Export a tamper-evident signed evidence bundle for a single framework.

    The bundle pairs each control with the blast-radius findings that map to
    its tags, the audit-log entries within the requested time window, and
    integrity totals from the HMAC-chained log.

    Security properties of the bundle:

    - **Integrity** — ``X-Agent-Bom-Compliance-Report-Signature`` is the
      HMAC-SHA256 of the canonical body. Any tampering with any field
      invalidates the signature.
    - **Replay protection** — the body carries ``nonce`` (128-bit) and
      ``expires_at``; both are inside the signed envelope so a captured
      bundle cannot be re-used after its expiry window. Consumers should
      reject bundles where ``expires_at`` is in the past.
    - **Confidentiality** — the bundle is cleartext at the application
      layer by design (auditors need to read it). Operators MUST serve
      ``/v1/compliance/*`` over TLS so evidence is not sniffable in
      transit.
    - **Non-repudiation** — HMAC is a shared secret so it does not provide
      true non-repudiation; for forensic use, correlate with the
      ``compliance.report_exported`` entry in the audit log (which
      records the nonce of every exported bundle).
    - **Tenant isolation** — controls evidence and audit events are
      filtered by the authed tenant; cross-tenant data never appears
      in a bundle belonging to another tenant.

    Query params:
      - ``since`` ISO-8601 timestamp (default: now − 30 days)
      - ``until`` ISO-8601 timestamp (default: now)
      - ``format`` ``json`` (default) or ``jsonl`` for streaming consumers
    """
    fmt = format.lower()
    if fmt not in {"json", "jsonl"}:
        raise HTTPException(status_code=400, detail="format must be one of: json, jsonl")

    now = datetime.now(timezone.utc)
    since_dt = _parse_iso_or_default(since, now - timedelta(days=30))
    until_dt = _parse_iso_or_default(until, now)
    if since_dt >= until_dt:
        raise HTTPException(status_code=400, detail="since must be earlier than until")

    full = await get_compliance(request)
    from agent_bom.compliance_coverage import framework_report_labels_by_slug

    framework_map = framework_report_labels_by_slug()
    key_label = framework_map.get(framework.lower())
    if not key_label:
        raise HTTPException(
            status_code=400,
            detail=f"Unknown framework '{framework}'. Supported: {', '.join(framework_map.keys())}",
        )
    framework_key, framework_label = key_label
    controls = full.get(framework_key, [])

    tenant_id = _tenant_id(request)
    actor = getattr(request.state, "api_key_name", "") or "system"

    tenant_jobs = _tenant_jobs(request)
    blast_by_tag = _index_blast_radii_by_tag(tenant_jobs)

    from agent_bom.api.audit_log import get_audit_log, log_action

    store = get_audit_log()
    audit_since_iso = since_dt.isoformat()
    # Cap audit fetch for export sanity; consumers paginate further via /v1/audit.
    # ``list_entries`` returns most-recent-first, so hitting the cap drops the
    # OLDEST in-window entries — the bundle must say so rather than present a
    # partial window as complete.
    audit_fetch_limit = _AUDIT_EVIDENCE_FETCH_LIMIT
    audit_entries = store.list_entries(since=audit_since_iso, limit=audit_fetch_limit, tenant_id=tenant_id)
    audit_truncated = len(audit_entries) >= audit_fetch_limit
    until_iso = until_dt.isoformat()
    audit_in_window = [e for e in audit_entries if audit_since_iso <= (e.timestamp or "") <= until_iso]
    verified, tampered = _verify_audit_entries(audit_in_window)

    completed_scan_count = sum(1 for job in tenant_jobs if job.status == JobStatus.DONE and bool(job.result))
    enriched_controls, evidence_row_count, distinct_finding_ids, status_counts = _enrich_controls_with_evidence(
        controls,
        blast_by_tag,
        completed_scan_count=completed_scan_count,
    )
    pass_count = status_counts["pass"]
    warn_count = status_counts["warning"]
    fail_count = status_counts["fail"]
    incomplete_count = status_counts["incomplete"]
    not_evaluated_count = status_counts["not_evaluated"]

    # An applicability overlay (ATT&CK) has no pass rate: a score would read as
    # "0% of ATT&CK passing" for something that cannot pass. Null says so — the
    # applicable counters carry the signal. Matches the evidence pack, which
    # already nulls the score for a scored=False framework.
    from agent_bom.compliance_coverage import TAG_MAPPED_FRAMEWORKS

    bundle_scored = next((m.scored for m in TAG_MAPPED_FRAMEWORKS if m.output_key == framework_key), True)
    # Same scorer as every other surface; the detective passes it discounts are
    # the ones the bundle now preserves rather than downgrading to incomplete.
    bundle_verdict = score_compliance(
        passed=pass_count,
        warned=warn_count,
        failed=fail_count,
        detective_passes=_detective_pass_count(controls, pass_count),
        has_evidence=completed_scan_count > 0,
    )

    # Replay-protection envelope: every bundle carries a fresh 128-bit nonce
    # and an explicit expiry. The signature is computed over the canonical
    # body that includes both, so tampering with either invalidates the
    # signature and a captured bundle cannot be re-used after expiry.
    nonce = secrets.token_hex(16)
    bundle_ttl_seconds = int(os.environ.get("AGENT_BOM_COMPLIANCE_BUNDLE_TTL_SECONDS", "86400"))
    bundle_ttl_seconds = max(60, min(bundle_ttl_seconds, 30 * 86400))  # 1 min to 30 days
    expires_at = now + timedelta(seconds=bundle_ttl_seconds)

    # Resolve signer config up-front so the algorithm, key_id, and public key
    # are part of the canonical body that gets signed — verifiers read the
    # same fields and reconstruct the exact canonical form.
    from agent_bom.api.compliance_signing import (
        canonical_bundle_payload,
        describe_signer_disclosure,
        sign_compliance_bundle,
    )

    signer = describe_signer_disclosure()
    signing_algorithm = signer.algorithm
    signing_key_id = signer.key_id
    signing_public_key_pem = signer.public_key_pem

    body: dict[str, Any] = {
        "schema_version": "v1",
        "framework": framework,
        "framework_key": framework_key,
        "framework_label": framework_label,
        "tenant_id": tenant_id,
        "generated_at": now.isoformat(),
        "expires_at": expires_at.isoformat(),
        "nonce": nonce,
        "scope": {
            "since": since_dt.isoformat(),
            "until": until_dt.isoformat(),
            "control_count": len(controls),
            # One finding maps to many controls. ``evidence_row_count`` counts
            # control-to-finding mapping rows; ``distinct_finding_count`` counts
            # the findings themselves and reconciles with /v1/findings.
            "evidence_row_count": evidence_row_count,
            "distinct_finding_count": len(distinct_finding_ids),
            "audit_event_count": len(audit_in_window),
            "audit_events_truncated": audit_truncated,
            "audit_event_limit": audit_fetch_limit,
            "completed_scan_count": completed_scan_count,
        },
        "summary": {
            "pass": pass_count,
            "warning": warn_count,
            "fail": fail_count,
            "incomplete": incomplete_count,
            "not_evaluated": not_evaluated_count,
            "applicable": status_counts["applicable"],
            "not_applicable": status_counts["not_applicable"],
            "score": bundle_verdict.score if bundle_scored else None,
            "status": bundle_verdict.status if bundle_scored else "not_scored",
            # The score is over EVALUATED controls; it never travels alone.
            "evaluated": bundle_verdict.evaluated,
        },
        "controls": enriched_controls,
        "audit_events": [entry.to_dict() for entry in audit_in_window],
        "audit_log_integrity": {
            "verified": verified,
            "tampered": tampered,
            "checked": len(audit_in_window),
            "truncated": audit_truncated,
        },
        "signature_algorithm": signing_algorithm,
        # Verifiability travels INSIDE the signed envelope (everything except
        # `signature` is canonicalised and signed), so a bundle from a
        # default deployment — per-process HMAC key, verifiable by nobody —
        # cannot be handed to an auditor with the disclosure quietly removed.
        "signature_disclosure": signer.as_bundle_field(),
        "threat_model": {
            "integrity": (
                f"{signing_algorithm} over the canonical UTF-8 body. Tampering with any field invalidates the signature."
                if signer.signature_verifiable
                else f"{signing_algorithm} over the canonical UTF-8 body, but with a signing key no verifier can hold — "
                "see signature_disclosure. Treat this bundle as unsigned evidence until the deployment is reconfigured "
                "and the bundle re-exported."
            ),
            "confidentiality": (
                "The bundle is cleartext at the application layer by design — auditors "
                "need to read it. Operators MUST serve /v1/compliance/* over TLS so the "
                "bundle is not sniffable in transit."
            ),
            "replay": (
                "nonce + expires_at are inside the signed envelope. A re-issued bundle "
                "past expires_at is expected to be rejected by the consumer."
            ),
            "non_repudiation": (
                "Ed25519 provides asymmetric non-repudiation — verifiers only need the "
                "public key (at /v1/compliance/verification-key). HMAC is a shared secret "
                "so it does NOT provide true non-repudiation; for forensic cases cross-"
                "reference the compliance.report_exported audit entry."
                if signing_algorithm == "Ed25519"
                else "HMAC is a shared secret between server and auditor; it does NOT provide "
                "true non-repudiation. For forensic cases requiring non-repudiation, "
                "cross-reference the compliance.report_exported audit entry, or configure "
                "AGENT_BOM_COMPLIANCE_ED25519_PRIVATE_KEY_PEM to switch to Ed25519 signing."
            ),
        },
    }
    if signing_key_id is not None:
        body["signature_key_id"] = signing_key_id
    if signing_public_key_pem is not None:
        body["signature_public_key_pem"] = signing_public_key_pem

    # Embed the signature IN the document. Shipping it only as a response header
    # meant `curl -o bundle.json` produced a file that advertised
    # signature_algorithm and carried nothing to verify. The signature covers the
    # canonical body with the `signature` field itself removed
    # (compliance_signing.canonical_bundle_payload) — the same canonical form for
    # both the json and jsonl renderings, so either saved artifact verifies
    # identically and byte-preserving the HTTP stream is no longer required.
    canonical = canonical_bundle_payload(body)
    bundle_signature = sign_compliance_bundle(canonical)
    body["signature"] = bundle_signature.signature_hex

    log_action(
        "compliance.report_exported",
        actor=actor,
        resource=f"compliance/{framework_key}",
        tenant_id=tenant_id,
        format=fmt,
        since=since_dt.isoformat(),
        until=until_dt.isoformat(),
        control_count=len(controls),
        evidence_row_count=evidence_row_count,
        distinct_finding_count=len(distinct_finding_ids),
        audit_event_count=len(audit_in_window),
        nonce=nonce,
        expires_at=expires_at.isoformat(),
    )

    filename = f"agent-bom-compliance-{framework_key.replace('_', '-')}.{'jsonl' if fmt == 'jsonl' else 'json'}"

    def _signing_headers() -> dict[str, str]:
        """Mirror the embedded signature into headers for streaming consumers."""
        headers = {
            "X-Agent-Bom-Compliance-Report-Signature": bundle_signature.signature_hex,
            "X-Agent-Bom-Compliance-Signature-Algorithm": bundle_signature.algorithm,
        }
        if bundle_signature.key_id is not None:
            headers["X-Agent-Bom-Compliance-Signature-KeyId"] = bundle_signature.key_id
        return headers

    from agent_bom.api.metrics import record_compliance_export

    if fmt == "jsonl":
        # jsonl streams one control per line so SIEM and security-lake
        # consumers can ingest without loading the whole bundle. The meta line
        # carries the same embedded `signature` as the json rendering, and it
        # covers the same canonical JSON body — a consumer reassembles
        # meta + controls + audit_events and verifies without depending on the
        # stream's byte layout.
        lines = [json.dumps({"meta": {k: v for k, v in body.items() if k not in {"controls", "audit_events"}}}, sort_keys=True)]
        for control in body["controls"]:
            lines.append(json.dumps({"control": control}, sort_keys=True))
        for entry in body["audit_events"]:
            lines.append(json.dumps({"audit": entry}, sort_keys=True))
        payload = ("\n".join(lines) + "\n").encode()
        record_compliance_export(signing_algorithm, framework_key, len(payload))

        async def _iter_chunks(data: bytes, chunk_size: int = 64 * 1024) -> AsyncIterator[bytes]:
            for offset in range(0, len(data), chunk_size):
                yield data[offset : offset + chunk_size]

        return StreamingResponse(
            _iter_chunks(payload),
            media_type="application/x-ndjson",
            headers={
                "Content-Disposition": f'attachment; filename="{filename}"',
                "Content-Length": str(len(payload)),
                **_signing_headers(),
            },
        )

    record_compliance_export(signing_algorithm, framework_key, len(json.dumps(body, sort_keys=True).encode()))
    return JSONResponse(
        content=body,
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            **_signing_headers(),
        },
    )


# ─── Multi-framework evidence pack ─────────────────────────────────────────


@router.get("/compliance/report/pack", tags=["compliance"])
async def export_compliance_pack(
    request: Request,
    since: str | None = None,
    until: str | None = None,
) -> JSONResponse:
    """Export one signed evidence pack covering every tag-mapped framework.

    This is the auditor "grab everything" download: instead of pulling a
    per-framework bundle from ``/v1/compliance/{framework}/report`` one at a
    time, operators get a single tamper-evident JSON with each framework's
    controls, mapped findings, and the shared audit-window integrity totals.

    The pack shares the single-bundle security envelope: a fresh 128-bit
    ``nonce`` and explicit ``expires_at`` are inside the signed body, the
    signature (``X-Agent-Bom-Compliance-Report-Signature``) covers the
    canonical UTF-8 body, and every framework's evidence + the audit events
    are tenant-filtered so cross-tenant data never leaks into the pack.
    """
    now = datetime.now(timezone.utc)
    since_dt = _parse_iso_or_default(since, now - timedelta(days=30))
    until_dt = _parse_iso_or_default(until, now)
    if since_dt >= until_dt:
        raise HTTPException(status_code=400, detail="since must be earlier than until")

    full = await get_compliance(request)
    from agent_bom.compliance_coverage import framework_report_labels_by_slug

    framework_map = framework_report_labels_by_slug()

    tenant_id = _tenant_id(request)
    actor = getattr(request.state, "api_key_name", "") or "system"

    tenant_jobs = _tenant_jobs(request)
    blast_by_tag = _index_blast_radii_by_tag(tenant_jobs)
    completed_scan_count = sum(1 for job in tenant_jobs if job.status == JobStatus.DONE and bool(job.result))

    from agent_bom.api.audit_log import get_audit_log, log_action

    store = get_audit_log()
    audit_since_iso = since_dt.isoformat()
    # Same honest-truncation contract as the single-framework report: a window
    # deeper than the cap is marked truncated, never presented as complete.
    audit_fetch_limit = _AUDIT_EVIDENCE_FETCH_LIMIT
    audit_entries = store.list_entries(since=audit_since_iso, limit=audit_fetch_limit, tenant_id=tenant_id)
    audit_truncated = len(audit_entries) >= audit_fetch_limit
    until_iso = until_dt.isoformat()
    audit_in_window = [e for e in audit_entries if audit_since_iso <= (e.timestamp or "") <= until_iso]
    verified, tampered = _verify_audit_entries(audit_in_window)

    from agent_bom.compliance_coverage import TAG_MAPPED_FRAMEWORKS

    scored_by_slug = {metadata.slug: metadata.scored for metadata in TAG_MAPPED_FRAMEWORKS}

    framework_bundles: list[dict[str, Any]] = []
    total_evidence_rows = 0
    all_finding_ids: set[str] = set()
    total_controls = 0
    combined_summary = {
        "pass": 0,
        "warning": 0,
        "fail": 0,
        "incomplete": 0,
        "not_evaluated": 0,
        "applicable": 0,
        "not_applicable": 0,
    }
    combined_detective_passes = 0
    for slug, (framework_key, framework_label) in framework_map.items():
        controls = full.get(framework_key, [])
        scored = scored_by_slug.get(slug, True)
        enriched_controls, framework_rows, framework_finding_ids, status_counts = _enrich_controls_with_evidence(
            controls,
            blast_by_tag,
            completed_scan_count=completed_scan_count,
        )
        total_evidence_rows += framework_rows
        all_finding_ids |= framework_finding_ids
        if scored:
            total_controls += len(controls)
        for key in combined_summary:
            combined_summary[key] += status_counts[key]
        if scored:
            combined_detective_passes += _detective_pass_count(controls, status_counts["pass"])
        framework_bundles.append(
            {
                "framework": slug,
                "framework_key": framework_key,
                "framework_label": framework_label,
                # An applicability overlay has no pass rate to report — a score
                # would read as "0% of ATT&CK passing" for something that cannot
                # pass. Null says so; the applicable counts carry the signal.
                "scored": scored,
                "summary": {
                    **status_counts,
                    "score": (
                        score_compliance(
                            passed=status_counts["pass"],
                            warned=status_counts["warning"],
                            failed=status_counts["fail"],
                            detective_passes=_detective_pass_count(controls, status_counts["pass"]),
                            has_evidence=completed_scan_count > 0,
                        ).score
                        if scored
                        else None
                    ),
                },
                "control_count": len(controls),
                "evidence_row_count": framework_rows,
                "distinct_finding_count": len(framework_finding_ids),
                "controls": enriched_controls,
            }
        )

    nonce = secrets.token_hex(16)
    bundle_ttl_seconds = int(os.environ.get("AGENT_BOM_COMPLIANCE_BUNDLE_TTL_SECONDS", "86400"))
    bundle_ttl_seconds = max(60, min(bundle_ttl_seconds, 30 * 86400))
    expires_at = now + timedelta(seconds=bundle_ttl_seconds)

    from agent_bom.api.compliance_signing import (
        canonical_bundle_payload,
        describe_signer_disclosure,
        sign_compliance_bundle,
    )

    signer = describe_signer_disclosure()
    signing_algorithm = signer.algorithm
    signing_key_id = signer.key_id
    signing_public_key_pem = signer.public_key_pem

    body: dict[str, Any] = {
        "schema_version": "v1",
        "document_type": "compliance-evidence-pack",
        "tenant_id": tenant_id,
        "generated_at": now.isoformat(),
        "expires_at": expires_at.isoformat(),
        "nonce": nonce,
        "scope": {
            "since": since_dt.isoformat(),
            "until": until_dt.isoformat(),
            "framework_count": len(framework_bundles),
            # Scored controls only — an applicability overlay has no controls to
            # count toward a control total.
            "control_count": total_controls,
            # A single finding maps to many controls across many frameworks, so
            # summing per-framework counts yields MAPPING ROWS, not findings.
            # Reporting rows as `finding_count` made a 25-finding tenant read as
            # 1342 findings in a document handed to an auditor.
            # `distinct_finding_count` reconciles with the findings spine.
            "evidence_row_count": total_evidence_rows,
            "distinct_finding_count": len(all_finding_ids),
            "audit_event_count": len(audit_in_window),
            "audit_events_truncated": audit_truncated,
            "audit_event_limit": audit_fetch_limit,
            "completed_scan_count": completed_scan_count,
        },
        "summary": {
            **combined_summary,
            # Same scorer as every other surface. Scoring pass/total_controls
            # here let the pack disagree with the aggregate: once detective
            # passes were preserved (rather than downgraded to `incomplete`),
            # this reported 3.3% over an estate the aggregate calls no_data.
            "score": score_compliance(
                passed=combined_summary["pass"],
                warned=combined_summary["warning"],
                failed=combined_summary["fail"],
                detective_passes=min(combined_detective_passes, combined_summary["pass"]),
                has_evidence=completed_scan_count > 0,
            ).score,
        },
        "frameworks": framework_bundles,
        "audit_events": [entry.to_dict() for entry in audit_in_window],
        "audit_log_integrity": {
            "verified": verified,
            "tampered": tampered,
            "checked": len(audit_in_window),
            "truncated": audit_truncated,
        },
        "signature_algorithm": signing_algorithm,
        # Same in-envelope disclosure contract as the single-framework bundle.
        "signature_disclosure": signer.as_bundle_field(),
    }
    if signing_key_id is not None:
        body["signature_key_id"] = signing_key_id
    if signing_public_key_pem is not None:
        body["signature_public_key_pem"] = signing_public_key_pem

    # Same embedded-signature contract as the single-framework bundle: the pack
    # carries its own signature so a saved file is verifiable off-line.
    sig_result = sign_compliance_bundle(canonical_bundle_payload(body))
    body["signature"] = sig_result.signature_hex

    log_action(
        "compliance.pack_exported",
        actor=actor,
        resource="compliance/pack",
        tenant_id=tenant_id,
        since=since_dt.isoformat(),
        until=until_dt.isoformat(),
        framework_count=len(framework_bundles),
        control_count=total_controls,
        evidence_row_count=total_evidence_rows,
        distinct_finding_count=len(all_finding_ids),
        audit_event_count=len(audit_in_window),
        nonce=nonce,
        expires_at=expires_at.isoformat(),
    )

    from agent_bom.api.metrics import record_compliance_export

    record_compliance_export(signing_algorithm, "pack", len(json.dumps(body, sort_keys=True).encode()))
    headers = {
        "Content-Disposition": 'attachment; filename="agent-bom-compliance-pack.json"',
        "X-Agent-Bom-Compliance-Report-Signature": sig_result.signature_hex,
        "X-Agent-Bom-Compliance-Signature-Algorithm": sig_result.algorithm,
    }
    if sig_result.key_id is not None:
        headers["X-Agent-Bom-Compliance-Signature-KeyId"] = sig_result.key_id
    return JSONResponse(content=body, headers=headers)


# ─── Posture Scorecard ─────────────────────────────────────────────────────


@router.get("/posture", tags=["compliance"])
async def get_posture_scorecard(request: Request) -> dict:
    """Compute enterprise posture scorecard from the latest completed scan.

    Returns a letter grade (A-F), numeric score (0-100), and per-dimension
    breakdown covering vulnerability posture, credential hygiene, supply
    chain quality, compliance coverage, active exploitation, and configuration.
    """
    latest_result = None
    for job in _tenant_jobs(request):
        if job.status != JobStatus.DONE or not job.result:
            continue
        latest_result = job.result
        break  # list_all returns newest first

    if latest_result is None:
        return {
            "grade": "N/A",
            "score": 0,
            "summary": "No completed scans available",
            "dimensions": {},
            "no_data": True,
        }

    # Did-we-scan guard: a completed scan that examined ZERO gradable artifacts
    # must not report a passing grade. Mirror the honest no-data / N/A treatment
    # rather than surfacing a fallback "B" from empty-default dimensions.
    summary = latest_result.get("summary") or {}
    examined_artifacts = (
        int(summary.get("total_packages") or 0)
        + int(summary.get("total_mcp_servers") or 0)
        + int(summary.get("total_findings") or 0)
        + int(summary.get("total_vulnerabilities") or 0)
    )
    if examined_artifacts == 0:
        return {
            "grade": "N/A",
            "score": 0,
            "summary": "No artifacts scanned — posture grade unavailable. Connect a surface or run a scan to grade posture.",
            "dimensions": {},
            "no_data": True,
        }

    scorecard = latest_result.get("posture_scorecard")
    if scorecard:
        return cast(dict, scorecard)

    return {
        "grade": "N/A",
        "score": 0,
        "summary": "Scorecard not computed for this scan",
        "dimensions": {},
        "no_data": True,
    }


@router.get("/posture/enrichment", tags=["compliance"])
async def get_enrichment_posture() -> dict:
    """Report runtime health for external vulnerability enrichment sources."""

    from agent_bom.enrichment_posture import describe_enrichment_posture

    return describe_enrichment_posture()


@router.get("/posture/backpressure", tags=["compliance"], deprecated=True)
async def get_backpressure_posture() -> dict:
    """Report adaptive runtime backpressure state for expensive paths.

    Soft-deprecated: no UI/CLI/MCP product consumer (#3666 Phase 2).
    """

    from agent_bom.backpressure import describe_backpressure_posture

    return describe_backpressure_posture()


def _compound_issue_count(tenant_jobs: list[Any]) -> int:
    """Count high-priority compound issues from blast-radius correlation.

    A compound issue is a KEV vuln that is also reachable or exposes a
    credential, or a high-CVSS + high-EPSS vuln — the reachability/exposure
    correlation that lives in ``blast_radius`` (not a raw severity count).
    Deduped by vulnerability id across scans.
    """
    seen_ids: set[str] = set()
    compound = 0
    for job in tenant_jobs:
        if job.status != JobStatus.DONE or not job.result:
            continue
        for b in job.result.get("blast_radius", []):
            vid = b.get("vulnerability_id", "")
            if vid in seen_ids:
                continue
            seen_ids.add(vid)
            is_kev = bool(b.get("cisa_kev") or b.get("is_kev"))
            if is_kev and (b.get("reachable_tools") or b.get("exposed_credentials")):
                compound += 1
            elif (b.get("epss_score") or 0) >= 0.3 and (b.get("cvss_score") or 0) >= 7:
                compound += 1
    return compound


@router.get("/posture/counts", tags=["compliance"])
async def get_posture_counts(request: Request) -> dict:
    """Aggregate open-finding severity counts across all completed scans.

    Lightweight endpoint used by the dashboard nav to show Critical/High
    badges. Reads the SAME reconciled source of truth as the ``/v1/overview``
    exec headline — the unified findings spine folded with hub-ingested
    evidence (#3961) — so the nav badges can never disagree with the overview's
    critical/high. The CVE-only ``blast_radius`` is used only for the
    correlation-based ``compound_issues`` metric, where reachability/exposure
    lives. ``unrated`` is an explicit bucket so the histogram sums to ``total``.

    Returns:
        {critical, high, medium, low, unrated, total, kev, compound_issues, …}
    """
    try:
        async with adaptive_backpressure("overview"):
            return await anyio.to_thread.run_sync(_get_posture_counts_impl, request)
    except BackpressureRejectedError as exc:
        raise HTTPException(
            status_code=429,
            detail=exc.to_dict(),
            headers={"Retry-After": str(exc.retry_after_seconds)},
        ) from exc


def _get_posture_counts_impl(request: Request) -> dict:
    """Synchronous posture-count composition, executed in a worker thread."""
    from agent_bom.api.routes.overview import exec_severity_counts

    tenant_jobs = _tenant_jobs(request)
    reconciled = exec_severity_counts(request, tenant_jobs)
    counts: dict[str, Any] = {
        "critical": reconciled["critical"],
        "high": reconciled["high"],
        "medium": reconciled["medium"],
        "low": reconciled["low"],
        "unrated": reconciled["unrated"],
        "total": reconciled["total"],
        "kev": reconciled["kev"],
        "compound_issues": _compound_issue_count(tenant_jobs),
    }

    counts.update(_derive_deployment_context(request, tenant_jobs))
    tenant_id = require_request_tenant_id(request)
    from agent_bom.api.service_registry import derive_service_registry

    counts["services"] = derive_service_registry(tenant_id, dict(counts))["services"]
    return counts


@router.get("/posture/credentials", tags=["compliance"])
async def get_credential_risk_ranking(request: Request) -> dict:
    """Rank credentials by blast radius exposure from the latest scan.

    Returns credentials sorted by risk tier (critical to low) with
    associated vulnerability counts and affected agents.
    """
    tenant_id = _tenant_id(request)
    rotation_governance = _credential_rotation_governance(tenant_id)
    latest_result = None
    for job in _tenant_jobs(request):
        if job.status != JobStatus.DONE or not job.result:
            continue
        latest_result = job.result
        break

    if latest_result is None:
        return {"credentials": [], "count": 0, "rotation_governance": rotation_governance}

    ranking = latest_result.get("credential_risk_ranking", [])
    return {"credentials": ranking, "count": len(ranking), "rotation_governance": rotation_governance}


@router.get("/posture/incidents", tags=["compliance"])
async def get_incident_correlation(request: Request) -> dict:
    """Group vulnerabilities by agent for SOC incident correlation.

    Returns agent-centric incident summaries with priority (P1-P4),
    severity counts, credential exposure, and recommended actions.
    """
    latest_result = None
    for job in _tenant_jobs(request):
        if job.status != JobStatus.DONE or not job.result:
            continue
        latest_result = job.result
        break

    if latest_result is None:
        return {"incidents": [], "count": 0}

    incidents = latest_result.get("incident_correlation", [])
    incidents = redact_for_persistence(incidents, EvidenceTier.SAFE_TO_STORE)
    return {"incidents": incidents, "count": len(incidents)}


# ─── Compliance Hub (#1044 PR C) ──────────────────────────────────────────────


_HUB_VALID_FORMATS = ("sarif", "cyclonedx", "csv", "json")


def _native_hub_findings(request: Request) -> list[dict[str, Any]]:
    """Return native scan findings in the compliance-hub list shape.

    The hub posture endpoint already aggregates native scans and external
    ingests together. This keeps the list endpoint aligned with that contract
    so operators can drill into both sides of the combined posture count.
    """
    from agent_bom.api.routes.scan import _iter_scan_findings
    from agent_bom.compliance_coverage import TAG_MAPPED_FRAMEWORKS
    from agent_bom.compliance_hub import select_frameworks
    from agent_bom.finding import FindingSource, FindingType

    slug_to_tag_field: tuple[tuple[str, str], ...] = tuple((metadata.slug, metadata.tag_field) for metadata in TAG_MAPPED_FRAMEWORKS)
    rows: list[dict[str, Any]] = []
    for job in _tenant_jobs(request):
        if job.status != JobStatus.DONE or not job.result:
            continue
        for row in _iter_scan_findings(job):
            package_name = str(row.get("package") or row.get("package_name") or "")
            vulnerability_id = str(row.get("vulnerability_id") or row.get("cve_id") or row.get("id") or "")
            has_mcp_context = bool(row.get("affected_agents") or row.get("affected_servers"))
            source = FindingSource.MCP_SCAN if has_mcp_context else FindingSource.SBOM
            asset_type = "mcp_server" if has_mcp_context else "package"
            frameworks = [slug for slug, field in slug_to_tag_field if row.get(field)]
            if not frameworks:
                frameworks = select_frameworks(source, asset_type=asset_type, finding_type=FindingType.CVE)
            payload = {
                **row,
                "id": row.get("id") or f"{job.job_id}:{vulnerability_id}:{package_name}",
                "title": row.get("title") or f"{vulnerability_id or 'Vulnerability'} in {package_name or 'native scan asset'}",
                "finding_type": FindingType.CVE.value,
                "source": source.value,
                "origin": "native_scan",
                "asset": {
                    "name": package_name or vulnerability_id or "native scan asset",
                    "asset_type": asset_type,
                    "identifier": f"pkg:{package_name}" if package_name else None,
                    "location": None,
                    "stable_id": None,
                },
                "scan_id": job.job_id,
                "applicable_frameworks": frameworks,
                "effective_severity": row.get("severity", "unknown"),
            }
            clean = redact_for_persistence(payload, EvidenceTier.SAFE_TO_STORE)
            if isinstance(clean, dict):
                rows.append(clean)
    return rows


@router.post(
    "/compliance/ingest",
    tags=["compliance"],
    status_code=201,
    dependencies=[_dep("scan")],
)
async def ingest_compliance_findings(request: Request) -> dict:
    """Ingest external findings (SARIF / CycloneDX / CSV / JSON).

    Body:
        {"format": "sarif" | "cyclonedx" | "csv" | "json",
         "content": "<file body as a string>"}

    The content is parsed via the matching adapter in
    ``compliance_hub_ingest``; every produced finding is hub-classified
    and appended to the tenant's hub store. Returns the per-framework
    framework-hit breakdown so the caller can verify classification ran.
    """
    import tempfile
    from pathlib import Path

    from agent_bom.api.compliance_hub_store import get_compliance_hub_store
    from agent_bom.compliance_coverage import normalize_framework_slug
    from agent_bom.compliance_hub_ingest import ingest_findings

    body = await request.json()
    if not isinstance(body, dict):
        raise HTTPException(status_code=400, detail="Body must be a JSON object")
    fmt = (body.get("format") or "").lower()
    if fmt not in _HUB_VALID_FORMATS:
        raise HTTPException(
            status_code=400,
            detail=f"format must be one of {list(_HUB_VALID_FORMATS)}",
        )
    content = body.get("content")
    if not isinstance(content, str) or not content.strip():
        raise HTTPException(status_code=400, detail="content (string) is required")

    suffix = ".csv" if fmt == "csv" else ".json"
    with tempfile.NamedTemporaryFile(mode="w", suffix=suffix, delete=False, encoding="utf-8") as tmp:
        tmp.write(content)
        tmp_path = Path(tmp.name)

    try:
        findings = ingest_findings(tmp_path, fmt=fmt)
    finally:
        try:
            tmp_path.unlink(missing_ok=True)
        except OSError:
            pass

    if not findings:
        raise HTTPException(
            status_code=422,
            detail=f"No findings parsed from {fmt} content. Check the format matches the body shape (e.g. SARIF runs[].results[]).",
        )

    payloads = [f.to_dict() for f in findings]
    for payload in payloads:
        # Preserve the parser's semantic finding source (for example
        # ``EXTERNAL``) separately from the durable import stream used to scope
        # absent reconciliation.  Conflating the two made a CSV/SARIF
        # reconcile report success while resolving zero prior findings.
        payload["ingest_source"] = fmt
        payload["origin"] = "bulk_ingest"
        frameworks = payload.get("applicable_frameworks")
        if isinstance(frameworks, list):
            payload["applicable_frameworks"] = [normalize_framework_slug(str(slug)) for slug in frameworks if slug]
    tenant_id = _tenant_id(request)
    store = get_compliance_hub_store()
    from agent_bom.api.finding_lifecycle import normalize_observed_at

    observed_at = normalize_observed_at(body.get("observed_at"))
    # Deterministic batch id keyed on the Idempotency-Key header (if any) or the
    # request-content fingerprint, so re-POSTing the same document collapses onto
    # one observation batch instead of inflating ``scan_count`` on every resend
    # (P1-5). The (canonical, batch_id) observation key must be stable per body.
    from agent_bom.api.idempotency_store import deterministic_batch_id, idempotency_request_fingerprint

    idem_key = request.headers.get("Idempotency-Key") or ""
    batch_id = deterministic_batch_id(idem_key or idempotency_request_fingerprint(body))

    # Offload the blocking psycopg write sequence (ledger append + current-state
    # upsert + reconcile + delta emission) to a worker thread so concurrent
    # compliance ingest cannot freeze the event loop and unrelated requests
    # (mirrors the bulk ingest and read paths). See ``hub_ingest_store_writes`` /
    # ``hub_store_call``.
    from agent_bom.api.hub_ingest import hub_ingest_store_writes, hub_store_call
    from agent_bom.api.hub_observations_partition import ObservationPartitionRangeError

    try:
        store_result = await hub_store_call(
            hub_ingest_store_writes,
            store,
            tenant_id,
            payloads,
            observed_at=observed_at,
            batch_id=batch_id,
            source=fmt,
            reconcile_absent=bool(body.get("reconcile_absent")),
        )
    except ObservationPartitionRangeError as exc:
        # observed_at is so far past/future it is almost certainly bad data — a
        # clean 422 instead of a raw partition CheckViolation 500 (mirrors the
        # bulk ingest route).
        raise HTTPException(status_code=422, detail=sanitize_error(exc)) from exc
    new_total = store_result["new_total"]
    reconciled = store_result["reconciled"]
    delta_results = store_result["delta_results"]

    framework_counts: dict[str, int] = {}
    for payload in payloads:
        for slug in payload.get("applicable_frameworks") or []:
            framework_counts[slug] = framework_counts.get(slug, 0) + 1

    response = {
        "ingested": len(payloads),
        "distinct_findings": store_result["distinct_findings"],
        "duplicate_payloads": store_result["duplicate_payloads"],
        "tenant_total": new_total,
        "format": fmt,
        "observed_at": observed_at,
        "framework_hits": dict(sorted(framework_counts.items())),
    }
    if body.get("reconcile_absent"):
        response["reconciled"] = reconciled
    if delta_results:
        delivered = sum(
            1
            for result in delta_results
            if (result.get("status") == "delivered" if isinstance(result, dict) else getattr(result, "delivered", False))
        )
        response["delta_stream"] = {"emitted_batches": len(delta_results), "delivered": delivered}
    return response


def _unpack_hub_list_page(result: tuple[Any, ...]) -> tuple[list[dict[str, Any]], int | None, str | None]:
    page = result[0]
    total = result[1] if len(result) > 1 else None
    next_cursor = result[2] if len(result) > 2 else None
    return page, total, next_cursor


_HUB_LIST_CURSOR_VERSION = 1


def _hub_native_fingerprint(findings: list[dict[str, Any]]) -> str:
    ids = [str(row.get("id") or "") for row in findings]
    raw = json.dumps(ids, separators=(",", ":"), ensure_ascii=True).encode()
    return hashlib.sha256(raw).hexdigest()[:24]


def _hub_tenant_fingerprint(tenant_id: str) -> str:
    return hashlib.sha256(tenant_id.encode()).hexdigest()[:24]


def _encode_hub_list_cursor(
    *,
    tenant_id: str,
    native_findings: list[dict[str, Any]],
    native_index: int,
    hub_cursor: str,
    total: int,
) -> str:
    payload = {
        "v": _HUB_LIST_CURSOR_VERSION,
        "t": _hub_tenant_fingerprint(tenant_id),
        "n": native_index,
        "nf": _hub_native_fingerprint(native_findings),
        "h": hub_cursor,
        "total": total,
    }
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def _decode_hub_list_cursor(
    cursor: str,
    *,
    tenant_id: str,
    native_findings: list[dict[str, Any]],
) -> tuple[int, str, int]:
    try:
        if not cursor or len(cursor) > 4096:
            raise ValueError
        padded = cursor + "=" * (-len(cursor) % 4)
        payload = json.loads(base64.b64decode(padded.encode(), altchars=b"-_", validate=True).decode())
        if not isinstance(payload, dict) or payload.get("v") != _HUB_LIST_CURSOR_VERSION:
            raise ValueError
        if payload.get("t") != _hub_tenant_fingerprint(tenant_id):
            raise ValueError
        if payload.get("nf") != _hub_native_fingerprint(native_findings):
            raise ValueError
        native_index = int(payload["n"])
        total = int(payload["total"])
        hub_cursor = str(payload.get("h") or "")
        if native_index < 0 or native_index > len(native_findings) or total < 0:
            raise ValueError
        return native_index, hub_cursor, total
    except Exception as exc:
        raise ValueError("Invalid or stale compliance hub cursor") from exc


@router.get("/compliance/hub/findings", tags=["compliance"])
async def list_hub_findings(request: Request, limit: int = 200, offset: int = 0, cursor: str | None = None) -> dict:
    """List compliance-hub findings for the current tenant.

    Returns the canonical finding-list envelope (#3666) shared with
    ``/v1/findings`` so consumers learn one shape across every finding surface.
    Includes durable external ingests plus native scan findings projected into
    the same shape so the list endpoint matches `/hub/posture` totals.

    Ordering is ingest-order (``sort="ordinal"``) so the list matches the way
    findings were imported. ``cursor`` is the scale path: it walks the native
    scan prefix and the durable hub store with a bounded opaque continuation,
    then uses the indexed ``(ledger_ordinal, first_seen, canonical_id)`` keyset.
    ``limit`` / ``offset`` remain as a compatibility path capped at offset
    10,000; deeper walks must follow ``next_cursor``.

    The synchronous store read (page fetch + count) runs in a worker thread
    under adaptive backpressure so a deep page against a large tenant cannot
    block the event loop and starve ``/health`` (mirrors ``/v1/findings``);
    under saturation it sheds with ``429 + Retry-After``.
    """
    try:
        async with adaptive_backpressure("compliance"):
            return await anyio.to_thread.run_sync(_list_hub_findings_impl, request, limit, offset, cursor)
    except BackpressureRejectedError as exc:
        raise HTTPException(
            status_code=429,
            detail=exc.to_dict(),
            headers={"Retry-After": str(exc.retry_after_seconds)},
        ) from exc
    except ValueError as exc:
        detail = "Invalid or stale compliance hub cursor" if cursor else "Invalid compliance hub pagination"
        raise HTTPException(status_code=400, detail=detail) from exc


def _list_hub_findings_impl(request: Request, limit: int, offset: int, cursor: str | None = None) -> dict:
    """Synchronous body of :func:`list_hub_findings` (runs in a worker thread)."""
    from agent_bom.api.compliance_hub_store import get_compliance_hub_store
    from agent_bom.api.finding_list_envelope import finding_list_envelope

    tenant_id = _tenant_id(request)
    safe_limit = max(1, min(limit, 1000))
    safe_offset = max(0, offset)
    if safe_offset > _HUB_LIST_OFFSET_CEILING:
        raise ValueError("offset exceeds compatibility ceiling; use cursor")
    if cursor and safe_offset:
        raise ValueError("cursor and offset cannot be combined")
    sort = "ordinal"
    native = _native_hub_findings(request)

    # Validate the opaque continuation before resolving the store. Malformed,
    # cross-tenant, or stale-native cursors therefore perform no database work.
    if cursor:
        native_index, hub_cursor, stable_total = _decode_hub_list_cursor(
            cursor,
            tenant_id=tenant_id,
            native_findings=native,
        )
    else:
        native_index, hub_cursor, stable_total = 0, "", -1

    store = get_compliance_hub_store()
    list_page = getattr(store, "list_current_page", None) or getattr(store, "list_page", None)
    if not callable(list_page):
        if cursor:
            raise ValueError("cursor pagination requires a paged compliance store")
        findings = store.list(tenant_id) + native
        page = findings[safe_offset : safe_offset + safe_limit]
        total = len(findings)
        next_cursor = ""
    elif safe_offset:
        # Backward-compatible, explicitly bounded OFFSET behavior. New clients
        # use cursor and never issue an OFFSET against the durable store.
        window = safe_offset + safe_limit
        legacy_hub_rows, legacy_hub_total, _ = _unpack_hub_list_page(list_page(tenant_id, limit=window, offset=0, sort=sort))
        combined = native + legacy_hub_rows
        page = combined[safe_offset : safe_offset + safe_limit]
        total = len(native) + int(legacy_hub_total or 0)
        next_cursor = ""
    else:
        page = native[native_index : native_index + safe_limit]
        next_native_index = native_index + len(page)
        remaining = safe_limit - len(page)
        hub_rows: list[dict[str, Any]] = []
        hub_total: int | None = None
        hub_next: str | None = None
        if remaining > 0:
            hub_rows, hub_total, hub_next = _unpack_hub_list_page(
                list_page(
                    tenant_id,
                    limit=remaining,
                    offset=0,
                    sort=sort,
                    include_total=not cursor,
                    cursor=hub_cursor or None,
                )
            )
            page.extend(hub_rows)
        elif not cursor:
            # Exact first-page total without hydrating a durable row. A limit=0
            # query fetches only the keyset lookahead and returns COUNT(*).
            _unused, hub_total, _unused_cursor = _unpack_hub_list_page(
                list_page(tenant_id, limit=0, offset=0, sort=sort, include_total=True)
            )

        total = stable_total if cursor else len(native) + int(hub_total or 0)
        has_native_more = next_native_index < len(native)
        hub_unstarted_with_rows = remaining == 0 and not hub_cursor and total > len(native)
        has_hub_more = bool(hub_next) or hub_unstarted_with_rows
        if has_native_more or has_hub_more:
            continuation_hub_cursor = hub_cursor if remaining == 0 else str(hub_next or "")
            next_cursor = _encode_hub_list_cursor(
                tenant_id=tenant_id,
                native_findings=native,
                native_index=next_native_index,
                hub_cursor=continuation_hub_cursor,
                total=total,
            )
        else:
            next_cursor = ""
    return finding_list_envelope(
        findings=page,
        # A continuation is not a database snapshot: concurrent ingests may
        # change the matching cardinality between pages. Return null instead of
        # replaying a potentially stale first-page COUNT as if it were exact.
        total=None if cursor else total,
        limit=safe_limit,
        offset=safe_offset,
        sort=sort,
        cursor=cursor or "",
        next_cursor=next_cursor,
        source="native_and_compliance_hub_findings",
        scope="tenant compliance-hub current findings",
    )


@router.get("/compliance/hub/posture", tags=["compliance"])
async def get_hub_posture(request: Request) -> dict:
    """Aggregate compliance posture across native scans + hub-ingested findings.

    Returns per-framework counts, severity breakdown, and source mix
    (native vs external) so the dashboard /compliance page can render a
    single posture story across every entry point.

    The synchronous store aggregates (severity GROUP BY, SQL-side framework
    counts, tenant total) plus the native-job fold run in a worker thread under
    adaptive backpressure so this O(table) read cannot block the event loop and
    starve ``/health`` (mirrors ``/v1/findings``); under saturation it sheds with
    ``429 + Retry-After``.
    """
    try:
        async with adaptive_backpressure("compliance"):
            return await anyio.to_thread.run_sync(_get_hub_posture_impl, request)
    except BackpressureRejectedError as exc:
        raise HTTPException(
            status_code=429,
            detail=exc.to_dict(),
            headers={"Retry-After": str(exc.retry_after_seconds)},
        ) from exc


def _get_hub_posture_impl(request: Request) -> dict:
    """Synchronous body of :func:`get_hub_posture` (runs in a worker thread)."""
    from agent_bom.api.compliance_hub_store import get_compliance_hub_store
    from agent_bom.compliance_coverage import TAG_MAPPED_FRAMEWORKS, normalize_framework_slug

    tenant_id = _tenant_id(request)
    store = get_compliance_hub_store()
    severity_breakdown = getattr(store, "severity_breakdown", None)
    framework_counts_fn = getattr(store, "framework_slug_counts", None)
    if callable(severity_breakdown) and callable(framework_counts_fn):
        hub_severity_counts = severity_breakdown(tenant_id)
        hub_framework_counts = framework_counts_fn(tenant_id)
        hub_total = store.count(tenant_id)
    else:
        hub_findings = store.list(tenant_id)
        hub_total = len(hub_findings)
        hub_severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "unknown": 0}
        hub_framework_counts = {}
        for f in hub_findings:
            sev = (f.get("severity") or "unknown").lower()
            hub_severity_counts[sev] = hub_severity_counts.get(sev, 0) + 1
            for slug in f.get("applicable_frameworks") or []:
                canonical = normalize_framework_slug(str(slug))
                hub_framework_counts[canonical] = hub_framework_counts.get(canonical, 0) + 1

    # Native sources: count blast radii from completed scan jobs as a
    # proxy for "native finding count per framework" using their tag fields.
    # Driven by TAG_MAPPED_FRAMEWORKS so all 15 frameworks (owasp-llm, owasp-mcp,
    # owasp-agentic, atlas, attack, nist, nist-csf, nist-800-53, fedramp,
    # eu-ai-act, iso-27001, soc2, cis, cmmc, pci-dss) aggregate consistently.
    # Slug→field
    # is NOT a pure replace (e.g. nist → nist_ai_rmf_tags), so we read the
    # canonical mapping straight off the metadata.
    slug_to_tag_field: tuple[tuple[str, str], ...] = tuple((metadata.slug, metadata.tag_field) for metadata in TAG_MAPPED_FRAMEWORKS)

    native_framework_counts: dict[str, int] = {}
    native_total = 0
    for job in _tenant_jobs(request):
        if job.status != JobStatus.DONE or not job.result:
            continue
        for br in job.result.get("blast_radius", []) or []:
            native_total += 1
            for slug, field in slug_to_tag_field:
                if br.get(field):
                    native_framework_counts[slug] = native_framework_counts.get(slug, 0) + 1

    combined: dict[str, int] = {}
    for slug, count in native_framework_counts.items():
        combined[slug] = combined.get(slug, 0) + count
    for slug, count in hub_framework_counts.items():
        combined[slug] = combined.get(slug, 0) + count

    return {
        "totals": {
            "native": native_total,
            "hub": hub_total,
            "combined": native_total + hub_total,
        },
        "framework_counts": {
            "native": dict(sorted(native_framework_counts.items())),
            "hub": dict(sorted(hub_framework_counts.items())),
            "combined": dict(sorted(combined.items())),
        },
        "hub_severity_breakdown": hub_severity_counts,
    }


@router.delete("/compliance/hub/findings", tags=["compliance"], dependencies=[_dep("policy_write")])
async def clear_hub_findings(request: Request) -> dict:
    """Clear all hub-ingested findings for the current tenant.

    Useful when a tenant wants to re-import a clean batch (e.g. after
    a scanner-version upgrade). Native scan results are not affected.
    """
    from agent_bom.api.compliance_hub_store import get_compliance_hub_store

    removed = await anyio.to_thread.run_sync(get_compliance_hub_store().clear, _tenant_id(request))
    return {"removed": removed}
