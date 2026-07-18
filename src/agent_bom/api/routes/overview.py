"""Cross-domain overview aggregation route.

Composes existing per-domain summary logic into a single read-only payload that
powers the unified overview / command-center landing page. No new scan or
ingestion logic lives here — every metric is read from a store or summary
function that another route already exposes:

    * Cloud / CNAPP + Ops + Findings  -> scan-job store (unified findings spine)
    * Runtime                          -> deployment-context signals
    * LLM cost                         -> cost store summary
    * NHI / identity                   -> agent-identity store + fleet store
    * Posture + headline               -> the SAME unified findings spine the
      coverage lanes read, folded with compliance-hub current-state severity
      counts so findings ingested via ``POST /v1/findings/bulk`` move the
      grade/headline (not scan jobs alone)

The exec headline severity counts and risk grade use the exact default-window,
parent-job exclusion, and cross-job replacement semantics of ``/v1/findings``.
The five coverage lanes remain historical scan summaries. This separation is
intentional: compact summaries can describe prior scan coverage, but cannot
create executive severity counts whose underlying finding rows no longer exist
for drill-down. The shared current-state fold includes non-CVE findings and
canonicalized ``blast_radius`` evidence, so re-scans replace rather than inflate
the executive count (#3961/#4106).

Domain tiles (cloud / vuln / code / runtime / ...) remain scan-scoped by
design; only the top-level posture + headline aggregate scan + ingested
evidence.

Endpoints:
    GET /v1/overview   cross-domain posture snapshot for the landing page
"""

from __future__ import annotations

import hashlib
import logging
import os
import threading
import time
from typing import Any, cast
from urllib.parse import urlencode

import anyio.to_thread
from fastapi import APIRouter, HTTPException, Request

from agent_bom.api.models import ExecScoreConfigUpdateRequest, JobStatus
from agent_bom.api.stores import _get_fleet_store, _get_store
from agent_bom.api.tenancy import require_request_tenant_id
from agent_bom.backpressure import BackpressureRejectedError, adaptive_backpressure
from agent_bom.exec_score import compute_exec_score
from agent_bom.rbac import require_authenticated_permission

router = APIRouter(dependencies=[cast(Any, require_authenticated_permission("read"))])
_logger = logging.getLogger(__name__)

# Per-tenant overview cache (#3963 follow-up). ``_build_overview`` folds every
# finding of every completed scan (O(estate)); a burst of landing-page reads
# would refold the whole estate each time. We cache the composed payload keyed by
# a cheap job-metadata fingerprint so a re-read within the TTL that sees no new
# scan data skips the fold. The fingerprint (job id/status/timestamp — never the
# folded findings) invalidates the cache the instant new evidence lands, so the
# numbers can never go stale relative to the spine.
_OVERVIEW_CACHE_TTL_SECONDS_DEFAULT = 15.0
_overview_cache: dict[str, tuple[float, str, dict[str, Any]]] = {}
_overview_cache_lock = threading.Lock()


def _overview_cache_ttl() -> float:
    raw = os.environ.get("AGENT_BOM_OVERVIEW_CACHE_TTL_SECONDS")
    if raw is None:
        return _OVERVIEW_CACHE_TTL_SECONDS_DEFAULT
    try:
        return max(0.0, float(raw))
    except ValueError:
        return _OVERVIEW_CACHE_TTL_SECONDS_DEFAULT


def _overview_fingerprint(jobs: list[Any], hub_severity: dict[str, int]) -> str:
    """Cheap change-detector over job metadata + hub current-state — no fold.

    Captures job identity, status and the freshest per-job timestamp so a new
    scan, a status transition, or a re-run all change the fingerprint. It also
    folds in the hub severity histogram (a cheap indexed GROUP BY) so findings
    ingested via ``POST /v1/findings/bulk`` — which never touch a scan job —
    still invalidate the cache. Neither input pays the O(estate) rollup cost, so
    the headline can never go stale relative to the reconciled spine.
    """
    parts = []
    for job in jobs:
        stamp = getattr(job, "completed_at", None) or getattr(job, "updated_at", None) or getattr(job, "created_at", None) or ""
        status = getattr(job, "status", "")
        parts.append(f"{getattr(job, 'job_id', '')}|{getattr(status, 'value', status)}|{stamp}")
    parts.sort()
    hub_part = "|".join(f"{k}={int(hub_severity.get(k, 0) or 0)}" for k in sorted(hub_severity))
    digest = hashlib.sha256(("\x1e".join(parts) + "\x1d" + hub_part).encode("utf-8")).hexdigest()
    return f"{len(jobs)}:{digest}"


def _overview_cache_get(tenant_id: str, fingerprint: str) -> dict[str, Any] | None:
    ttl = _overview_cache_ttl()
    if ttl <= 0:
        return None
    now = time.monotonic()
    with _overview_cache_lock:
        entry = _overview_cache.get(tenant_id)
        if entry is None:
            return None
        cached_at, cached_fp, payload = entry
        if cached_fp != fingerprint or (now - cached_at) > ttl:
            return None
        return payload


def _overview_cache_put(tenant_id: str, fingerprint: str, payload: dict[str, Any]) -> None:
    if _overview_cache_ttl() <= 0:
        return
    with _overview_cache_lock:
        _overview_cache[tenant_id] = (time.monotonic(), fingerprint, payload)


def _reset_overview_cache() -> None:
    """Test hook: drop all cached overview payloads."""
    with _overview_cache_lock:
        _overview_cache.clear()


_SEVERITY_KEYS = ("critical", "high", "medium", "low")
# ``unrated`` is the honest home for findings whose severity the histogram does
# not recognize (empty / "unknown" / vendor-specific). Without it those findings
# incremented the CVE count but were dropped from the severity strip, producing
# the "39 CVEs / 0 severities" mismatch. Every severity histogram in this module
# now carries it so ``sum(severity.values())`` reconciles with the counted total.
_UNRATED_KEY = "unrated"
_ALL_SEVERITY_KEYS = (*_SEVERITY_KEYS, _UNRATED_KEY)
_HUB_SEVERITY_KEYS = ("critical", "high", "medium", "low", "info", "unknown")

# Coverage lanes — the five security domains, in display order (issue #3946).
# Symmetric posture-management family: CSPM · ASPM · DSPM · AISPM, plus Vuln
# mgmt as the cross-surface CVE lane.
_COVERAGE_DOMAINS = ("cspm", "vuln", "aspm", "dspm", "aispm")
_COVERAGE_LABELS = {
    "cspm": "CSPM",
    "vuln": "Vuln mgmt",
    "aspm": "ASPM",
    "dspm": "DSPM",
    "aispm": "AISPM",
}


def _tenant_id(request: Request) -> str:
    return require_request_tenant_id(request)


def _empty_severity() -> dict[str, int]:
    return {key: 0 for key in _ALL_SEVERITY_KEYS}


def _bucket(sev: str | None, severity: dict[str, int]) -> str:
    """Return the histogram bucket for ``sev`` — an exact match or ``unrated``.

    The single choke point shared by every rollup so a finding is counted in one
    and only one bucket and no unknown severity is silently dropped.
    """
    key = (sev or "").strip().lower()
    return key if key in _SEVERITY_KEYS else _UNRATED_KEY


def _graph_drill_href(
    *,
    rollup: bool = True,
    severity: str | None = None,
    relationships: str | None = None,
    layers: str | None = None,
) -> str:
    """Build a /graph deep-link for overview domain tiles."""
    params: dict[str, str] = {}
    if rollup:
        params["rollup"] = "1"
    if severity:
        params["severity"] = severity
    if relationships:
        params["relationships"] = relationships
    if layers:
        params["layers"] = layers
    query = urlencode(params)
    return f"/graph?{query}" if query else "/graph"


def _cloud_graph_href(severity: dict[str, int]) -> str:
    if severity["critical"] > 0:
        return _graph_drill_href(severity="critical")
    if severity["high"] > 0:
        return _graph_drill_href(severity="high")
    return _graph_drill_href()


def _severity_from_summary(
    summary: dict[str, Any],
    finding_summary: dict[str, Any] | None = None,
) -> dict[str, int]:
    """Rebuild severity histogram from compact scan ``summary`` metadata."""
    severity = _empty_severity()
    total = int(summary.get("total_vulnerabilities") or summary.get("total_findings") or 0)
    by_sev = (finding_summary or {}).get("by_severity") or {}
    if isinstance(by_sev, dict) and by_sev:
        for raw_key, raw_val in by_sev.items():
            severity[_bucket(str(raw_key), severity)] += int(raw_val or 0)
        counted = sum(severity.values())
        # Reconcile with the scalar total so no finding is lost to a severity
        # band the per-severity map omitted (info/unknown/vendor-specific).
        if total > counted:
            severity[_UNRATED_KEY] += total - counted
        return severity
    severity["critical"] = int(summary.get("critical_unified_findings") or summary.get("critical_findings") or 0)
    severity["high"] = int(summary.get("high_unified_findings") or 0)
    # The remainder are of unknown band (only critical/high are itemized in the
    # compact summary) — record them as ``unrated`` rather than fabricating a
    # ``medium`` count. This keeps ``sum(severity) == total``.
    remainder = max(0, total - severity["critical"] - severity["high"])
    if remainder:
        severity[_UNRATED_KEY] = remainder
    return severity


def _rollup_from_blast_radius(blast_radius: list[dict[str, Any]]) -> dict[str, Any]:
    severity = _empty_severity()
    kev = 0
    credential_exposed = 0
    seen_ids: set[str] = set()
    top_risks: list[dict[str, Any]] = []

    for b in blast_radius:
        vid = b.get("vulnerability_id", "")
        if vid and vid in seen_ids:
            continue
        if vid:
            seen_ids.add(vid)
        sev = (b.get("severity") or "").lower()
        # Always count into exactly one bucket — unknown severities land in
        # ``unrated`` instead of being dropped (the 39-CVEs / 0-severities bug).
        severity[_bucket(sev, severity)] += 1
        is_kev = bool(b.get("cisa_kev") or b.get("is_kev"))
        if is_kev:
            kev += 1
        creds = b.get("exposed_credentials") or []
        if creds:
            credential_exposed += 1
        risk = b.get("risk_score")
        if risk is None:
            risk = (b.get("blast_score") or 0) / 10
        top_risks.append(
            {
                "vulnerability_id": vid,
                "package": b.get("package"),
                "severity": sev or "low",
                "risk_score": round(float(risk or 0), 1),
                "is_kev": is_kev,
                "cvss_score": b.get("cvss_score"),
                "epss_score": b.get("epss_score"),
                "affected_agents": list(b.get("affected_agents") or []),
            }
        )

    top_risks.sort(key=lambda r: r["risk_score"], reverse=True)
    # One source of truth: the CVE count is the histogram total, so the severity
    # strip and the headline number can never disagree.
    return {
        "severity": severity,
        "kev": kev,
        "credential_exposed": credential_exposed,
        "unique_cves": sum(severity.values()),
        "top_risks": top_risks[:10],
    }


def _rollup_from_summary(result: dict[str, Any]) -> dict[str, Any]:
    summary = cast(dict[str, Any], result.get("summary") or {})
    finding_summary = cast(dict[str, Any], result.get("finding_summary") or {})
    severity = _severity_from_summary(summary, finding_summary)
    # ``_severity_from_summary`` reconciles the histogram with the scalar total,
    # so the histogram sum is the single source of truth for the CVE count.
    unique_cves = sum(severity.values())
    return {
        "severity": severity,
        "kev": 0,
        "credential_exposed": 0,
        "unique_cves": unique_cves,
        "unique_packages": int(summary.get("unique_packages") or summary.get("total_packages") or 0),
        "top_risks": [],
    }


# Per-severity risk floor (0–10) so a top-risk entry ranks by its severity band
# first and its CVSS refines only WITHIN the band. A hub/connector finding often
# carries only a severity (no CVSS, no reachability), so keying purely on CVSS
# scored a critical-without-CVSS at 0.0 — sorting it below a medium@6.5. The
# floor keeps the worst-severity finding worst-first regardless of missing CVSS.
_SEVERITY_RISK_FLOOR: dict[str, float] = {
    "critical": 9.0,
    "high": 7.0,
    "medium": 4.0,
    "low": 1.5,
}
_UNRATED_RISK_FLOOR = 0.5


def _row_risk_score(row: dict[str, Any]) -> float:
    """Comparable 0–10 risk for a top-risk entry, spine or hub-ingested.

    Prefers an explicit ``risk_score`` (the scan spine always sets one). A
    hub-ingested / bulk finding carries no ``risk_score`` and usually no
    reachability signal, so we derive a band-dominant blend: the finding's
    severity floor (:data:`_SEVERITY_RISK_FLOOR`) plus a small CVSS refinement
    (``cvss / 100``) that orders findings WITHIN a band without ever crossing it.
    That keeps a critical worst-first even when it carries no CVSS — the earlier
    CVSS-only fallback scored such a critical at 0.0, burying it below a
    medium@6.5. Result clamped to [0, 10].
    """
    risk = row.get("risk_score")
    if risk is not None:
        try:
            return round(min(10.0, max(0.0, float(risk or 0))), 1)
        except (TypeError, ValueError):
            return 0.0
    severity = str(row.get("severity") or "").strip().lower()
    floor = _SEVERITY_RISK_FLOOR.get(severity, _UNRATED_RISK_FLOOR)
    try:
        cvss = float(row.get("cvss_score") or 0.0)
    except (TypeError, ValueError):
        cvss = 0.0
    refine = min(max(cvss, 0.0), 10.0) / 100.0
    return round(min(10.0, max(0.0, floor + refine)), 1)


def _finding_top_risk(row: dict[str, Any]) -> dict[str, Any]:
    """Build a top-risk strip entry from a unified findings-spine or hub row."""
    asset = row.get("asset") if isinstance(row.get("asset"), dict) else {}
    evidence = row.get("evidence") if isinstance(row.get("evidence"), dict) else {}
    return {
        "vulnerability_id": str(row.get("cve_id") or row.get("canonical_id") or row.get("id") or row.get("finding_id") or ""),
        "package": row.get("package") or (asset or {}).get("name") or (evidence or {}).get("package_name"),
        "severity": (str(row.get("severity") or "").strip().lower() or "low"),
        "risk_score": _row_risk_score(row),
        "is_kev": bool(row.get("is_kev") or row.get("cisa_kev")),
        "cvss_score": row.get("cvss_score"),
        "epss_score": row.get("epss_score"),
        "affected_agents": list(row.get("affected_agents") or []),
    }


def _fold_findings(
    findings: list[Any],
    *,
    severity: dict[str, int],
    lanes: dict[str, dict[str, int]],
    lane_counts: dict[str, int],
    seen: set[str],
    top_risks: list[dict[str, Any]],
    failing_frameworks: set[str],
) -> tuple[int, int, int]:
    """Fold unified findings-spine rows into the shared estate accumulators.

    Every row is counted once into exactly one bucket of the all-domain severity
    histogram (the headline/grade basis) AND into EVERY coverage lens it belongs
    to (the coverage lanes are overlapping posture disciplines, not a partition —
    a repo dependency CVE counts under both ``vuln`` and ``aspm``). Because lanes
    overlap, the sum of lane counts is not the total; the histogram is the
    single source of truth for the headline. Returns
    ``(added, kev, credential_exposed)`` for this batch. A finding whose severity
    is critical/high marks each of its ``applicable_frameworks`` as failing
    (feeds the exec grade's compliance driver, #3962).
    """
    from agent_bom.compliance_coverage import normalize_framework_slug

    added = 0
    kev = 0
    credential_exposed = 0
    for row in findings:
        if not isinstance(row, dict):
            continue
        identity = str(row.get("id") or row.get("canonical_id") or row.get("cve_id") or id(row))
        if identity in seen:
            continue
        seen.add(identity)
        bucket = _bucket(str(row.get("severity") or ""), severity)
        # All-domain histogram: once per finding (the headline/grade basis).
        severity[bucket] += 1
        # Coverage lanes: increment EVERY applicable lens (lanes overlap).
        for dom in _row_lenses(row):
            lanes[dom][bucket] += 1
            lane_counts[dom] += 1
        added += 1
        if bool(row.get("is_kev") or row.get("cisa_kev")):
            kev += 1
        if row.get("exposed_credentials"):
            credential_exposed += 1
        if bucket in ("critical", "high"):
            for slug in row.get("applicable_frameworks") or []:
                if slug:
                    failing_frameworks.add(normalize_framework_slug(str(slug)))
        top_risks.append(_finding_top_risk(row))
    return added, kev, credential_exposed


def _job_package_count(result: dict[str, Any]) -> int:
    """Count discovered packages across the scan's agents/servers."""
    packages = 0
    for agent in result.get("agents", []) or []:
        for server in agent.get("mcp_servers", []) or []:
            for pkg in server.get("packages", []) or []:
                if pkg.get("name"):
                    packages += 1
    return packages


def _estate_rollup(jobs: list[Any]) -> dict[str, Any]:
    """Single reconciled rollup over the unified findings spine (#3961/#3962/#3963).

    The exec headline severity counts, the five coverage lanes, the top-risk
    strip, and the risk grade are all built from ONE pass over the same
    ``findings`` stream so a scan-produced non-CVE critical can never be visible
    in one surface and invisible in another. Per completed scan the richest
    evidence available is folded in, in precedence order:

      1. the unified ``findings`` spine (the superset — carries the non-CVE
         findings the pipeline adds beyond ``blast_radius``),
      2. else the CVE-only ``blast_radius`` (legacy / pre-spine results),
      3. else the compact ``summary`` (after hot-cache compaction drops both).

    Findings are deduped by id across re-scans (mirrors the coverage-lane
    dedup). ``compliance_failing`` counts the distinct frameworks with at least
    one critical/high finding — cheap because it is accumulated in this same
    pass, not a second control-by-control evaluation.
    """
    severity = _empty_severity()
    lanes: dict[str, dict[str, int]] = {dom: _empty_severity() for dom in _COVERAGE_DOMAINS}
    lane_counts: dict[str, int] = {dom: 0 for dom in _COVERAGE_DOMAINS}
    seen: set[str] = set()
    failing_frameworks: set[str] = set()
    top_risks: list[dict[str, Any]] = []
    sources: set[str] = set()
    scan_count = 0
    done_count = 0
    failed_count = 0
    running_count = 0
    kev = 0
    credential_exposed = 0
    unique_findings = 0
    unique_packages = 0
    latest_scan_at: str | None = None

    for job in jobs:
        status = getattr(job, "status", None)
        if status == JobStatus.FAILED:
            failed_count += 1
        elif status == JobStatus.RUNNING:
            running_count += 1
        if status != JobStatus.DONE or not job.result:
            continue
        scan_count += 1
        done_count += 1
        result = cast(dict[str, Any], job.result)

        created = getattr(job, "created_at", None)
        created_str = str(created) if created is not None else None
        if created_str and (latest_scan_at is None or created_str > latest_scan_at):
            latest_scan_at = created_str

        for src in result.get("scan_sources", []) or []:
            if src:
                sources.add(str(src))

        findings = result.get("findings")
        blast_radius = result.get("blast_radius") or []
        if findings:
            added, add_kev, add_cred = _fold_findings(
                cast(list[Any], findings),
                severity=severity,
                lanes=lanes,
                lane_counts=lane_counts,
                seen=seen,
                top_risks=top_risks,
                failing_frameworks=failing_frameworks,
            )
            kev += add_kev
            credential_exposed += add_cred
            unique_findings += added
            unique_packages += _job_package_count(result)
        elif blast_radius:
            # Fallback: no spine on this result — CVE-only blast_radius. Every
            # entry is a dependency CVE, so it folds into the vuln lane.
            partial = _rollup_from_blast_radius(cast(list[dict[str, Any]], blast_radius))
            for key in _ALL_SEVERITY_KEYS:
                severity[key] += partial["severity"][key]
                lanes["vuln"][key] += partial["severity"][key]
            lane_counts["vuln"] += partial["unique_cves"]
            kev += partial["kev"]
            credential_exposed += partial["credential_exposed"]
            unique_findings += partial["unique_cves"]
            top_risks.extend(partial["top_risks"])
            unique_packages += _job_package_count(result)
        else:
            # Fallback: compacted result — only the compact summary survives.
            partial = _rollup_from_summary(result)
            for key in _ALL_SEVERITY_KEYS:
                severity[key] += partial["severity"][key]
                lanes["vuln"][key] += partial["severity"][key]
            lane_counts["vuln"] += partial["unique_cves"]
            unique_findings += partial["unique_cves"]
            unique_packages = max(unique_packages, partial["unique_packages"])

    top_risks.sort(key=lambda r: r["risk_score"], reverse=True)
    coverage = [
        {
            "domain": dom,
            "label": _COVERAGE_LABELS[dom],
            "href": f"/findings?domain={dom}",
            "count": lane_counts[dom],
            "severity": lanes[dom],
        }
        for dom in _COVERAGE_DOMAINS
    ]

    return {
        # All-domain reconciled histogram — the headline + grade basis.
        "severity": severity,
        "coverage": coverage,
        # Vuln-lane specifics for the scan-scoped "Vuln / SCA" domain tile.
        "vuln_severity": lanes["vuln"],
        "unique_cves": lane_counts["vuln"],
        "sources": sorted(sources),
        "scan_count": scan_count,
        "done_count": done_count,
        "failed_count": failed_count,
        "running_count": running_count,
        "kev": kev,
        "credential_exposed": credential_exposed,
        "unique_findings": unique_findings,
        "unique_packages": unique_packages,
        "top_risks": top_risks[:10],
        "latest_scan_at": latest_scan_at,
        "compliance_failing": len(failing_frameworks),
    }


def _row_domain(row: dict[str, Any]) -> str:
    """Return the security domain for a serialized finding row.

    Prefers the first-class ``security_domain`` field (set by
    ``Finding.to_dict``); falls back to the source/type mapping for legacy rows.
    ``vuln`` is the safe default for legacy CVE rows that predate the taxonomy.
    """
    from agent_bom.finding_scope import domain_for_row

    return domain_for_row(row) or "vuln"


def _row_lenses(row: dict[str, Any]) -> set[str]:
    """Overlapping coverage lenses for a row, guaranteeing the primary lane.

    The coverage lanes are posture lenses, not a partition — a repo dependency
    CVE counts under both ``vuln`` and ``aspm``. The primary lane (or the
    ``vuln`` default for legacy rows) is always included so every finding lands
    in at least one lane, while the all-domain histogram is still counted once
    per finding.
    """
    from agent_bom.finding_scope import lenses_for_row

    lenses = set(lenses_for_row(row))
    lenses.add(_row_domain(row))
    return {dom for dom in lenses if dom in _COVERAGE_DOMAINS}


def _posture_snapshot(jobs: list[Any]) -> dict[str, Any]:
    """Letter grade + score from the latest completed scan (same as /v1/posture)."""
    for job in jobs:
        if job.status != JobStatus.DONE or not job.result:
            continue
        result = cast(dict[str, Any], job.result)
        scorecard = result.get("posture_scorecard")
        if isinstance(scorecard, dict) and scorecard:
            return {
                "grade": scorecard.get("grade", "N/A"),
                "score": scorecard.get("score", 0),
                "summary": scorecard.get("summary", ""),
            }
        summary = result.get("summary")
        if isinstance(summary, dict) and (summary.get("total_vulnerabilities") or summary.get("total_findings")):
            from agent_bom.posture import _score_to_grade

            critical = int(summary.get("critical_unified_findings") or summary.get("critical_findings") or 0)
            high = int(summary.get("high_unified_findings") or 0)
            total = int(summary.get("total_vulnerabilities") or summary.get("total_findings") or 0)
            penalty = min(100.0, critical * 12.0 + high * 6.0 + max(0, total - critical - high) * 1.5)
            score = max(0.0, round(100.0 - penalty, 1))
            return {
                "grade": _score_to_grade(score),
                "score": score,
                "summary": f"{total} finding(s) from latest completed scan",
            }
        break
    return {"grade": "N/A", "score": 0, "summary": "No completed scans available"}


def _runtime_snapshot(request: Request, jobs: list[Any]) -> dict[str, Any]:
    """Runtime signals (gateway / proxy / traces / mesh) for the Runtime domain.

    Reuses the same deployment-context derivation that powers nav badges so the
    overview and the rest of the UI agree on what runtime surfaces are live.
    """
    try:
        from agent_bom.api.routes.compliance import _derive_deployment_context

        ctx = _derive_deployment_context(request, jobs)
    except Exception:  # pragma: no cover - defensive; degrade to empty signals
        _logger.debug("deployment-context derivation failed", exc_info=True)
        ctx = {}
    active = sum(1 for key in ("has_gateway", "has_proxy", "has_traces", "has_mesh") if ctx.get(key))
    return {
        "has_gateway": bool(ctx.get("has_gateway")),
        "has_proxy": bool(ctx.get("has_proxy")),
        "has_traces": bool(ctx.get("has_traces")),
        "has_mesh": bool(ctx.get("has_mesh")),
        "deployment_mode": ctx.get("deployment_mode", "local"),
        "active_surfaces": active,
    }


def _cost_snapshot(request: Request) -> dict[str, Any]:
    """LLM spend rollup from the cost store (same source as /v1/observability/costs)."""
    try:
        from agent_bom.api.cost_store import get_cost_store, summarize

        store = get_cost_store()
        records = store.list_records(_tenant_id(request), limit=10000)
        report = summarize(records)
        budget = store.get_budget(_tenant_id(request), "")
        return {
            "total_cost_usd": report.get("total_cost_usd", 0.0),
            "total_calls": report.get("total_calls", 0),
            "agents": len(report.get("by_agent", {}) or {}),
            "budget_configured": budget is not None,
        }
    except Exception:  # pragma: no cover - cost store optional
        _logger.debug("cost snapshot failed", exc_info=True)
        return {"total_cost_usd": 0.0, "total_calls": 0, "agents": 0, "budget_configured": False}


def _identity_snapshot(request: Request) -> dict[str, Any]:
    """NHI / fleet counts from the identity + fleet stores."""
    tenant_id = _tenant_id(request)
    identities = 0
    try:
        from agent_bom.api.agent_identity_store import get_agent_identity_store

        identities = len(get_agent_identity_store().list(tenant_id, limit=1000))
    except Exception:  # pragma: no cover - identity store optional
        _logger.debug("identity snapshot failed", exc_info=True)

    fleet_total = 0
    low_trust = 0
    try:
        agents = _get_fleet_store().list_by_tenant(tenant_id)
        fleet_total = len(agents)
        low_trust = sum(1 for a in agents if float(getattr(a, "trust_score", 0.0) or 0.0) < 50)
    except Exception:  # pragma: no cover - fleet store optional
        _logger.debug("fleet snapshot failed", exc_info=True)

    return {
        "managed_identities": identities,
        "fleet_agents": fleet_total,
        "low_trust_agents": low_trust,
    }


def _hub_severity_snapshot(request: Request) -> dict[str, int]:
    """Per-severity counts of hub-ingested findings (POST /v1/findings/bulk).

    Reads the CURRENT-STATE table (``hub_findings_current``) with the SAME
    origin + default read-window predicates that ``/v1/findings`` counts on, via
    the store's indexed ``current_severity_breakdown`` (a GROUP BY, no payload
    hydration). This is the exec-read honesty fix (#3961): the headline used to
    read the append-only ledger (``severity_breakdown`` — all-origin, unbounded,
    keeping resolved/aged rows forever), so it could exceed and contradict the
    drill-down. Deriving from current-state within the window makes the headline
    reconcile EXACTLY with a ``/v1/findings`` click-through.

    Tenant scope is owned by the request; the store method is tenant-keyed.
    Degrades to zeros if the hub store is unavailable so the overview never fails
    closed on an optional dependency.
    """
    empty = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "unknown": 0}
    tenant_id = _tenant_id(request)
    # Memoise the O(rows) severity GROUP BY per tenant. This snapshot feeds BOTH
    # the cache fingerprint and the composed payload, so without this it ran the
    # full scan on every /v1/overview request (~360ms at 1M). The cache is
    # invalidated on every hub mutation (ingest / clear), so a hit is exact
    # and reconciles with the findings API by construction (wave-2 residual #3).
    from agent_bom.api import hub_overview_cache

    cached = hub_overview_cache.get_cached_severity(tenant_id)
    if cached is not None:
        return cached
    try:
        from agent_bom.api import time_window
        from agent_bom.api.compliance_hub_store import get_compliance_hub_store

        store = get_compliance_hub_store()
        current_breakdown = getattr(store, "current_severity_breakdown", None)
        if callable(current_breakdown):
            # Same default read-window ``/v1/findings`` applies (window_days
            # unset ⇒ server default ≈90d), the same ``bulk_ingest`` origin scope,
            # AND the same default OPEN lifecycle basis — resolved findings must
            # not inflate the exec headline. So the headline == the drill-down for
            # the same window + live posture (P1: lifecycle-aware exec read).
            since = time_window.window_since_iso(time_window.normalize_window_days(None))
            counts = current_breakdown(tenant_id, origin="bulk_ingest", since=since, status="open") or {}
        else:
            breakdown = getattr(store, "severity_breakdown", None)
            if not callable(breakdown):
                return empty
            counts = breakdown(tenant_id) or {}
    except Exception:  # pragma: no cover - hub store optional
        _logger.debug("hub severity snapshot failed", exc_info=True)
        return empty
    for key, value in counts.items():
        empty[str(key).lower()] = empty.get(str(key).lower(), 0) + int(value or 0)
    hub_overview_cache.set_cached_severity(tenant_id, empty)
    return empty


_HUB_TOP_RISK_LIMIT = 10


def _hub_top_risks(request: Request, *, limit: int = _HUB_TOP_RISK_LIMIT) -> list[dict[str, Any]]:
    """Top hub-ingested findings for the exec top-risk strip (P0 #1).

    ``_estate_rollup`` walks scan jobs only, so a connector/bulk-ingested estate
    rendered an empty top-risk strip even with a million open findings that DO
    move the grade + headline (via ``_hub_severity_snapshot``). This folds the
    hub finding spine into the strip. It reads a single bounded page ordered by
    the materialised ``severity_rank`` (index-backed on the SQL backends), so it
    stays sub-linear at million-row scale — it never hydrates the whole ledger
    (mirrors the #3963 rule that the overview must not fold every hub payload).

    Sorting by severity, NOT ``effective_reach``: the bulk/connector payload this
    targets carries only severity + CVSS, so ``compute_effective_reach_score`` is
    0.0 for every row — a reach-ordered page ties them all at 0.0 and degenerates
    to ingest/rowid order, so the single worst finding (a lone critical behind
    thousands of mediums) fell off the strip entirely. Severity-first ordering
    guarantees the worst band is surfaced regardless of ingest order; the
    per-entry ``_row_risk_score`` blend then refines within-band by CVSS.
    Degrades to an empty list if the hub store is unavailable so the overview
    never fails closed on an optional dependency.
    """
    if limit <= 0:
        return []
    try:
        from agent_bom.api.compliance_hub_store import get_compliance_hub_store

        store = get_compliance_hub_store()
        page = store.list_page(
            _tenant_id(request),
            limit=limit,
            sort="severity",
            include_total=False,
        )
    except Exception:  # pragma: no cover - hub store optional
        _logger.debug("hub top risks failed", exc_info=True)
        return []
    rows = page[0] if isinstance(page, tuple) else page
    return [_finding_top_risk(row) for row in rows or [] if isinstance(row, dict)]


def _merge_top_risks(*groups: list[dict[str, Any]], limit: int = 10) -> list[dict[str, Any]]:
    """Merge scan + hub top-risk entries: dedupe by id, sort by risk, cap.

    Deduped on ``vulnerability_id`` (keeping the higher-risk occurrence) so a
    finding present in both the scan spine and the hub ledger is not doubled;
    keyless entries (no id) are always kept.
    """
    best_by_id: dict[str, dict[str, Any]] = {}
    keyless: list[dict[str, Any]] = []
    for group in groups:
        for entry in group:
            key = str(entry.get("vulnerability_id") or "")
            if not key:
                keyless.append(entry)
                continue
            existing = best_by_id.get(key)
            if existing is None or float(entry.get("risk_score") or 0.0) > float(existing.get("risk_score") or 0.0):
                best_by_id[key] = entry
    merged = [*best_by_id.values(), *keyless]
    merged.sort(key=lambda r: float(r.get("risk_score") or 0.0), reverse=True)
    return merged[:limit]


def _combined_severity(scan_severity: dict[str, int], hub_severity: dict[str, int]) -> dict[str, int]:
    """Merge scan + hub-ingested severity into the five reconciled buckets.

    The hub histogram carries ``info``/``unknown`` bands the exec-score model
    doesn't rate — they fold into ``unrated`` so nothing is dropped and the
    merged buckets still sum to the true counted total (the same invariant PR1's
    coverage lanes hold).
    """
    merged = {key: int(scan_severity.get(key, 0) or 0) for key in _ALL_SEVERITY_KEYS}
    for band in ("critical", "high", "medium", "low"):
        merged[band] += int(hub_severity.get(band, 0) or 0)
    merged[_UNRATED_KEY] += int(hub_severity.get("info", 0) or 0) + int(hub_severity.get("unknown", 0) or 0)
    return merged


def _reconciled_exec_counts(estate: dict[str, Any], hub_severity: dict[str, int]) -> dict[str, int]:
    """The single exec-facing severity source of truth (#3961).

    Both the ``/v1/overview`` headline and ``/v1/posture/counts`` derive their
    critical/high/… from THIS reconciliation of the canonical, windowed scan
    current state with hub-ingested current evidence. The honest ``unrated``
    bucket is carried through and the buckets sum to ``total`` (no silent drop).
    """
    combined = _combined_severity(estate["severity"], hub_severity)
    return {
        "critical": combined["critical"],
        "high": combined["high"],
        "medium": combined["medium"],
        "low": combined["low"],
        "unrated": combined[_UNRATED_KEY],
        "total": sum(combined.values()),
        "kev": int(estate.get("kev", 0) or 0),
        "credential_exposed": int(estate.get("credential_exposed", 0) or 0),
    }


def _current_scan_severity(jobs: list[Any]) -> dict[str, int]:
    """Severity histogram with the exact scan semantics of ``/v1/findings``."""
    from agent_bom.api import time_window
    from agent_bom.api.compliance_hub_store import status_matches
    from agent_bom.api.findings_current import current_scan_findings
    from agent_bom.api.routes.scan import _iter_scan_findings

    since = time_window.window_since_iso(time_window.normalize_window_days(None))
    findings = current_scan_findings(
        jobs,
        since=since,
        scan_id=None,
        iter_findings=_iter_scan_findings,
    )
    severity = _empty_severity()
    for row in findings:
        # Default OPEN basis, matching ``/v1/findings`` and the hub snapshot so
        # the exec headline derives from live findings only. Scan findings carry
        # no lifecycle status, so they count as open by construction.
        if not status_matches(row, "open"):
            continue
        severity[_bucket(str(row.get("severity") or ""), severity)] += 1
    return severity


def _exec_estate(estate: dict[str, Any], jobs: list[Any]) -> dict[str, Any]:
    """Overlay canonical current scan counts without changing domain history."""
    return {**estate, "severity": _current_scan_severity(jobs)}


def exec_severity_counts(request: Request, jobs: list[Any]) -> dict[str, int]:
    """Reconciled current exec severity counts for ``jobs`` + hub evidence.

    Public entry point shared with ``/v1/posture/counts`` so nav badges and the
    overview headline read one number. Recomputes the estate rollup and hub
    snapshot; a caller that already holds them should use
    ``_reconciled_exec_counts`` directly to avoid a second pass.
    """
    estate = _estate_rollup(jobs)
    return _reconciled_exec_counts(_exec_estate(estate, jobs), _hub_severity_snapshot(request))


def _exec_posture(
    request: Request,
    scan_posture: dict[str, Any],
    estate: dict[str, Any],
    hub_severity: dict[str, int],
) -> dict[str, Any]:
    """Compute the configurable exec risk score from the honest estate counts.

    The grade derives from the same reconciled severity buckets (the unified
    findings spine + hub-ingested evidence), KEV, credential exposure, and the
    live count of failing compliance frameworks the overview already exposes —
    so it can never contradict them (a non-zero counted total always carries
    penalty). An authoritative scan scorecard is passed as a *floor*: the final
    score is the worst of the count-derived score and that scorecard, so
    ingested/benign evidence can only move the grade down, never launder a
    failing posture up. Reads the tenant's persisted score-config
    (defaults < env < tenant override).
    """
    from agent_bom.api.exec_score_config import resolve_exec_score_config

    combined = _combined_severity(estate["severity"], hub_severity)
    floor: float | None = None
    if scan_posture.get("grade") not in (None, "N/A"):
        floor = float(scan_posture.get("score") or 0.0)
    config = resolve_exec_score_config(_tenant_id(request))
    return compute_exec_score(
        severity=combined,
        kev=int(estate.get("kev", 0) or 0),
        exposure=int(estate.get("credential_exposed", 0) or 0),
        # Live count of failing compliance frameworks, accumulated in the same
        # estate rollup (#3962): a framework with a critical/high finding fails.
        # Cheap — no second control-by-control evaluation on this hot endpoint.
        compliance_failing=int(estate.get("compliance_failing", 0) or 0),
        config=config,
        floor_score=floor,
        floor_summary=str(scan_posture.get("summary") or "") or None,
    )


def _cloud_account_count(request: Request) -> int:
    """Connected cloud accounts for the Cloud posture domain tile."""
    try:
        from agent_bom.api.connection_store import get_connection_store

        return len(get_connection_store().list_for_tenant(_tenant_id(request)))
    except Exception:  # pragma: no cover - connection store optional
        _logger.debug("cloud account snapshot failed", exc_info=True)
        return 0


def _repo_scan_count(jobs: list[Any]) -> int:
    """Count completed jobs that targeted a remote repo URL or repo scan source."""
    count = 0
    for job in jobs:
        if job.status != JobStatus.DONE:
            continue
        request = getattr(job, "request", None)
        repo_url = getattr(request, "repo_url", None) if request is not None else None
        if isinstance(repo_url, str) and repo_url.strip():
            count += 1
            continue
        result = cast(dict[str, Any], getattr(job, "result", None) or {})
        sources = result.get("scan_sources") or []
        if isinstance(sources, list) and any(
            isinstance(src, str) and ("repo" in src.lower() or "project" in src.lower()) for src in sources
        ):
            count += 1
    return count


@router.get("/overview", tags=["overview"])
async def get_overview(request: Request) -> dict[str, Any]:
    """Cross-domain posture snapshot for the unified landing page.

    Read-only. Composes existing stores and summary helpers into one payload
    keyed by domain so the overview page can render a tile per domain plus a
    shared top-risks strip without fanning out to a dozen endpoints.

    The store + DB work (job rollup, hub severity GROUP BY, cost/identity/fleet
    stores) is offloaded off the event loop under the adaptive backpressure
    guard so a burst of overview reads cannot starve ``/health`` (#3963).
    """
    try:
        async with adaptive_backpressure("overview"):
            return await anyio.to_thread.run_sync(_build_overview, request)
    except BackpressureRejectedError as exc:
        raise HTTPException(
            status_code=429,
            detail=exc.to_dict(),
            headers={"Retry-After": str(exc.retry_after_seconds)},
        ) from exc


def _build_overview(request: Request) -> dict[str, Any]:
    """Synchronous overview composition (runs in a worker thread, #3963).

    Serves a cached payload when the tenant's job-metadata fingerprint is
    unchanged within the TTL, so repeated landing-page reads don't refold the
    whole estate (#3963 follow-up). Cache misses (new/changed scan data or an
    expired entry) recompute and refresh the cache.
    """
    tenant_id = _tenant_id(request)
    jobs = _get_store().list_all(tenant_id=tenant_id)
    hub_severity = _hub_severity_snapshot(request)

    fingerprint = _overview_fingerprint(jobs, hub_severity)
    cached = _overview_cache_get(tenant_id, fingerprint)
    if cached is not None:
        return cached

    payload = _compose_overview(request, tenant_id, jobs, hub_severity)
    _overview_cache_put(tenant_id, fingerprint, payload)
    return payload


def _compose_overview(request: Request, tenant_id: str, jobs: list[Any], hub_severity: dict[str, int]) -> dict[str, Any]:
    """Fold the estate into the overview payload (the O(estate) hot path)."""
    estate = _estate_rollup(jobs)
    exec_estate = _exec_estate(estate, jobs)
    coverage = estate["coverage"]
    posture = _exec_posture(request, _posture_snapshot(jobs), exec_estate, hub_severity)
    runtime = _runtime_snapshot(request, jobs)
    cost = _cost_snapshot(request)
    identity = _identity_snapshot(request)

    hub_findings = sum(int(hub_severity.get(k, 0) or 0) for k in _HUB_SEVERITY_KEYS)
    # Headline severity reads the SAME reconciled source of truth that
    # /v1/posture/counts reads — the unified spine folded with hub-ingested
    # evidence — never the CVE-only blast_radius (#3961). Both exec surfaces
    # route through ``_reconciled_exec_counts`` so they can never disagree.
    exec_counts = _reconciled_exec_counts(exec_estate, hub_severity)
    headline_critical = exec_counts["critical"]
    headline_high = exec_counts["high"]
    critical_high = headline_critical + headline_high

    cloud_accounts = _cloud_account_count(request)
    repo_scans = _repo_scan_count(jobs)
    vuln_severity = estate["vuln_severity"]

    # Fold hub-ingested findings into the exec top-risk strip so a
    # connector/bulk-ingested estate (scan jobs alone) no longer renders an empty
    # strip while a million open findings drive the grade (P0 #1).
    top_risks = _merge_top_risks(estate["top_risks"], _hub_top_risks(request))

    domains = {
        "cloud": {
            "label": "Cloud posture",
            "href": "/connections",
            "graph_href": _cloud_graph_href(estate["severity"]),
            "metric": cloud_accounts,
            "metric_label": "accounts connected",
            "status": "ok" if cloud_accounts > 0 else "idle",
            "detail": {
                "accounts": cloud_accounts,
                "sources": estate["sources"],
            },
        },
        "vuln": {
            "label": "Vuln / SCA",
            "href": "/findings?issue=vulnerability",
            "graph_href": _cloud_graph_href(vuln_severity),
            "metric": estate["unique_cves"],
            "metric_label": "open CVEs",
            "status": _status_for(vuln_severity["critical"], vuln_severity["high"]),
            "detail": {
                "critical": vuln_severity["critical"],
                "high": vuln_severity["high"],
                "kev": estate["kev"],
                "packages": estate["unique_packages"],
                # Full histogram (incl. ``unrated``) so the UI never renders a
                # metric that contradicts its severity strip.
                "severity": vuln_severity,
            },
        },
        "code": {
            "label": "Code / repo",
            "href": "/scan",
            "graph_href": _graph_drill_href(layers="directory,source_file,config_file,package,framework,vulnerability"),
            "metric": repo_scans,
            "metric_label": "repo scans",
            "status": "ok" if repo_scans > 0 else "idle",
            "detail": {"repo_scans": repo_scans, "packages": estate["unique_packages"]},
        },
        "runtime": {
            "label": "Runtime",
            "href": "/gateway",
            "graph_href": _graph_drill_href(relationships="runtime"),
            "metric": runtime["active_surfaces"],
            "metric_label": "active surfaces",
            "status": "ok" if runtime["active_surfaces"] > 0 else "idle",
            "detail": runtime,
        },
        "cost": {
            "label": "LLM Cost",
            "href": "/cost",
            "metric": round(float(cost["total_cost_usd"]), 2),
            "metric_label": "USD tracked",
            "status": "ok" if cost["total_calls"] > 0 else "idle",
            "detail": cost,
        },
        "identity": {
            "label": "NHI / Identity",
            "href": "/identity",
            "graph_href": _graph_drill_href(layers="agent,user,role,policy", relationships="governance"),
            "metric": identity["managed_identities"] + identity["fleet_agents"],
            "metric_label": "identities + agents",
            "status": _identity_status(identity),
            "detail": identity,
        },
        "ops": {
            "label": "Ops",
            "href": "/jobs",
            "metric": estate["scan_count"],
            "metric_label": "completed scans",
            "status": "warn" if estate["failed_count"] > 0 else ("ok" if estate["scan_count"] > 0 else "idle"),
            "detail": {
                "done": estate["done_count"],
                "failed": estate["failed_count"],
                "running": estate["running_count"],
                "packages": estate["unique_packages"],
            },
        },
    }

    return {
        "schema_version": "overview.v1",
        "tenant_id": tenant_id,
        "posture": posture,
        "headline": {
            "critical": headline_critical,
            "high": headline_high,
            "critical_high": critical_high,
            "kev": estate["kev"],
            "credential_exposed": estate["credential_exposed"],
            "scans": estate["scan_count"],
            "latest_scan_at": estate["latest_scan_at"],
            "hub_findings": hub_findings,
        },
        "domains": domains,
        "coverage": coverage,
        "top_risks": top_risks,
    }


@router.get("/overview/score-config", tags=["overview"])
async def get_overview_score_config(request: Request) -> dict[str, Any]:
    """Return the tenant's effective exec risk-score model + display config (#3940).

    Read-only view of the documented default weighting model, any tenant
    overrides, the effective weights/thresholds, and the active display format.
    """
    from agent_bom.api.exec_score_config import exec_score_config_runtime

    return exec_score_config_runtime(_tenant_id(request))


@router.put("/overview/score-config", tags=["overview"])
async def update_overview_score_config(request: Request, req: ExecScoreConfigUpdateRequest) -> dict[str, Any]:
    """Update the tenant's exec risk-score weights, thresholds, or display format.

    Admin-gated (mutating ``/v1`` verb). The body is canonicalized and clamped
    server-side — out-of-range weights are pinned into range, unknown keys are
    dropped, and an invalid display format falls back to the default, so a bad
    override never raises.
    """
    from agent_bom.api.audit_log import log_action
    from agent_bom.api.exec_score_config import exec_score_config_runtime, set_exec_score_config

    tenant_id = _tenant_id(request)
    updates = req.model_dump(exclude_none=True)
    if not updates:
        from fastapi import HTTPException

        raise HTTPException(status_code=400, detail="Provide at least one of weights, grade_thresholds, or display_format.")

    actor = getattr(request.state, "api_key_name", "") or "system"
    canonical = set_exec_score_config(tenant_id, updates)
    log_action(
        "overview.score_config_updated",
        actor=actor,
        resource=f"tenant/{tenant_id}",
        tenant_id=tenant_id,
        updated_fields=sorted(updates),
        display_format=canonical.get("display_format"),
    )
    return exec_score_config_runtime(tenant_id)


@router.delete("/overview/score-config", tags=["overview"], status_code=204)
async def reset_overview_score_config(request: Request) -> None:
    """Clear the tenant's exec risk-score overrides (revert to defaults)."""
    from agent_bom.api.audit_log import log_action
    from agent_bom.api.exec_score_config import clear_exec_score_config

    tenant_id = _tenant_id(request)
    actor = getattr(request.state, "api_key_name", "") or "system"
    cleared = clear_exec_score_config(tenant_id)
    if cleared:
        log_action(
            "overview.score_config_reset",
            actor=actor,
            resource=f"tenant/{tenant_id}",
            tenant_id=tenant_id,
        )


def _status_for(critical: int, high: int) -> str:
    if critical > 0:
        return "critical"
    if high > 0:
        return "warn"
    return "ok"


def _identity_status(identity: dict[str, Any]) -> str:
    if identity["low_trust_agents"] > 0:
        return "warn"
    if identity["fleet_agents"] or identity["managed_identities"]:
        return "ok"
    return "idle"
