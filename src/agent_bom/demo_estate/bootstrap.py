"""Bootstrap a labeled demo estate on first API start."""

from __future__ import annotations

import logging
import os
import threading
import uuid
from datetime import datetime, timezone
from typing import Any

from agent_bom.api.models import JobStatus, ScanJob, ScanRequest
from agent_bom.api.pipeline import _now
from agent_bom.api.store import DEMO_ESTATE_TRIGGERED_BY
from agent_bom.demo_estate.showcase_graph import (
    SHOWCASE_TENANT,
    seed_showcase_fleet_and_runtime,
    seed_showcase_graph_if_empty,
    seed_showcase_identities,
)

_logger = logging.getLogger(__name__)

_TRUTHY = {"1", "true", "yes", "on"}

# The UTC day the day-scoped demo evidence was last refreshed for. Guards the
# per-request hook down to one string compare once the day is current.
_daily_evidence_lock = threading.Lock()
_daily_evidence_day: str | None = None


def demo_estate_enabled() -> bool:
    return os.environ.get("AGENT_BOM_DEMO_ESTATE", "").strip().lower() in _TRUTHY


def reset_daily_evidence_day() -> None:
    """Forget which day the evidence was refreshed for. For tests and resets."""
    global _daily_evidence_day
    with _daily_evidence_lock:
        _daily_evidence_day = None


def refresh_demo_daily_evidence(*, tenant_id: str = SHOWCASE_TENANT, now: datetime | None = None) -> dict[str, Any]:
    """Re-seed the demo evidence that is scoped to a single UTC day.

    The gateway KPI header, proxy status, firewall stats and the cost page all
    window on ``[UTC midnight, request time]``. Evidence seeded at boot carries
    the boot day's timestamps, so the moment the UTC day advances every one of
    those surfaces reads 0 — a demo that claims no traffic on an estate the same
    page describes as busy. Seeding once was never enough; the day has to be
    re-checked, and the 60s maintenance loop alone leaves a visible window right
    after midnight.

    The day marker is claimed BEFORE seeding, so a concurrent burst of requests
    at rollover produces one reseed rather than a stampede, and a seeding
    failure is retried by the maintenance loop rather than by every request.
    """
    global _daily_evidence_day

    if not demo_estate_enabled():
        return {"refreshed": False, "reason": "disabled"}

    today = (now or datetime.now(timezone.utc)).date().isoformat()
    with _daily_evidence_lock:
        if _daily_evidence_day == today:
            return {"refreshed": False, "reason": "current", "day": today}
        _daily_evidence_day = today

    summary: dict[str, Any] = {"refreshed": True, "day": today, "tenant_id": tenant_id}
    try:
        from agent_bom.demo_estate.showcase_gateway import seed_showcase_gateway_events

        summary["gateway_feed"] = seed_showcase_gateway_events(tenant_id=tenant_id, now=now)
    except Exception:
        _logger.warning("demo estate daily gateway refresh failed", exc_info=True)
        summary["gateway_feed_error"] = True
    try:
        from agent_bom.demo_estate.showcase_governance import seed_showcase_governance_and_cost

        summary["governance_cost"] = seed_showcase_governance_and_cost(tenant_id=tenant_id, now=now)
    except Exception:
        _logger.warning("demo estate daily cost refresh failed", exc_info=True)
        summary["governance_cost_error"] = True
    return summary


def demo_estate_force_reseed() -> bool:
    """Operator override: always reseed scan jobs even when usable ones exist."""
    return os.environ.get("AGENT_BOM_DEMO_ESTATE_FORCE", "").strip().lower() in _TRUTHY


def _job_has_demo_source(job: Any) -> bool:
    result = getattr(job, "result", None) or {}
    sources = result.get("scan_sources") or []
    if any("demo" in str(src).lower() for src in sources):
        return True
    return getattr(job, "triggered_by", None) == DEMO_ESTATE_TRIGGERED_BY


def _job_has_findings(job: Any) -> bool:
    result = getattr(job, "result", None) or {}
    findings = result.get("findings") or result.get("vulnerabilities") or []
    return bool(findings)


def _tenant_has_demo_jobs(store: Any, tenant_id: str) -> bool:
    """True when the tenant already has a *usable* demo scan job.

    Presence alone is not enough: an empty or FAILED demo marker (or a job
    whose findings were never persisted) must not block reseed — that is how
    the public demo can boot with graph/catalog populated but findings=[].
    """
    list_fn = getattr(store, "list_all", None)
    if not callable(list_fn):
        return False
    jobs = list_fn(tenant_id=tenant_id)
    for job in jobs:
        status = getattr(job, "status", None)
        if status is not None and status != JobStatus.DONE and str(status).lower() != "done":
            continue
        if _job_has_demo_source(job) and _job_has_findings(job):
            return True
    return False


def _estate_findings(tenant_id: str) -> list[Any]:
    """Return the composed estate's findings for the demo scan job.

    Seeded through the SAME ``findings`` list every other generator uses, so the
    findings list, the severity facets, the exec tiles, SARIF and every export
    read one derivation. Anything else would let the demo's own surfaces
    disagree with each other, which is precisely what the estate exists to
    disprove.
    """
    from agent_bom.demo_estate.enterprise_composition import build_demo_estate
    from agent_bom.demo_estate.enterprise_findings import build_estate_findings

    return list(build_estate_findings(build_demo_estate(tenant_id=tenant_id)))


def _estate_blast_radii(tenant_id: str) -> list[Any]:
    """Return the blast radii behind the estate's CVE findings.

    Not optional, and not a duplicate of the findings above.
    ``output.finding_views.cve_findings`` resolves the report's CVE array from
    ``report.blast_radii`` whenever that list is non-empty, and the unified
    ``findings`` array excludes ``CVE`` by design. An estate that contributed
    CVE findings but no blast radii therefore had its entire vulnerability lane
    dropped between the seeder and the API — ``/v1/findings`` reported 1,833 of
    2,601 seeded rows and no surface said a lane was missing.
    """
    from agent_bom.demo_estate.enterprise_composition import build_demo_estate
    from agent_bom.demo_estate.enterprise_risk import build_vulnerability_blast_radii

    return list(build_vulnerability_blast_radii(build_demo_estate(tenant_id=tenant_id)))


def _run_demo_scan_report(*, tenant_id: str) -> dict[str, Any]:
    from agent_bom.cli._common import _build_agents_from_inventory
    from agent_bom.demo import DEMO_INVENTORY
    from agent_bom.finding import blast_radius_to_finding
    from agent_bom.mcp_auth_posture import evaluate_mcp_auth_posture
    from agent_bom.mcp_blocklist import blocklist_findings_for_agents
    from agent_bom.models import AIBOMReport
    from agent_bom.output import to_json
    from agent_bom.scanners import scan_agents_sync

    agents = _build_agents_from_inventory(DEMO_INVENTORY, "agent-bom --demo")
    blast_radii = scan_agents_sync(
        agents,
        compliance_enabled=True,
        show_scan_banner=False,
        offline=True,
        demo_advisories=True,
    )
    findings = [blast_radius_to_finding(br) for br in blast_radii]
    findings.extend(blocklist_findings_for_agents(agents))
    findings.extend(evaluate_mcp_auth_posture(agents))
    findings.extend(_estate_findings(tenant_id))
    # Both halves of the vulnerability lane, or neither surfaces (see
    # ``_estate_blast_radii``).
    blast_radii = [*blast_radii, *_estate_blast_radii(tenant_id)]
    report = to_json(
        AIBOMReport(
            agents=agents,
            blast_radii=blast_radii,
            findings=findings,
            scan_sources=["demo", "demo-estate"],
            scan_id="showcase",
        )
    )

    report.setdefault("scan_sources", [])
    if "demo" not in report["scan_sources"]:
        report["scan_sources"].append("demo")
    if "demo-estate" not in report["scan_sources"]:
        report["scan_sources"].append("demo-estate")

    # Overlay a curated multi-cloud CIS benchmark posture so the CIS/compliance
    # surfaces render a believable AWS/GCP/Azure pass-fail spread. The keys are
    # exactly what build_cis_benchmark_check_rows() reads from a scan result.
    from agent_bom.demo_estate.showcase_cis import demo_cis_benchmarks

    for key, benchmark in demo_cis_benchmarks().items():
        report.setdefault(key, benchmark)
    return report


def _store_demo_scan_job(report: dict[str, Any], *, tenant_id: str) -> str:
    from agent_bom.api.stores import _get_store, _jobs_put

    job = ScanJob(
        job_id=str(uuid.uuid4()),
        tenant_id=tenant_id,
        triggered_by=DEMO_ESTATE_TRIGGERED_BY,
        created_at=_now(),
        request=ScanRequest(offline=True),
    )
    job.status = JobStatus.DONE
    job.completed_at = _now()
    job.result = report
    job.progress.append("Seeded demo estate scan (offline curated sample)")
    store = _get_store()
    store.put(job)
    _jobs_put(job.job_id, job)
    return job.job_id


def maybe_bootstrap_demo_estate(*, tenant_id: str = SHOWCASE_TENANT) -> dict[str, Any]:
    """Seed showcase graph + curated findings when demo estate mode is enabled."""
    if not demo_estate_enabled():
        return {"enabled": False, "seeded": False}

    from agent_bom.api.stores import _get_graph_store, _get_store

    store = _get_store()
    graph_store = _get_graph_store()
    summary: dict[str, Any] = {"enabled": True, "tenant_id": tenant_id, "seeded": False}
    force = demo_estate_force_reseed()
    if force:
        summary["force"] = True

    # Validate and fingerprint the versioned synthetic-estate contract on every
    # demo boot. PRs that project this evidence into graph/runtime/UI surfaces
    # can now consume one deterministic source instead of inventing unrelated
    # rows per screen. A malformed fixture remains an explicit bootstrap error.
    try:
        from agent_bom.demo_estate.enterprise import CollectionStatus
        from agent_bom.demo_estate.enterprise_composition import build_demo_estate

        enterprise = build_demo_estate(tenant_id=tenant_id)
        summary["enterprise_contract"] = {
            "schema_version": enterprise.schema_version,
            "estate_id": enterprise.estate_id,
            "content_hash": enterprise.content_hash,
            "assets": len(enterprise.assets),
            "observations": len(enterprise.observations),
            "snapshots": len(enterprise.snapshots),
            "partial_sources": sorted(run.source.value for run in enterprise.collection_runs if run.status is CollectionStatus.PARTIAL),
        }
    except Exception:
        _logger.warning("demo enterprise contract validation failed", exc_info=True)
        summary["enterprise_contract_error"] = True

    # Graph seed is isolated and stale-aware: a real scan is left untouched, a
    # current demo seed is a no-op, and a stale demo seed is refreshed (see
    # seed_showcase_graph_if_empty). Any failure must NOT block the findings/scan
    # or identity seeding below — those keep posture + NHI non-empty on start.
    graph_seeded = False
    try:
        graph_seeded = seed_showcase_graph_if_empty(graph_store, tenant_id=tenant_id)
    except Exception:
        _logger.warning("demo estate graph seeding failed", exc_info=True)
        summary["graph_error"] = True
    summary["graph_seeded"] = graph_seeded

    # Seed the live agent-identity store (NHI estate) independently of the graph
    # snapshot so the NHI/Identity overview tile and the nhi-governance posture
    # survive a restart even when the graph already exists. Idempotent.
    try:
        summary["identities"] = seed_showcase_identities(tenant_id=tenant_id)
    except Exception:
        _logger.warning("demo estate identity seeding failed", exc_info=True)
        summary["identity_error"] = True

    # The AI BOM page reads the fleet registry and the MCP observation store —
    # neither of which the graph/findings seeds touch, so it rendered every
    # count as 0 on a fully populated estate. Same isolation as the identity
    # seed above: its failure must not block the rest of the bootstrap.
    try:
        summary["fleet_runtime"] = seed_showcase_fleet_and_runtime(tenant_id=tenant_id)
    except Exception:
        _logger.warning("demo estate fleet/runtime seeding failed", exc_info=True)
        summary["fleet_runtime_error"] = True

    # Seed the runtime gateway feed (proxy alerts + metrics + firewall
    # decisions) so the gateway/proxy/runtime dashboards show the AI-firewall in
    # action on the demo. Idempotent and independent of the scan-job seeding
    # below, so it must run even when demo jobs already exist.
    try:
        from agent_bom.demo_estate.showcase_gateway import seed_showcase_gateway_events

        summary["gateway_feed"] = seed_showcase_gateway_events(tenant_id=tenant_id)
    except Exception:
        _logger.warning("demo estate gateway feed seeding failed", exc_info=True)
        summary["gateway_feed_error"] = True

    # build_showcase_graph computes drift incidents into a private store it hands
    # back to its caller, while every drift surface reads the process-global
    # drift store. Without this the demo described drift in its own graph and
    # reported 0 incidents on every tile above it.
    try:
        from agent_bom.demo_estate.showcase_drift import seed_showcase_drift_incidents

        summary["drift_incidents"] = seed_showcase_drift_incidents(tenant_id=tenant_id)
    except Exception:
        _logger.warning("demo estate drift seeding failed", exc_info=True)
        summary["drift_error"] = True

    try:
        from agent_bom.demo_estate.showcase_catalog import seed_showcase_catalog_if_empty

        summary["catalog"] = seed_showcase_catalog_if_empty(tenant_id=tenant_id)
    except Exception:
        _logger.warning("demo estate catalog seeding failed", exc_info=True)
        summary["catalog_error"] = True

    # Governance blueprints and LLM spend live in their own stores, which the
    # graph/findings seeds never touch — the same gap the fleet/runtime seed
    # above closed for the AI BOM page. Without this the governance page showed
    # `count: 0` and the cost page a single call on an estate with thousands of
    # assets, which reads as a broken product rather than an unconfigured one.
    try:
        from agent_bom.demo_estate.showcase_governance import seed_showcase_governance_and_cost

        summary["governance_cost"] = seed_showcase_governance_and_cost(tenant_id=tenant_id)
    except Exception:
        _logger.warning("demo estate governance/cost seeding failed", exc_info=True)
        summary["governance_cost_error"] = True

    if not force and _tenant_has_demo_jobs(store, tenant_id):
        summary["reason"] = "demo_jobs_present"
        return summary

    try:
        report = _run_demo_scan_report(tenant_id=tenant_id)
        finding_count = len(report.get("findings") or report.get("vulnerabilities") or [])
        if finding_count < 1:
            raise RuntimeError("demo estate scan produced zero findings")
        job_id = _store_demo_scan_job(report, tenant_id=tenant_id)
        summary.update(
            {
                "seeded": True,
                "job_id": job_id,
                "agents": len(report.get("agents") or []),
                "findings": finding_count,
            }
        )
        _logger.info(
            "demo estate bootstrap complete tenant=%s graph_seeded=%s job_id=%s findings=%s",
            tenant_id,
            graph_seeded,
            job_id,
            summary.get("findings"),
        )
    except Exception:
        _logger.warning("demo estate scan bootstrap failed", exc_info=True)
        summary["seeded"] = graph_seeded
        summary["scan_error"] = True

    return summary
