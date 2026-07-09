"""Bootstrap a labeled demo estate on first API start."""

from __future__ import annotations

import logging
import os
import uuid
from typing import Any

from agent_bom.api.models import JobStatus, ScanJob, ScanRequest
from agent_bom.api.pipeline import _now
from agent_bom.demo_estate.showcase_graph import SHOWCASE_TENANT, seed_showcase_graph_if_empty

_logger = logging.getLogger(__name__)

_TRUTHY = {"1", "true", "yes", "on"}


def demo_estate_enabled() -> bool:
    return os.environ.get("AGENT_BOM_DEMO_ESTATE", "").strip().lower() in _TRUTHY


def _tenant_has_demo_jobs(store: Any, tenant_id: str) -> bool:
    list_fn = getattr(store, "list_all", None)
    if not callable(list_fn):
        return False
    jobs = list_fn(tenant_id=tenant_id)
    for job in jobs:
        result = getattr(job, "result", None) or {}
        sources = result.get("scan_sources") or []
        if any("demo" in str(src).lower() for src in sources):
            return True
    return False


def _run_demo_scan_report() -> dict[str, Any]:
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
        triggered_by="demo-estate-bootstrap",
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

    graph_seeded = seed_showcase_graph_if_empty(graph_store, tenant_id=tenant_id)
    summary["graph_seeded"] = graph_seeded

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

    if _tenant_has_demo_jobs(store, tenant_id):
        summary["reason"] = "demo_jobs_present"
        return summary

    try:
        report = _run_demo_scan_report()
        job_id = _store_demo_scan_job(report, tenant_id=tenant_id)
        summary.update(
            {
                "seeded": True,
                "job_id": job_id,
                "agents": len(report.get("agents") or []),
                "findings": len(report.get("findings") or report.get("vulnerabilities") or []),
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
