"""Bootstrap a labeled demo estate on first API start."""

from __future__ import annotations

import json
import logging
import os
import tempfile
import uuid
from pathlib import Path
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
    from click.testing import CliRunner

    from agent_bom.cli import main

    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as handle:
        out_path = handle.name
    try:
        runner = CliRunner()
        result = runner.invoke(
            main,
            [
                "agents",
                "--demo",
                "--offline",
                "--quiet",
                "--no-auto-update-db",
                "-f",
                "json",
                "-o",
                out_path,
            ],
        )
        if result.exit_code != 0:
            raise RuntimeError(f"demo scan failed: {result.output}")
        report = json.loads(Path(out_path).read_text(encoding="utf-8"))
    finally:
        Path(out_path).unlink(missing_ok=True)

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
