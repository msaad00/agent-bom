"""Miscellaneous endpoints: traces, push, assets."""

from __future__ import annotations

import logging
import uuid

from fastapi import APIRouter, HTTPException

from agent_bom.api.models import JobStatus, PushPayload, ScanJob, ScanRequest
from agent_bom.api.pipeline import _now
from agent_bom.api.stores import _get_store
from agent_bom.security import sanitize_error

router = APIRouter()
_logger = logging.getLogger(__name__)


# ─── OpenTelemetry Trace Ingestion ───────────────────────────────────────────


@router.post("/v1/traces", tags=["observability"])
async def ingest_traces(body: dict) -> dict:
    """Ingest OpenTelemetry trace data and flag vulnerable tool calls."""
    try:
        from agent_bom.otel_ingest import flag_vulnerable_tool_calls, parse_otel_traces

        traces = parse_otel_traces(body)
        if not traces:
            return {"traces": 0, "flagged": [], "message": "No tool call traces found"}

        vuln_packages: list[str] = []
        vuln_servers: list[str] = []
        for job in _get_store().list_all():
            if job.status == JobStatus.DONE and job.result:
                for br in job.result.get("blast_radius", []):
                    pkg = br.get("package", "")
                    if pkg:
                        vuln_packages.append(pkg)
                    for srv in br.get("affected_servers", []):
                        name = srv if isinstance(srv, str) else srv.get("name", "")
                        if name:
                            vuln_servers.append(name)

        flagged = flag_vulnerable_tool_calls(traces, {p: [] for p in vuln_packages}, set(vuln_servers))

        return {
            "traces": len(traces),
            "flagged": [
                {
                    "tool_name": f.trace.tool_name,
                    "reason": f.reason,
                    "severity": f.severity,
                    "span_id": f.trace.span_id,
                }
                for f in flagged
            ],
        }
    except Exception as exc:  # noqa: BLE001
        _logger.exception("Request failed")
        raise HTTPException(status_code=500, detail=sanitize_error(exc)) from exc


# ─── Hybrid Push — receive results from CLI ──────────────────────────────────


@router.post("/v1/results/push", tags=["push"], status_code=201)
async def receive_push(body: PushPayload) -> dict:
    """Receive pushed scan results from a CLI instance."""
    job = ScanJob(
        job_id=str(uuid.uuid4()),
        created_at=_now(),
        request=ScanRequest(),
    )
    job.status = JobStatus.DONE
    job.result = {
        "agents": body.agents,
        "blast_radii": body.blast_radii,
        "warnings": body.warnings,
        "source_id": body.source_id,
        "pushed": True,
    }
    job.progress.append(f"Received via push from source={body.source_id}")
    _get_store().put(job)
    return {"job_id": job.job_id, "source_id": body.source_id, "status": "stored"}


# ─── Asset Tracking ──────────────────────────────────────────────────────────


@router.get("/v1/assets", tags=["assets"])
async def list_assets(
    status: str | None = None,
    severity: str | None = None,
    limit: int = 500,
) -> dict:
    """List tracked vulnerability assets with first_seen / last_seen / status."""
    try:
        from agent_bom.asset_tracker import AssetTracker

        tracker = AssetTracker()
        assets = tracker.list_assets(status=status, severity=severity, limit=limit)
        stats = tracker.stats()
        mttr = tracker.mttr_days()
        tracker.close()
        return {
            "assets": assets,
            "count": len(assets),
            "stats": stats,
            "mttr_days": mttr,
        }
    except Exception as exc:
        _logger.exception("Failed to list assets")
        return {
            "assets": [],
            "count": 0,
            "stats": {},
            "mttr_days": None,
            "error": sanitize_error(exc),
        }


@router.get("/v1/assets/stats", tags=["assets"])
async def get_asset_stats() -> dict:
    """Return aggregate asset tracking statistics including MTTR."""
    try:
        from agent_bom.asset_tracker import AssetTracker

        tracker = AssetTracker()
        stats = tracker.stats()
        mttr = tracker.mttr_days()
        tracker.close()
        return {"stats": stats, "mttr_days": mttr}
    except Exception as exc:
        _logger.exception("Failed to get asset stats")
        return {
            "stats": {},
            "mttr_days": None,
            "error": sanitize_error(exc),
        }
