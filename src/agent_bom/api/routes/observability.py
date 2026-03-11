"""Observability and data ingestion API routes.

Endpoints:
    POST /v1/traces        ingest OpenTelemetry traces
    POST /v1/results/push  receive pushed scan results from CLI
"""

from __future__ import annotations

import logging
import uuid

from fastapi import APIRouter, HTTPException

from agent_bom.api.models import JobStatus, PushPayload, ScanJob, ScanRequest
from agent_bom.api.stores import _get_store
from agent_bom.security import sanitize_error

router = APIRouter()
_logger = logging.getLogger(__name__)


def _now() -> str:
    from datetime import datetime, timezone

    return datetime.now(timezone.utc).isoformat()


@router.post("/v1/traces", tags=["observability"])
async def ingest_traces(body: dict) -> dict:
    """Ingest OpenTelemetry trace data and flag vulnerable tool calls.

    Accepts OTLP JSON format traces containing `adk.tool.*` spans.
    Cross-references tool calls against completed scan results to flag
    any calls that touch packages with known CVEs.
    """
    try:
        from agent_bom.otel_ingest import flag_vulnerable_tool_calls, parse_otel_traces

        traces = parse_otel_traces(body)
        if not traces:
            return {"traces": 0, "flagged": [], "message": "No tool call traces found"}

        # Gather vulnerable packages and servers from scan history
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


@router.post("/v1/results/push", tags=["push"], status_code=201)
async def receive_push(body: PushPayload) -> dict:
    """Receive pushed scan results from a CLI instance.

    Stores as a completed ScanJob with source metadata.
    """
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
