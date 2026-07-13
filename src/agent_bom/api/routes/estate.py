"""Estate correlation read API — cross-environment agent matches from scan evidence.

Surfaces the same ``correlate_cross_environment`` matcher the graph builder uses
when emitting ``CORRELATES_WITH`` / ``POSSIBLY_CORRELATES_WITH`` edges, without
requiring a full graph load.
"""

from __future__ import annotations

from dataclasses import asdict
from typing import Any, cast

from fastapi import APIRouter, HTTPException, Query, Request

from agent_bom.api.models import JobStatus
from agent_bom.api.stores import _get_store
from agent_bom.api.tenancy import require_request_tenant_id
from agent_bom.cross_env_correlation import CorrelationConfidence, correlate_cross_environment
from agent_bom.rbac import require_authenticated_permission

router = APIRouter(dependencies=[cast(Any, require_authenticated_permission("read"))])


def _tenant_id(request: Request) -> str:
    return require_request_tenant_id(request)


def _latest_done_job(tenant_id: str, *, scan_id: str | None = None) -> Any | None:
    jobs = _get_store().list_all(tenant_id=tenant_id)
    if scan_id:
        for job in jobs:
            if job.job_id == scan_id and job.status == JobStatus.DONE and job.result:
                return job
        return None
    for job in jobs:
        if job.status == JobStatus.DONE and job.result:
            return job
    return None


def _match_payload(match: Any) -> dict[str, Any]:
    payload = asdict(match)
    confidence = payload.pop("confidence", None)
    if isinstance(confidence, CorrelationConfidence):
        payload["confidence"] = confidence.value
    elif hasattr(confidence, "value"):
        payload["confidence"] = confidence.value
    payload["matched_signals"] = list(payload.get("matched_signals") or ())
    return payload


@router.get("/estate/correlations", tags=["estate"], deprecated=True)
async def get_estate_correlations(
    request: Request,
    scan_id: str | None = Query(None, description="Scan job ID; latest completed scan if omitted"),
) -> dict[str, Any]:
    """Return local↔cloud agent correlation matches for a completed scan.

    Soft-deprecated: no UI/CLI/MCP product consumer (#3666 Phase 2).
    """
    tenant_id = _tenant_id(request)
    job = _latest_done_job(tenant_id, scan_id=scan_id)
    if job is None:
        if scan_id:
            raise HTTPException(status_code=404, detail=f"Completed scan '{scan_id}' not found")
        return {
            "schema_version": "estate.correlations.v1",
            "tenant_id": tenant_id,
            "scan_id": None,
            "count": 0,
            "high_confidence_count": 0,
            "low_confidence_count": 0,
            "matches": [],
        }

    agents = job.result.get("agents") if isinstance(job.result, dict) else None
    if not isinstance(agents, list):
        agents = []

    result = correlate_cross_environment(agents)
    matches = [_match_payload(match) for match in result.matches]
    high = len(result.by_confidence(CorrelationConfidence.HIGH))
    low = len(result.by_confidence(CorrelationConfidence.LOW))

    return {
        "schema_version": "estate.correlations.v1",
        "tenant_id": tenant_id,
        "scan_id": job.job_id,
        "count": len(matches),
        "high_confidence_count": high,
        "low_confidence_count": low,
        "matches": matches,
    }
