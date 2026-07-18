"""Governance and Snowflake observability API routes.

Endpoints:
    GET  /v1/governance            governance discovery report
    GET  /v1/governance/findings   governance findings (filterable)
    GET  /v1/activity              agent activity timeline
    GET  /v1/cortex/telemetry      aggregated Cortex agent telemetry
    GET  /v1/cortex/agents/{name}/telemetry  per-agent telemetry
    GET  /v1/cortex/health         Cortex agent health status
    GET  /v1/siem/formats          supported SIEM event formats

Every handler here mines Snowflake ACCESS_HISTORY / QUERY_HISTORY / usage
history synchronously. Those blocking calls run off the event loop via
``anyio.to_thread.run_sync`` under an adaptive-backpressure guard (mirroring the
cloud + fleet read paths) so a slow Snowflake mine can never stall ``/health`` or
any unrelated request; a burst sheds with a 429 + ``Retry-After`` instead.
"""

from __future__ import annotations

import logging
from typing import Any, Callable, TypeVar

import anyio.to_thread
from fastapi import APIRouter, HTTPException

from agent_bom.backpressure import BackpressureRejectedError, adaptive_backpressure
from agent_bom.security import sanitize_error

router = APIRouter()
_logger = logging.getLogger(__name__)

_T = TypeVar("_T")


async def _offload(build: Callable[[], _T]) -> _T:
    """Run a synchronous Snowflake-mining callable off the event loop.

    Guarded by the shared ``governance`` backpressure controller so a pile-up of
    concurrent mines sheds cleanly (429 + ``Retry-After``) rather than starving
    the loop.
    """
    try:
        async with adaptive_backpressure("governance"):
            return await anyio.to_thread.run_sync(build)
    except BackpressureRejectedError as exc:
        raise HTTPException(
            status_code=429,
            detail=exc.to_dict(),
            headers={"Retry-After": str(exc.retry_after_seconds)},
        ) from exc


@router.get("/governance", tags=["governance"])
async def governance_report(days: int = 30):
    """Run Snowflake governance discovery and return findings.

    Mines ACCESS_HISTORY, GRANTS_TO_ROLES, TAG_REFERENCES, and
    CORTEX_AGENT_USAGE_HISTORY. Requires SNOWFLAKE_ACCOUNT env var.
    """
    import os

    days = max(1, min(days, 365))

    if not os.environ.get("SNOWFLAKE_ACCOUNT"):
        raise HTTPException(
            status_code=400,
            detail="SNOWFLAKE_ACCOUNT env var not set. Governance requires Snowflake.",
        )

    def _run() -> dict[str, Any]:
        from agent_bom.cloud import discover_governance

        report = discover_governance(provider="snowflake", days=days)
        return report.to_dict()

    try:
        return await _offload(_run)
    except HTTPException:
        raise
    except Exception as exc:
        _logger.exception("Request failed")
        raise HTTPException(status_code=500, detail=sanitize_error(exc))


@router.get("/governance/findings", tags=["governance"])
async def governance_findings(
    days: int = 30,
    severity: str | None = None,
    category: str | None = None,
    limit: int = 500,
    offset: int = 0,
):
    """Return only governance findings, optionally filtered.

    Returns the canonical finding-list envelope (#3666) shared with
    ``/v1/findings`` so consumers learn one shape across every finding surface.
    Governance findings are computed on demand from Snowflake discovery rather
    than served from a keyset store, so pagination is in-memory ``limit`` /
    ``offset`` over the materialized list; ``cursor`` / ``next_cursor`` stay
    empty for this surface.
    """
    import os

    days = max(1, min(days, 365))
    safe_limit = max(1, min(limit, 1000))
    safe_offset = max(0, offset)

    if not os.environ.get("SNOWFLAKE_ACCOUNT"):
        raise HTTPException(
            status_code=400,
            detail="SNOWFLAKE_ACCOUNT env var not set.",
        )

    def _run() -> dict[str, Any]:
        from agent_bom.api.finding_list_envelope import finding_list_envelope
        from agent_bom.cloud import discover_governance

        report = discover_governance(provider="snowflake", days=days)
        findings = [f.to_dict() for f in report.findings]

        if severity:
            findings = [f for f in findings if f["severity"] == severity.lower()]
        if category:
            findings = [f for f in findings if f["category"] == category.lower()]

        total = len(findings)
        page = findings[safe_offset : safe_offset + safe_limit]
        return finding_list_envelope(
            findings=page,
            total=total,
            limit=safe_limit,
            offset=safe_offset,
            warnings=list(report.warnings),
        )

    try:
        return await _offload(_run)
    except HTTPException:
        raise
    except Exception as exc:
        _logger.exception("Request failed")
        raise HTTPException(status_code=500, detail=sanitize_error(exc))


@router.get("/activity", tags=["governance"])
async def activity_timeline(days: int = 30):
    """Agent activity timeline from Snowflake QUERY_HISTORY + AI_OBSERVABILITY_EVENTS.

    Reconstructs agent execution history from 365-day query history
    and AI observability traces.
    """
    import os

    days = max(1, min(days, 365))

    if not os.environ.get("SNOWFLAKE_ACCOUNT"):
        raise HTTPException(
            status_code=400,
            detail="SNOWFLAKE_ACCOUNT env var not set. Activity requires Snowflake.",
        )

    def _run() -> dict[str, Any]:
        from agent_bom.cloud import discover_activity

        timeline = discover_activity(provider="snowflake", days=days)
        return timeline.to_dict()

    try:
        return await _offload(_run)
    except HTTPException:
        raise
    except Exception as exc:
        _logger.exception("Request failed")
        raise HTTPException(status_code=500, detail=sanitize_error(exc))


@router.get("/cortex/telemetry", tags=["governance"], deprecated=True)
async def cortex_telemetry(hours: int = 24):
    """Aggregated Cortex agent telemetry with health assessments.

    Combines CORTEX_AGENT_USAGE_HISTORY and AI_OBSERVABILITY_EVENTS
    into per-agent metrics, error rates, latency percentiles, and
    health status.

    Soft-deprecated: no UI/CLI/MCP product consumer (#3666 Phase 2).
    """
    import os

    hours = max(1, min(hours, 8760))

    if not os.environ.get("SNOWFLAKE_ACCOUNT"):
        raise HTTPException(
            status_code=400,
            detail="SNOWFLAKE_ACCOUNT env var not set.",
        )

    def _run() -> Any:
        from agent_bom.cloud.snowflake import _get_connection  # type: ignore[attr-defined]
        from agent_bom.cloud.snowflake_observability import get_cortex_telemetry

        conn = _get_connection()
        try:
            return get_cortex_telemetry(conn, hours=hours)
        finally:
            conn.close()

    try:
        return await _offload(_run)
    except HTTPException:
        raise
    except Exception as exc:
        _logger.exception("Request failed")
        raise HTTPException(status_code=500, detail=sanitize_error(exc))


@router.get("/cortex/agents/{name}/telemetry", tags=["governance"])
async def cortex_agent_telemetry(name: str, hours: int = 24):
    """Telemetry for a specific Cortex agent."""
    import os

    if not os.environ.get("SNOWFLAKE_ACCOUNT"):
        raise HTTPException(
            status_code=400,
            detail="SNOWFLAKE_ACCOUNT env var not set.",
        )

    def _run() -> Any:
        from agent_bom.cloud.snowflake import _get_connection  # type: ignore[attr-defined]
        from agent_bom.cloud.snowflake_observability import get_cortex_telemetry

        conn = _get_connection()
        try:
            return get_cortex_telemetry(conn, agent_name=name, hours=hours)
        finally:
            conn.close()

    try:
        return await _offload(_run)
    except HTTPException:
        raise
    except Exception as exc:
        _logger.exception("Request failed")
        raise HTTPException(status_code=500, detail=sanitize_error(exc))


@router.get("/cortex/health", tags=["governance"])
async def cortex_health():
    """Health status for all Cortex agents."""
    import os

    if not os.environ.get("SNOWFLAKE_ACCOUNT"):
        raise HTTPException(
            status_code=400,
            detail="SNOWFLAKE_ACCOUNT env var not set.",
        )

    def _run() -> dict[str, Any]:
        from agent_bom.cloud.snowflake import _get_connection, _mine_cortex_agent_usage
        from agent_bom.cloud.snowflake_observability import (
            aggregate_agent_metrics,
            assess_agent_health,
        )

        conn = _get_connection()
        try:
            records, warnings = _mine_cortex_agent_usage(conn, days=1)
        finally:
            conn.close()

        metrics = aggregate_agent_metrics(records, hours=24)
        health = [assess_agent_health(m) for m in metrics]

        return {
            "agents": [
                {
                    "name": h.agent_name,
                    "status": h.status,
                    "issues": h.issues,
                }
                for h in health
            ],
            "warnings": warnings,
        }

    try:
        return await _offload(_run)
    except HTTPException:
        raise
    except Exception as exc:
        _logger.exception("Request failed")
        raise HTTPException(status_code=500, detail=sanitize_error(exc))


@router.get("/siem/formats", tags=["siem"])
async def siem_formats():
    """List supported SIEM event formats."""
    from agent_bom.siem import list_formats

    return {"formats": list_formats()}
