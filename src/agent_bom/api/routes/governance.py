"""Governance and Snowflake observability API routes.

Endpoints:
    GET  /v1/governance            governance discovery report
    GET  /v1/governance/findings   governance findings (filterable)
    GET  /v1/activity              agent activity timeline
    GET  /v1/cortex/telemetry      aggregated Cortex agent telemetry
    GET  /v1/cortex/agents/{name}/telemetry  per-agent telemetry
    GET  /v1/cortex/health         Cortex agent health status
    GET  /v1/siem/formats          supported SIEM event formats
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, HTTPException

from agent_bom.security import sanitize_error

router = APIRouter()
_logger = logging.getLogger(__name__)


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

    try:
        from agent_bom.cloud import discover_governance

        report = discover_governance(provider="snowflake", days=days)
        return report.to_dict()
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

    from agent_bom.api.finding_list_envelope import finding_list_envelope

    days = max(1, min(days, 365))
    safe_limit = max(1, min(limit, 1000))
    safe_offset = max(0, offset)

    if not os.environ.get("SNOWFLAKE_ACCOUNT"):
        raise HTTPException(
            status_code=400,
            detail="SNOWFLAKE_ACCOUNT env var not set.",
        )

    try:
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

    try:
        from agent_bom.cloud import discover_activity

        timeline = discover_activity(provider="snowflake", days=days)
        return timeline.to_dict()
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

    try:
        from agent_bom.cloud.snowflake import _get_connection  # type: ignore[attr-defined]
        from agent_bom.cloud.snowflake_observability import get_cortex_telemetry

        conn = _get_connection()
        result = get_cortex_telemetry(conn, hours=hours)
        conn.close()
        return result
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

    try:
        from agent_bom.cloud.snowflake import _get_connection  # type: ignore[attr-defined]
        from agent_bom.cloud.snowflake_observability import get_cortex_telemetry

        conn = _get_connection()
        result = get_cortex_telemetry(conn, agent_name=name, hours=hours)
        conn.close()
        return result
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

    try:
        from agent_bom.cloud.snowflake import _get_connection, _mine_cortex_agent_usage
        from agent_bom.cloud.snowflake_observability import (
            aggregate_agent_metrics,
            assess_agent_health,
        )

        conn = _get_connection()
        records, warnings = _mine_cortex_agent_usage(conn, days=1)
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
    except Exception as exc:
        _logger.exception("Request failed")
        raise HTTPException(status_code=500, detail=sanitize_error(exc))


@router.get("/siem/formats", tags=["siem"])
async def siem_formats():
    """List supported SIEM event formats."""
    from agent_bom.siem import list_formats

    return {"formats": list_formats()}
