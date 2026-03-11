"""Governance, activity timeline, and Cortex observability endpoints."""

from __future__ import annotations

import logging

from fastapi import APIRouter, HTTPException

from agent_bom.security import sanitize_error

router = APIRouter()
_logger = logging.getLogger(__name__)


@router.get("/v1/governance", tags=["governance"])
async def governance_report(days: int = 30):
    """Run Snowflake governance discovery and return findings."""
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


@router.get("/v1/governance/findings", tags=["governance"])
async def governance_findings(
    days: int = 30,
    severity: str | None = None,
    category: str | None = None,
):
    """Return only governance findings, optionally filtered."""
    import os

    days = max(1, min(days, 365))

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

        return {
            "findings": findings,
            "count": len(findings),
            "warnings": report.warnings,
        }
    except Exception as exc:
        _logger.exception("Request failed")
        raise HTTPException(status_code=500, detail=sanitize_error(exc))


@router.get("/v1/activity", tags=["governance"])
async def activity_timeline(days: int = 30):
    """Agent activity timeline from Snowflake QUERY_HISTORY + AI_OBSERVABILITY_EVENTS."""
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


# ─── Cortex Agent Observability ─────────────────────────────────────────────


@router.get("/v1/cortex/telemetry", tags=["governance"])
async def cortex_telemetry(hours: int = 24):
    """Aggregated Cortex agent telemetry with health assessments."""
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


@router.get("/v1/cortex/agents/{name}/telemetry", tags=["governance"])
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


@router.get("/v1/cortex/health", tags=["governance"])
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
