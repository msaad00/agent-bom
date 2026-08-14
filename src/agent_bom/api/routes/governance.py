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
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, TypeVar, cast

import anyio.to_thread
from fastapi import APIRouter, HTTPException, Request

from agent_bom.api.tenancy import require_request_tenant_id
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
async def governance_report(days: int = 30) -> dict[str, Any]:
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
        return cast(dict[str, Any], report.to_dict())

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
) -> dict[str, Any]:
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
            filters={key: value for key, value in {"severity": severity, "category": category}.items() if value},
            warnings=list(report.warnings),
            source="snowflake_governance_discovery",
            scope="requested Snowflake governance discovery",
            window={"days": days},
        )

    try:
        return await _offload(_run)
    except HTTPException:
        raise
    except Exception as exc:
        _logger.exception("Request failed")
        raise HTTPException(status_code=500, detail=sanitize_error(exc))


_ACTIVITY_EVENT_LIMIT = 500


def _runtime_activity_events(tenant_id: str, *, days: int, sources: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Agent / MCP tool-call activity from the durable runtime store.

    This is the source that exists in every deployment: it is populated by the
    proxy, the gateway, and OTel ingest, with no external warehouse involved.
    """
    from agent_bom.api.runtime_event_store import get_runtime_event_store

    try:
        records = get_runtime_event_store().list_observations(tenant_id, limit=_ACTIVITY_EVENT_LIMIT)
    except Exception as exc:  # a runtime-store outage must not sink the whole timeline
        _logger.warning("Runtime activity source unavailable: %s", exc)
        sources.append({"source": "runtime", "status": "unavailable", "event_count": 0, "detail": sanitize_error(exc)})
        return []

    cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
    events = [
        {
            "observed_at": record.observed_at,
            "source": "runtime",
            "event_type": record.event_type,
            "agent_name": record.agent_name,
            "tool_name": record.tool_name,
            "severity": record.severity,
            "verdict": record.verdict,
            "session_id": record.session_id,
            "trace_id": record.trace_id,
        }
        for record in records
        if str(record.observed_at) >= cutoff
    ]
    sources.append(
        {
            "source": "runtime",
            "status": "active" if events else "empty",
            "event_count": len(events),
            "detail": "" if events else f"no runtime observations in the last {days} days",
        }
    )
    return events


def _snowflake_activity_events(*, days: int, sources: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Snowflake QUERY_HISTORY activity — optional, and reported as such."""
    import os

    if not os.environ.get("SNOWFLAKE_ACCOUNT"):
        sources.append(
            {
                "source": "snowflake",
                "status": "not_configured",
                "event_count": 0,
                "detail": "SNOWFLAKE_ACCOUNT is not set; Snowflake query history is not included",
            }
        )
        return []

    from agent_bom.cloud import discover_activity

    try:
        timeline = cast(dict[str, Any], discover_activity(provider="snowflake", days=days).to_dict())
    except Exception as exc:  # one provider failing must not fail the request
        _logger.warning("Snowflake activity source unavailable: %s", exc)
        sources.append({"source": "snowflake", "status": "unavailable", "event_count": 0, "detail": sanitize_error(exc)})
        return []

    raw = timeline.get("events") or timeline.get("activity") or timeline.get("query_history") or []
    events = [{**event, "source": "snowflake"} for event in raw if isinstance(event, dict)]
    sources.append(
        {
            "source": "snowflake",
            "status": "active" if events else "empty",
            "event_count": len(events),
            "detail": "",
            # The full Snowflake timeline rides along so the query-history and
            # per-account views keep everything they had before this became a
            # multi-source endpoint. Nesting it under the source keeps the
            # top-level envelope source-agnostic.
            "timeline": timeline,
        }
    )
    return events


@router.get("/activity", tags=["governance"])
async def activity_timeline(request: Request, days: int = 30) -> dict[str, Any]:
    """Agent activity timeline across every configured runtime source.

    "Activity" is the agent/MCP runtime story: which agents ran, which tools
    they called, and what the gateway decided. Snowflake query history is ONE
    source of that, not the definition of it.

    This used to hard-fail with 400 when ``SNOWFLAKE_ACCOUNT`` was unset, which
    made the whole Activity surface unreachable for the large majority of
    deployments that run agents and MCP servers without Snowflake at all. A
    self-hosted install scanning its own fleet has genuine runtime activity to
    show and was told to go configure a data warehouse.

    Every source now reports its own state — ``active``, ``empty``, or
    ``not_configured`` — the same contract ``nhi_discover`` and
    ``cloud_inventory`` already use for optional providers. An unconfigured
    source contributes zero events and a clear reason; it never fails the
    request, and it is never silently omitted either, so an empty timeline can
    always be told apart from an unconfigured one.
    """
    days = max(1, min(days, 365))
    tenant_id = require_request_tenant_id(request)

    def _run() -> dict[str, Any]:
        sources: list[dict[str, Any]] = []
        events: list[dict[str, Any]] = []

        events.extend(_runtime_activity_events(tenant_id, days=days, sources=sources))
        events.extend(_snowflake_activity_events(days=days, sources=sources))

        events.sort(key=lambda event: str(event.get("observed_at") or ""), reverse=True)
        active = [s for s in sources if s["status"] == "active"]
        return {
            "schema_version": "activity.timeline.v2",
            "tenant_id": tenant_id,
            "window_days": days,
            "event_count": len(events),
            "events": events[:_ACTIVITY_EVENT_LIMIT],
            "truncated": len(events) > _ACTIVITY_EVENT_LIMIT,
            "sources": sources,
            # Distinguishes "nothing happened" from "nothing is wired up" so the
            # UI can offer the right next step instead of a bare empty state.
            "status": "active" if active else ("empty" if events else "no_sources_configured"),
        }

    try:
        return await _offload(_run)
    except HTTPException:
        raise
    except Exception as exc:
        _logger.exception("Request failed")
        raise HTTPException(status_code=500, detail=sanitize_error(exc))


@router.get("/cortex/telemetry", tags=["governance"], deprecated=True)
async def cortex_telemetry(hours: int = 24) -> dict[str, Any]:
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

    def _run() -> dict[str, Any]:
        from agent_bom.cloud.snowflake import _get_connection
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
async def cortex_agent_telemetry(name: str, hours: int = 24) -> dict[str, Any]:
    """Telemetry for a specific Cortex agent."""
    import os

    if not os.environ.get("SNOWFLAKE_ACCOUNT"):
        raise HTTPException(
            status_code=400,
            detail="SNOWFLAKE_ACCOUNT env var not set.",
        )

    def _run() -> dict[str, Any]:
        from agent_bom.cloud.snowflake import _get_connection
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
async def cortex_health() -> dict[str, Any]:
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
async def siem_formats() -> dict[str, Any]:
    """List supported SIEM event formats."""
    from agent_bom.siem import list_formats

    return {"formats": list_formats()}
