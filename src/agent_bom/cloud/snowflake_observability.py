"""Snowflake Cortex Agent observability — aggregation, health scoring, telemetry.

Builds on raw telemetry from ``_mine_cortex_agent_usage()`` and
``_mine_observability_events()`` in ``snowflake.py`` to provide
aggregated metrics, health assessments, and API-ready summaries.
"""

from __future__ import annotations

import logging
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from agent_bom.governance import AgentUsageRecord, ObservabilityEvent

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Aggregated metrics
# ---------------------------------------------------------------------------


@dataclass
class CortexAgentMetrics:
    """Aggregated metrics for a single Cortex agent."""

    agent_name: str
    total_calls: int = 0
    error_count: int = 0
    error_rate: float = 0.0
    avg_latency_ms: float = 0.0
    p95_latency_ms: float = 0.0
    total_tokens: int = 0
    total_credits: float = 0.0
    top_tools: list[str] = field(default_factory=list)
    period_hours: int = 24


@dataclass
class CortexAgentHealth:
    """Health assessment for a Cortex agent."""

    agent_name: str
    status: str = "healthy"  # "healthy" | "degraded" | "unhealthy"
    issues: list[str] = field(default_factory=list)
    metrics: CortexAgentMetrics | None = None


# ---------------------------------------------------------------------------
# Aggregation functions
# ---------------------------------------------------------------------------


def _parse_timestamp(ts: str) -> datetime | None:
    """Best-effort ISO timestamp parsing."""
    if not ts:
        return None
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        return None


def _compute_latencies(records: list[AgentUsageRecord]) -> list[float]:
    """Compute latencies in ms from start_time/end_time pairs."""
    latencies: list[float] = []
    for r in records:
        start = _parse_timestamp(r.start_time)
        end = _parse_timestamp(r.end_time)
        if start and end:
            delta_ms = (end - start).total_seconds() * 1000
            if delta_ms >= 0:
                latencies.append(delta_ms)
    return latencies


def aggregate_agent_metrics(
    usage_records: list[AgentUsageRecord],
    obs_events: list[ObservabilityEvent] | None = None,
    hours: int = 24,
) -> list[CortexAgentMetrics]:
    """Aggregate raw usage records into per-agent metrics.

    Groups by ``agent_name``, computes totals, error rate, latency
    percentiles, and top tools (from observability events if available).
    """
    if not usage_records:
        return []

    by_agent: dict[str, list[AgentUsageRecord]] = defaultdict(list)
    for r in usage_records:
        by_agent[r.agent_name].append(r)

    # Build tool frequency from observability events
    tool_freq: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    if obs_events:
        for ev in obs_events:
            if ev.tool_name and ev.agent_name:
                tool_freq[ev.agent_name][ev.tool_name] += 1

    results: list[CortexAgentMetrics] = []
    for agent_name, records in sorted(by_agent.items()):
        total_calls = len(records)
        error_count = sum(1 for r in records if r.status.upper() in ("FAILED", "ERROR", "FAIL"))
        error_rate = error_count / total_calls if total_calls else 0.0

        latencies = _compute_latencies(records)
        avg_latency = sum(latencies) / len(latencies) if latencies else 0.0
        p95_latency = 0.0
        if latencies:
            sorted_lat = sorted(latencies)
            p95_idx = int(len(sorted_lat) * 0.95)
            p95_latency = sorted_lat[min(p95_idx, len(sorted_lat) - 1)]

        total_tokens = sum(r.total_tokens for r in records)
        total_credits = sum(r.credits_used for r in records)

        # Top tools
        agent_tools = tool_freq.get(agent_name, {})
        top_tools = sorted(agent_tools, key=agent_tools.get, reverse=True)[:5]

        results.append(
            CortexAgentMetrics(
                agent_name=agent_name,
                total_calls=total_calls,
                error_count=error_count,
                error_rate=round(error_rate, 4),
                avg_latency_ms=round(avg_latency, 1),
                p95_latency_ms=round(p95_latency, 1),
                total_tokens=total_tokens,
                total_credits=round(total_credits, 6),
                top_tools=top_tools,
                period_hours=hours,
            )
        )

    return results


def aggregate_observability(
    events: list[ObservabilityEvent],
    hours: int = 24,
) -> dict[str, Any]:
    """Aggregate observability events into a summary.

    Returns event type breakdown, per-tool call frequency and latency,
    error rate per agent, and trace chain counts.
    """
    if not events:
        return {"event_count": 0, "period_hours": hours}

    # Event type breakdown
    type_counts: dict[str, int] = defaultdict(int)
    for ev in events:
        type_counts[ev.event_type] += 1

    # Per-tool stats
    tool_stats: dict[str, dict[str, Any]] = defaultdict(lambda: {"count": 0, "total_duration_ms": 0, "errors": 0})
    for ev in events:
        if ev.tool_name:
            tool_stats[ev.tool_name]["count"] += 1
            tool_stats[ev.tool_name]["total_duration_ms"] += ev.duration_ms
            if ev.status.upper() in ("FAILED", "ERROR", "FAIL"):
                tool_stats[ev.tool_name]["errors"] += 1

    # Per-agent error rate
    agent_calls: dict[str, int] = defaultdict(int)
    agent_errors: dict[str, int] = defaultdict(int)
    for ev in events:
        if ev.agent_name:
            agent_calls[ev.agent_name] += 1
            if ev.status.upper() in ("FAILED", "ERROR", "FAIL"):
                agent_errors[ev.agent_name] += 1

    agent_error_rates = {name: round(agent_errors.get(name, 0) / count, 4) if count else 0.0 for name, count in agent_calls.items()}

    # Trace chains (unique trace_ids)
    trace_ids = {ev.trace_id for ev in events if ev.trace_id}

    return {
        "event_count": len(events),
        "period_hours": hours,
        "event_types": dict(type_counts),
        "tool_stats": {
            name: {
                "count": s["count"],
                "avg_duration_ms": round(s["total_duration_ms"] / s["count"], 1) if s["count"] else 0,
                "errors": s["errors"],
            }
            for name, s in sorted(tool_stats.items())
        },
        "agent_error_rates": agent_error_rates,
        "unique_traces": len(trace_ids),
    }


# ---------------------------------------------------------------------------
# Health assessment
# ---------------------------------------------------------------------------


def assess_agent_health(metrics: CortexAgentMetrics) -> CortexAgentHealth:
    """Assess health status of a Cortex agent based on its metrics.

    Thresholds:
        - unhealthy: error_rate > 0.25 OR p95_latency > 30000ms
        - degraded:  error_rate > 0.10 OR p95_latency > 10000ms
        - healthy:   everything else
    """
    issues: list[str] = []

    if metrics.error_rate > 0.25:
        issues.append(f"High error rate: {metrics.error_rate:.1%}")
    elif metrics.error_rate > 0.10:
        issues.append(f"Elevated error rate: {metrics.error_rate:.1%}")

    if metrics.p95_latency_ms > 30000:
        issues.append(f"Very high P95 latency: {metrics.p95_latency_ms:.0f}ms")
    elif metrics.p95_latency_ms > 10000:
        issues.append(f"High P95 latency: {metrics.p95_latency_ms:.0f}ms")

    if metrics.total_credits > 100:
        issues.append(f"High credit usage: {metrics.total_credits:.2f}")

    # Determine status
    if metrics.error_rate > 0.25 or metrics.p95_latency_ms > 30000:
        status = "unhealthy"
    elif metrics.error_rate > 0.10 or metrics.p95_latency_ms > 10000:
        status = "degraded"
    else:
        status = "healthy"

    return CortexAgentHealth(
        agent_name=metrics.agent_name,
        status=status,
        issues=issues,
        metrics=metrics,
    )


# ---------------------------------------------------------------------------
# High-level telemetry summary
# ---------------------------------------------------------------------------


def get_cortex_telemetry(
    conn: Any,
    agent_name: str | None = None,
    hours: int = 24,
) -> dict[str, Any]:
    """Fetch, aggregate, and score Cortex agent telemetry.

    Calls the existing ``_mine_cortex_agent_usage()`` and
    ``_mine_observability_events()`` functions, then aggregates
    metrics and runs health assessments.

    Args:
        conn: Snowflake connection object.
        agent_name: Optional filter for a single agent.
        hours: Lookback window in hours.

    Returns:
        JSON-serializable summary dict.
    """
    from agent_bom.cloud.snowflake import (
        _mine_cortex_agent_usage,
        _mine_observability_events,
    )

    days = max(1, hours // 24) if hours >= 24 else 1

    usage_records, usage_warnings = _mine_cortex_agent_usage(conn, days)
    obs_events, obs_warnings = _mine_observability_events(conn, days)

    # Filter by agent name if specified
    if agent_name:
        usage_records = [r for r in usage_records if r.agent_name == agent_name]
        obs_events = [e for e in obs_events if e.agent_name == agent_name]

    # Aggregate
    agent_metrics = aggregate_agent_metrics(usage_records, obs_events, hours)
    obs_summary = aggregate_observability(obs_events, hours)

    # Health assessments
    health_results = [assess_agent_health(m) for m in agent_metrics]

    return {
        "period_hours": hours,
        "agent_filter": agent_name,
        "agents": [
            {
                "name": m.agent_name,
                "total_calls": m.total_calls,
                "error_count": m.error_count,
                "error_rate": m.error_rate,
                "avg_latency_ms": m.avg_latency_ms,
                "p95_latency_ms": m.p95_latency_ms,
                "total_tokens": m.total_tokens,
                "total_credits": m.total_credits,
                "top_tools": m.top_tools,
                "health": {
                    "status": h.status,
                    "issues": h.issues,
                },
            }
            for m, h in zip(agent_metrics, health_results)
        ],
        "observability": obs_summary,
        "warnings": usage_warnings + obs_warnings,
    }
