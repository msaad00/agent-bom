"""Tests for Snowflake Cortex Agent observability module."""

from __future__ import annotations

from agent_bom.cloud.snowflake_observability import (
    CortexAgentHealth,
    CortexAgentMetrics,
    aggregate_agent_metrics,
    aggregate_observability,
    assess_agent_health,
)
from agent_bom.governance import AgentUsageRecord, ObservabilityEvent

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _usage(
    agent: str = "my_agent",
    status: str = "SUCCESS",
    tokens: int = 100,
    credits: float = 0.01,
    start: str = "2026-03-01T10:00:00+00:00",
    end: str = "2026-03-01T10:00:01+00:00",
) -> AgentUsageRecord:
    return AgentUsageRecord(
        agent_name=agent,
        start_time=start,
        end_time=end,
        total_tokens=tokens,
        credits_used=credits,
        status=status,
    )


def _obs_event(
    agent: str = "my_agent",
    event_type: str = "TOOL_CALL",
    tool_name: str = "search",
    status: str = "SUCCESS",
    duration_ms: int = 200,
    trace_id: str = "trace-1",
) -> ObservabilityEvent:
    return ObservabilityEvent(
        event_id="evt-1",
        event_type=event_type,
        agent_name=agent,
        tool_name=tool_name,
        status=status,
        duration_ms=duration_ms,
        trace_id=trace_id,
    )


# ---------------------------------------------------------------------------
# Aggregate agent metrics
# ---------------------------------------------------------------------------


class TestAggregateMetrics:
    def test_single_agent(self):
        records = [_usage(), _usage(), _usage()]
        metrics = aggregate_agent_metrics(records)
        assert len(metrics) == 1
        assert metrics[0].agent_name == "my_agent"
        assert metrics[0].total_calls == 3
        assert metrics[0].total_tokens == 300

    def test_multiple_agents(self):
        records = [
            _usage(agent="agent_a"),
            _usage(agent="agent_b"),
            _usage(agent="agent_a"),
        ]
        metrics = aggregate_agent_metrics(records)
        assert len(metrics) == 2
        names = {m.agent_name for m in metrics}
        assert names == {"agent_a", "agent_b"}

    def test_error_rate(self):
        records = [
            _usage(status="SUCCESS"),
            _usage(status="SUCCESS"),
            _usage(status="FAILED"),
            _usage(status="ERROR"),
        ]
        metrics = aggregate_agent_metrics(records)
        assert metrics[0].error_count == 2
        assert metrics[0].error_rate == 0.5

    def test_latency_calculation(self):
        records = [
            _usage(start="2026-03-01T10:00:00+00:00", end="2026-03-01T10:00:02+00:00"),  # 2000ms
            _usage(start="2026-03-01T10:00:00+00:00", end="2026-03-01T10:00:01+00:00"),  # 1000ms
        ]
        metrics = aggregate_agent_metrics(records)
        assert metrics[0].avg_latency_ms == 1500.0

    def test_p95_latency(self):
        # 20 records, latency = 1000ms each, one outlier at 5000ms
        records = [_usage(start="2026-03-01T10:00:00+00:00", end="2026-03-01T10:00:01+00:00") for _ in range(19)]
        records.append(_usage(start="2026-03-01T10:00:00+00:00", end="2026-03-01T10:00:05+00:00"))
        metrics = aggregate_agent_metrics(records)
        # P95 should pick the outlier
        assert metrics[0].p95_latency_ms >= 1000.0

    def test_credits_aggregation(self):
        records = [_usage(credits=0.05), _usage(credits=0.10)]
        metrics = aggregate_agent_metrics(records)
        assert metrics[0].total_credits == 0.15

    def test_top_tools_from_observability(self):
        records = [_usage()]
        events = [
            _obs_event(tool_name="search"),
            _obs_event(tool_name="search"),
            _obs_event(tool_name="fetch"),
        ]
        metrics = aggregate_agent_metrics(records, obs_events=events)
        assert metrics[0].top_tools == ["search", "fetch"]

    def test_empty_records(self):
        assert aggregate_agent_metrics([]) == []

    def test_period_hours(self):
        metrics = aggregate_agent_metrics([_usage()], hours=48)
        assert metrics[0].period_hours == 48


# ---------------------------------------------------------------------------
# Aggregate observability events
# ---------------------------------------------------------------------------


class TestAggregateObservability:
    def test_event_type_breakdown(self):
        events = [
            _obs_event(event_type="TOOL_CALL"),
            _obs_event(event_type="TOOL_CALL"),
            _obs_event(event_type="LLM_INFERENCE"),
        ]
        summary = aggregate_observability(events)
        assert summary["event_types"]["TOOL_CALL"] == 2
        assert summary["event_types"]["LLM_INFERENCE"] == 1

    def test_tool_stats(self):
        events = [
            _obs_event(tool_name="search", duration_ms=100),
            _obs_event(tool_name="search", duration_ms=300),
            _obs_event(tool_name="fetch", duration_ms=200),
        ]
        summary = aggregate_observability(events)
        assert summary["tool_stats"]["search"]["count"] == 2
        assert summary["tool_stats"]["search"]["avg_duration_ms"] == 200.0

    def test_agent_error_rates(self):
        events = [
            _obs_event(agent="a", status="SUCCESS"),
            _obs_event(agent="a", status="FAILED"),
            _obs_event(agent="b", status="SUCCESS"),
        ]
        summary = aggregate_observability(events)
        assert summary["agent_error_rates"]["a"] == 0.5
        assert summary["agent_error_rates"]["b"] == 0.0

    def test_unique_traces(self):
        events = [
            _obs_event(trace_id="t1"),
            _obs_event(trace_id="t1"),
            _obs_event(trace_id="t2"),
        ]
        summary = aggregate_observability(events)
        assert summary["unique_traces"] == 2

    def test_empty_events(self):
        summary = aggregate_observability([])
        assert summary["event_count"] == 0


# ---------------------------------------------------------------------------
# Health assessment
# ---------------------------------------------------------------------------


class TestHealthAssessment:
    def test_healthy(self):
        m = CortexAgentMetrics(
            agent_name="agent1",
            total_calls=100,
            error_rate=0.02,
            p95_latency_ms=500,
        )
        h = assess_agent_health(m)
        assert h.status == "healthy"
        assert h.issues == []

    def test_degraded_error_rate(self):
        m = CortexAgentMetrics(
            agent_name="agent1",
            total_calls=100,
            error_rate=0.15,
            p95_latency_ms=500,
        )
        h = assess_agent_health(m)
        assert h.status == "degraded"
        assert any("error rate" in i.lower() for i in h.issues)

    def test_degraded_latency(self):
        m = CortexAgentMetrics(
            agent_name="agent1",
            total_calls=100,
            error_rate=0.01,
            p95_latency_ms=15000,
        )
        h = assess_agent_health(m)
        assert h.status == "degraded"
        assert any("latency" in i.lower() for i in h.issues)

    def test_unhealthy_error_rate(self):
        m = CortexAgentMetrics(
            agent_name="agent1",
            total_calls=100,
            error_rate=0.30,
            p95_latency_ms=500,
        )
        h = assess_agent_health(m)
        assert h.status == "unhealthy"

    def test_unhealthy_latency(self):
        m = CortexAgentMetrics(
            agent_name="agent1",
            total_calls=100,
            error_rate=0.01,
            p95_latency_ms=35000,
        )
        h = assess_agent_health(m)
        assert h.status == "unhealthy"

    def test_high_credits_issue(self):
        m = CortexAgentMetrics(
            agent_name="agent1",
            total_calls=100,
            error_rate=0.01,
            p95_latency_ms=500,
            total_credits=150.0,
        )
        h = assess_agent_health(m)
        assert any("credit" in i.lower() for i in h.issues)

    def test_metrics_attached(self):
        m = CortexAgentMetrics(agent_name="agent1")
        h = assess_agent_health(m)
        assert h.metrics is m


# ---------------------------------------------------------------------------
# Dataclass defaults
# ---------------------------------------------------------------------------


class TestDataclasses:
    def test_metrics_defaults(self):
        m = CortexAgentMetrics(agent_name="test")
        assert m.total_calls == 0
        assert m.error_rate == 0.0
        assert m.top_tools == []

    def test_health_defaults(self):
        h = CortexAgentHealth(agent_name="test")
        assert h.status == "healthy"
        assert h.issues == []
        assert h.metrics is None
