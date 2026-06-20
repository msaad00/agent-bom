"""Cost + behavior anomaly detection (z-score outliers)."""

from __future__ import annotations

import pytest
from starlette.testclient import TestClient

from agent_bom.api.anomaly import (
    detect_behavior_anomalies,
    detect_cost_anomalies,
    detect_temporal_cost_anomalies,
    scan_anomalies,
)
from agent_bom.api.cost_store import InMemoryCostStore, LLMCostRecord, set_cost_store
from agent_bom.api.runtime_event_store import InMemoryRuntimeEventStore, set_runtime_event_store


def test_cost_spike_is_flagged():
    # One agent spends wildly more than its peers -> flagged.
    spend = {"a": 1.0, "b": 1.2, "c": 0.9, "d": 1.1, "e": 50.0}
    anomalies = detect_cost_anomalies(spend)
    assert any(x["agent"] == "e" and x["type"] == "cost_spike" for x in anomalies)
    assert not any(x["agent"] in ("a", "b", "c", "d") for x in anomalies)


def test_no_anomaly_when_uniform():
    assert detect_cost_anomalies({"a": 1.0, "b": 1.0, "c": 1.0, "d": 1.0, "e": 1.0}) == []


def test_too_few_samples_returns_nothing():
    assert detect_cost_anomalies({"a": 1.0, "b": 100.0}) == []


def test_behavior_call_rate_spike():
    calls = {"s1": 5, "s2": 6, "s3": 4, "s4": 5, "s5": 500}
    anomalies = detect_behavior_anomalies(calls)
    assert any(x["session_id"] == "s5" and x["type"] == "call_rate_spike" for x in anomalies)


# ── temporal / seasonal baselines (#2926) ────────────────────────────────────────


def test_predictable_nightly_spike_is_not_flagged():
    # Every night at 02:00 UTC the agent runs a big batch job (~$5), and during
    # the day it is quiet (~$0.5). The latest night job is in-pattern, so the
    # seasonal baseline absorbs it and it must NOT be flagged.
    series = []
    for day in range(1, 8):  # 7 days of history
        series.append((f"2026-06-0{day}T02:00:00Z", 5.0))  # nightly batch
        series.append((f"2026-06-0{day}T10:00:00Z", 0.5))  # daytime
        series.append((f"2026-06-0{day}T14:00:00Z", 0.5))  # daytime
    # latest occurrence is another in-pattern nightly batch
    series.append(("2026-06-08T02:00:00Z", 5.2))
    out = detect_temporal_cost_anomalies({"batch-agent": series})
    assert out == []


def test_slow_creep_is_flagged():
    # Same 02:00 slot, but the latest run is a large surge over both the seasonal
    # baseline for that slot AND the agent's overall EWMA -> flagged.
    series = []
    for day in range(1, 8):
        series.append((f"2026-06-0{day}T02:00:00Z", 5.0))
        series.append((f"2026-06-0{day}T10:00:00Z", 0.5))
    series.append(("2026-06-08T02:00:00Z", 60.0))  # surge, ~12x the slot baseline
    out = detect_temporal_cost_anomalies({"batch-agent": series})
    assert len(out) == 1
    spike = out[0]
    assert spike["type"] == "temporal_cost_spike"
    assert spike["agent"] == "batch-agent"
    assert "seasonal" in spike["signals"]
    assert spike["bucket"]["hour"] == 2


def test_temporal_needs_minimum_history():
    series = [("2026-06-01T02:00:00Z", 1.0), ("2026-06-01T03:00:00Z", 99.0)]
    assert detect_temporal_cost_anomalies({"a": series}) == []


@pytest.fixture()
def stores():
    cost = InMemoryCostStore()
    for i, (agent, amt) in enumerate([("a", 1.0), ("b", 1.1), ("c", 0.9), ("d", 1.0), ("runaway", 80.0)]):
        cost.record_cost(LLMCostRecord("default", f"c{i}", agent, "s", "openai", "gpt-4o", 1000, 1000, amt, True, "2026-06-02"))
    events = InMemoryRuntimeEventStore()
    set_cost_store(cost)
    set_runtime_event_store(events)
    try:
        yield cost, events
    finally:
        set_cost_store(None)
        set_runtime_event_store(None)


def test_scan_anomalies_finds_runaway_agent(stores):
    result = scan_anomalies("default")
    assert result["anomaly_count"] >= 1
    assert any(a["agent"] == "runaway" for a in result["cost_anomalies"])


def test_anomalies_endpoint(stores):
    from agent_bom.api.server import app

    client = TestClient(app)
    resp = client.get("/v1/observability/anomalies")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["schema_version"] == "observability.anomalies.v1"
    assert any(a["agent"] == "runaway" for a in body["cost_anomalies"])
