"""Cost + behavior anomaly detection (z-score outliers)."""

from __future__ import annotations

import pytest
from starlette.testclient import TestClient

from agent_bom.api.anomaly import detect_behavior_anomalies, detect_cost_anomalies, scan_anomalies
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
