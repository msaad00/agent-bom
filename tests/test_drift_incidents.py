"""Blueprint-drift closed loop: detected drift becomes a durable, resolvable incident."""

from __future__ import annotations

from typing import Any

import pytest
from starlette.testclient import TestClient

from agent_bom.api.drift_incident_store import (
    DriftIncident,
    InMemoryDriftIncidentStore,
    incident_signature,
    record_drift_if_detected,
    set_drift_incident_store,
)
from agent_bom.runtime_blueprints import evaluate_runtime_blueprint_drift


def _index(tool: str, count: int = 5) -> dict[str, Any]:
    return {"status": "active", "traffic": {"calls_by_tool": {tool: count}, "total_tool_calls": count}}


# ── evaluation -> incident ──────────────────────────────────────────────────────


def test_restricted_tool_produces_drift_incident():
    # 'deploy' classifies as production_write, restricted for the developer blueprint.
    result = evaluate_runtime_blueprint_drift("developer", _index("deploy"), tenant_id="t1")
    assert result["status"] == "drift_detected"

    store = InMemoryDriftIncidentStore()
    incident = record_drift_if_detected(store, result)
    assert incident is not None
    assert incident.blueprint_id == "developer"
    assert incident.violation_count >= 1
    assert store.list("t1")[0].incident_id == incident.incident_id


def test_aligned_runtime_records_no_incident():
    result = evaluate_runtime_blueprint_drift("developer", _index("read_file"), tenant_id="t1")
    assert result["status"] != "drift_detected"
    assert record_drift_if_detected(InMemoryDriftIncidentStore(), result) is None


def test_repeated_drift_dedupes_and_counts_occurrences():
    store = InMemoryDriftIncidentStore()
    result = evaluate_runtime_blueprint_drift("developer", _index("deploy"), tenant_id="t1")
    first = record_drift_if_detected(store, result)
    second = record_drift_if_detected(store, result)
    assert first.incident_id == second.incident_id
    assert len(store.list("t1")) == 1
    assert store.list("t1")[0].occurrences == 2


def test_signature_is_stable_per_tenant_blueprint_tools():
    v = [{"tool_name": "deploy", "type": "restricted_tool_category"}]
    assert incident_signature("t1", "developer", v) == incident_signature("t1", "developer", v)
    assert incident_signature("t1", "developer", v) != incident_signature("t2", "developer", v)


def test_resolve_marks_incident_and_hides_from_open_list():
    store = InMemoryDriftIncidentStore()
    record_drift_if_detected(store, evaluate_runtime_blueprint_drift("developer", _index("deploy"), tenant_id="t1"))
    incident_id = store.list("t1")[0].incident_id
    resolved = store.resolve("t1", incident_id, by="alice", note="moved agent to admin blueprint", at="2026-06-01T00:00:00Z")
    assert resolved.resolved is True
    assert store.list("t1") == []  # open list excludes resolved
    assert len(store.list("t1", include_resolved=True)) == 1


# ── API surface ─────────────────────────────────────────────────────────────────


@pytest.fixture()
def client():
    from agent_bom.api.server import app

    store = InMemoryDriftIncidentStore()
    store.upsert(
        DriftIncident(
            incident_id="inc-1",
            tenant_id="default",
            blueprint_id="developer",
            status="drift_detected",
            drift_score=0.5,
            violation_count=1,
            warning_count=0,
            top_violations=[{"tool_name": "deploy", "severity": "high"}],
            first_detected_at="2026-06-01T00:00:00Z",
            last_detected_at="2026-06-01T00:00:00Z",
        )
    )
    set_drift_incident_store(store)
    try:
        yield TestClient(app)
    finally:
        set_drift_incident_store(None)


def test_list_and_resolve_endpoints(client):
    listing = client.get("/v1/runtime/drift/incidents").json()
    assert listing["open_count"] == 1
    assert listing["incidents"][0]["incident_id"] == "inc-1"

    resolved = client.post("/v1/runtime/drift/incidents/inc-1/resolve", json={"note": "reconciled"})
    assert resolved.status_code == 200, resolved.text
    assert resolved.json()["incident"]["resolved"] is True

    after = client.get("/v1/runtime/drift/incidents").json()
    assert after["open_count"] == 0


def test_resolve_unknown_incident_404s(client):
    assert client.post("/v1/runtime/drift/incidents/nope/resolve", json={}).status_code == 404
