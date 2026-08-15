from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient

from agent_bom.api.middleware import APIKeyMiddleware
from agent_bom.api.server import app
from agent_bom.db.adoption_events import AdoptionEventStore, set_adoption_event_store


def test_adoption_api_reports_privacy_and_accepts_only_supported_events(tmp_path: Path) -> None:
    store = AdoptionEventStore(tmp_path / "adoption.sqlite", enabled=True)
    set_adoption_event_store(store)
    try:
        client = TestClient(app)
        recorded = client.post(
            "/v1/observability/adoption/events",
            json={"event": "artifact_created", "channel": "control_plane", "artifact_type": "sarif"},
        )
        assert recorded.status_code == 202, recorded.text
        assert recorded.json() == {"schema_version": "adoption-event.v1", "recorded": True}

        summary = client.get("/v1/observability/adoption")
        assert summary.status_code == 200, summary.text
        assert summary.json()["counts"]["artifact_created"] == 1
        assert summary.json()["privacy"]["telemetry_disabled_by_default"] is True
        assert summary.json()["funnel"] == {
            "unit": "bounded_event_counts_not_unique_users",
            "transitions": {
                "artifact_to_investigation": {
                    "denominator": 1,
                    "numerator": 0,
                    "rate": 0.0,
                },
                "investigation_to_verification": {
                    "denominator": 0,
                    "numerator": 0,
                    "rate": None,
                },
                "scan_to_artifact": {
                    "denominator": 0,
                    "numerator": 1,
                    "rate": None,
                },
            },
            "limitations": [
                "Rates describe event progression on this installation, not unique people or market adoption.",
                "Numerators are not forced below denominators; retries and multiple artifacts remain visible.",
            ],
        }

        rejected = client.post(
            "/v1/observability/adoption/events",
            json={"event": "artifact_created", "channel": "control_plane", "resource_id": "customer-vm-123"},
        )
        assert rejected.status_code == 422

        incomplete = client.post(
            "/v1/observability/adoption/events",
            json={"event": "scan_completed", "channel": "control_plane"},
        )
        assert incomplete.status_code == 422
    finally:
        set_adoption_event_store(None)


def test_disabled_adoption_api_does_not_create_storage(tmp_path: Path) -> None:
    db_path = tmp_path / "disabled.sqlite"
    set_adoption_event_store(AdoptionEventStore(db_path, enabled=False))
    try:
        client = TestClient(app)
        response = client.post(
            "/v1/observability/adoption/events",
            json={"event": "scan_completed", "channel": "cli", "outcome": "complete"},
        )
        assert response.status_code == 202
        assert response.json()["recorded"] is False
        assert not db_path.exists()
    finally:
        set_adoption_event_store(None)


def test_adoption_api_has_explicit_read_and_write_scopes() -> None:
    middleware = APIKeyMiddleware(app, api_key="static-secret")
    assert middleware._required_role("GET", "/v1/observability/adoption") == "admin"
    assert middleware._required_role("POST", "/v1/observability/adoption/events") == "analyst"
    assert middleware._required_scope("GET", "/v1/observability/adoption") == "audit:read"
    assert middleware._required_scope("POST", "/v1/observability/adoption/events") == "scan:write"


def test_adoption_summary_computes_honest_event_transition_rates(tmp_path: Path) -> None:
    store = AdoptionEventStore(tmp_path / "funnel.sqlite", enabled=True)
    store.record("scan_completed", channel="cli", outcome="complete")
    store.record("scan_completed", channel="cli", outcome="complete")
    store.record("artifact_created", channel="cli", artifact_type="cyclonedx")
    store.record("investigation_started", channel="control_plane")

    summary = store.summary()

    assert summary["funnel"]["transitions"] == {
        "scan_to_artifact": {"numerator": 1, "denominator": 2, "rate": 0.5},
        "artifact_to_investigation": {"numerator": 1, "denominator": 1, "rate": 1.0},
        "investigation_to_verification": {"numerator": 0, "denominator": 1, "rate": 0.0},
    }
