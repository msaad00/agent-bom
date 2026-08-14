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
