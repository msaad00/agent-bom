"""Gateway feed freshness is separate from whether historical events exist."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from starlette.testclient import TestClient

from agent_bom.api.routes import gateway_feed as gateway_feed_routes
from agent_bom.api.routes.gateway_feed import build_gateway_feed_health
from agent_bom.api.server import app

NOW = datetime(2026, 7, 26, 12, 0, 0, tzinfo=timezone.utc)


def test_feed_health_requires_an_enabled_transport_and_recent_heartbeat() -> None:
    unavailable = build_gateway_feed_health(
        transport_enabled=False,
        heartbeat_at=None,
        now=NOW,
    )
    live = build_gateway_feed_health(
        transport_enabled=True,
        heartbeat_at=(NOW - timedelta(seconds=30)).isoformat(),
        now=NOW,
    )
    stale = build_gateway_feed_health(
        transport_enabled=True,
        heartbeat_at=(NOW - timedelta(minutes=10)).isoformat(),
        now=NOW,
    )

    assert unavailable["state"] == "unavailable"
    assert unavailable["live"] is False
    assert live["state"] == "live"
    assert live["live"] is True
    assert stale["state"] == "stale"
    assert stale["live"] is False
    assert stale["age_seconds"] == 600


def test_synthetic_feed_health_is_sample_never_live() -> None:
    health = build_gateway_feed_health(
        transport_enabled=True,
        heartbeat_at=NOW.isoformat(),
        now=NOW,
        sample=True,
    )

    assert health["state"] == "sample"
    assert health["live"] is False


def test_historical_events_without_transport_heartbeat_do_not_make_feed_live(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        gateway_feed_routes,
        "_load_tenant_alerts",
        lambda _tenant_id: [
            {
                "ts": NOW.isoformat(),
                "agent_name": "synthetic-agent",
                "event_type": "gateway.tool_call.allowed",
                "decision": "allow",
                "tool_name": "read_file",
            }
        ],
    )
    monkeypatch.setattr(gateway_feed_routes, "_load_tenant_llm_records", lambda _tenant_id, limit: [])
    monkeypatch.setattr(gateway_feed_routes, "_load_tenant_transport_metrics", lambda _tenant_id: None)

    response = TestClient(app).get("/v1/gateway/feed")

    assert response.status_code == 200
    assert response.json()["count"] == 1
    assert response.json()["health"]["state"] == "unavailable"
    assert response.json()["health"]["live"] is False
    assert response.json()["health"]["heartbeat_at"] is None
    assert response.json()["health"]["age_seconds"] is None


def test_gateway_feed_openapi_declares_health_contract() -> None:
    schema = app.openapi()
    response_schema = schema["paths"]["/v1/gateway/feed"]["get"]["responses"]["200"]["content"][
        "application/json"
    ]["schema"]

    assert response_schema["$ref"].endswith("/GatewayFeedResponseModel")
    health = schema["components"]["schemas"]["GatewayFeedHealthModel"]
    assert health["required"] == [
        "state",
        "live",
        "heartbeat_at",
        "age_seconds",
        "stale_after_seconds",
        "reason",
    ]
    assert health["properties"]["state"]["enum"] == ["live", "stale", "unavailable", "sample"]
