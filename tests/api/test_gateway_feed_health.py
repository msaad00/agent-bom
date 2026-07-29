"""Gateway feed freshness is separate from whether historical events exist."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from starlette.testclient import TestClient

from agent_bom.api.routes import gateway_feed as gateway_feed_routes
from agent_bom.api.routes.gateway_feed import _feed_health_from_metrics, build_gateway_feed_health
from agent_bom.api.server import app, configure_api

NOW = datetime(2026, 7, 26, 12, 0, 0, tzinfo=timezone.utc)
PROXY_SECRET = "gateway-health-proxy-secret-with-32-plus-bytes"


def _headers(tenant_id: str, *, role: str) -> dict[str, str]:
    return {
        "X-Agent-Bom-Role": role,
        "X-Agent-Bom-Tenant-ID": tenant_id,
        "X-Agent-Bom-Proxy-Secret": PROXY_SECRET,
    }


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
    future = build_gateway_feed_health(
        transport_enabled=True,
        heartbeat_at=(NOW + timedelta(minutes=10)).isoformat(),
        now=NOW,
    )

    assert unavailable["state"] == "unavailable"
    assert unavailable["live"] is False
    assert live["state"] == "live"
    assert live["live"] is True
    assert stale["state"] == "stale"
    assert stale["live"] is False
    assert stale["age_seconds"] == 600
    assert future["state"] == "unavailable"
    assert future["live"] is False
    assert future["age_seconds"] is None
    assert future["reason"] == "transport_heartbeat_in_future"


def test_synthetic_feed_health_is_sample_never_live() -> None:
    health = build_gateway_feed_health(
        transport_enabled=True,
        heartbeat_at=NOW.isoformat(),
        now=NOW,
        sample=True,
    )

    assert health["state"] == "sample"
    assert health["live"] is False


def test_client_event_timestamp_alone_is_not_a_transport_heartbeat() -> None:
    health = _feed_health_from_metrics(
        {
            "timestamp": "2099-01-01T00:00:00+00:00",
            "ts": 4_071_004_800,
            "total_tool_calls": 1,
        }
    )

    assert health["state"] == "unavailable"
    assert health["live"] is False
    assert health["heartbeat_at"] is None


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


def test_future_client_timestamp_cannot_keep_transport_live(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Only server receipt time can establish a tenant transport heartbeat."""
    from agent_bom.api.routes import proxy as proxy_routes

    monkeypatch.setenv("AGENT_BOM_TRUST_PROXY_AUTH", "1")
    monkeypatch.setenv("AGENT_BOM_TRUST_PROXY_AUTH_SECRET", PROXY_SECRET)
    configure_api(api_key=None)
    proxy_routes._reset_proxy_runtime_for_tests()
    tenant_id = "tenant-gateway-health"
    other_tenant_id = "tenant-gateway-other"
    future = "2099-01-01T00:00:00+00:00"
    client = TestClient(app)

    try:
        before = datetime.now(timezone.utc)
        ingest = client.post(
            "/v1/proxy/audit",
            headers=_headers(tenant_id, role="admin"),
            json={
                "source_id": "gateway-health-source",
                "session_id": "gateway-health-session",
                "summary": {
                    "type": "proxy_summary",
                    "received_at": future,
                    "timestamp": future,
                    "ts": 4_071_004_800,
                    "total_tool_calls": 1,
                },
            },
        )
        after = datetime.now(timezone.utc)

        assert ingest.status_code == 200, ingest.text
        health = client.get(
            "/v1/gateway/feed",
            headers=_headers(tenant_id, role="viewer"),
        ).json()["health"]
        heartbeat = datetime.fromisoformat(health["heartbeat_at"])
        assert before <= heartbeat <= after
        assert health["state"] == "live"
        assert health["live"] is True

        stored = proxy_routes._runtime_metrics_for_tenant(tenant_id)
        assert stored is not None
        assert stored["timestamp"] == future
        assert stored["received_at"] != future

        later = build_gateway_feed_health(
            transport_enabled=True,
            heartbeat_at=health["heartbeat_at"],
            now=heartbeat + timedelta(seconds=121),
        )
        assert later["state"] == "stale"
        assert later["live"] is False

        other_health = client.get(
            "/v1/gateway/feed",
            headers=_headers(other_tenant_id, role="viewer"),
        ).json()["health"]
        assert other_health["state"] == "unavailable"
        assert other_health["live"] is False
        assert other_health["heartbeat_at"] is None
    finally:
        proxy_routes._reset_proxy_runtime_for_tests()
        monkeypatch.delenv("AGENT_BOM_TRUST_PROXY_AUTH", raising=False)
        monkeypatch.delenv("AGENT_BOM_TRUST_PROXY_AUTH_SECRET", raising=False)
        configure_api(api_key=None)


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

    response = schema["components"]["schemas"]["GatewayFeedResponseModel"]
    assert response["properties"]["events"]["items"]["$ref"].endswith("/GatewayFeedEventModel")
    assert {"next_cursor", "has_more", "source", "completeness"} <= response["properties"].keys()
    assert response["properties"]["completeness"]["$ref"].endswith("/GatewayFeedCompletenessModel")
    event = schema["components"]["schemas"]["GatewayFeedEventModel"]
    assert {"input_tokens", "output_tokens", "cost_usd", "ingest_ordinal"} <= event["properties"].keys()

    kpis = schema["components"]["schemas"]["GatewayFeedKpisModel"]
    assert {"source", "completeness", "window"} <= kpis["properties"].keys()
    assert kpis["properties"]["window"]["$ref"].endswith("/GatewayFeedWindowModel")
