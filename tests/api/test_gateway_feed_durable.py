"""Durable gateway feed contracts across API replica and restart boundaries."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest
from starlette.testclient import TestClient

from agent_bom.api.gateway_activity_store import (
    InMemoryGatewayActivityStore,
    set_gateway_activity_store,
)
from agent_bom.api.routes import gateway_feed as gateway_feed_routes
from agent_bom.api.routes import proxy as proxy_routes
from agent_bom.api.server import app, configure_api

PROXY_SECRET = "durable-gateway-feed-secret-with-32-plus-bytes"


def _headers(tenant_id: str, *, role: str = "viewer") -> dict[str, str]:
    return {
        "X-Agent-Bom-Role": role,
        "X-Agent-Bom-Tenant-ID": tenant_id,
        "X-Agent-Bom-Proxy-Secret": PROXY_SECRET,
    }


def _event(event_id: str, *, tool: str) -> dict[str, object]:
    return {
        "schema_version": "gateway.runtime.event.v1",
        "event_id": event_id,
        "decision_id": event_id,
        "event_type": "gateway.tool_call.allowed",
        "event_timestamp": datetime.now(timezone.utc).isoformat(),
        "agent_id": "fleet-agent-1",
        "upstream": "filesystem",
        "tool": tool,
        "decision": "allow",
        "policy_source": "runtime_profile",
        "trace_id": f"trace-{event_id}",
    }


def _blocked_event(event_id: str) -> dict[str, object]:
    event = _event(event_id, tool="delete_all")
    event.update(
        {
            "event_type": "gateway.tool_call.blocked",
            "decision": "deny",
            "reason_code": "unknown_agent",
        }
    )
    return event


@pytest.fixture(autouse=True)
def _isolated_gateway_feed(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("AGENT_BOM_TRUST_PROXY_AUTH", "1")
    monkeypatch.setenv("AGENT_BOM_TRUST_PROXY_AUTH_SECRET", PROXY_SECRET)
    configure_api(api_key=None)
    proxy_routes._reset_proxy_runtime_for_tests()
    set_gateway_activity_store(InMemoryGatewayActivityStore(max_events_per_tenant=20))
    try:
        yield
    finally:
        set_gateway_activity_store(None)
        proxy_routes._reset_proxy_runtime_for_tests()
        configure_api(api_key=None)


def test_feed_survives_ring_loss_and_cursor_resumes_without_gaps() -> None:
    client = TestClient(app)
    tenant_id = "tenant-durable-feed"

    first_ingest = client.post(
        "/v1/proxy/audit",
        headers=_headers(tenant_id, role="admin"),
        json={
            "source_id": "gateway-a",
            "session_id": "session-a",
            "alerts": [_event("evt-1", tool="read_file"), _event("evt-2", tool="list_files")],
        },
    )
    assert first_ingest.status_code == 200, first_ingest.text
    assert first_ingest.json()["durable_accepted_count"] == 2

    # Simulate another API replica, or a process restart: the ring is gone but
    # the shared ledger remains the authoritative feed source.
    proxy_routes._reset_proxy_runtime_for_tests()
    first_page = client.get(
        "/v1/gateway/feed",
        headers=_headers(tenant_id),
        params={"limit": 10},
    )
    assert first_page.status_code == 200, first_page.text
    first_body = first_page.json()
    assert [event["event_id"] for event in first_body["events"]] == ["evt-2", "evt-1"]
    assert first_body["source"] == "gateway_activity_ledger"
    assert first_body["completeness"]["status"] == "complete"
    assert first_body["next_cursor"]
    assert first_body["has_more"] is False

    second_ingest = client.post(
        "/v1/proxy/audit",
        headers=_headers(tenant_id, role="admin"),
        json={
            "source_id": "gateway-b",
            "session_id": "session-b",
            "alerts": [_event("evt-3", tool="stat")],
        },
    )
    assert second_ingest.status_code == 200, second_ingest.text
    proxy_routes._reset_proxy_runtime_for_tests()

    resumed = client.get(
        "/v1/gateway/feed",
        headers=_headers(tenant_id),
        params={"cursor": first_body["next_cursor"], "limit": 10},
    )
    assert resumed.status_code == 200, resumed.text
    resumed_body = resumed.json()
    assert [event["event_id"] for event in resumed_body["events"]] == ["evt-3"]
    assert resumed_body["next_cursor"] != first_body["next_cursor"]

    foreign = client.get(
        "/v1/gateway/feed",
        headers=_headers("tenant-other"),
        params={"cursor": first_body["next_cursor"]},
    )
    assert foreign.status_code == 400


def test_kpis_use_exact_utc_window_over_durable_events_after_ring_loss() -> None:
    client = TestClient(app)
    tenant_id = "tenant-durable-kpis"
    ingest = client.post(
        "/v1/proxy/audit",
        headers=_headers(tenant_id, role="admin"),
        json={
            "source_id": "gateway-a",
            "session_id": "session-a",
            "alerts": [
                _event("evt-allow", tool="read_file"),
                _blocked_event("evt-block"),
            ],
        },
    )
    assert ingest.status_code == 200, ingest.text
    proxy_routes._reset_proxy_runtime_for_tests()

    response = client.get("/v1/gateway/feed/kpis", headers=_headers(tenant_id))

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["tool_calls_authorized"] == 1
    assert body["blocked_today"] == 1
    assert body["shadow_ai_blocked"] == 1
    assert body["calls_today"] == 2
    assert body["source"] == "gateway_activity_ledger"
    assert body["completeness"]["status"] == "complete"
    assert body["window"]["timezone"] == "UTC"
    assert body["window"]["start"].endswith("+00:00")
    assert body["window"]["end"].endswith("+00:00")
    assert body["window"]["exact"] is True


def test_retention_marks_initial_backfill_partial_and_expires_old_cursor() -> None:
    store = InMemoryGatewayActivityStore(max_events_per_tenant=2)
    set_gateway_activity_store(store)
    client = TestClient(app)
    tenant_id = "tenant-retained-feed"
    stale_cursor = store.encode_cursor(tenant_id, 0)
    ingest = client.post(
        "/v1/proxy/audit",
        headers=_headers(tenant_id, role="admin"),
        json={
            "source_id": "gateway-a",
            "session_id": "session-a",
            "alerts": [
                _event("evt-1", tool="one"),
                _event("evt-2", tool="two"),
                _event("evt-3", tool="three"),
            ],
        },
    )
    assert ingest.status_code == 200, ingest.text
    proxy_routes._reset_proxy_runtime_for_tests()

    initial = client.get("/v1/gateway/feed", headers=_headers(tenant_id)).json()
    assert [event["event_id"] for event in initial["events"]] == ["evt-3", "evt-2"]
    assert initial["completeness"]["status"] == "partial"
    assert "retention_floor_advanced" in initial["completeness"]["reasons"]

    expired = client.get(
        "/v1/gateway/feed",
        headers=_headers(tenant_id),
        params={"cursor": stale_cursor},
    )
    assert expired.status_code == 410
    assert expired.json()["detail"]["retention_floor_ordinal"] == 2


def test_store_outage_is_explicitly_degraded_and_cannot_resume_cursor() -> None:
    class _UnavailableStore:
        max_events_per_tenant = 50_000
        max_tombstones_per_tenant = 100_000

        def init_schema(self) -> None:
            return None

        def append_batch(self, records):
            raise RuntimeError("database URL with secret must not escape")

        def list_activity(self, tenant_id, *, cursor=None, limit=100):
            raise RuntimeError("database URL with secret must not escape")

        def encode_cursor(self, tenant_id, ordinal):
            return "opaque"

    set_gateway_activity_store(_UnavailableStore())
    now = datetime.now(timezone.utc).timestamp()
    proxy_routes.push_proxy_alert(
        {
            "ts": now,
            "tenant_id": "tenant-degraded",
            "agent_name": "legacy-agent",
            "event_type": "gateway.policy_blocked",
            "decision": "deny",
            "tool_name": "exec",
        }
    )
    client = TestClient(app, raise_server_exceptions=False)

    initial = client.get("/v1/gateway/feed", headers=_headers("tenant-degraded"))

    assert initial.status_code == 200, initial.text
    body = initial.json()
    assert body["source"] == "degraded_single_process"
    assert body["completeness"]["status"] == "partial"
    assert "ledger_unavailable" in body["completeness"]["reasons"]
    assert [event["agent"] for event in body["events"]] == ["legacy-agent"]
    assert "database URL" not in initial.text

    kpis = client.get("/v1/gateway/feed/kpis", headers=_headers("tenant-degraded"))
    assert kpis.status_code == 200, kpis.text
    assert kpis.json()["source"] == "degraded_single_process"
    assert "ledger_unavailable" in kpis.json()["completeness"]["reasons"]
    assert kpis.json()["blocked_today"] == 1
    assert "database URL" not in kpis.text

    resumed = client.get(
        "/v1/gateway/feed",
        headers=_headers("tenant-degraded"),
        params={"cursor": "opaque-cursor"},
    )
    assert resumed.status_code == 503
    assert "database URL" not in resumed.text


def test_observability_outage_marks_feed_and_kpis_partial(monkeypatch: pytest.MonkeyPatch) -> None:
    def _unavailable(_tenant_id: str, *, limit: int):
        raise RuntimeError("cost store URL with secret must not escape")

    monkeypatch.setattr(gateway_feed_routes, "_load_tenant_llm_records", _unavailable)
    client = TestClient(app, raise_server_exceptions=False)

    feed = client.get("/v1/gateway/feed", headers=_headers("tenant-observability-outage"))
    assert feed.status_code == 200, feed.text
    assert "observability_unavailable" in feed.json()["completeness"]["reasons"]
    assert "cost store URL" not in feed.text

    kpis = client.get("/v1/gateway/feed/kpis", headers=_headers("tenant-observability-outage"))
    assert kpis.status_code == 200, kpis.text
    assert "observability_unavailable" in kpis.json()["completeness"]["reasons"]
    assert kpis.json()["window"]["exact"] is False
    assert "cost store URL" not in kpis.text
