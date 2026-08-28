"""A canonical gateway event is either durably committed or rejected — never both.

PR #4558 committed canonical gateway events before acknowledging ingest. A
canonical ``event_type`` carrying a falsy ``event_id`` slipped past that
guarantee: it fell through to the legacy ring-only path and was answered
``200``, so a gateway decision the API had acknowledged lived only in a
process-local deque. A missing required field on a canonical event is a
``422``, exactly like every other missing required field.
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest
from starlette.testclient import TestClient

from agent_bom.api.gateway_activity_store import (
    InMemoryGatewayActivityStore,
    set_gateway_activity_store,
)
from agent_bom.api.routes import proxy as proxy_routes
from agent_bom.api.server import app, configure_api

PROXY_SECRET = "canonical-gateway-validation-secret-with-32-plus-bytes"

CANONICAL_EVENT_TYPES = [
    "gateway.tool_call.allowed",
    "gateway.tool_call.blocked",
    "gateway.dlp.arguments_redacted",
    "gateway.dlp.result_redacted",
    "gateway.dlp.result_blocked",
    "gateway.visual.redacted",
    "gateway.runtime_profile.warned",
    "gateway.runtime_profile.dev_bypass",
    "gateway.runtime_profile.blocked",
    "gateway.enforcement.warned",
    "gateway.enforcement.observed",
    "gateway.enforcement.blocked",
]


def _headers(tenant_id: str, *, role: str = "admin") -> dict[str, str]:
    return {
        "X-Agent-Bom-Role": role,
        "X-Agent-Bom-Tenant-ID": tenant_id,
        "X-Agent-Bom-Proxy-Secret": PROXY_SECRET,
    }


def _event(event_type: str = "gateway.tool_call.allowed", **overrides: object) -> dict[str, object]:
    event: dict[str, object] = {
        "schema_version": "gateway.runtime.event.v1",
        "event_id": "evt-canonical-1",
        "decision_id": "evt-canonical-1",
        "event_type": event_type,
        "event_timestamp": datetime.now(timezone.utc).isoformat(),
        "agent_id": "fleet-agent-1",
        "upstream": "filesystem",
        "tool": "read_file",
        "decision": "deny" if "blocked" in event_type else "allow",
        "policy_source": "runtime_profile",
        "trace_id": "trace-canonical-1",
    }
    event.update(overrides)
    return event


@pytest.fixture(autouse=True)
def _isolated_gateway(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("AGENT_BOM_TRUST_PROXY_AUTH", "1")
    monkeypatch.setenv("AGENT_BOM_TRUST_PROXY_AUTH_SECRET", PROXY_SECRET)
    configure_api(api_key=None)
    proxy_routes._reset_proxy_runtime_for_tests()
    set_gateway_activity_store(InMemoryGatewayActivityStore(max_events_per_tenant=50))
    try:
        yield
    finally:
        set_gateway_activity_store(None)
        proxy_routes._reset_proxy_runtime_for_tests()
        configure_api(api_key=None)


def _ingest(client: TestClient, tenant_id: str, alert: dict[str, object]):
    return client.post(
        "/v1/proxy/audit",
        headers=_headers(tenant_id),
        json={"source_id": "gateway-a", "session_id": "session-a", "alerts": [alert]},
    )


@pytest.mark.parametrize("event_type", CANONICAL_EVENT_TYPES)
@pytest.mark.parametrize("missing", ["", "   ", None])
def test_canonical_event_without_event_id_is_rejected(event_type: str, missing: object) -> None:
    client = TestClient(app)
    tenant_id = "tenant-canonical-reject"

    response = _ingest(client, tenant_id, _event(event_type, event_id=missing))

    assert response.status_code == 422, response.text
    # Nothing was acknowledged, so nothing may be visible on the feed either.
    feed = client.get("/v1/gateway/feed", headers=_headers(tenant_id, role="viewer"), params={"limit": 20})
    assert feed.json()["events"] == [], feed.text


def test_canonical_event_missing_event_id_key_entirely_is_rejected() -> None:
    client = TestClient(app)
    alert = _event()
    del alert["event_id"]

    response = _ingest(client, "tenant-canonical-missing-key", alert)

    assert response.status_code == 422, response.text


def test_one_bad_event_rejects_the_whole_batch_rather_than_half_committing() -> None:
    """Partial acceptance would re-create the same silent-loss hole per batch."""
    client = TestClient(app)
    tenant_id = "tenant-canonical-batch"

    response = client.post(
        "/v1/proxy/audit",
        headers=_headers(tenant_id),
        json={
            "source_id": "gateway-a",
            "alerts": [_event(event_id="evt-good-1"), _event(event_id="")],
        },
    )

    assert response.status_code == 422, response.text
    feed = client.get("/v1/gateway/feed", headers=_headers(tenant_id, role="viewer"), params={"limit": 20})
    assert feed.json()["events"] == [], feed.text


@pytest.mark.parametrize("event_type", CANONICAL_EVENT_TYPES)
def test_canonical_event_with_event_id_is_durably_committed(event_type: str) -> None:
    """The other direction: a well-formed canonical event still commits."""
    client = TestClient(app)
    tenant_id = "tenant-canonical-accept"

    response = _ingest(client, tenant_id, _event(event_type))

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["accepted_alert_count"] == 1, body
    assert body["durable_accepted_count"] == 1, body


def test_legacy_non_canonical_alert_without_event_id_still_accepted() -> None:
    """Legacy proxy envelopes are not canonical gateway events — do not break them."""
    client = TestClient(app)
    tenant_id = "tenant-legacy"

    response = _ingest(
        client,
        tenant_id,
        {"type": "runtime_alert", "detector": "credential_leak", "severity": "high", "message": "leak"},
    )

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["accepted_alert_count"] == 1, body
    # Legacy envelopes are explicitly a degraded, ring-only path.
    assert body["durable_accepted_count"] == 0, body


# ── event_timestamp: the sibling required field ───────────────────────────────
#
# ``event_id`` was hardened above; ``event_timestamp`` kept returning ``None``,
# which drops the event onto the legacy ring-only path and answers 200. The
# caller is told its gateway decision was accepted while nothing was committed —
# the exact silent downgrade the docstring rules out. A malformed value already
# 422s, so absent/blank was the one shape that still slipped through.


@pytest.mark.parametrize("event_type", CANONICAL_EVENT_TYPES)
@pytest.mark.parametrize("missing", ["", "   ", None])
def test_canonical_event_without_event_timestamp_is_rejected(event_type: str, missing: object) -> None:
    client = TestClient(app)
    tenant_id = "tenant-canonical-ts-reject"

    response = _ingest(client, tenant_id, _event(event_type, event_timestamp=missing))

    assert response.status_code == 422, response.text
    feed = client.get("/v1/gateway/feed", headers=_headers(tenant_id, role="viewer"), params={"limit": 20})
    assert feed.json()["events"] == [], feed.text


def test_canonical_event_missing_event_timestamp_key_entirely_is_rejected() -> None:
    client = TestClient(app)
    alert = _event()
    del alert["event_timestamp"]

    response = _ingest(client, "tenant-canonical-ts-missing-key", alert)

    assert response.status_code == 422, response.text


def test_canonical_event_with_an_unrepresentable_numeric_timestamp_is_rejected() -> None:
    """An epoch value no calendar can hold is not a timestamp either.

    ``datetime.fromtimestamp`` raises, and that branch also answered 200 with
    the event committed nowhere.
    """
    client = TestClient(app)

    response = _ingest(client, "tenant-canonical-ts-overflow", _event(event_timestamp=10**30))

    assert response.status_code == 422, response.text


def test_a_numeric_event_timestamp_is_still_accepted() -> None:
    """Epoch seconds remain a supported wire shape — do not over-reject."""
    client = TestClient(app)
    tenant_id = "tenant-canonical-ts-epoch"

    response = _ingest(client, tenant_id, _event(event_timestamp=1_785_000_000))

    assert response.status_code == 200, response.text
    assert response.json()["durable_accepted_count"] == 1, response.text


def test_timestamp_fallback_field_still_satisfies_the_requirement() -> None:
    """Callers that send ``timestamp`` instead of ``event_timestamp`` still work."""
    client = TestClient(app)
    tenant_id = "tenant-canonical-ts-fallback"
    alert = _event()
    del alert["event_timestamp"]
    alert["timestamp"] = datetime.now(timezone.utc).isoformat()

    response = _ingest(client, tenant_id, alert)

    assert response.status_code == 200, response.text
    assert response.json()["durable_accepted_count"] == 1, response.text
