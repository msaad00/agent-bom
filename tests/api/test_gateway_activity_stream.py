"""Authenticated ledger-to-SSE handoff and reconnect contracts."""

from __future__ import annotations

import json
import time
from datetime import datetime, timezone

import pytest
from starlette.testclient import TestClient

from agent_bom.api.gateway_activity_store import (
    InMemoryGatewayActivityStore,
    SQLiteGatewayActivityStore,
    gateway_activity_record_from_event,
    set_gateway_activity_store,
)
from agent_bom.api.proxy_provenance import GatewaySubmissionProvenance
from agent_bom.api.routes import gateway_feed
from agent_bom.api.server import app, configure_api

URL = "/v1/gateway/feed/stream"
SECRET = "gateway-stream-test-proxy-secret-32-bytes"


def headers(tenant="tenant-a"):
    return {"X-Agent-Bom-Role": "viewer", "X-Agent-Bom-Tenant-ID": tenant, "X-Agent-Bom-Proxy-Secret": SECRET}


def record(index, tenant="tenant-a", event_type="gateway.tool_call.allowed", provenance=None):
    return gateway_activity_record_from_event(
        {
            "schema_version": "gateway.runtime.event.v1",
            "event_id": f"evt-{index}",
            "decision_id": f"evt-{index}",
            "event_type": event_type,
            # Deliberately reverse caller timestamps: only commit order is causal.
            "event_timestamp": f"2026-07-28T11:{59 - index % 60:02d}:00+00:00",
            "agent_id": "agent-a",
            "profile_id": "finance-prod",
            "profile_revision": 3,
            "blueprint_id": "finance",
            "blueprint_revision": 1,
            "upstream": "filesystem",
            "tool": "read_file",
            "decision": "deny" if event_type.endswith("blocked") else "allow",
            "policy_source": "runtime_profile",
            "policy_id": "policy-7",
            "evidence_id": "evidence-7",
            "trace_id": f"trace-{index}",
        },
        tenant_id=tenant,
        source_id="gateway-a",
        session_id="session-a",
        received_at=datetime(2026, 7, 28, 12, tzinfo=timezone.utc),
        submission_provenance=provenance,
    )


def frames(response):
    text = response.text if hasattr(response, "text") else response
    result = []
    for frame in text.replace("\r\n", "\n").split("\n\n"):
        fields = dict(line.split(": ", 1) for line in frame.splitlines() if ": " in line and not line.startswith(":"))
        if "data" in fields:
            fields["data"] = json.loads(fields["data"])
            result.append(fields)
    return result


@pytest.fixture
def store(tmp_path, monkeypatch):
    monkeypatch.setenv("AGENT_BOM_TRUST_PROXY_AUTH", "1")
    monkeypatch.setenv("AGENT_BOM_TRUST_PROXY_AUTH_SECRET", SECRET)
    # Bounded connections also let TestClient consume an entire SSE response.
    monkeypatch.setattr(gateway_feed, "_STREAM_MAX_SECONDS", 0.25)
    monkeypatch.setattr(gateway_feed, "_STREAM_POLL_SECONDS", 0.001)
    configure_api(api_key=None)
    ledger = SQLiteGatewayActivityStore(str(tmp_path / "activity.db"), max_events_per_tenant=1000)
    set_gateway_activity_store(ledger)
    yield ledger
    set_gateway_activity_store(None)
    configure_api(api_key=None)


def test_stream_requires_auth_even_in_local_no_auth_mode(store, monkeypatch):
    monkeypatch.delenv("AGENT_BOM_TRUST_PROXY_AUTH")
    monkeypatch.delenv("AGENT_BOM_TRUST_PROXY_AUTH_SECRET")
    assert TestClient(app).get(URL).status_code == 401


def test_stream_backfills_beyond_latest_200_and_preserves_every_event_class(store):
    records = [record(i) for i in range(230)]
    records += [record(230, event_type="gateway.runtime_profile.blocked"), record(231, event_type="gateway.enforcement.warned")]
    store.append_batch(records)
    store.append_batch([record(1, tenant="tenant-b")])
    response = TestClient(app).get(URL, headers=headers(), params={"limit": 50})
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/event-stream")
    assert response.headers["x-accel-buffering"] == "no"
    received = frames(response)
    events = [event for frame in received if frame["event"] == "activity" for event in frame["data"]["events"]]
    assert [event["event_id"] for event in events] == [f"evt-{i}" for i in range(232)]
    assert [event["ingest_ordinal"] for event in events] == list(range(1, 233))
    assert all(event["tenant_id"] == "tenant-a" for event in events)
    assert events[-1]["policy_id"] == "policy-7"
    assert events[-1]["evidence_id"] == "evidence-7"
    assert received[-1]["event"] == "reconnect"


def test_rest_cursor_handoff_and_last_event_id_precedence(store):
    store.append_batch([record(1)])
    client = TestClient(app)
    cursor = client.get("/v1/gateway/feed", headers=headers()).json()["next_cursor"]
    store.append_batch([record(2), record(3)])
    response = client.get(URL, headers={**headers(), "Last-Event-ID": store.encode_cursor("tenant-a", 2)}, params={"cursor": cursor})
    assert response.status_code == 200
    events = [event for frame in frames(response) if frame["event"] == "activity" for event in frame["data"]["events"]]
    assert [event["event_id"] for event in events] == ["evt-3"]
    resumed = client.get(URL, headers={**headers(), "Last-Event-ID": next(f["id"] for f in frames(response) if f["event"] == "activity")})
    assert not [frame for frame in frames(resumed) if frame["event"] == "activity"]


@pytest.mark.parametrize("cursor", ["malformed", "foreign", "future"])
def test_stream_rejects_invalid_cursor_before_sse_headers(store, cursor):
    if cursor == "foreign":
        cursor = store.encode_cursor("tenant-b", 0)
    elif cursor == "future":
        cursor = store.encode_cursor("tenant-a", 1)
    response = TestClient(app).get(URL, headers=headers(), params={"cursor": cursor})
    assert response.status_code == 400


def test_expired_cursor_requires_explicit_history_reset(store):
    store.max_events_per_tenant = 2
    store.append_batch([record(1), record(2), record(3)])
    response = TestClient(app).get(URL, headers=headers(), params={"cursor": store.encode_cursor("tenant-a", 0)})
    assert response.status_code == 410
    assert response.json()["detail"]["retention_floor_ordinal"] == 2


def test_storage_failure_never_falls_back_to_process_ring(store, monkeypatch):
    def unavailable(*args, **kwargs):
        raise RuntimeError("postgres://secret@private-db")

    monkeypatch.setattr(store, "list_activity", unavailable)
    response = TestClient(app).get(URL, headers=headers())
    assert response.status_code == 503
    assert "secret" not in response.text


def test_stream_contract_is_published_in_openapi(store):
    operation = app.openapi()["paths"][URL]["get"]
    assert "text/event-stream" in operation["responses"]["200"]["content"]
    assert operation["responses"]["200"]["content"]["text/event-stream"]["schema"]["type"] == "object"
    assert {"400", "401", "410", "503"} <= operation["responses"].keys()
    assert "Last-Event-ID" in {parameter["name"] for parameter in operation["parameters"]}


def test_ephemeral_backend_cannot_claim_resumable_durability(store):
    set_gateway_activity_store(InMemoryGatewayActivityStore())
    assert TestClient(app).get(URL, headers=headers()).status_code == 503


def test_browser_session_is_authenticated_again_on_reconnect(store, monkeypatch):
    from agent_bom.api.browser_session import SESSION_COOKIE_NAME, create_browser_session_token

    monkeypatch.setenv("AGENT_BOM_BROWSER_SESSION_SIGNING_KEY", "stream-browser-session-test-key")
    token, _ = create_browser_session_token(
        subject="stream-reader", role="viewer", tenant_id="tenant-a", auth_method="browser_session", max_age_seconds=60
    )
    client = TestClient(app)
    client.cookies.set(SESSION_COOKIE_NAME, token)
    first = client.get(URL)
    assert first.status_code == 200
    checkpoint = next(frame["id"] for frame in frames(first) if frame["event"] == "checkpoint")
    expired, _ = create_browser_session_token(
        subject="stream-reader", role="viewer", tenant_id="tenant-a", auth_method="browser_session", max_age_seconds=-10
    )
    client.cookies.set(SESSION_COOKIE_NAME, expired)
    assert client.get(URL, headers={"Last-Event-ID": checkpoint}).status_code == 401


@pytest.mark.asyncio
async def test_backfill_to_tail_and_replica_reconnect_are_one_cursor(store, tmp_path):
    store.append_batch([record(1), record(2)])
    first = gateway_feed._read_stream_page("tenant-a", None, 1)
    iterator = gateway_feed._stream_activity("tenant-a", first, 1, time.monotonic() + 10)
    received = [await anext(iterator)]
    # Another gateway/API replica appends between the snapshot and tail read.
    second_replica = SQLiteGatewayActivityStore(str(tmp_path / "activity.db"), max_events_per_tenant=1000)
    second_replica.append_batch([record(3)])
    received.append(await anext(iterator))
    received.append(await anext(iterator))
    await iterator.aclose()
    assert [json.loads(frame["data"])["events"][0]["event_id"] for frame in received] == ["evt-1", "evt-2", "evt-3"]
    # Reconnect on a newly constructed store; replaying an occurrence cannot
    # allocate another ordinal or deliver it again.
    second_replica.append_batch([record(3), record(4)])
    set_gateway_activity_store(second_replica)
    resumed = gateway_feed._read_stream_page("tenant-a", received[-1]["id"], 100)
    assert [event.event_id for event in resumed.events] == ["evt-4"]


@pytest.mark.asyncio
async def test_initial_empty_checkpoint_cannot_skip_concurrent_append(store):
    first = gateway_feed._read_stream_page("tenant-a", None, 100)
    store.append_batch([record(1)])
    iterator = gateway_feed._stream_activity("tenant-a", first, 100, time.monotonic() + 10)
    checkpoint = await anext(iterator)
    assert checkpoint["event"] == "checkpoint"
    assert checkpoint["id"] == store.encode_cursor("tenant-a", 0)
    event = await anext(iterator)
    assert json.loads(event["data"])["events"][0]["event_id"] == "evt-1"
    await iterator.aclose()


@pytest.mark.asyncio
async def test_slow_reader_gets_gap_without_cursor_advancement(store):
    store.max_events_per_tenant = 2
    store.append_batch([record(1), record(2)])
    first = gateway_feed._read_stream_page("tenant-a", None, 1)
    iterator = gateway_feed._stream_activity("tenant-a", first, 1, time.monotonic() + 10)
    await anext(iterator)
    store.append_batch([record(3), record(4)])
    gap = await anext(iterator)
    assert gap["event"] == "gap"
    assert json.loads(gap["data"]) == {"reason": "cursor_expired", "retention_floor_ordinal": 3}
    assert "id" not in gap
    with pytest.raises(StopAsyncIteration):
        await anext(iterator)


@pytest.mark.asyncio
async def test_midstream_outage_is_terminal_and_sanitized(store, monkeypatch):
    first = gateway_feed._read_stream_page("tenant-a", None, 100)
    iterator = gateway_feed._stream_activity("tenant-a", first, 100, time.monotonic() + 10)
    await anext(iterator)

    def unavailable(*args, **kwargs):
        raise RuntimeError("postgres://secret@private-db")

    monkeypatch.setattr(store, "list_activity", unavailable)
    terminal = await anext(iterator)
    assert terminal == {"event": "unavailable", "data": '{"reason":"ledger_unavailable"}'}
    with pytest.raises(StopAsyncIteration):
        await anext(iterator)


def test_stream_preserves_submission_assurance_and_payload_exclusion(store):
    provenance = GatewaySubmissionProvenance(
        submission_source_id="gateway-a", submission_session_id="session-a", producer_assurance="caller_asserted"
    )
    store.append_batch([record(1, provenance=provenance)])
    response = TestClient(app).get(URL, headers=headers())
    event = next(frame for frame in frames(response) if frame["event"] == "activity")["data"]["events"][0]
    assert event["submission_provenance"]["producer_assurance"] == "caller_asserted"
    assert not event["raw_payload_stored"]
    assert not {"arguments", "result", "prompt", "token", "preview"} & event.keys()


@pytest.mark.asyncio
async def test_cancellation_during_idle_read_stops_future_polls(store, monkeypatch):
    import asyncio

    first = gateway_feed._read_stream_page("tenant-a", None, 100)
    iterator = gateway_feed._stream_activity("tenant-a", first, 100, time.monotonic() + 10)
    await anext(iterator)
    monkeypatch.setattr(gateway_feed, "_STREAM_POLL_SECONDS", 10)
    pending = asyncio.create_task(anext(iterator))
    await asyncio.sleep(0)
    pending.cancel()
    with pytest.raises(asyncio.CancelledError):
        await pending
    with pytest.raises(StopAsyncIteration):
        await anext(iterator)


def test_stream_capacity_is_bounded_and_released_after_response(store, monkeypatch):
    import threading

    slots = threading.BoundedSemaphore(1)
    monkeypatch.setattr(gateway_feed, "_stream_slots", slots, raising=False)
    assert slots.acquire(blocking=False)
    client = TestClient(app)
    response = client.get(URL, headers=headers())
    assert response.status_code == 503
    slots.release()
    assert client.get(URL, headers=headers()).status_code == 200
    assert slots.acquire(blocking=False), "finished SSE response leaked its capacity slot"
    slots.release()


@pytest.mark.asyncio
async def test_ledger_poll_keeps_event_loop_and_tenant_context_available(store, monkeypatch):
    import asyncio
    import threading

    from agent_bom.api.postgres_common import _current_tenant, reset_current_tenant, set_current_tenant

    first = gateway_feed._read_stream_page("tenant-a", None, 100)
    store.append_batch([record(1)])
    read = store.list_activity
    main_thread = threading.get_ident()
    observed = []

    def slow_read(*args, **kwargs):
        observed.append((threading.get_ident(), _current_tenant.get()))
        time.sleep(0.03)
        return read(*args, **kwargs)

    monkeypatch.setattr(store, "list_activity", slow_read)
    token = set_current_tenant("tenant-a")
    try:
        iterator = gateway_feed._stream_activity("tenant-a", first, 100, time.monotonic() + 10)
        await anext(iterator)
        pending = asyncio.create_task(anext(iterator))
        await asyncio.sleep(0.01)
        assert not pending.done()
        assert (await pending)["event"] == "activity"
        await iterator.aclose()
        assert observed[0][0] != main_thread
        assert observed[0][1] == "tenant-a"
    finally:
        reset_current_tenant(token)
