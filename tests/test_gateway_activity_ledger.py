"""Canonical gateway activity ledger contracts for #4152."""

from __future__ import annotations

import sqlite3
import threading
from dataclasses import replace
from datetime import datetime, timezone

import pytest

from agent_bom.api.gateway_activity_store import (
    GATEWAY_ACTIVITY_STORE_SCHEMA,
    MAX_ACTIVITY_BATCH_SIZE,
    GatewayActivityConflictError,
    GatewayActivityCursorError,
    GatewayActivityCursorExpiredError,
    InMemoryGatewayActivityStore,
    SQLiteGatewayActivityStore,
    gateway_activity_record_from_event,
)
from agent_bom.api.runtime_event_store import SQLiteRuntimeEventStore
from agent_bom.storage.base import TenantScopedStore

NOW = datetime(2026, 7, 28, 12, 0, tzinfo=timezone.utc)


def test_store_schema_has_backend_parity_and_stores_conform(tmp_path) -> None:
    assert GATEWAY_ACTIVITY_STORE_SCHEMA.drift_report() == {}
    assert isinstance(InMemoryGatewayActivityStore(), TenantScopedStore)
    assert isinstance(SQLiteGatewayActivityStore(str(tmp_path / "activity.db")), TenantScopedStore)


def _event(event_id: str, *, timestamp: str = "2026-07-28T11:59:00+00:00", **overrides: object) -> dict[str, object]:
    event: dict[str, object] = {
        "schema_version": "gateway.runtime.event.v1",
        "event_id": event_id,
        "decision_id": event_id,
        "event_type": "gateway.tool_call.allowed",
        "event_timestamp": timestamp,
        "tenant_id": "attacker-selected-tenant",
        "agent_id": "agent-a",
        "identity_id": "identity-a",
        "profile_id": "profile-finance-prod",
        "profile_revision": 3,
        "blueprint_id": "finance",
        "blueprint_revision": 1,
        "policy_ids": ["policy-finance@7"],
        "upstream": "filesystem",
        "tool": "read_file",
        "decision": "allow",
        "policy_source": "runtime_profile",
        "trace_id": f"trace-{event_id}",
    }
    event.update(overrides)
    return event


def _record(event_id: str, *, tenant_id: str = "tenant-a", **overrides: object):
    return gateway_activity_record_from_event(
        _event(event_id, **overrides),
        tenant_id=tenant_id,
        source_id="gateway-node-a",
        session_id="session-a",
        received_at=NOW,
    )


def test_mapping_is_strict_server_scoped_and_metadata_only() -> None:
    event = _event("evt-1")
    event["arguments"] = {"token": "sk-live-never-store"}
    with pytest.raises(ValueError, match="unexpected gateway activity field"):
        gateway_activity_record_from_event(
            event,
            tenant_id="tenant-a",
            source_id="gateway-node-a",
            session_id="session-a",
            received_at=NOW,
        )

    record = _record("evt-1")
    assert record.tenant_id == "tenant-a"
    assert record.event_id == "evt-1"
    assert record.decision_id == "evt-1"
    assert record.event_schema_version == "gateway.runtime.event.v1"
    assert record.record_schema_version == "gateway.activity.record.v1"
    assert record.profile_id == "profile-finance-prod"
    assert record.blueprint_id == "finance"
    assert record.policy_ids == ("policy-finance@7",)
    assert record.ingest_ordinal == 0
    assert record.raw_payload_stored is False
    assert "attacker-selected-tenant" not in record.to_json()


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ({"schema_version": "gateway.runtime.event.v0"}, "schema_version"),
        ({"decision_id": "different"}, "decision_id"),
        ({"decision": "deny"}, "decision"),
        ({"event_timestamp": "2026-07-28T11:59:00"}, "timezone"),
        ({"event_timestamp": "2026-07-28T12:06:00+00:00"}, "future"),
        ({"event_type": "gateway.policy_allowed"}, "event_type"),
        ({"development_mode": "false"}, "development_mode"),
    ],
)
def test_mapping_rejects_invalid_or_inconsistent_events(overrides: dict[str, object], message: str) -> None:
    with pytest.raises(ValueError, match=message):
        _record("evt-invalid", **overrides)


@pytest.mark.parametrize("store_kind", ["memory", "sqlite"])
def test_append_is_idempotent_conflict_aware_and_tenant_atomic(store_kind: str, tmp_path) -> None:
    store = (
        InMemoryGatewayActivityStore(max_events_per_tenant=10)
        if store_kind == "memory"
        else SQLiteGatewayActivityStore(str(tmp_path / "activity.db"), max_events_per_tenant=10)
    )
    first = _record("evt-1")
    result = store.append_batch([first])
    assert result.inserted_event_ids == ("evt-1",)
    assert result.duplicate_event_ids == ()

    replay = store.append_batch([first])
    assert replay.inserted_event_ids == ()
    assert replay.duplicate_event_ids == ("evt-1",)
    with pytest.raises(GatewayActivityConflictError):
        store.append_batch([_record("evt-1", tool="write_file")])

    before = store.list_activity("tenant-a", limit=10)
    with pytest.raises(ValueError, match="one tenant"):
        store.append_batch([_record("evt-2"), _record("evt-3", tenant_id="tenant-b")])
    after = store.list_activity("tenant-a", limit=10)
    assert after.events == before.events


@pytest.mark.parametrize("store_kind", ["memory", "sqlite"])
def test_append_rejects_tampered_digest(store_kind: str, tmp_path) -> None:
    store = (
        InMemoryGatewayActivityStore(max_events_per_tenant=10)
        if store_kind == "memory"
        else SQLiteGatewayActivityStore(str(tmp_path / "activity.db"), max_events_per_tenant=10)
    )
    with pytest.raises(ValueError, match="digest"):
        store.append_batch([replace(_record("evt-tampered"), event_digest="0" * 64)])


def test_store_rejects_unbounded_retention_configuration() -> None:
    with pytest.raises(ValueError, match="max_events_per_tenant"):
        InMemoryGatewayActivityStore(max_events_per_tenant=0)
    with pytest.raises(ValueError, match="max_tombstones_per_tenant"):
        InMemoryGatewayActivityStore(max_tombstones_per_tenant=0)


def test_append_rejects_oversized_batch_atomically() -> None:
    store = InMemoryGatewayActivityStore(max_events_per_tenant=MAX_ACTIVITY_BATCH_SIZE + 1)
    records = [_record(f"evt-{index}") for index in range(MAX_ACTIVITY_BATCH_SIZE + 1)]
    with pytest.raises(ValueError, match="batch"):
        store.append_batch(records)
    assert store.list_activity("tenant-a").events == []


@pytest.mark.parametrize("store_kind", ["memory", "sqlite"])
def test_cursor_uses_server_ordinal_not_caller_timestamp(store_kind: str, tmp_path) -> None:
    store = (
        InMemoryGatewayActivityStore(max_events_per_tenant=10)
        if store_kind == "memory"
        else SQLiteGatewayActivityStore(str(tmp_path / "activity.db"), max_events_per_tenant=10)
    )
    store.append_batch([_record("evt-a", timestamp="2026-07-28T11:59:30+00:00")])
    first = store.list_activity("tenant-a", limit=1)
    assert [event["event_id"] for event in first.events] == ["evt-a"]
    assert first.next_cursor

    # Late evidence has an older observation timestamp but a newer server-owned
    # ordinal. It must still appear after the issued cursor exactly once.
    store.append_batch([_record("evt-late", timestamp="2026-07-28T11:58:00+00:00")])
    resumed = store.list_activity("tenant-a", cursor=first.next_cursor, limit=10)
    assert [event["event_id"] for event in resumed.events] == ["evt-late"]
    assert resumed.events[0]["ingest_ordinal"] > first.events[0]["ingest_ordinal"]
    assert store.list_activity("tenant-a", cursor=resumed.next_cursor, limit=10).events == []


def test_cursor_rejects_malformed_foreign_and_future_values() -> None:
    store = InMemoryGatewayActivityStore(max_events_per_tenant=10)
    store.append_batch([_record("evt-1")])
    cursor = store.list_activity("tenant-a", limit=1).next_cursor
    assert cursor
    with pytest.raises(GatewayActivityCursorError):
        store.list_activity("tenant-a", cursor="not-a-cursor")
    with pytest.raises(GatewayActivityCursorError):
        store.list_activity("tenant-b", cursor=cursor)
    with pytest.raises(GatewayActivityCursorError):
        store.list_activity("tenant-a", cursor=store.encode_cursor("tenant-a", 999))


@pytest.mark.parametrize("store_kind", ["memory", "sqlite"])
def test_retention_expires_old_cursor_and_tombstone_blocks_reinsert(store_kind: str, tmp_path) -> None:
    store = (
        InMemoryGatewayActivityStore(max_events_per_tenant=2)
        if store_kind == "memory"
        else SQLiteGatewayActivityStore(
            str(tmp_path / "activity.db"),
            max_events_per_tenant=2,
        )
    )
    store.append_batch([_record("evt-1"), _record("evt-2")])
    stale_cursor = store.encode_cursor("tenant-a", 0)
    store.append_batch([_record("evt-3")])

    with pytest.raises(GatewayActivityCursorExpiredError) as exc_info:
        store.list_activity("tenant-a", cursor=stale_cursor, limit=10)
    assert exc_info.value.retention_floor_ordinal == 2
    replay = store.append_batch([_record("evt-1")])
    assert replay.inserted_event_ids == ()
    assert replay.duplicate_event_ids == ("evt-1",)
    with pytest.raises(GatewayActivityConflictError):
        store.append_batch([_record("evt-1", tool="write_file")])

    # Retention invalidates an explicit historical cursor, but a new reader has
    # no historical claim and must begin at the current retained floor.
    fresh = store.list_activity("tenant-a", limit=10)
    assert [event["event_id"] for event in fresh.events] == ["evt-2", "evt-3"]


@pytest.mark.parametrize("store_kind", ["memory", "sqlite"])
def test_pruned_event_id_remains_idempotent_without_expiry(store_kind: str, tmp_path) -> None:
    path = str(tmp_path / "activity.db")
    store = (
        InMemoryGatewayActivityStore(max_events_per_tenant=1)
        if store_kind == "memory"
        else SQLiteGatewayActivityStore(path, max_events_per_tenant=1)
    )
    original = _record("evt-1")
    store.append_batch([original, _record("evt-2")])
    if store_kind == "sqlite":
        store = SQLiteGatewayActivityStore(path, max_events_per_tenant=1)
    assert store.append_batch([original]).duplicate_event_ids == ("evt-1",)
    with pytest.raises(GatewayActivityConflictError):
        store.append_batch([_record("evt-1", tool="write_file")])


@pytest.mark.parametrize("store_kind", ["memory", "sqlite"])
def test_dedupe_history_is_count_bounded_and_reports_window(store_kind: str, tmp_path) -> None:
    store = (
        InMemoryGatewayActivityStore(max_events_per_tenant=1, max_tombstones_per_tenant=2)
        if store_kind == "memory"
        else SQLiteGatewayActivityStore(
            str(tmp_path / "activity.db"),
            max_events_per_tenant=1,
            max_tombstones_per_tenant=2,
        )
    )
    records = [_record(f"evt-{index}") for index in range(1, 5)]
    store.append_batch(records)
    page = store.list_activity("tenant-a")
    assert page.dedupe_window_events == 3
    assert [event["event_id"] for event in page.events] == ["evt-4"]
    assert store.append_batch([records[1]]).duplicate_event_ids == ("evt-2",)

    # evt-1 has aged beyond the explicit three-event dedupe window. The
    # bounded ledger is intentionally at-least-once outside that window.
    assert store.append_batch([records[0]]).inserted_event_ids == ("evt-1",)


@pytest.mark.parametrize("first_store", ["runtime", "gateway"])
def test_sqlite_runtime_v2_schema_converges_in_both_initialization_orders(tmp_path, first_store: str) -> None:
    path = str(tmp_path / f"{first_store}.db")
    constructors = {
        "runtime": lambda: SQLiteRuntimeEventStore(path),
        "gateway": lambda: SQLiteGatewayActivityStore(path),
    }
    constructors[first_store]()
    constructors["gateway" if first_store == "runtime" else "runtime"]()

    with sqlite3.connect(path) as connection:
        marker = connection.execute(
            "SELECT version FROM control_plane_schema_versions WHERE component = ?",
            ("runtime_events",),
        ).fetchone()
        tables = {
            row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type = 'table' AND name LIKE 'gateway_activity_%'")
        }
    assert marker == (2,)
    assert tables == {
        "gateway_activity_events",
        "gateway_activity_sequences",
        "gateway_activity_tombstones",
    }


def test_sqlite_restart_preserves_order_and_cursor(tmp_path) -> None:
    path = str(tmp_path / "activity.db")
    first_store = SQLiteGatewayActivityStore(path, max_events_per_tenant=10)
    first_store.append_batch([_record("evt-1"), _record("evt-2")])
    cursor = first_store.list_activity("tenant-a", limit=1).next_cursor
    assert cursor

    reopened = SQLiteGatewayActivityStore(path, max_events_per_tenant=10)
    resumed = reopened.list_activity("tenant-a", cursor=cursor, limit=10)
    assert [event["event_id"] for event in resumed.events] == ["evt-2"]


def test_sqlite_cursor_query_uses_tenant_ordinal_index(tmp_path) -> None:
    store = SQLiteGatewayActivityStore(str(tmp_path / "activity.db"), max_events_per_tenant=10)
    plan = store.query_plan("tenant-a", after_ordinal=10, limit=100)
    assert "idx_gateway_activity_events_tenant_ordinal" in plan

    window_plan = store._conn.execute(
        "EXPLAIN QUERY PLAN SELECT data FROM gateway_activity_events WHERE tenant_id = ? AND event_timestamp >= ? AND event_timestamp <= ?",
        ("tenant-a", "2026-07-28T00:00:00+00:00", "2026-07-28T23:59:59+00:00"),
    ).fetchall()
    rendered = " ".join(str(column) for row in window_plan for column in row)
    assert "idx_gateway_activity_events_tenant_event_time" in rendered


def test_sqlite_concurrent_writers_allocate_unique_ordinals(tmp_path) -> None:
    store = SQLiteGatewayActivityStore(str(tmp_path / "activity.db"), max_events_per_tenant=20)
    barrier = threading.Barrier(8)
    errors: list[Exception] = []

    def worker(index: int) -> None:
        try:
            barrier.wait()
            store.append_batch([_record(f"evt-{index}")])
        except Exception as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=worker, args=(index,)) for index in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert errors == []
    events = store.list_activity("tenant-a", limit=20).events
    assert [event["ingest_ordinal"] for event in events] == list(range(1, 9))


def test_two_sqlite_api_replicas_share_one_gap_free_tenant_sequence(tmp_path) -> None:
    path = str(tmp_path / "activity.db")
    stores = [
        SQLiteGatewayActivityStore(path, max_events_per_tenant=20),
        SQLiteGatewayActivityStore(path, max_events_per_tenant=20),
    ]
    barrier = threading.Barrier(8)
    errors: list[Exception] = []

    def worker(index: int) -> None:
        try:
            barrier.wait()
            stores[index % 2].append_batch([_record(f"replica-evt-{index}")])
        except Exception as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=worker, args=(index,)) for index in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert errors == []
    page = stores[0].list_activity("tenant-a", limit=20)
    assert [event["ingest_ordinal"] for event in page.events] == list(range(1, 9))
    assert len({event["event_id"] for event in page.events}) == 8


@pytest.mark.parametrize("store_kind", ["memory", "sqlite"])
def test_window_summary_counts_canonical_events_without_materializing_payloads(store_kind: str, tmp_path) -> None:
    store = (
        InMemoryGatewayActivityStore(max_events_per_tenant=20)
        if store_kind == "memory"
        else SQLiteGatewayActivityStore(str(tmp_path / "activity.db"), max_events_per_tenant=20)
    )
    store.append_batch(
        [
            _record("allowed"),
            _record(
                "blocked",
                event_type="gateway.tool_call.blocked",
                decision="deny",
                reason_code="unknown_agent",
            ),
            _record(
                "redacted",
                event_type="gateway.dlp.result_redacted",
                decision="allow",
                data_action="pii_redacted",
            ),
            _record("outside", timestamp="2026-07-27T11:59:00+00:00"),
        ]
    )

    summary = store.summarize_window(
        "tenant-a",
        start="2026-07-28T00:00:00+00:00",
        end="2026-07-28T23:59:59+00:00",
    )

    assert summary.tool_calls_authorized == 1
    assert summary.blocked == 1
    assert summary.shadow_blocked == 1
    assert summary.data_filters == 1
    assert summary.retention_floor_ordinal == 1
    assert summary.latest_ordinal == 4


@pytest.mark.parametrize("store_kind", ["memory", "sqlite"])
@pytest.mark.parametrize(
    "reason_code",
    ["identity_invalid", "managed_identity_required", "tenant_mismatch", "profile_revoked"],
)
def test_window_summary_counts_canonical_unsanctioned_profile_block_as_shadow(store_kind: str, reason_code: str, tmp_path) -> None:
    store = (
        InMemoryGatewayActivityStore(max_events_per_tenant=20)
        if store_kind == "memory"
        else SQLiteGatewayActivityStore(str(tmp_path / "activity.db"), max_events_per_tenant=20)
    )
    store.append_batch(
        [
            _record(
                "revoked-profile",
                event_type="gateway.tool_call.blocked",
                decision="deny",
                reason_code=reason_code,
            )
        ]
    )

    summary = store.summarize_window(
        "tenant-a",
        start="2026-07-28T00:00:00+00:00",
        end="2026-07-28T23:59:59+00:00",
    )

    assert summary.blocked == 1
    assert summary.shadow_blocked == 1


@pytest.mark.parametrize("store_kind", ["memory", "sqlite"])
def test_cursor_ordinal_beyond_the_storage_range_is_a_bad_cursor_not_an_outage(store_kind: str, tmp_path) -> None:
    """A read client must not be able to make the ledger report itself down.

    ``_decode_cursor`` bounded the ordinal below (>= 0) but not above, so a
    hand-made cursor carrying 2**80 was accepted as valid and handed to the
    storage layer. SQLite cannot bind an integer that large: the OverflowError
    escaped the cursor-error path and the feed answered
    503 "Gateway activity storage unavailable" — the control plane declaring
    its own ledger unavailable on request, from any caller with read access.
    """
    store = (
        InMemoryGatewayActivityStore(max_events_per_tenant=10)
        if store_kind == "memory"
        else SQLiteGatewayActivityStore(str(tmp_path / "activity.db"), max_events_per_tenant=10)
    )
    store.append_batch([_record("evt-1")])

    for ordinal in (2**63, 2**80):
        with pytest.raises(GatewayActivityCursorError):
            store.list_activity("tenant-a", cursor=store.encode_cursor("tenant-a", ordinal))


def test_the_largest_storable_cursor_ordinal_is_still_accepted() -> None:
    """The bound must reject only what storage cannot hold."""
    from agent_bom.api.gateway_activity_store import _decode_cursor, _encode_cursor

    largest = 2**63 - 1
    assert _decode_cursor(_encode_cursor("tenant-a", largest), "tenant-a") == largest
