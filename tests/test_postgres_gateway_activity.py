"""Postgres contracts for the durable gateway activity ledger."""

from __future__ import annotations

import os
import threading
import uuid
from datetime import datetime, timezone

import pytest

from agent_bom.api.gateway_activity_store import GatewayActivityConflictError, gateway_activity_record_from_event
from agent_bom.api.postgres_common import _tenant_connection, reset_current_tenant, set_current_tenant
from agent_bom.api.postgres_gateway_activity import PostgresGatewayActivityStore


def _record(event_id: str, tenant_id: str, *, timestamp: str | None = None, tool: str = "read_file"):
    return gateway_activity_record_from_event(
        {
            "schema_version": "gateway.runtime.event.v1",
            "event_id": event_id,
            "decision_id": event_id,
            "event_type": "gateway.tool_call.allowed",
            "event_timestamp": timestamp or datetime.now(timezone.utc).isoformat(),
            "agent_id": "agent-a",
            "upstream": "filesystem",
            "tool": tool,
            "decision": "allow",
            "policy_source": "runtime_profile",
            "trace_id": f"trace-{event_id}",
        },
        tenant_id=tenant_id,
        source_id="gateway-node-a",
        session_id="session-a",
    )


def _cleanup(store: PostgresGatewayActivityStore, tenant_id: str) -> None:
    token = set_current_tenant(tenant_id)
    try:
        with _tenant_connection(store._pool) as conn:
            conn.execute("DELETE FROM gateway_activity_events WHERE tenant_id = %s", (tenant_id,))
            conn.execute("DELETE FROM gateway_activity_tombstones WHERE tenant_id = %s", (tenant_id,))
            conn.execute("DELETE FROM gateway_activity_sequences WHERE tenant_id = %s", (tenant_id,))
            conn.commit()
    finally:
        reset_current_tenant(token)


def test_postgres_ledger_serializes_same_tenant_sequence_before_dedupe() -> None:
    source = (
        __import__("pathlib").Path(__file__).parents[1]
        / "src"
        / "agent_bom"
        / "api"
        / "postgres_gateway_activity.py"
    ).read_text()
    lock_position = source.index("FOR UPDATE")
    active_lookup_position = source.index("SELECT event_id, event_digest FROM gateway_activity_events")
    assert lock_position < active_lookup_position
    assert "ON CONFLICT (tenant_id, event_id) DO NOTHING" not in source
    assert 'ensure_postgres_schema_version(conn, "runtime_events", version=GATEWAY_ACTIVITY_STORAGE_VERSION)' in source

    legacy_source = (
        __import__("pathlib").Path(__file__).parents[1]
        / "src"
        / "agent_bom"
        / "api"
        / "postgres_runtime_event.py"
    ).read_text()
    assert 'ensure_postgres_schema_version(conn, "runtime_events", version=GATEWAY_ACTIVITY_STORAGE_VERSION)' in legacy_source
    assert "bootstrap_postgres_gateway_activity_schema(conn)" in legacy_source


@pytest.mark.skipif(
    not os.environ.get("AGENT_BOM_POSTGRES_URL"),
    reason="requires a migrated live PostgreSQL database",
)
def test_postgres_concurrent_same_tenant_appends_get_unique_contiguous_ordinals() -> None:
    store = PostgresGatewayActivityStore(max_events_per_tenant=100)
    tenant_id = f"gateway-ledger-{uuid.uuid4().hex}"
    barrier = threading.Barrier(8)
    errors: list[Exception] = []

    def worker(index: int) -> None:
        token = set_current_tenant(tenant_id)
        try:
            barrier.wait()
            result = store.append_batch([_record(f"evt-{index}", tenant_id)])
            assert result.inserted_count == 1
        except Exception as exc:  # noqa: BLE001
            errors.append(exc)
        finally:
            reset_current_tenant(token)

    try:
        threads = [threading.Thread(target=worker, args=(index,)) for index in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        assert errors == []
        token = set_current_tenant(tenant_id)
        try:
            page = store.list_activity(tenant_id, limit=20)
        finally:
            reset_current_tenant(token)
        assert sorted(event["ingest_ordinal"] for event in page.events) == list(range(1, 9))
        assert len({event["event_id"] for event in page.events}) == 8
    finally:
        _cleanup(store, tenant_id)


@pytest.mark.skipif(
    not os.environ.get("AGENT_BOM_POSTGRES_URL"),
    reason="requires a migrated live PostgreSQL database",
)
def test_postgres_concurrent_exact_replay_inserts_once() -> None:
    store = PostgresGatewayActivityStore(max_events_per_tenant=100)
    tenant_id = f"gateway-replay-{uuid.uuid4().hex}"
    record = _record("evt-shared", tenant_id)
    barrier = threading.Barrier(4)
    results = []
    errors: list[Exception] = []

    def worker() -> None:
        token = set_current_tenant(tenant_id)
        try:
            barrier.wait()
            results.append(store.append_batch([record]))
        except Exception as exc:  # noqa: BLE001
            errors.append(exc)
        finally:
            reset_current_tenant(token)

    try:
        threads = [threading.Thread(target=worker) for _ in range(4)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        assert errors == []
        assert sum(result.inserted_count for result in results) == 1
        assert sum(result.duplicate_count for result in results) == 3
    finally:
        _cleanup(store, tenant_id)


@pytest.mark.skipif(
    not os.environ.get("AGENT_BOM_POSTGRES_URL"),
    reason="requires a migrated live PostgreSQL database",
)
def test_postgres_conflict_rolls_back_and_rls_hides_foreign_tenant() -> None:
    store = PostgresGatewayActivityStore(max_events_per_tenant=100)
    tenant_id = f"gateway-conflict-{uuid.uuid4().hex}"
    foreign_tenant = f"gateway-foreign-{uuid.uuid4().hex}"
    timestamp = datetime.now(timezone.utc).isoformat()
    token = set_current_tenant(tenant_id)
    try:
        assert store.append_batch([_record("evt-shared", tenant_id, timestamp=timestamp)]).inserted_count == 1
        with pytest.raises(GatewayActivityConflictError):
            store.append_batch([_record("evt-shared", tenant_id, timestamp=timestamp, tool="write_file")])
        assert store.append_batch([_record("evt-next", tenant_id)]).inserted_count == 1
        assert [event["ingest_ordinal"] for event in store.list_activity(tenant_id).events] == [1, 2]
    finally:
        reset_current_tenant(token)

    foreign_token = set_current_tenant(foreign_tenant)
    try:
        assert store.list_activity(tenant_id).events == []
    finally:
        reset_current_tenant(foreign_token)
        _cleanup(store, tenant_id)
