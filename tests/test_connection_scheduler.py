"""Tests for the cloud-connection scan scheduler (Phase B.2).

Covers due-detection (interval elapsed vs not, never-scanned, no-interval),
the cluster-safe compare-and-swap claim (a second replica cannot double-run a
claimed scan), the run-once orchestration (durable job queued + ``last_scan_at``
advanced + status ``pending``), failure isolation (a rejected enqueue is marked
``error`` and the loop continues), provider-neutral admission, and the env toggle
that keeps the loop off in CLI/dev.

Also covers the three hardening invariants the scheduler must hold:

* the persisted ``status_detail`` uses fixed safe text so no exception text
  reaches ``GET /v1/cloud/connections``;
* every per-connection unit of work runs with the connection's Postgres tenant
  bound, and a raising scan restores the previous tenant;
* no persistence failure escapes a tick — ``execute_connection_scan`` never
  raises and both ``gather`` fan-outs survive a raising task.

Plus idle observability: an enabled loop whose connections carry neither cadence
gate says so once per throttle window, and a tick that ran a scan never emits
that notice.
"""

from __future__ import annotations

import asyncio
import logging
import os
import time
import uuid
from collections.abc import Iterator
from contextlib import suppress
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from typing import Any

import pytest
from cryptography.fernet import Fernet

from agent_bom.api import connection_crypto
from agent_bom.api.connection_scheduler import (
    _log_idle_notice,
    claim_due_connections,
    connection_scheduler_loop,
    connections_scheduler_enabled,
    describe_idle_scheduler,
    drain_continuous_events,
    execute_connection_scan,
    is_due,
    run_due_scans_once,
    select_due_connections,
)
from agent_bom.api.connection_store import (
    SCAN_MODE_CONTINUOUS,
    SCAN_MODE_FULL,
    STATUS_ERROR,
    STATUS_PENDING,
    CloudConnectionRecord,
    InMemoryConnectionStore,
    SQLiteConnectionStore,
    set_connection_store,
)
from agent_bom.api.postgres_common import _current_tenant

_TEST_KEY = Fernet.generate_key().decode("ascii")

# A realistic boto3 ``AssumeRole`` denial. ``sanitize_error`` without
# ``generic=True`` strips URLs, absolute paths, and ``key=value`` credential
# assignments — it leaves the account-bearing ARN prefix and the ExternalId
# value intact, and the message is short enough to survive both the 200-char
# sanitizer truncation and the 300-char ``status_detail`` cap. Anything that
# persists this text verbatim leaks a secret to ``GET /v1/cloud/connections``.
_LEAK_EXTERNAL_ID = "super-secret-external-id"
_LEAK_ACCOUNT_ARN = "arn:aws:sts::111122223333:assumed-role"
_BROKER_FAILURE_MESSAGE = (
    "An error occurred (AccessDenied) when calling the AssumeRole operation: "
    f"{_LEAK_ACCOUNT_ARN}/abom is not authorized "
    f"(ExternalId {_LEAK_EXTERNAL_ID})"
)


@pytest.fixture(autouse=True)
def _scheduler_env() -> Iterator[None]:
    """Provide an encryption key and an isolated in-memory store per test."""
    prior_key = os.environ.get(connection_crypto.CONNECTIONS_KEY_ENV)
    prior_flag = os.environ.get("AGENT_BOM_CONNECTIONS_SCHEDULER")
    os.environ[connection_crypto.CONNECTIONS_KEY_ENV] = _TEST_KEY
    os.environ.pop("AGENT_BOM_CONNECTIONS_SCHEDULER", None)
    try:
        yield
    finally:
        for key, value in (
            (connection_crypto.CONNECTIONS_KEY_ENV, prior_key),
            ("AGENT_BOM_CONNECTIONS_SCHEDULER", prior_flag),
        ):
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
        set_connection_store(None)


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _record(
    tenant_id: str = "tenant-a",
    *,
    provider: str = "aws",
    scan_interval_minutes: int | None = 60,
    last_scan_at: str | None = None,
    status: str = STATUS_PENDING,
    scan_mode: str = SCAN_MODE_FULL,
) -> CloudConnectionRecord:
    return CloudConnectionRecord(
        id=str(uuid.uuid4()),
        tenant_id=tenant_id,
        provider=provider,
        display_name="prod-readonly",
        role_ref="arn:aws:iam::123456789012:role/agent-bom-readonly",
        external_id_encrypted=connection_crypto.encrypt_secret("super-secret-external-id"),
        regions=["us-east-1"],
        status=status,
        created_at="2026-06-26T00:00:00+00:00",
        updated_at="2026-06-26T00:00:00+00:00",
        last_scan_at=last_scan_at,
        scan_interval_minutes=scan_interval_minutes,
        scan_mode=scan_mode,
    )


class _TenantRecordingStore(InMemoryConnectionStore):
    """In-memory store that records the bound Postgres tenant on every write.

    ``put`` is the scheduler's write path (via ``_mark_connection``). On
    Postgres the ``WITH CHECK`` half of each ``*_tenant_isolation`` policy
    compares the row's ``tenant_id`` against ``app.tenant_id``, which
    ``_apply_tenant_session`` reads from the ``_current_tenant`` contextvar —
    so an unbound tenant means the write is rejected. Ids added to
    ``fail_ids`` raise on write to simulate that rejection.
    """

    def __init__(self) -> None:
        super().__init__()
        self.put_tenants: list[tuple[str, str]] = []
        self.fail_ids: set[str] = set()

    def put(self, record: CloudConnectionRecord) -> None:
        self.put_tenants.append((record.id, _current_tenant.get()))
        if record.id in self.fail_ids:
            raise RuntimeError('new row violates row-level security policy for table "cloud_connections"')
        super().put(record)

    def observed_tenant(self, connection_id: str) -> str | None:
        """Tenant bound during the most recent write for *connection_id*."""
        for record_id, tenant in reversed(self.put_tenants):
            if record_id == connection_id:
                return tenant
        return None


def _install_scan_mocks(
    monkeypatch: pytest.MonkeyPatch,
    *,
    fail: bool = False,
    fail_ids: set[str] | None = None,
) -> dict[str, Any]:
    """Patch durable queue admission, the scheduler's owned execution boundary.

    *fail* rejects every enqueue; *fail_ids* rejects only those connections so a
    tick can mix a rejected and an accepted handoff. Provider execution belongs
    to the scan worker and is intentionally outside these scheduler tests.
    """
    from agent_bom.api.routes import cloud_connections

    calls: dict[str, Any] = {"queued_ids": [], "queue_tenants": []}

    def _fake_queue(record: CloudConnectionRecord, *, actor: str) -> Any:
        assert actor == "scheduler"
        calls["queued_ids"].append(record.id)
        calls["queue_tenants"].append((record.id, _current_tenant.get()))
        if fail or (fail_ids is not None and record.id in fail_ids):
            raise RuntimeError(_BROKER_FAILURE_MESSAGE)
        return SimpleNamespace(job_id=f"scheduled-{record.id}")

    monkeypatch.setattr(cloud_connections, "queue_connection_scan_record", _fake_queue)
    return calls


# --------------------------------------------------------------------------- #
# Due-detection
# --------------------------------------------------------------------------- #


def test_is_due_never_scanned() -> None:
    assert is_due(_record(last_scan_at=None), _now()) is True


def test_is_due_interval_elapsed() -> None:
    now = _now()
    stale = (now - timedelta(minutes=61)).isoformat()
    assert is_due(_record(scan_interval_minutes=60, last_scan_at=stale), now) is True


def test_is_due_interval_not_elapsed() -> None:
    now = _now()
    recent = (now - timedelta(minutes=5)).isoformat()
    assert is_due(_record(scan_interval_minutes=60, last_scan_at=recent), now) is False


def test_is_due_no_interval_is_manual_only() -> None:
    assert is_due(_record(scan_interval_minutes=None, last_scan_at=None), _now()) is False


def test_select_due_only_returns_due_with_interval() -> None:
    now = _now()
    store = InMemoryConnectionStore()
    due = _record(scan_interval_minutes=60, last_scan_at=(now - timedelta(hours=2)).isoformat())
    not_due = _record(scan_interval_minutes=60, last_scan_at=(now - timedelta(minutes=1)).isoformat())
    manual = _record(scan_interval_minutes=None)
    for record in (due, not_due, manual):
        store.put(record)

    selected_ids = {r.id for r in select_due_connections(store, now)}
    assert selected_ids == {due.id}


# --------------------------------------------------------------------------- #
# Cluster-safe claim (compare-and-swap)
# --------------------------------------------------------------------------- #


def test_claim_prevents_double_run_in_memory() -> None:
    store = InMemoryConnectionStore()
    record = _record(last_scan_at=None)
    store.put(record)
    claimed_at = _now().isoformat()

    # Two replicas each read the same connection (last_scan_at=None) and race.
    replica_a = store.get(record.tenant_id, record.id)
    replica_b = store.get(record.tenant_id, record.id)
    assert replica_a is not None and replica_b is not None

    assert store.claim_due_scan(replica_a, claimed_at) is True
    assert store.claim_due_scan(replica_b, claimed_at) is False


def test_claim_prevents_double_run_sqlite(tmp_path: Any) -> None:
    store = SQLiteConnectionStore(str(tmp_path / "connections.db"))
    record = _record(last_scan_at=None)
    store.put(record)
    claimed_at = _now().isoformat()

    replica_a = store.get(record.tenant_id, record.id)
    replica_b = store.get(record.tenant_id, record.id)
    assert replica_a is not None and replica_b is not None

    assert store.claim_due_scan(replica_a, claimed_at) is True
    assert store.claim_due_scan(replica_b, claimed_at) is False
    # The stored row carries the winner's claim timestamp.
    assert store.get(record.tenant_id, record.id).last_scan_at == claimed_at  # type: ignore[union-attr]


def test_claim_due_connections_claims_all_providers() -> None:
    store = InMemoryConnectionStore()
    now = _now()
    records = [_record(provider=p, last_scan_at=None) for p in ("aws", "azure", "gcp", "snowflake")]
    for record in records:
        store.put(record)

    claimed = claim_due_connections(store, now)
    # Every supported provider is broker-enabled and therefore claimed.
    assert {r.provider for r in claimed} == {"aws", "azure", "gcp", "snowflake"}


# --------------------------------------------------------------------------- #
# Run-once orchestration
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_run_once_queues_scan_and_updates_last_scan_at(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = _install_scan_mocks(monkeypatch)
    store = InMemoryConnectionStore()
    set_connection_store(store)
    record = _record(scan_interval_minutes=60, last_scan_at=None)
    store.put(record)

    count = await run_due_scans_once(store, _now())
    assert count == 1
    assert calls["queued_ids"] == [record.id]

    fetched = store.get(record.tenant_id, record.id)
    assert fetched is not None
    assert fetched.status == STATUS_PENDING
    assert fetched.status_detail == ""
    assert fetched.last_scan_at is not None


@pytest.mark.asyncio
async def test_run_once_no_due_connections_is_noop(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = _install_scan_mocks(monkeypatch)
    store = InMemoryConnectionStore()
    set_connection_store(store)
    now = _now()
    # Manual-only + a recently scanned connection: neither is due.
    store.put(_record(scan_interval_minutes=None))
    store.put(_record(scan_interval_minutes=60, last_scan_at=(now - timedelta(minutes=1)).isoformat()))

    count = await run_due_scans_once(store, now)
    assert count == 0
    assert calls["queued_ids"] == []


@pytest.mark.asyncio
async def test_run_once_rejected_enqueue_marked_error_and_loop_continues(monkeypatch: pytest.MonkeyPatch) -> None:
    # Queue admission always fails, but the run still completes for both
    # connections (one bad connection never sinks the loop).
    _install_scan_mocks(monkeypatch, fail=True)
    store = InMemoryConnectionStore()
    set_connection_store(store)
    first = _record(scan_interval_minutes=60, last_scan_at=None)
    second = _record(scan_interval_minutes=60, last_scan_at=None)
    store.put(first)
    store.put(second)

    count = await run_due_scans_once(store, _now())
    assert count == 2
    for record in (first, second):
        fetched = store.get(record.tenant_id, record.id)
        assert fetched is not None
        assert fetched.status == STATUS_ERROR
        assert fetched.status_detail
        assert _LEAK_EXTERNAL_ID not in fetched.status_detail
        assert _LEAK_ACCOUNT_ARN not in fetched.status_detail


@pytest.mark.asyncio
async def test_scheduled_enqueue_failure_detail_is_fixed_and_sanitized(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A queue failure persists fixed text without exception-controlled data.

    ``status_detail`` is returned verbatim by ``GET /v1/cloud/connections``, so
    queue, database, and quota exceptions must not control its contents.
    """
    _install_scan_mocks(monkeypatch, fail=True)
    store = InMemoryConnectionStore()
    set_connection_store(store)
    record = _record(scan_interval_minutes=60, last_scan_at=None)
    store.put(record)

    assert await run_due_scans_once(store, _now()) == 1

    fetched = store.get(record.tenant_id, record.id)
    assert fetched is not None
    assert fetched.status_detail == ("Scheduled scan could not be queued. Retry after checking worker and database health.")
    assert "AccessDenied" not in fetched.status_detail
    assert _LEAK_EXTERNAL_ID not in fetched.status_detail
    assert _LEAK_ACCOUNT_ARN not in fetched.status_detail


# --------------------------------------------------------------------------- #
# Tenant context binding (Postgres RLS WITH CHECK)
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_run_once_binds_each_connections_tenant_for_writes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Each connection's writes run under its own tenant, not the default one."""
    _install_scan_mocks(monkeypatch)
    store = _TenantRecordingStore()
    set_connection_store(store)
    first = _record(tenant_id="tenant-a", scan_interval_minutes=60, last_scan_at=None)
    second = _record(tenant_id="tenant-b", scan_interval_minutes=60, last_scan_at=None)
    store.put(first)
    store.put(second)
    store.put_tenants.clear()

    assert await run_due_scans_once(store, _now()) == 2

    assert store.observed_tenant(first.id) == "tenant-a"
    assert store.observed_tenant(second.id) == "tenant-b"
    assert "default" not in {tenant for _id, tenant in store.put_tenants}


def test_execute_connection_scan_restores_tenant_after_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A raising scan resets the tenant so it cannot leak into the next unit."""
    _install_scan_mocks(monkeypatch, fail=True)
    store = _TenantRecordingStore()
    set_connection_store(store)
    record = _record(tenant_id="tenant-a")
    store.put(record)
    store.put_tenants.clear()

    assert execute_connection_scan(record) is False
    assert store.observed_tenant(record.id) == "tenant-a"
    assert _current_tenant.get() == "default"


def test_rejected_enqueue_does_not_leak_tenant_into_next_connection(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Two tenants in one tick: the first raising must not taint the second."""
    store = _TenantRecordingStore()
    set_connection_store(store)
    failing = _record(tenant_id="tenant-a", scan_interval_minutes=60, last_scan_at=None)
    healthy = _record(tenant_id="tenant-b", scan_interval_minutes=60, last_scan_at=None)
    store.put(failing)
    store.put(healthy)
    store.put_tenants.clear()
    calls = _install_scan_mocks(monkeypatch, fail_ids={failing.id})

    # Sequential in-thread calls share one context, so a missing reset shows up.
    assert execute_connection_scan(failing) is False
    assert execute_connection_scan(healthy) is True

    assert dict(calls["queue_tenants"]) == {failing.id: "tenant-a", healthy.id: "tenant-b"}
    assert store.observed_tenant(healthy.id) == "tenant-b"
    assert _current_tenant.get() == "default"


@pytest.mark.asyncio
async def test_drain_continuous_events_binds_connection_tenant(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The event drain's ``last_event_at`` stamp also needs the tenant bound."""
    os.environ["AGENT_BOM_CONNECTIONS_SCHEDULER"] = "1"
    os.environ["AGENT_BOM_AWS_EVENT_QUEUE_URL"] = "https://sqs.example/queue"
    observed: list[str] = []

    def _fake_consume(record: CloudConnectionRecord, **kwargs: Any) -> dict[str, Any]:
        observed.append(_current_tenant.get())
        return {"status": "ok", "processed": 0}

    monkeypatch.setattr("agent_bom.cloud.event_ingest.consume_aws_events", _fake_consume)

    store = InMemoryConnectionStore()
    set_connection_store(store)
    store.put(_record(tenant_id="tenant-b", scan_mode=SCAN_MODE_CONTINUOUS))

    assert await drain_continuous_events(store) == 1
    assert observed == ["tenant-b"]


# --------------------------------------------------------------------------- #
# Persistence failures never sink a tick
# --------------------------------------------------------------------------- #


def test_execute_connection_scan_never_raises_when_store_write_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A rejected store write is reported as a failed scan, not raised."""
    _install_scan_mocks(monkeypatch)
    store = _TenantRecordingStore()
    set_connection_store(store)
    record = _record(scan_interval_minutes=60, last_scan_at=None)
    store.put(record)
    store.fail_ids.add(record.id)

    assert execute_connection_scan(record) is False


@pytest.mark.asyncio
async def test_run_once_survives_a_connection_whose_store_write_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """One connection's persistence failure cannot abort the whole tick."""
    calls = _install_scan_mocks(monkeypatch)
    store = _TenantRecordingStore()
    set_connection_store(store)
    broken = _record(scan_interval_minutes=60, last_scan_at=None)
    healthy = _record(scan_interval_minutes=60, last_scan_at=None)
    store.put(broken)
    store.put(healthy)
    store.fail_ids.add(broken.id)

    count = await run_due_scans_once(store, _now())

    assert count == 2
    assert set(calls["queued_ids"]) == {broken.id, healthy.id}
    fetched = store.get(healthy.tenant_id, healthy.id)
    assert fetched is not None
    assert fetched.status == STATUS_PENDING


@pytest.mark.asyncio
async def test_run_once_survives_a_raising_scan_task(monkeypatch: pytest.MonkeyPatch) -> None:
    """The due-scan gather must collect task errors instead of aborting the tick."""
    from agent_bom.api import connection_scheduler as sched

    _install_scan_mocks(monkeypatch)
    store = InMemoryConnectionStore()
    set_connection_store(store)
    boom = _record(scan_interval_minutes=60, last_scan_at=None)
    healthy = _record(scan_interval_minutes=60, last_scan_at=None)
    store.put(boom)
    store.put(healthy)
    ran: list[str] = []

    def _explode(record: CloudConnectionRecord) -> bool:
        if record.id == boom.id:
            raise RuntimeError("worker thread failure")
        ran.append(record.id)
        return True

    monkeypatch.setattr(sched, "execute_connection_scan", _explode)

    assert await run_due_scans_once(store, _now()) == 2
    assert ran == [healthy.id]


@pytest.mark.asyncio
async def test_drain_continuous_events_survives_store_listing_failure() -> None:
    """A store outage while listing continuous connections cannot sink the tick."""
    os.environ["AGENT_BOM_CONNECTIONS_SCHEDULER"] = "1"

    class _BrokenListing(InMemoryConnectionStore):
        def list_continuous(self) -> list[CloudConnectionRecord]:
            raise RuntimeError("connection pool exhausted")

    store = _BrokenListing()
    set_connection_store(store)

    assert await drain_continuous_events(store) == 0


@pytest.mark.asyncio
async def test_drain_continuous_events_survives_a_raising_drain_task(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The drain gather must collect task errors instead of aborting the tick."""
    from agent_bom.api import connection_scheduler as sched

    os.environ["AGENT_BOM_CONNECTIONS_SCHEDULER"] = "1"
    os.environ["AGENT_BOM_AWS_EVENT_QUEUE_URL"] = "https://sqs.example/queue"
    monkeypatch.setattr(
        "agent_bom.cloud.event_ingest.consume_aws_events",
        lambda record, **k: {"status": "ok"},
    )

    store = InMemoryConnectionStore()
    set_connection_store(store)
    boom = _record(scan_mode=SCAN_MODE_CONTINUOUS)
    healthy = _record(scan_mode=SCAN_MODE_CONTINUOUS)
    store.put(boom)
    store.put(healthy)
    drained: list[str] = []

    def _explode(record: CloudConnectionRecord, store_arg: Any, **kwargs: Any) -> None:
        if record.id == boom.id:
            raise RuntimeError("worker thread failure")
        drained.append(record.id)

    monkeypatch.setattr(sched, "_consume_continuous_events", _explode)

    assert await drain_continuous_events(store) == 2
    assert drained == [healthy.id]


@pytest.mark.asyncio
async def test_run_once_queues_non_aws_provider(monkeypatch: pytest.MonkeyPatch) -> None:
    """The scheduler admits non-AWS providers to the same durable queue."""
    calls = _install_scan_mocks(monkeypatch)

    store = InMemoryConnectionStore()
    set_connection_store(store)
    gcp = _record(provider="gcp", scan_interval_minutes=60, last_scan_at=None)
    store.put(gcp)

    count = await run_due_scans_once(store, _now())
    assert count == 1
    assert calls["queued_ids"] == [gcp.id]
    fetched = store.get(gcp.tenant_id, gcp.id)
    assert fetched is not None
    assert fetched.status == STATUS_PENDING
    assert fetched.last_scan_at is not None


# --------------------------------------------------------------------------- #
# Env toggle
# --------------------------------------------------------------------------- #


def test_scheduler_disabled_by_default() -> None:
    os.environ.pop("AGENT_BOM_CONNECTIONS_SCHEDULER", None)
    assert connections_scheduler_enabled() is False


@pytest.mark.parametrize("value", ["1", "true", "on", "yes", "enabled", "TRUE"])
def test_scheduler_enabled_when_flag_truthy(value: str) -> None:
    os.environ["AGENT_BOM_CONNECTIONS_SCHEDULER"] = value
    assert connections_scheduler_enabled() is True


@pytest.mark.parametrize("value", ["0", "false", "off", "", "no"])
def test_scheduler_disabled_when_flag_falsy(value: str) -> None:
    os.environ["AGENT_BOM_CONNECTIONS_SCHEDULER"] = value
    assert connections_scheduler_enabled() is False


# --------------------------------------------------------------------------- #
# Continuous event drain (before due full scans)
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_drain_continuous_events_invokes_provider_consume(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Continuous + provider queue env → consume_* once; last_scan_at untouched."""
    from agent_bom.api.connection_store import get_connection_store

    os.environ["AGENT_BOM_CONNECTIONS_SCHEDULER"] = "1"
    os.environ["AGENT_BOM_AWS_EVENT_QUEUE_URL"] = "https://sqs.example/queue"
    consumed: list[str] = []

    def _fake_consume(record: CloudConnectionRecord, **kwargs: Any) -> dict[str, Any]:
        consumed.append(record.id)
        # Mimic event_ingest: stamp last_event_at only.
        fresh = get_connection_store().get(record.tenant_id, record.id)
        assert fresh is not None
        fresh.last_event_at = "2026-07-24T12:00:00+00:00"
        get_connection_store().put(fresh)
        return {"status": "ok", "processed": 1}

    monkeypatch.setattr("agent_bom.cloud.event_ingest.consume_aws_events", _fake_consume)

    store = InMemoryConnectionStore()
    set_connection_store(store)
    continuous = _record(
        scan_mode=SCAN_MODE_CONTINUOUS,
        scan_interval_minutes=60,
        last_scan_at=(_now() - timedelta(minutes=5)).isoformat(),
    )
    store.put(continuous)
    prior_last_scan = continuous.last_scan_at

    count = await drain_continuous_events(store)
    assert count == 1
    assert consumed == [continuous.id]
    fetched = store.get(continuous.tenant_id, continuous.id)
    assert fetched is not None
    assert fetched.last_event_at == "2026-07-24T12:00:00+00:00"
    # Full-scan cadence untouched by event drain.
    assert fetched.last_scan_at == prior_last_scan


@pytest.mark.asyncio
async def test_drain_continuous_events_scheduler_off_is_noop(monkeypatch: pytest.MonkeyPatch) -> None:
    os.environ.pop("AGENT_BOM_CONNECTIONS_SCHEDULER", None)
    os.environ["AGENT_BOM_AWS_EVENT_QUEUE_URL"] = "https://sqs.example/queue"
    consumed: list[str] = []
    monkeypatch.setattr(
        "agent_bom.cloud.event_ingest.consume_aws_events",
        lambda record, **k: consumed.append(record.id) or {"status": "ok"},
    )
    store = InMemoryConnectionStore()
    set_connection_store(store)
    store.put(_record(scan_mode=SCAN_MODE_CONTINUOUS))

    assert await drain_continuous_events(store) == 0
    assert consumed == []


@pytest.mark.asyncio
async def test_drain_continuous_events_full_mode_skips(monkeypatch: pytest.MonkeyPatch) -> None:
    os.environ["AGENT_BOM_CONNECTIONS_SCHEDULER"] = "1"
    os.environ["AGENT_BOM_AWS_EVENT_QUEUE_URL"] = "https://sqs.example/queue"
    consumed: list[str] = []
    monkeypatch.setattr(
        "agent_bom.cloud.event_ingest.consume_aws_events",
        lambda record, **k: consumed.append(record.id) or {"status": "ok"},
    )
    store = InMemoryConnectionStore()
    set_connection_store(store)
    store.put(_record(scan_mode=SCAN_MODE_FULL))

    assert await drain_continuous_events(store) == 0
    assert consumed == []


@pytest.mark.asyncio
async def test_drain_continuous_events_skips_without_provider_queue(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    os.environ["AGENT_BOM_CONNECTIONS_SCHEDULER"] = "1"
    os.environ.pop("AGENT_BOM_AWS_EVENT_QUEUE_URL", None)
    consumed: list[str] = []
    monkeypatch.setattr(
        "agent_bom.cloud.event_ingest.consume_aws_events",
        lambda record, **k: consumed.append(record.id) or {"status": "ok"},
    )
    store = InMemoryConnectionStore()
    set_connection_store(store)
    store.put(_record(scan_mode=SCAN_MODE_CONTINUOUS))

    assert await drain_continuous_events(store) == 0
    assert consumed == []


@pytest.mark.asyncio
async def test_drain_continuous_events_parallel_under_semaphore(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Multiple continuous connections drain via concurrent to_thread, not a serial loop."""
    import threading
    import time

    os.environ["AGENT_BOM_CONNECTIONS_SCHEDULER"] = "1"
    os.environ["AGENT_BOM_AWS_EVENT_QUEUE_URL"] = "https://sqs.example/queue"

    lock = threading.Lock()
    in_flight = 0
    max_in_flight = 0
    wait_kwargs: list[int | None] = []

    def _fake_consume(record: CloudConnectionRecord, **kwargs: Any) -> dict[str, Any]:
        nonlocal in_flight, max_in_flight
        wait_kwargs.append(kwargs.get("wait_seconds"))
        with lock:
            in_flight += 1
            max_in_flight = max(max_in_flight, in_flight)
        time.sleep(0.08)
        with lock:
            in_flight -= 1
        return {"status": "ok", "processed": 0}

    monkeypatch.setattr("agent_bom.cloud.event_ingest.consume_aws_events", _fake_consume)

    store = InMemoryConnectionStore()
    set_connection_store(store)
    for _ in range(4):
        store.put(_record(scan_mode=SCAN_MODE_CONTINUOUS, last_scan_at=_now().isoformat()))

    started = time.monotonic()
    count = await drain_continuous_events(store, max_concurrency=4)
    elapsed = time.monotonic() - started

    assert count == 4
    assert max_in_flight >= 2, f"expected overlapping consumes, max_in_flight={max_in_flight}"
    # Serial 4×0.08s ≈ 0.32s; parallel under concurrency 4 should finish closer to one sleep.
    assert elapsed < 0.28, f"drain looked serial (elapsed={elapsed:.3f}s)"
    assert wait_kwargs == [0, 0, 0, 0], "scheduler path must shorten SQS WaitTimeSeconds"


@pytest.mark.asyncio
async def test_drain_continuous_events_respects_max_concurrency(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import threading
    import time

    os.environ["AGENT_BOM_CONNECTIONS_SCHEDULER"] = "1"
    os.environ["AGENT_BOM_AWS_EVENT_QUEUE_URL"] = "https://sqs.example/queue"

    lock = threading.Lock()
    in_flight = 0
    max_in_flight = 0

    def _fake_consume(record: CloudConnectionRecord, **kwargs: Any) -> dict[str, Any]:
        nonlocal in_flight, max_in_flight
        with lock:
            in_flight += 1
            max_in_flight = max(max_in_flight, in_flight)
        time.sleep(0.05)
        with lock:
            in_flight -= 1
        return {"status": "ok"}

    monkeypatch.setattr("agent_bom.cloud.event_ingest.consume_aws_events", _fake_consume)

    store = InMemoryConnectionStore()
    set_connection_store(store)
    for _ in range(4):
        store.put(_record(scan_mode=SCAN_MODE_CONTINUOUS, last_scan_at=_now().isoformat()))

    assert await drain_continuous_events(store, max_concurrency=2) == 4
    assert max_in_flight == 2


@pytest.mark.asyncio
async def test_run_once_drains_continuous_before_due_full_scans(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Each tick drains continuous events first, then claims due full scans."""
    os.environ["AGENT_BOM_CONNECTIONS_SCHEDULER"] = "1"
    os.environ["AGENT_BOM_AWS_EVENT_QUEUE_URL"] = "https://sqs.example/queue"
    order: list[str] = []

    def _fake_consume(record: CloudConnectionRecord, **kwargs: Any) -> dict[str, Any]:
        order.append(f"drain:{record.id}")
        return {"status": "ok", "processed": 0}

    monkeypatch.setattr("agent_bom.cloud.event_ingest.consume_aws_events", _fake_consume)
    calls = _install_scan_mocks(monkeypatch)
    # Wrap scan so we can assert ordering vs drain.
    from agent_bom.api import connection_scheduler as sched

    real_execute = sched.execute_connection_scan

    def _tracked_execute(record: CloudConnectionRecord) -> bool:
        order.append(f"scan:{record.id}")
        return real_execute(record)

    monkeypatch.setattr(sched, "execute_connection_scan", _tracked_execute)

    store = InMemoryConnectionStore()
    set_connection_store(store)
    continuous_due = _record(
        scan_mode=SCAN_MODE_CONTINUOUS,
        scan_interval_minutes=60,
        last_scan_at=None,
    )
    store.put(continuous_due)

    count = await run_due_scans_once(store, _now())
    assert count == 1
    assert order[0] == f"drain:{continuous_due.id}"
    assert order[1] == f"scan:{continuous_due.id}"
    assert calls["queued_ids"] == [continuous_due.id]


# --------------------------------------------------------------------------- #
# Idle observability (an enabled scheduler with no cadence must not be silent)
# --------------------------------------------------------------------------- #


@pytest.fixture
def _scheduler_log(caplog: pytest.LogCaptureFixture) -> Iterator[pytest.LogCaptureFixture]:
    """Capture scheduler records regardless of test order.

    ``setup_logging`` may already have configured the ``agent_bom`` tree with
    ``propagate=False``, which silently drops records before ``caplog``'s root
    handler sees them. Pin both the level and propagation for this logger only.
    """
    scheduler_logger = logging.getLogger("agent_bom.api.connection_scheduler")
    prior_propagate = scheduler_logger.propagate
    scheduler_logger.propagate = True
    caplog.set_level(logging.INFO, logger="agent_bom.api.connection_scheduler")
    try:
        yield caplog
    finally:
        scheduler_logger.propagate = prior_propagate


async def _run_one_tick(store: InMemoryConnectionStore, done: Any, *, timeout: float = 5.0) -> None:
    """Run the scheduler loop until *done()* or *timeout*, then cancel it.

    ``poll_seconds`` is set high so the loop performs exactly one tick and then
    parks in its inter-poll sleep, which makes "logged once" assertions
    deterministic without patching ``asyncio.sleep``.
    """
    task = asyncio.create_task(connection_scheduler_loop(store, poll_seconds=3600))
    deadline = time.monotonic() + timeout
    try:
        while time.monotonic() < deadline and not done():
            await asyncio.sleep(0.01)
    finally:
        task.cancel()
        with suppress(asyncio.CancelledError):
            await task


def _idle_records(caplog: pytest.LogCaptureFixture) -> list[str]:
    return [record.getMessage() for record in caplog.records if "enabled but idle" in record.getMessage()]


@pytest.mark.asyncio
async def test_idle_scheduler_logs_once_when_no_cadence_is_configured(
    _scheduler_log: pytest.LogCaptureFixture,
) -> None:
    """An enabled scheduler with no interval and no continuous mode says so — once."""
    os.environ["AGENT_BOM_CONNECTIONS_SCHEDULER"] = "1"
    store = InMemoryConnectionStore()
    set_connection_store(store)
    # Manual-only, full-mode: neither cadence gate is satisfied, so the loop can
    # never do anything until an operator sets one.
    store.put(_record(scan_interval_minutes=None, scan_mode=SCAN_MODE_FULL))

    await _run_one_tick(store, lambda: bool(_idle_records(_scheduler_log)))

    messages = _idle_records(_scheduler_log)
    assert len(messages) == 1, messages
    assert "scan_interval_minutes" in messages[0]
    assert "scan_mode=continuous" in messages[0]


def test_idle_notice_is_throttled_within_its_window(_scheduler_log: pytest.LogCaptureFixture) -> None:
    """Repeated idle ticks reuse the throttle anchor instead of logging again."""
    store = InMemoryConnectionStore()
    set_connection_store(store)
    store.put(_record(scan_interval_minutes=None, scan_mode=SCAN_MODE_FULL))

    first = _log_idle_notice(store, None, 60)
    second = _log_idle_notice(store, first, 60)

    messages = _idle_records(_scheduler_log)
    assert len(messages) == 1, messages
    assert second == first


def test_idle_notice_silent_while_a_cadence_exists() -> None:
    """A connection carrying an interval is configured cadence, not a misconfiguration."""
    store = InMemoryConnectionStore()
    set_connection_store(store)
    store.put(
        _record(
            scan_interval_minutes=60,
            last_scan_at=(_now() - timedelta(minutes=1)).isoformat(),
        )
    )

    assert describe_idle_scheduler(store) is None


@pytest.mark.asyncio
async def test_busy_tick_does_not_log_the_idle_notice(
    monkeypatch: pytest.MonkeyPatch,
    _scheduler_log: pytest.LogCaptureFixture,
) -> None:
    """A tick that actually ran a due scan logs the run, never the idle notice."""
    os.environ["AGENT_BOM_CONNECTIONS_SCHEDULER"] = "1"
    _install_scan_mocks(monkeypatch)
    store = InMemoryConnectionStore()
    set_connection_store(store)
    store.put(_record(scan_interval_minutes=60, last_scan_at=None))

    def _ran() -> bool:
        return any("ran 1 due cloud-connection scan" in r.getMessage() for r in _scheduler_log.records)

    await _run_one_tick(store, _ran)

    assert _ran(), [r.getMessage() for r in _scheduler_log.records]
    assert _idle_records(_scheduler_log) == []
