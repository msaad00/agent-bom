"""Tests for the cloud-connection scan scheduler (Phase B.2).

Covers due-detection (interval elapsed vs not, never-scanned, no-interval),
the cluster-safe compare-and-swap claim (a second replica cannot double-run a
claimed scan), the run-once orchestration (scan triggered + ``last_scan_at``
advanced + status ``active``), failure isolation (a failing connection is marked
``error`` and the loop continues), non-AWS skip (the broker is AWS-only), and the
env toggle that keeps the loop off in CLI/dev.
"""

from __future__ import annotations

import os
import uuid
from collections.abc import Iterator
from datetime import datetime, timedelta, timezone
from typing import Any

import pytest
from cryptography.fernet import Fernet

from agent_bom.api import connection_crypto
from agent_bom.api.connection_scheduler import (
    claim_due_connections,
    connections_scheduler_enabled,
    is_due,
    run_due_scans_once,
    select_due_connections,
)
from agent_bom.api.connection_store import (
    STATUS_ACTIVE,
    STATUS_ERROR,
    STATUS_PENDING,
    CloudConnectionRecord,
    InMemoryConnectionStore,
    SQLiteConnectionStore,
    set_connection_store,
)

_TEST_KEY = Fernet.generate_key().decode("ascii")


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
    )


_BROKER_SESSION_SENTINEL = object()


def _install_scan_mocks(monkeypatch: pytest.MonkeyPatch, *, fail: bool = False) -> dict[str, Any]:
    """Patch the broker + AWS inventory/CIS the scheduler's scan path reuses."""
    from agent_bom.cloud import aws_cis_benchmark, aws_inventory, connection_broker

    calls: dict[str, Any] = {"scanned_ids": []}

    def _fake_broker(record: CloudConnectionRecord, **kwargs: Any) -> Any:
        calls["scanned_ids"].append(record.id)
        if fail:
            raise connection_broker.ConnectionBrokerError(f"AssumeRole failed for connection {record.id}.")
        return _BROKER_SESSION_SENTINEL

    def _fake_inventory(region: str | None = None, force: bool = False, session: Any = None, **kwargs: Any) -> dict[str, Any]:
        return {
            "provider": "aws",
            "status": "ok",
            "account_id": "123456789012",
            "region": region or "us-east-1",
            "buckets": [],
            "instances": [],
            "security_groups": [],
            "roles": [],
            "users": [],
            "warnings": [],
        }

    class _FakeCISReport:
        def to_dict(self) -> dict[str, Any]:
            return {
                "benchmark": "CIS AWS Foundations",
                "benchmark_version": "3.0.0",
                "account_id": "123456789012",
                "region": "us-east-1",
                "pass_rate": 50.0,
                "passed": 1,
                "failed": 1,
                "total": 2,
                "checks": [],
            }

    def _fake_cis(region: str | None = None, session: Any = None, **kwargs: Any) -> Any:
        return _FakeCISReport()

    monkeypatch.setattr(connection_broker, "broker_session", _fake_broker)
    monkeypatch.setattr(aws_inventory, "discover_inventory", _fake_inventory)
    monkeypatch.setattr(aws_cis_benchmark, "run_benchmark", _fake_cis)
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


def test_claim_due_connections_skips_non_aws() -> None:
    store = InMemoryConnectionStore()
    now = _now()
    aws = _record(provider="aws", last_scan_at=None)
    azure = _record(provider="azure", last_scan_at=None)
    store.put(aws)
    store.put(azure)

    claimed = claim_due_connections(store, now)
    assert [r.id for r in claimed] == [aws.id]
    # The non-AWS connection was never claimed (last_scan_at untouched).
    assert store.get(azure.tenant_id, azure.id).last_scan_at is None  # type: ignore[union-attr]


# --------------------------------------------------------------------------- #
# Run-once orchestration
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_run_once_triggers_scan_and_updates_last_scan_at(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = _install_scan_mocks(monkeypatch)
    store = InMemoryConnectionStore()
    set_connection_store(store)
    record = _record(scan_interval_minutes=60, last_scan_at=None)
    store.put(record)

    count = await run_due_scans_once(store, _now())
    assert count == 1
    assert calls["scanned_ids"] == [record.id]

    fetched = store.get(record.tenant_id, record.id)
    assert fetched is not None
    assert fetched.status == STATUS_ACTIVE
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
    assert calls["scanned_ids"] == []


@pytest.mark.asyncio
async def test_run_once_failing_connection_marked_error_and_loop_continues(monkeypatch: pytest.MonkeyPatch) -> None:
    # Broker always fails: every claimed scan errors, but the run still completes
    # for both connections (one bad connection never sinks the loop).
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
        assert "super-secret-external-id" not in fetched.status_detail


@pytest.mark.asyncio
async def test_run_once_skips_non_aws(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = _install_scan_mocks(monkeypatch)
    store = InMemoryConnectionStore()
    set_connection_store(store)
    azure = _record(provider="azure", scan_interval_minutes=60, last_scan_at=None)
    store.put(azure)

    count = await run_due_scans_once(store, _now())
    assert count == 0
    assert calls["scanned_ids"] == []
    # Untouched: not claimed, status unchanged, never scanned.
    fetched = store.get(azure.tenant_id, azure.id)
    assert fetched is not None
    assert fetched.last_scan_at is None
    assert fetched.status == STATUS_PENDING


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
