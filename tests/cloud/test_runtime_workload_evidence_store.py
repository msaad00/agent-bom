"""Persistence + isolation tests for the runtime workload-evidence store.

Covers both backends: SQLite (restart-safe, cross-process concurrency) and — when
``AGENT_BOM_POSTGRES_URL`` is set — real Postgres (roundtrip, dedup, cross-tenant
isolation, cross-process concurrency). Tenant isolation and dedup are the
security-critical properties (issue #4158).
"""

from __future__ import annotations

import multiprocessing as mp
import os
import uuid

import pytest

from agent_bom.cloud.runtime_workload_evidence import RuntimeWorkloadSignal
from agent_bom.cloud.runtime_workload_evidence_store import (
    InMemoryRuntimeWorkloadEvidenceStore,
    PostgresRuntimeWorkloadEvidenceStore,
    SQLiteRuntimeWorkloadEvidenceStore,
)

_PG_URL = os.environ.get("AGENT_BOM_POSTGRES_URL")
_requires_pg = pytest.mark.skipif(not _PG_URL, reason="AGENT_BOM_POSTGRES_URL required for real Postgres tests")


def _signal(
    *,
    tenant: str = "tenant-a",
    provider: str = "aws",
    account: str = "123456789012",
    workload: str = "i-0abc",
    dedup: str = "evt-1",
    stype: str = "ioc_detection",
    observed: str = "2026-07-18T12:00:00Z",
) -> RuntimeWorkloadSignal:
    return RuntimeWorkloadSignal(
        tenant_id=tenant,
        provider=provider,
        account_id=account,
        workload_ref=workload,
        signal_type=stype,  # type: ignore[arg-type]
        severity="high",
        observed_at=observed,
        source_id="edr-1",
        source_kind="edr",
        dedup_key=dedup,
        title="known C2 domain contacted",
        evidence={"ioc_type": "domain"},
    )


# ── in-memory (default backend) ──────────────────────────────────────────────


def test_in_memory_put_batch_dedups_and_lists_by_tenant():
    store = InMemoryRuntimeWorkloadEvidenceStore()
    assert store.put_batch([_signal(), _signal()]) == 1
    assert store.put_batch([_signal()]) == 0  # already persisted
    rows = store.list_for_tenant("tenant-a")
    assert len(rows) == 1
    assert store.list_for_tenant("tenant-b") == []


# ── SQLite: restart persistence + isolation + dedup ──────────────────────────


def test_sqlite_persists_across_reopen(tmp_path):
    path = str(tmp_path / "rwe.sqlite")
    store = SQLiteRuntimeWorkloadEvidenceStore(path)
    assert store.put_batch([_signal()]) == 1
    reopened = SQLiteRuntimeWorkloadEvidenceStore(path)
    rows = reopened.list_for_tenant("tenant-a")
    assert len(rows) == 1
    assert rows[0].workload_ref == "i-0abc"
    assert rows[0].source_kind == "edr"


def test_sqlite_cross_tenant_same_dedup_key_both_persist_no_leak(tmp_path):
    path = str(tmp_path / "rwe.sqlite")
    store = SQLiteRuntimeWorkloadEvidenceStore(path)
    # Two tenants, IDENTICAL logical key (same account/workload/dedup_key).
    store.put_batch([_signal(tenant="tenant-a")])
    store.put_batch([_signal(tenant="tenant-b")])
    a = store.list_for_tenant("tenant-a")
    b = store.list_for_tenant("tenant-b")
    assert len(a) == 1 and len(b) == 1  # neither dropped
    assert a[0].tenant_id == "tenant-a"
    assert b[0].tenant_id == "tenant-b"  # no cross-tenant leak


def test_sqlite_dedup_within_tenant(tmp_path):
    path = str(tmp_path / "rwe.sqlite")
    store = SQLiteRuntimeWorkloadEvidenceStore(path)
    assert store.put_batch([_signal(dedup="a"), _signal(dedup="a"), _signal(dedup="b")]) == 2


def _writer(path: str, tenant: str, dedup_keys: list[str]) -> None:
    store = SQLiteRuntimeWorkloadEvidenceStore(path)
    for key in dedup_keys:
        store.put_batch([_signal(tenant=tenant, dedup=key)])


def test_sqlite_cross_process_writers_do_not_duplicate_or_corrupt(tmp_path):
    path = str(tmp_path / "rwe.sqlite")
    SQLiteRuntimeWorkloadEvidenceStore(path)  # create schema first
    keys = [f"evt-{i}" for i in range(25)]
    ctx = mp.get_context("spawn")
    procs = [ctx.Process(target=_writer, args=(path, "tenant-a", keys)) for _ in range(3)]
    for p in procs:
        p.start()
    for p in procs:
        p.join(30)
        assert p.exitcode == 0
    rows = SQLiteRuntimeWorkloadEvidenceStore(path).list_for_tenant("tenant-a", limit=1000)
    # 3 processes each wrote the SAME 25 dedup keys -> exactly 25 unique rows.
    assert len(rows) == 25
    assert len({r.dedup_key for r in rows}) == 25


# ── Postgres: real backend ───────────────────────────────────────────────────


@pytest.fixture
def pg_store():
    assert _PG_URL
    table = f"runtime_workload_evidence_test_{uuid.uuid4().hex[:8]}"
    store = PostgresRuntimeWorkloadEvidenceStore(_PG_URL, table=table)
    try:
        yield store
    finally:
        store.drop_table()


@_requires_pg
def test_postgres_roundtrip_and_dedup(pg_store):
    assert pg_store.put_batch([_signal(), _signal()]) == 1
    assert pg_store.put_batch([_signal()]) == 0
    rows = pg_store.list_for_tenant("tenant-a")
    assert len(rows) == 1
    assert rows[0].signal_type.value == "ioc_detection"
    assert rows[0].evidence.get("ioc_type") == "domain"


@_requires_pg
def test_postgres_cross_tenant_same_key_both_persist_no_leak(pg_store):
    pg_store.put_batch([_signal(tenant="tenant-a")])
    pg_store.put_batch([_signal(tenant="tenant-b")])
    a = pg_store.list_for_tenant("tenant-a")
    b = pg_store.list_for_tenant("tenant-b")
    assert len(a) == 1 and len(b) == 1
    assert a[0].tenant_id == "tenant-a"
    assert b[0].tenant_id == "tenant-b"
    # a tenant-a query must never surface tenant-b rows
    assert all(r.tenant_id == "tenant-a" for r in a)


def _pg_writer(dsn: str, table: str, tenant: str, dedup_keys: list[str]) -> None:
    store = PostgresRuntimeWorkloadEvidenceStore(dsn, table=table)
    for key in dedup_keys:
        store.put_batch([_signal(tenant=tenant, dedup=key)])


@_requires_pg
def test_postgres_cross_process_writers_do_not_duplicate(pg_store):
    assert _PG_URL
    keys = [f"evt-{i}" for i in range(20)]
    ctx = mp.get_context("spawn")
    procs = [ctx.Process(target=_pg_writer, args=(_PG_URL, pg_store.table, "tenant-a", keys)) for _ in range(3)]
    for p in procs:
        p.start()
    for p in procs:
        p.join(30)
        assert p.exitcode == 0
    rows = pg_store.list_for_tenant("tenant-a", limit=1000)
    assert len(rows) == 20
    assert len({r.dedup_key for r in rows}) == 20
