"""Persistence + isolation tests for the runtime workload-evidence store.

Covers both backends: SQLite (restart-safe, cross-process concurrency) and — when
``AGENT_BOM_POSTGRES_URL`` is set — real Postgres (roundtrip, dedup, cross-tenant
isolation, cross-process concurrency). Tenant isolation and dedup are the
security-critical properties (issue #4158).
"""

from __future__ import annotations

import json
import multiprocessing as mp
import os
import sqlite3
import uuid

import pytest

from agent_bom.cloud import runtime_workload_evidence_store as store_module
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
    with sqlite3.connect(path) as connection:
        marker = connection.execute(
            "SELECT version FROM control_plane_schema_versions WHERE component = ?",
            ("runtime_workload_evidence",),
        ).fetchone()
    assert marker == (2,)


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


def test_sqlite_orders_fractional_utc_timestamps_chronologically(tmp_path):
    path = str(tmp_path / "rwe.sqlite")
    store = SQLiteRuntimeWorkloadEvidenceStore(path)
    store.put_batch(
        [
            _signal(dedup="zero-fraction", observed="2026-07-18T12:00:00Z"),
            _signal(dedup="later-fraction", observed="2026-07-18T12:00:00.100000Z"),
        ]
    )

    rows = store.list_for_tenant("tenant-a")
    assert [row.dedup_key for row in rows] == ["later-fraction", "zero-fraction"]
    assert [row.observed_at for row in rows] == [
        "2026-07-18T12:00:00.100000Z",
        "2026-07-18T12:00:00.000000Z",
    ]


def test_sqlite_upgrade_normalizes_legacy_timestamps_and_scrubs_payload(tmp_path):
    path = str(tmp_path / "rwe.sqlite")
    store = SQLiteRuntimeWorkloadEvidenceStore(path)
    store.put_batch(
        [
            _signal(dedup="zero-fraction", observed="2026-07-18T12:00:00Z"),
            _signal(dedup="later-fraction", observed="2026-07-18T12:00:00.100000Z"),
        ]
    )
    with sqlite3.connect(path) as connection:
        rows = connection.execute("SELECT dedup_key, payload_json FROM runtime_workload_evidence").fetchall()
        payloads = {dedup: json.loads(payload) for dedup, payload in rows}
        payloads["zero-fraction"]["observed_at"] = "2026-07-18T12:00:00Z"
        payloads["zero-fraction"]["title"] = "Authorization: Bearer legacy-title-secret"
        payloads["zero-fraction"]["evidence"] = {
            "ioc_type": "domain",
            "password": "legacy-password-secret",
        }
        payloads["later-fraction"]["observed_at"] = "2026-07-18T12:00:00.100000Z"
        connection.execute(
            "UPDATE runtime_workload_evidence SET observed_at = ?, payload_json = ? WHERE dedup_key = ?",
            ("2026-07-18T12:00:00Z", json.dumps(payloads["zero-fraction"]), "zero-fraction"),
        )
        connection.execute(
            "UPDATE runtime_workload_evidence SET observed_at = ?, payload_json = ? WHERE dedup_key = ?",
            ("2026-07-18T12:00:00.100000Z", json.dumps(payloads["later-fraction"]), "later-fraction"),
        )
        connection.execute(
            "UPDATE control_plane_schema_versions SET version = 1 WHERE component = ?",
            ("runtime_workload_evidence",),
        )

    reopened = SQLiteRuntimeWorkloadEvidenceStore(path)
    rows = reopened.list_for_tenant("tenant-a")
    assert [row.dedup_key for row in rows] == ["later-fraction", "zero-fraction"]
    assert rows[1].title == "<redacted>"
    assert rows[1].evidence == {"ioc_type": "domain"}
    with sqlite3.connect(path) as connection:
        stored = connection.execute(
            "SELECT observed_at, payload_json FROM runtime_workload_evidence WHERE dedup_key = ?",
            ("zero-fraction",),
        ).fetchone()
        marker = connection.execute(
            "SELECT version FROM control_plane_schema_versions WHERE component = ?",
            ("runtime_workload_evidence",),
        ).fetchone()
    assert stored is not None
    assert stored[0] == "2026-07-18T12:00:00.000000Z"
    assert "legacy-password-secret" not in stored[1]
    assert "legacy-title-secret" not in stored[1]
    assert marker == (2,)


def test_sqlite_upgrade_pages_without_skipping_rows(tmp_path, monkeypatch):
    path = str(tmp_path / "rwe.sqlite")
    store = SQLiteRuntimeWorkloadEvidenceStore(path)
    store.put_batch([_signal(dedup=f"event-{index}") for index in range(5)])
    with sqlite3.connect(path) as connection:
        connection.execute(
            "UPDATE control_plane_schema_versions SET version = 1 WHERE component = ?",
            ("runtime_workload_evidence",),
        )
        rows = connection.execute("SELECT rowid, payload_json FROM runtime_workload_evidence").fetchall()
        for rowid, raw_payload in rows:
            payload = json.loads(raw_payload)
            payload["observed_at"] = "2026-07-18T12:00:00Z"
            payload["title"] = f"legacy-{rowid}"
            payload["evidence"] = {"ioc_type": "domain"}
            connection.execute(
                "UPDATE runtime_workload_evidence SET observed_at = ?, payload_json = ? WHERE rowid = ?",
                ("2026-07-18T12:00:00Z", json.dumps(payload), rowid),
            )

    monkeypatch.setattr(store_module, "_SQLITE_MIGRATION_PAGE_SIZE", 2)
    migrated = SQLiteRuntimeWorkloadEvidenceStore(path).list_for_tenant("tenant-a")

    assert len(migrated) == 5
    assert all(signal.observed_at == "2026-07-18T12:00:00.000000Z" for signal in migrated)
    assert all(signal.title.startswith("legacy-") for signal in migrated)
    assert all(signal.evidence == {"ioc_type": "domain"} for signal in migrated)


def test_sqlite_upgrade_uses_table_identity_and_drops_unknown_payload_fields(tmp_path):
    path = str(tmp_path / "rwe.sqlite")
    SQLiteRuntimeWorkloadEvidenceStore(path).put_batch([_signal(dedup="column-dedup")])
    with sqlite3.connect(path) as connection:
        raw_payload = connection.execute("SELECT payload_json FROM runtime_workload_evidence").fetchone()[0]
        payload = json.loads(raw_payload)
        payload.update(
            {
                "tenant_id": "poison-tenant",
                "provider": "gcp",
                "account_id": "poison-account",
                "workload_ref": "poison-workload",
                "workload_id": "poison-workload-id",
                "signal_type": "process_exec",
                "severity": "low",
                "source_id": "poison-source",
                "source_kind": "poison-kind",
                "dedup_key": "poison-dedup",
                "unknown_top_level": "must-not-survive",
            }
        )
        connection.execute("UPDATE runtime_workload_evidence SET payload_json = ?", (json.dumps(payload),))
        connection.execute(
            "UPDATE control_plane_schema_versions SET version = 1 WHERE component = ?",
            ("runtime_workload_evidence",),
        )

    migrated = SQLiteRuntimeWorkloadEvidenceStore(path).list_for_tenant("tenant-a")

    assert len(migrated) == 1
    assert migrated[0].tenant_id == "tenant-a"
    assert migrated[0].provider == "aws"
    assert migrated[0].account_id == "123456789012"
    assert migrated[0].workload_ref == "i-0abc"
    assert migrated[0].signal_type.value == "ioc_detection"
    assert migrated[0].severity == "high"
    assert migrated[0].source_id == "edr-1"
    assert migrated[0].source_kind == "edr"
    assert migrated[0].dedup_key == "column-dedup"
    with sqlite3.connect(path) as connection:
        stored_workload_id, stored_payload = connection.execute(
            "SELECT workload_id, payload_json FROM runtime_workload_evidence"
        ).fetchone()
    assert stored_workload_id == migrated[0].workload_id
    assert json.loads(stored_payload) == migrated[0].to_dict()
    assert "unknown_top_level" not in stored_payload


def test_sqlite_rejects_newer_schema_without_downgrading_marker(tmp_path):
    path = str(tmp_path / "rwe.sqlite")
    SQLiteRuntimeWorkloadEvidenceStore(path)
    with sqlite3.connect(path) as connection:
        connection.execute(
            "UPDATE control_plane_schema_versions SET version = 3 WHERE component = ?",
            ("runtime_workload_evidence",),
        )

    with pytest.raises(RuntimeError, match="newer than this agent-bom binary"):
        SQLiteRuntimeWorkloadEvidenceStore(path)

    with sqlite3.connect(path) as connection:
        marker = connection.execute(
            "SELECT version FROM control_plane_schema_versions WHERE component = ?",
            ("runtime_workload_evidence",),
        ).fetchone()
    assert marker == (3,)


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
