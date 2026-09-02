"""Postgres graph-correlation store parity without requiring a live server."""

from __future__ import annotations

import hashlib
import json
from dataclasses import replace

import pytest

from agent_bom.graph.correlation import CorrelationRunStatus, GraphCorrelationRun


class _Cursor:
    def __init__(self, rows=None):
        self.rows = rows or []

    def fetchone(self):
        return self.rows[0] if self.rows else None

    def fetchall(self):
        return self.rows


class _Conn:
    def __init__(self):
        self.rows: dict[tuple[str, str], tuple] = {}
        self.commits = 0

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def execute(self, sql, params=None):
        low = " ".join(sql.strip().lower().split())
        params = tuple(params or ())
        if low.startswith("select set_config"):
            return _Cursor()
        if low.startswith("select correlation_id") and "idempotency_key = %s" in low:
            tenant, key = params
            return _Cursor([row for row in self.rows.values() if row[1] == tenant and row[2] == key])
        if low.startswith("select correlation_id") and "correlation_id = %s" in low:
            tenant, correlation_id = params
            row = self.rows.get((tenant, correlation_id))
            return _Cursor([row] if row else [])
        if low.startswith("select correlation_id") and "order by created_at" in low:
            tenant, limit = params
            rows = sorted((row for row in self.rows.values() if row[1] == tenant), key=lambda row: (row[12], row[0]), reverse=True)
            return _Cursor(rows[:limit])
        if low.startswith("insert into graph_correlation_runs"):
            tenant, correlation_id, idem = params[1], params[0], params[2]
            if (tenant, correlation_id) in self.rows or any(row[1] == tenant and row[2] == idem for row in self.rows.values()):
                return _Cursor()
            self.rows[(tenant, correlation_id)] = params
            return _Cursor([params])
        if low.startswith("update graph_correlation_runs"):
            status, manifest, result_manifest, output, failure, started, completed, tenant, correlation_id, expected = params
            row = self.rows.get((tenant, correlation_id))
            if row is None or row[4] != expected:
                return _Cursor()
            updated = (
                row[0],
                row[1],
                row[2],
                row[3],
                status,
                row[5],
                row[6],
                row[7],
                manifest,
                result_manifest,
                output,
                failure,
                row[12],
                started,
                completed,
            )
            self.rows[(tenant, correlation_id)] = updated
            return _Cursor([updated])
        return _Cursor()

    def commit(self):
        self.commits += 1


class _Pool:
    def __init__(self, conn):
        self.conn = conn

    def connection(self):
        return self.conn


class _SnapshotConn:
    def __init__(self):
        self.snapshots = [
            ("scan-1", "acme", "scan", "2026-08-30T00:00:00+00:00"),
            ("corr-1", "acme", "correlation", "2026-08-30T00:01:00+00:00"),
            ("scan-other", "other", "scan", "2026-08-30T00:02:00+00:00"),
        ]

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def execute(self, sql, params=None):
        low = " ".join(sql.strip().lower().split())
        params = tuple(params or ())
        if low.startswith("select set_config"):
            return _Cursor()
        if low.startswith("select scan_id") and "from graph_snapshots" in low:
            assert "snapshot_kind = %s" in low
            tenant_id, snapshot_kind = params
            matches = [row for row in self.snapshots if row[1] == tenant_id and row[2] == snapshot_kind]
            matches.sort(key=lambda row: (row[3], row[0]), reverse=True)
            return _Cursor([(matches[0][0],)] if matches else [])
        return _Cursor()


def _store(monkeypatch):
    from agent_bom.api import postgres_graph

    conn = _Conn()
    monkeypatch.setattr(postgres_graph.PostgresGraphStore, "_init_tables", lambda self: None)
    monkeypatch.setattr(postgres_graph.PostgresGraphStore, "_init_optional_search_indexes", lambda self: None)
    return postgres_graph.PostgresGraphStore(pool=_Pool(conn)), conn


def _run(correlation_id="corr-1", tenant="acme", key="idem-1"):
    return GraphCorrelationRun(
        correlation_id=correlation_id,
        tenant_id=tenant,
        idempotency_key=key,
        name="reference lab",
        status=CorrelationRunStatus.PENDING,
        max_age_hours=168,
        allow_stale=False,
        input_manifest=[{"scan_id": "scan-1"}, {"scan_id": "scan-2"}],
        created_at="2026-08-30T00:00:00+00:00",
    )


def test_postgres_correlation_create_replay_list_and_update(monkeypatch) -> None:
    store, conn = _store(monkeypatch)
    created, was_created = store.create_correlation_run(_run())
    replay, replay_created = store.create_correlation_run(_run(correlation_id="corr-retry"))

    assert was_created is True
    assert replay_created is False
    assert replay.correlation_id == created.correlation_id == "corr-1"
    assert store.get_correlation_run(tenant_id="other", correlation_id="corr-1") is None
    assert store.get_correlation_run_by_idempotency_key(tenant_id="acme", idempotency_key="idem-1") == created
    assert store.get_correlation_run_by_idempotency_key(tenant_id="other", idempotency_key="idem-1") is None
    assert [run.correlation_id for run in store.list_correlation_runs(tenant_id="acme")] == ["corr-1"]

    running = store.update_correlation_run(
        tenant_id="acme",
        correlation_id="corr-1",
        status=CorrelationRunStatus.RUNNING,
        started_at="2026-08-30T00:01:00+00:00",
    )
    result_manifest = {"correlation_id": "corr-1"}
    manifest_sha256 = "sha256:" + hashlib.sha256(json.dumps(result_manifest, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    complete = store.update_correlation_run(
        tenant_id="acme",
        correlation_id="corr-1",
        status=CorrelationRunStatus.COMPLETE,
        manifest_sha256=manifest_sha256,
        result_manifest=result_manifest,
        output_scan_id="corr-1",
        completed_at="2026-08-30T00:02:00+00:00",
    )
    assert running.status is CorrelationRunStatus.RUNNING
    assert complete.status is CorrelationRunStatus.COMPLETE
    assert json.loads(conn.rows[("acme", "corr-1")][7]) == _run().input_manifest
    assert conn.commits == 3


def test_postgres_latest_snapshot_selection_is_scoped_by_kind_and_tenant(monkeypatch) -> None:
    from agent_bom.api import postgres_graph

    monkeypatch.setattr(postgres_graph.PostgresGraphStore, "_init_tables", lambda self: None)
    monkeypatch.setattr(postgres_graph.PostgresGraphStore, "_init_optional_search_indexes", lambda self: None)
    store = postgres_graph.PostgresGraphStore(pool=_Pool(_SnapshotConn()))

    assert store.latest_snapshot_id(tenant_id="acme") == "scan-1"
    assert store.latest_snapshot_id(tenant_id="acme", snapshot_kind="correlation") == "corr-1"
    assert store.latest_snapshot_id(tenant_id="other", snapshot_kind="correlation") == ""

    with pytest.raises(ValueError, match="snapshot_kind"):
        store.latest_snapshot_id(tenant_id="acme", snapshot_kind="inventory")


def test_postgres_correlation_rejects_idempotency_key_reuse_for_different_request(monkeypatch) -> None:
    store, _conn = _store(monkeypatch)
    store.create_correlation_run(_run())

    with pytest.raises(ValueError, match="different correlation request"):
        store.create_correlation_run(replace(_run(), max_age_hours=24))
