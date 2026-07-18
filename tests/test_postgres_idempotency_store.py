"""Postgres-backed idempotency store: contract + tenant-RLS wiring.

A live Postgres is not required. These tests use a mock connection/pool that
records the store's DDL and implements just enough of the ``idempotency_keys``
SQL surface (INSERT ... ON CONFLICT / SELECT / prune DELETE) to exercise the
same replay / 409-mismatch / TTL-prune contract the SQLite backend guarantees,
plus assertions that the table is created tenant-scoped and registered under
``_ensure_tenant_rls`` like every other control-plane table.

The real-Postgres integration counterpart lives in test_postgres_integration.py
and is skipped when no live database is configured.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import pytest

from agent_bom.api import idempotency_store as idem_mod
from agent_bom.api.idempotency_store import (
    IdempotencyConflictError,
    PostgresIdempotencyStore,
    idempotency_request_fingerprint,
)


class _FakeCursor:
    def __init__(self, rows: list[tuple] | None = None) -> None:
        self._rows = rows or []
        self.rowcount = len(self._rows)

    def fetchone(self):
        return self._rows[0] if self._rows else None

    def fetchall(self):
        return self._rows


class _FakeConn:
    """Minimal in-memory stand-in for a psycopg connection.

    Stores ``idempotency_keys`` rows keyed by the four-part primary key and
    honours the exact statements the Postgres idempotency store issues.
    """

    def __init__(self, table: dict[tuple, dict]) -> None:
        self._table = table
        self.executed: list[tuple[str, object]] = []

    def __enter__(self) -> _FakeConn:
        return self

    def __exit__(self, *exc: object) -> None:
        return None

    def commit(self) -> None:
        return None

    def execute(self, sql: str, params: tuple | None = None) -> _FakeCursor:
        self.executed.append((sql, params))
        low = " ".join(sql.split()).lower()
        params = params or ()

        # Tenant-session setup (from _apply_tenant_session) and all DDL are no-ops.
        if low.startswith("select set_config"):
            return _FakeCursor()
        if (
            low.startswith("create table")
            or low.startswith("create index")
            or low.startswith("create or replace function")
            or low.startswith("alter table")
            or low.startswith("do $$")
        ):
            return _FakeCursor()
        if low.startswith("insert into control_plane_schema_versions"):
            return _FakeCursor()

        if low.startswith("insert into idempotency_keys"):
            endpoint, tenant_id, source_id, key, request_hash, response_json, created_at = params
            self._table[(endpoint, tenant_id, source_id, key)] = {
                "request_hash": request_hash,
                "response_json": response_json,
                "created_at": created_at,
            }
            return _FakeCursor()

        if low.startswith("select response_json, request_hash from idempotency_keys"):
            endpoint, tenant_id, source_id, key = params
            rec = self._table.get((endpoint, tenant_id, source_id, key))
            if rec is None:
                return _FakeCursor()
            return _FakeCursor([(rec["response_json"], rec["request_hash"])])

        if low.startswith("delete from idempotency_keys where created_at"):
            (cutoff,) = params
            stale = [pk for pk, rec in self._table.items() if rec["created_at"] < cutoff]
            for pk in stale:
                self._table.pop(pk, None)
            cur = _FakeCursor()
            cur.rowcount = len(stale)
            return cur

        raise AssertionError(f"unexpected SQL in fake conn: {sql!r}")


class _FakePool:
    """Pool that hands out one shared connection so DDL is inspectable."""

    def __init__(self) -> None:
        self.table: dict[tuple, dict] = {}
        self.conn = _FakeConn(self.table)

    def connection(self) -> _FakeConn:
        return self.conn


# ── RLS / DDL wiring ─────────────────────────────────────────────────────────


def test_postgres_idempotency_table_is_tenant_scoped_and_rls_registered(monkeypatch):
    """The table must carry tenant_id + be registered with _ensure_tenant_rls."""
    calls: list[tuple[str, str]] = []
    monkeypatch.setattr(idem_mod, "_ensure_tenant_rls", lambda conn, table, column: calls.append((table, column)))

    pool = _FakePool()
    PostgresIdempotencyStore(pool=pool)

    # Registered under the shared FORCE ROW LEVEL SECURITY backstop, keyed on tenant_id.
    assert ("idempotency_keys", "tenant_id") in calls

    # The CREATE TABLE carries tenant_id and the four-part primary key.
    ddl = "\n".join(sql for sql, _ in pool.conn.executed).lower()
    assert "create table if not exists idempotency_keys" in ddl
    assert "tenant_id text not null" in ddl
    assert "primary key (endpoint, tenant_id, source_id, idempotency_key)" in ddl


# ── Replay / conflict / TTL contract (mirrors the SQLite backend) ────────────


def test_postgres_idempotency_replays_same_payload_and_rejects_mismatch():
    store = PostgresIdempotencyStore(pool=_FakePool())
    request_hash = idempotency_request_fingerprint({"idempotency_key": "k-1", "value": 1})
    mismatch_hash = idempotency_request_fingerprint({"idempotency_key": "k-1", "value": 2})

    store.put("/v1/findings/bulk", "tenant-a", "source-a", "k-1", {"ok": True}, request_hash=request_hash)

    assert store.get("/v1/findings/bulk", "tenant-a", "source-a", "k-1", request_hash=request_hash) == {"ok": True}
    with pytest.raises(IdempotencyConflictError):
        store.get("/v1/findings/bulk", "tenant-a", "source-a", "k-1", request_hash=mismatch_hash)


def test_postgres_idempotency_miss_returns_none():
    store = PostgresIdempotencyStore(pool=_FakePool())
    assert store.get("/v1/findings/bulk", "tenant-a", "source-a", "absent") is None


def test_postgres_idempotency_isolates_by_tenant_key():
    """A key under tenant-a must not resolve for tenant-b (composite PK)."""
    store = PostgresIdempotencyStore(pool=_FakePool())
    store.put("/v1/findings/bulk", "tenant-a", "s", "k", {"who": "a"})
    assert store.get("/v1/findings/bulk", "tenant-b", "s", "k") is None
    assert store.get("/v1/findings/bulk", "tenant-a", "s", "k") == {"who": "a"}


def test_postgres_idempotency_put_prunes_expired_keys():
    pool = _FakePool()
    store = PostgresIdempotencyStore(pool=pool, ttl_hours=24)

    stale_ts = (datetime.now(timezone.utc) - timedelta(hours=48)).isoformat()
    pool.table[("/v1/findings/bulk", "t", "s", "old")] = {
        "request_hash": "",
        "response_json": json.dumps({}),
        "created_at": stale_ts,
    }

    store.put("/v1/findings/bulk", "t", "s", "new", {"ok": True})

    assert store.get("/v1/findings/bulk", "t", "s", "old") is None
    assert store.get("/v1/findings/bulk", "t", "s", "new") == {"ok": True}
    assert len(pool.table) == 1
