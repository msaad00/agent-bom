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
        # Keep fake inserts inside the production TTL window. A fixed wall-clock
        # date made every reservation expire once CI crossed the next UTC day.
        self.now = datetime.now(timezone.utc)

    def __enter__(self) -> _FakeConn:
        return self

    def __exit__(self, *exc: object) -> None:
        return None

    def commit(self) -> None:
        return None

    def rollback(self) -> None:
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
            if "reservation_owner, lease_expires_at" in low:
                endpoint, tenant_id, source_id, key, request_hash, response_json, owner, *lease = params
                created_at = self.now.isoformat()
                lease_expires_at = (self.now + timedelta(seconds=int(lease[0]))).isoformat() if lease else ""
            else:
                endpoint, tenant_id, source_id, key, request_hash, response_json, created_at = params
                owner = ""
                lease_expires_at = ""
            primary_key = (endpoint, tenant_id, source_id, key)
            if "do nothing" in low and primary_key in self._table:
                return _FakeCursor()
            self._table[(endpoint, tenant_id, source_id, key)] = {
                "request_hash": request_hash,
                "response_json": response_json,
                "created_at": created_at,
                "reservation_owner": owner,
                "lease_expires_at": lease_expires_at,
            }
            if "returning response_json, request_hash" in low:
                return _FakeCursor([(response_json, request_hash)])
            cur = _FakeCursor()
            cur.rowcount = 1
            return cur

        if low.startswith("select request_hash, reservation_owner") and "from idempotency_keys" in low:
            endpoint, tenant_id, source_id, key = params
            rec = self._table.get((endpoint, tenant_id, source_id, key))
            if rec is None:
                return _FakeCursor()
            return _FakeCursor([(rec["request_hash"], rec.get("reservation_owner", ""))])

        if low.startswith("select response_json, request_hash") and "from idempotency_keys" in low:
            endpoint, tenant_id, source_id, key = params
            rec = self._table.get((endpoint, tenant_id, source_id, key))
            if rec is None:
                return _FakeCursor()
            if "created_at" in low:
                return _FakeCursor(
                    [
                        (
                            rec["response_json"],
                            rec["request_hash"],
                            rec["created_at"],
                            rec.get("reservation_owner", ""),
                            rec.get("lease_expires_at", ""),
                        )
                    ]
                )
            return _FakeCursor([(rec["response_json"], rec["request_hash"])])

        if low.startswith("update idempotency_keys set created_at"):
            owner = params[0]
            offset = 1
            lease_seconds = 0
            if "lease_expires_at = to_char" in low:
                lease_seconds = int(params[offset])
                offset += 1
            endpoint, tenant_id, source_id, key, fallback_lease_seconds = params[offset:]
            rec = self._table.get((endpoint, tenant_id, source_id, key))
            if rec is None:
                return _FakeCursor()
            response = json.loads(rec["response_json"])
            expires_at = rec.get("lease_expires_at", "")
            if expires_at:
                expired = datetime.fromisoformat(expires_at) <= self.now
            else:
                created = datetime.fromisoformat(rec["created_at"])
                expired = created <= self.now - timedelta(seconds=int(fallback_lease_seconds))
            if response.get("committed") is not False or not expired:
                return _FakeCursor()
            rec["created_at"] = self.now.isoformat()
            rec["reservation_owner"] = owner
            rec["lease_expires_at"] = (self.now + timedelta(seconds=lease_seconds)).isoformat() if lease_seconds else ""
            return _FakeCursor([(rec["response_json"], rec["request_hash"])])

        if low.startswith("update idempotency_keys set lease_expires_at"):
            lease_seconds, endpoint, tenant_id, source_id, key, request_hash, owner = params
            rec = self._table.get((endpoint, tenant_id, source_id, key))
            matched = rec is not None and rec["request_hash"] == request_hash and rec.get("reservation_owner", "") == owner
            if matched:
                rec["lease_expires_at"] = (self.now + timedelta(seconds=int(lease_seconds))).isoformat()
            cur = _FakeCursor()
            cur.rowcount = int(matched)
            return cur

        if low.startswith("update idempotency_keys set response_json"):
            response_json, endpoint, tenant_id, source_id, key, request_hash, owner = params
            rec = self._table.get((endpoint, tenant_id, source_id, key))
            matched = rec is not None and rec["request_hash"] == request_hash and rec.get("reservation_owner", "") == owner
            if matched:
                rec.update(
                    response_json=response_json,
                    created_at=self.now.isoformat(),
                    reservation_owner="",
                    lease_expires_at="",
                )
            cur = _FakeCursor()
            cur.rowcount = int(matched)
            return cur

        if low.startswith("update idempotency_keys set request_hash"):
            request_hash, response_json, created_at, new_owner, endpoint, tenant_id, source_id, key, owner = params
            rec = self._table.get((endpoint, tenant_id, source_id, key))
            matched = rec is not None and rec.get("reservation_owner", "") == owner
            if matched:
                rec.update(
                    request_hash=request_hash,
                    response_json=response_json,
                    created_at=created_at,
                    reservation_owner=new_owner,
                    lease_expires_at="",
                )
            cur = _FakeCursor()
            cur.rowcount = int(matched)
            return cur

        if low.startswith("delete from idempotency_keys where created_at"):
            (cutoff,) = params
            stale = [pk for pk, rec in self._table.items() if rec["created_at"] < cutoff]
            for pk in stale:
                self._table.pop(pk, None)
            cur = _FakeCursor()
            cur.rowcount = len(stale)
            return cur

        if low.startswith("delete from idempotency_keys"):
            endpoint, tenant_id, source_id, key, request_hash, _same_hash, owner, _same_owner = params
            primary_key = (endpoint, tenant_id, source_id, key)
            record = self._table.get(primary_key)
            deleted = (
                record is not None
                and (not request_hash or record["request_hash"] == request_hash)
                and (not owner or record.get("reservation_owner", "") == owner)
            )
            if deleted:
                self._table.pop(primary_key, None)
            cur = _FakeCursor()
            cur.rowcount = int(deleted)
            return cur

        raise AssertionError(f"unexpected SQL in fake conn: {sql!r}")


class _FakePool:
    """Pool that hands out one shared connection so DDL is inspectable."""

    def __init__(self, table: dict[tuple, dict] | None = None) -> None:
        self.table = table if table is not None else {}
        self.conn = _FakeConn(self.table)

    def connection(self) -> _FakeConn:
        return self.conn


class _SingleCheckoutPool(_FakePool):
    """A deterministic one-slot pool that rejects nested checkouts."""

    class _Checkout:
        def __init__(self, pool: _SingleCheckoutPool) -> None:
            self._pool = pool

        def __enter__(self) -> _FakeConn:
            if self._pool.active:
                raise RuntimeError("connection pool exhausted")
            self._pool.active += 1
            self._pool.max_active = max(self._pool.max_active, self._pool.active)
            return self._pool.conn

        def __exit__(self, *_exc: object) -> None:
            self._pool.active -= 1

    def __init__(self, table: dict[tuple, dict] | None = None) -> None:
        super().__init__(table)
        self.active = 0
        self.max_active = 0

    def connection(self) -> _Checkout:
        return self._Checkout(self)


class _FinalizationRaceConn(_FakeConn):
    """Inject an owner change immediately before the final receipt update."""

    def __init__(self, table: dict[tuple, dict]) -> None:
        super().__init__(table)
        self.steal_before_finalize = False

    def execute(self, sql: str, params: tuple | None = None) -> _FakeCursor:
        low = " ".join(sql.split()).lower()
        if self.steal_before_finalize and low.startswith("update idempotency_keys set response_json"):
            assert params is not None
            _response, endpoint, tenant_id, source_id, key, _request_hash, _owner = params
            self._table[(endpoint, tenant_id, source_id, key)]["reservation_owner"] = "owner-b"
            self.steal_before_finalize = False
        return super().execute(sql, params)


class _FinalizationRacePool(_FakePool):
    def __init__(self, table: dict[tuple, dict] | None = None) -> None:
        self.table = table if table is not None else {}
        self.conn = _FinalizationRaceConn(self.table)


def _store(pool: _FakePool | None = None, *, fence_pool: _FakePool | None = None, ttl_hours: int | None = None):
    main = pool or _FakePool()
    fence = fence_pool or _FakePool(main.table)
    return PostgresIdempotencyStore(pool=main, fence_pool=fence, ttl_hours=ttl_hours)


# ── RLS / DDL wiring ─────────────────────────────────────────────────────────


def test_postgres_injected_pool_requires_distinct_commit_fence() -> None:
    pool = _FakePool()
    with pytest.raises(ValueError, match="distinct fence_pool"):
        PostgresIdempotencyStore(pool=pool)
    with pytest.raises(ValueError, match="must be distinct"):
        PostgresIdempotencyStore(pool=pool, fence_pool=pool)


def test_postgres_idempotency_table_is_tenant_scoped_and_rls_registered(monkeypatch):
    """The table must carry tenant_id + be registered with _ensure_tenant_rls."""
    calls: list[tuple[str, str]] = []
    monkeypatch.setattr(idem_mod, "_ensure_tenant_rls", lambda conn, table, column: calls.append((table, column)))

    pool = _FakePool()
    _store(pool)

    # Registered under the shared FORCE ROW LEVEL SECURITY backstop, keyed on tenant_id.
    assert ("idempotency_keys", "tenant_id") in calls

    # The CREATE TABLE carries tenant_id and the four-part primary key.
    ddl = "\n".join(sql for sql, _ in pool.conn.executed).lower()
    assert "create table if not exists idempotency_keys" in ddl
    assert "tenant_id text not null" in ddl
    assert "primary key (endpoint, tenant_id, source_id, idempotency_key)" in ddl


# ── Replay / conflict / TTL contract (mirrors the SQLite backend) ────────────


def test_postgres_idempotency_replays_same_payload_and_rejects_mismatch():
    store = _store()
    request_hash = idempotency_request_fingerprint({"idempotency_key": "k-1", "value": 1})
    mismatch_hash = idempotency_request_fingerprint({"idempotency_key": "k-1", "value": 2})

    store.put("/v1/findings/bulk", "tenant-a", "source-a", "k-1", {"ok": True}, request_hash=request_hash)

    assert store.get("/v1/findings/bulk", "tenant-a", "source-a", "k-1", request_hash=request_hash) == {"ok": True}
    with pytest.raises(IdempotencyConflictError):
        store.get("/v1/findings/bulk", "tenant-a", "source-a", "k-1", request_hash=mismatch_hash)


def test_postgres_idempotency_miss_returns_none():
    store = _store()
    assert store.get("/v1/findings/bulk", "tenant-a", "source-a", "absent") is None


def test_postgres_idempotency_claim_has_one_winner_and_can_release() -> None:
    store = _store()
    request_hash = idempotency_request_fingerprint({"value": 1})

    first, first_acquired = store.claim("/v1/scan", "tenant-a", "source-a", "key", {"job_id": "stable"}, request_hash=request_hash)
    second, second_acquired = store.claim("/v1/scan", "tenant-a", "source-a", "key", {"job_id": "other"}, request_hash=request_hash)

    assert first == second == {"job_id": "stable"}
    assert first_acquired is True
    assert second_acquired is False
    assert store.release("/v1/scan", "tenant-a", "source-a", "key", request_hash=request_hash) is True
    assert store.get("/v1/scan", "tenant-a", "source-a", "key") is None


def test_postgres_idempotency_claim_reclaims_expired_uncommitted_reservation() -> None:
    pool = _FakePool()
    store = _store(pool)
    request_hash = idempotency_request_fingerprint({"value": 1})
    args = ("/v1/scan", "tenant-a", "source-a", "key")
    store.claim(
        *args,
        {"job_id": "stable", "committed": False},
        request_hash=request_hash,
        reservation_lease_seconds=30,
    )
    pool.table[args]["created_at"] = (pool.conn.now - timedelta(seconds=31)).isoformat()

    recovered, acquired = store.claim(
        *args,
        {"job_id": "stable", "committed": False},
        request_hash=request_hash,
        reservation_lease_seconds=30,
    )

    assert acquired is True
    assert recovered == {"job_id": "stable", "committed": False}


def test_postgres_idempotency_lease_fences_stale_owner_after_takeover() -> None:
    pool = _FakePool()
    store = _store(pool)
    request_hash = idempotency_request_fingerprint({"value": 1})
    args = ("/v1/results/push", "tenant-a", "source-a", "key")

    _receipt, acquired = store.claim(
        *args,
        {"job_id": "stable", "committed": False},
        request_hash=request_hash,
        reservation_lease_seconds=30,
        owner_token="owner-a",
    )
    assert acquired is True
    assert (
        store.heartbeat(
            *args,
            request_hash=request_hash,
            owner_token="owner-a",
            reservation_lease_seconds=30,
        )
        is True
    )
    pool.table[args]["lease_expires_at"] = (pool.conn.now - timedelta(seconds=1)).isoformat()

    _takeover, owner_b_acquired = store.claim(
        *args,
        {"job_id": "changed", "committed": False},
        request_hash=request_hash,
        reservation_lease_seconds=30,
        owner_token="owner-b",
    )
    assert owner_b_acquired is True
    assert (
        store.put(
            *args,
            {"job_id": "stale", "committed": True},
            request_hash=request_hash,
            owner_token="owner-a",
        )
        is False
    )
    assert store.release(*args, request_hash=request_hash, owner_token="owner-a") is False
    assert (
        store.put(
            *args,
            {"job_id": "stable", "committed": True},
            request_hash=request_hash,
            owner_token="owner-b",
        )
        is True
    )


def test_postgres_commit_claim_releases_pool_checkout_while_action_runs() -> None:
    """A one-slot pool must remain available to the durable commit callback."""

    pool = _SingleCheckoutPool()
    fence_pool = _SingleCheckoutPool(pool.table)
    store = PostgresIdempotencyStore(pool=pool, fence_pool=fence_pool)
    request_hash = idempotency_request_fingerprint({"value": 1})
    args = ("/v1/results/push", "tenant-a", "source-a", "key")
    _receipt, acquired = store.claim(
        *args,
        {"job_id": "stable", "committed": False},
        request_hash=request_hash,
        reservation_lease_seconds=30,
        owner_token="owner-a",
    )
    assert acquired is True

    def _action_using_shared_pool() -> str:
        with pool.connection():
            return "persisted"

    result = store.commit_claim(
        *args,
        {"job_id": "stable", "committed": True},
        action=_action_using_shared_pool,
        request_hash=request_hash,
        owner_token="owner-a",
    )

    assert result == "persisted"
    assert pool.max_active == 1
    assert fence_pool.max_active == 1
    assert store.get(*args, request_hash=request_hash) == {"job_id": "stable", "committed": True}


def test_postgres_commit_claim_failure_can_be_compensated_and_retried() -> None:
    pool = _FakePool()
    store = _store(pool)
    request_hash = idempotency_request_fingerprint({"value": 1})
    args = ("/v1/results/push", "tenant-a", "source-a", "retry-key")
    store.claim(
        *args,
        {"job_id": "stable", "committed": False},
        request_hash=request_hash,
        reservation_lease_seconds=30,
        owner_token="owner-a",
    )

    with pytest.raises(RuntimeError, match="durable action failed"):
        store.commit_claim(
            *args,
            {"job_id": "stable", "committed": True},
            action=lambda: (_ for _ in ()).throw(RuntimeError("durable action failed")),
            request_hash=request_hash,
            owner_token="owner-a",
        )

    # Route-level compensation releases only the matching owner; a retry can
    # then reclaim the same deterministic job/evidence identity.
    assert store.release(*args, request_hash=request_hash, owner_token="owner-a") is True
    _receipt, acquired = store.claim(
        *args,
        {"job_id": "stable", "committed": False},
        request_hash=request_hash,
        reservation_lease_seconds=30,
        owner_token="owner-b",
    )
    assert acquired is True
    assert (
        store.commit_claim(
            *args,
            {"job_id": "stable", "committed": True},
            action=lambda: "recovered",
            request_hash=request_hash,
            owner_token="owner-b",
        )
        == "recovered"
    )


def test_postgres_commit_claim_rejects_stale_owner_before_action() -> None:
    pool = _FakePool()
    store = _store(pool)
    request_hash = idempotency_request_fingerprint({"value": 1})
    args = ("/v1/results/push", "tenant-a", "source-a", "stale-key")
    store.claim(
        *args,
        {"job_id": "stable", "committed": False},
        request_hash=request_hash,
        reservation_lease_seconds=30,
        owner_token="owner-a",
    )
    pool.table[args]["lease_expires_at"] = (pool.conn.now - timedelta(seconds=1)).isoformat()
    _receipt, acquired = store.claim(
        *args,
        {"job_id": "stable", "committed": False},
        request_hash=request_hash,
        reservation_lease_seconds=30,
        owner_token="owner-b",
    )
    assert acquired is True
    action_ran = False

    def _stale_action() -> None:
        nonlocal action_ran
        action_ran = True

    with pytest.raises(IdempotencyConflictError):
        store.commit_claim(
            *args,
            {"job_id": "stable", "committed": True},
            action=_stale_action,
            request_hash=request_hash,
            owner_token="owner-a",
        )
    assert action_ran is False


def test_postgres_commit_claim_rejects_owner_change_at_finalization() -> None:
    pool = _FinalizationRacePool()
    fence_pool = _FinalizationRacePool(pool.table)
    store = _store(pool, fence_pool=fence_pool)
    request_hash = idempotency_request_fingerprint({"value": 1})
    args = ("/v1/results/push", "tenant-a", "source-a", "finalize-race")
    store.claim(
        *args,
        {"job_id": "stable", "committed": False},
        request_hash=request_hash,
        reservation_lease_seconds=30,
        owner_token="owner-a",
    )
    fence_pool.conn.steal_before_finalize = True

    with pytest.raises(IdempotencyConflictError):
        store.commit_claim(
            *args,
            {"job_id": "stable", "committed": True},
            action=lambda: "persisted",
            request_hash=request_hash,
            owner_token="owner-a",
        )

    assert store.get(*args, request_hash=request_hash) == {"job_id": "stable", "committed": False}


def test_postgres_ownerless_writer_cannot_finalize_owned_reservation() -> None:
    store = _store()
    request_hash = idempotency_request_fingerprint({"value": 1})
    args = ("/v1/results/push", "tenant-a", "source-a", "key")
    store.claim(
        *args,
        {"job_id": "stable", "committed": False},
        request_hash=request_hash,
        reservation_lease_seconds=30,
        owner_token="owner-a",
    )

    assert store.put(*args, {"job_id": "stable", "committed": True}, request_hash=request_hash) is False
    assert store.get(*args, request_hash=request_hash) == {"job_id": "stable", "committed": False}


def test_postgres_fresh_ownerless_reservation_is_not_reclaimed_immediately() -> None:
    pool = _FakePool()
    store = _store(pool)
    request_hash = idempotency_request_fingerprint({"value": 1})
    args = ("/v1/results/push", "tenant-a", "source-a", "key")

    first, acquired = store.claim(
        *args,
        {"job_id": "stable", "committed": False},
        request_hash=request_hash,
        reservation_lease_seconds=30,
    )
    second, reclaimed = store.claim(
        *args,
        {"job_id": "changed", "committed": False},
        request_hash=request_hash,
        reservation_lease_seconds=30,
        owner_token="new-owner",
    )

    assert acquired is True
    assert reclaimed is False
    assert first == second == {"job_id": "stable", "committed": False}


def test_postgres_idempotency_leases_use_database_clock() -> None:
    pool = _FakePool()
    fence_pool = _FakePool(pool.table)
    store = _store(pool, fence_pool=fence_pool)
    request_hash = idempotency_request_fingerprint({"value": 1})
    args = ("/v1/results/push", "tenant-a", "source-a", "key")

    store.claim(
        *args,
        {"job_id": "stable", "committed": False},
        request_hash=request_hash,
        reservation_lease_seconds=30,
        owner_token="owner-a",
    )
    store.heartbeat(
        *args,
        request_hash=request_hash,
        owner_token="owner-a",
        reservation_lease_seconds=30,
    )

    lease_sql = "\n".join(sql for sql, _params in fence_pool.conn.executed if "lease_expires_at" in sql).lower()
    assert "now() at time zone 'utc'" in lease_sql
    assert "interval '1 second'" in lease_sql


def test_postgres_idempotency_requires_v2_schema_marker(monkeypatch) -> None:
    required: list[tuple[str, int]] = []
    monkeypatch.setattr(
        idem_mod,
        "ensure_postgres_schema_version",
        lambda _conn, component, version: required.append((component, version)) or False,
    )

    _store()

    assert required == [("idempotency", 2)]


def test_postgres_idempotency_isolates_by_tenant_key():
    """A key under tenant-a must not resolve for tenant-b (composite PK)."""
    store = _store()
    store.put("/v1/findings/bulk", "tenant-a", "s", "k", {"who": "a"})
    assert store.get("/v1/findings/bulk", "tenant-b", "s", "k") is None
    assert store.get("/v1/findings/bulk", "tenant-a", "s", "k") == {"who": "a"}


def test_postgres_idempotency_put_prunes_expired_keys():
    pool = _FakePool()
    store = _store(pool, ttl_hours=24)

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
