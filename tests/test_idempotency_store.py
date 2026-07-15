"""Tests for retry-safe idempotency storage."""

from __future__ import annotations

import pytest

from agent_bom.api.idempotency_store import (
    IdempotencyConflictError,
    InMemoryIdempotencyStore,
    SQLiteIdempotencyStore,
    idempotency_request_fingerprint,
)


@pytest.mark.parametrize("store_factory", [InMemoryIdempotencyStore])
def test_idempotency_store_replays_same_payload_and_rejects_mismatch(store_factory):
    store = store_factory()
    request_hash = idempotency_request_fingerprint({"idempotency_key": "k-1", "value": 1})
    mismatch_hash = idempotency_request_fingerprint({"idempotency_key": "k-1", "value": 2})

    store.put("/v1/test", "tenant-a", "source-a", "k-1", {"ok": True}, request_hash=request_hash)

    assert store.get("/v1/test", "tenant-a", "source-a", "k-1", request_hash=request_hash) == {"ok": True}
    with pytest.raises(IdempotencyConflictError):
        store.get("/v1/test", "tenant-a", "source-a", "k-1", request_hash=mismatch_hash)


def test_sqlite_idempotency_store_replays_same_payload_and_rejects_mismatch(tmp_path):
    store = SQLiteIdempotencyStore(str(tmp_path / "idempotency.db"))
    request_hash = idempotency_request_fingerprint({"idempotency_key": "k-1", "value": 1})
    mismatch_hash = idempotency_request_fingerprint({"idempotency_key": "k-1", "value": 2})

    store.put("/v1/test", "tenant-a", "source-a", "k-1", {"ok": True}, request_hash=request_hash)

    assert store.get("/v1/test", "tenant-a", "source-a", "k-1", request_hash=request_hash) == {"ok": True}
    with pytest.raises(IdempotencyConflictError):
        store.get("/v1/test", "tenant-a", "source-a", "k-1", request_hash=mismatch_hash)


# ── TTL prune on put (P1-6) ──────────────────────────────────────────────────


def test_sqlite_idempotency_put_prunes_expired_keys(tmp_path):
    """Old idempotency rows must be pruned on write so the table cannot grow unbounded."""
    from datetime import datetime, timedelta, timezone

    store = SQLiteIdempotencyStore(str(tmp_path / "idem.db"), ttl_hours=24)
    # Seed a stale row (created 48h ago), bypassing put() so its timestamp is old.
    stale_ts = (datetime.now(timezone.utc) - timedelta(hours=48)).isoformat()
    store._conn.execute(  # noqa: SLF001 - test seeds a pre-aged row directly
        """INSERT INTO idempotency_keys
           (endpoint, tenant_id, source_id, idempotency_key, request_hash, response_json, created_at)
           VALUES (?, ?, ?, ?, ?, ?, ?)""",
        ("/v1/test", "t", "s", "old-key", "", "{}", stale_ts),
    )
    store._conn.commit()  # noqa: SLF001

    # A fresh put triggers the prune sweep.
    store.put("/v1/test", "t", "s", "new-key", {"ok": True})

    assert store.get("/v1/test", "t", "s", "old-key") is None
    assert store.get("/v1/test", "t", "s", "new-key") == {"ok": True}
    remaining = store._conn.execute("SELECT COUNT(*) FROM idempotency_keys").fetchone()[0]  # noqa: SLF001
    assert remaining == 1


def test_sqlite_idempotency_put_keeps_fresh_keys(tmp_path):
    store = SQLiteIdempotencyStore(str(tmp_path / "idem.db"), ttl_hours=24)
    store.put("/v1/test", "t", "s", "k1", {"n": 1})
    store.put("/v1/test", "t", "s", "k2", {"n": 2})
    assert store.get("/v1/test", "t", "s", "k1") == {"n": 1}
    assert store.get("/v1/test", "t", "s", "k2") == {"n": 2}
