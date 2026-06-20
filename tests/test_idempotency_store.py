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
