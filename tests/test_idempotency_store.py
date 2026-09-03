"""Tests for retry-safe idempotency storage."""

from __future__ import annotations

import multiprocessing
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from agent_bom.api.idempotency_store import (
    IdempotencyConflictError,
    InMemoryIdempotencyStore,
    SQLiteIdempotencyStore,
    idempotency_request_fingerprint,
)


def _append_effect(path: str, owner: str) -> None:
    with Path(path).open("a", encoding="utf-8") as stream:
        stream.write(f"{owner}\n")


def _sqlite_commit_owner_process(
    db_path: str,
    effects_path: str,
    request_hash: str,
    started: object,
    release: object,
    outcomes: object,
) -> None:
    store = SQLiteIdempotencyStore(db_path)
    args = ("/v1/results/push", "tenant-a", "source-a", "cross-process-key")

    def _action() -> str:
        _append_effect(effects_path, "owner-a")
        started.set()  # type: ignore[attr-defined]
        if not release.wait(5):  # type: ignore[attr-defined]
            raise RuntimeError("test release was not signalled")
        return "owner-a"

    try:
        store.commit_claim(
            *args,
            {"job_id": "stable", "committed": True},
            action=_action,
            request_hash=request_hash,
            owner_token="owner-a",
        )
        outcomes.put(("owner-a", "committed"))  # type: ignore[attr-defined]
    except Exception as exc:  # noqa: BLE001 - subprocess returns the stable exception class to the parent test
        outcomes.put(("owner-a", type(exc).__name__))  # type: ignore[attr-defined]


def _sqlite_commit_rival_process(
    db_path: str,
    effects_path: str,
    request_hash: str,
    started: object,
    attempting: object,
    outcomes: object,
) -> None:
    if not started.wait(5):  # type: ignore[attr-defined]
        outcomes.put(("owner-b", "owner-never-started"))  # type: ignore[attr-defined]
        return
    time.sleep(1.2)
    store = SQLiteIdempotencyStore(db_path)
    args = ("/v1/results/push", "tenant-a", "source-a", "cross-process-key")
    attempting.set()  # type: ignore[attr-defined]
    _receipt, acquired = store.claim(
        *args,
        {"job_id": "stable", "committed": False},
        request_hash=request_hash,
        reservation_lease_seconds=1,
        owner_token="owner-b",
    )
    if acquired:
        store.commit_claim(
            *args,
            {"job_id": "stable", "committed": True},
            action=lambda: _append_effect(effects_path, "owner-b"),
            request_hash=request_hash,
            owner_token="owner-b",
        )
    outcomes.put(("owner-b", acquired))  # type: ignore[attr-defined]


@pytest.mark.parametrize("store_factory", [InMemoryIdempotencyStore])
def test_idempotency_claim_is_atomic_for_concurrent_callers(store_factory):
    from concurrent.futures import ThreadPoolExecutor

    store = store_factory()
    request_hash = idempotency_request_fingerprint({"value": 1})

    def _claim() -> tuple[dict, bool]:
        return store.claim(
            "/v1/scan",
            "tenant-a",
            "source-a",
            "same-key",
            {"job_id": "stable-job"},
            request_hash=request_hash,
        )

    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(lambda _index: _claim(), range(32)))

    assert sum(1 for _response, acquired in results if acquired) == 1
    assert {response["job_id"] for response, _acquired in results} == {"stable-job"}


def test_sqlite_idempotency_claim_is_atomic_for_concurrent_callers(tmp_path):
    from concurrent.futures import ThreadPoolExecutor

    db_path = str(tmp_path / "idempotency.db")
    request_hash = idempotency_request_fingerprint({"value": 1})

    def _claim() -> tuple[dict, bool]:
        store = SQLiteIdempotencyStore(db_path)
        return store.claim(
            "/v1/scan",
            "tenant-a",
            "source-a",
            "same-key",
            {"job_id": "stable-job"},
            request_hash=request_hash,
        )

    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(lambda _index: _claim(), range(16)))

    assert sum(1 for _response, acquired in results if acquired) == 1
    assert {response["job_id"] for response, _acquired in results} == {"stable-job"}


def test_in_memory_idempotency_claim_reclaims_only_expired_uncommitted_reservation() -> None:
    store = InMemoryIdempotencyStore()
    request_hash = idempotency_request_fingerprint({"value": 1})
    key = ("/v1/scan", "tenant-a", "source-a", "same-key")

    first, acquired = store.claim(
        *key,
        {"job_id": "stable-job", "committed": False},
        request_hash=request_hash,
        reservation_lease_seconds=30,
    )
    assert acquired is True
    assert first["committed"] is False

    active, active_acquired = store.claim(
        *key,
        {"job_id": "other-job", "committed": False},
        request_hash=request_hash,
        reservation_lease_seconds=30,
    )
    assert active_acquired is False
    assert active == {"job_id": "stable-job", "committed": False}

    store._records[key].created_at = (datetime.now(timezone.utc) - timedelta(seconds=31)).isoformat()  # noqa: SLF001
    recovered, recovered_acquired = store.claim(
        *key,
        {"job_id": "stable-job", "committed": False},
        request_hash=request_hash,
        reservation_lease_seconds=30,
    )
    assert recovered_acquired is True
    assert recovered == {"job_id": "stable-job", "committed": False}

    store.put(*key, {"job_id": "stable-job", "committed": True}, request_hash=request_hash)
    store._records[key].created_at = (datetime.now(timezone.utc) - timedelta(seconds=31)).isoformat()  # noqa: SLF001
    committed, committed_acquired = store.claim(
        *key,
        {"job_id": "other-job", "committed": False},
        request_hash=request_hash,
        reservation_lease_seconds=30,
    )
    assert committed_acquired is False
    assert committed == {"job_id": "stable-job", "committed": True}


def test_sqlite_idempotency_claim_reclaims_expired_reservation_without_cross_tenant_takeover(tmp_path) -> None:
    store = SQLiteIdempotencyStore(str(tmp_path / "idempotency.db"))
    request_hash = idempotency_request_fingerprint({"value": 1})
    mismatch_hash = idempotency_request_fingerprint({"value": 2})
    args = ("/v1/scan", "tenant-a", "source-a", "same-key")
    store.claim(
        *args,
        {"job_id": "stable-job", "committed": False},
        request_hash=request_hash,
        reservation_lease_seconds=30,
    )
    expired = (datetime.now(timezone.utc) - timedelta(seconds=31)).isoformat()
    store._conn.execute(  # noqa: SLF001
        "UPDATE idempotency_keys SET created_at = ? WHERE endpoint = ? AND tenant_id = ? AND source_id = ? AND idempotency_key = ?",
        (expired, *args),
    )
    store._conn.commit()  # noqa: SLF001

    with pytest.raises(IdempotencyConflictError):
        store.claim(
            *args,
            {"job_id": "wrong", "committed": False},
            request_hash=mismatch_hash,
            reservation_lease_seconds=30,
        )

    recovered, acquired = store.claim(
        *args,
        {"job_id": "stable-job", "committed": False},
        request_hash=request_hash,
        reservation_lease_seconds=30,
    )
    assert acquired is True
    assert recovered["job_id"] == "stable-job"

    other_tenant, other_acquired = store.claim(
        "/v1/scan",
        "tenant-b",
        "source-a",
        "same-key",
        {"job_id": "tenant-b-job", "committed": False},
        request_hash=mismatch_hash,
        reservation_lease_seconds=30,
    )
    assert other_acquired is True
    assert other_tenant["job_id"] == "tenant-b-job"


@pytest.mark.parametrize("store_factory", [InMemoryIdempotencyStore, lambda: SQLiteIdempotencyStore(":memory:")])
def test_idempotency_lease_heartbeat_and_owner_fencing(store_factory) -> None:
    store = store_factory()
    request_hash = idempotency_request_fingerprint({"value": 1})
    args = ("/v1/results/push", "tenant-a", "source-a", "same-key")

    _receipt, acquired = store.claim(
        *args,
        {"job_id": "stable-job", "committed": False},
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

    if isinstance(store, InMemoryIdempotencyStore):
        store._records[args].lease_expires_at = (datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat()  # noqa: SLF001
    else:
        store._conn.execute(  # noqa: SLF001
            "UPDATE idempotency_keys SET lease_expires_at = ? "
            "WHERE endpoint = ? AND tenant_id = ? AND source_id = ? AND idempotency_key = ?",
            ((datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat(), *args),
        )
        store._conn.commit()  # noqa: SLF001

    _takeover, owner_b_acquired = store.claim(
        *args,
        {"job_id": "changed-job", "committed": False},
        request_hash=request_hash,
        reservation_lease_seconds=30,
        owner_token="owner-b",
    )
    assert owner_b_acquired is True
    assert (
        store.put(
            *args,
            {"job_id": "stale-result", "committed": True},
            request_hash=request_hash,
            owner_token="owner-a",
        )
        is False
    )
    assert store.release(*args, request_hash=request_hash, owner_token="owner-a") is False
    assert (
        store.put(
            *args,
            {"job_id": "stable-job", "committed": True},
            request_hash=request_hash,
            owner_token="owner-b",
        )
        is True
    )
    assert store.get(*args, request_hash=request_hash) == {"job_id": "stable-job", "committed": True}


@pytest.mark.parametrize("store_factory", [InMemoryIdempotencyStore, lambda: SQLiteIdempotencyStore(":memory:")])
def test_ownerless_writer_cannot_finalize_an_owned_reservation(store_factory) -> None:
    store = store_factory()
    request_hash = idempotency_request_fingerprint({"value": 1})
    args = ("/v1/results/push", "tenant-a", "source-a", "same-key")
    store.claim(
        *args,
        {"job_id": "stable-job", "committed": False},
        request_hash=request_hash,
        reservation_lease_seconds=30,
        owner_token="owner-a",
    )

    assert (
        store.put(
            *args,
            {"job_id": "stable-job", "committed": True},
            request_hash=request_hash,
        )
        is False
    )
    assert store.get(*args, request_hash=request_hash) == {"job_id": "stable-job", "committed": False}


@pytest.mark.parametrize("store_factory", [InMemoryIdempotencyStore, lambda: SQLiteIdempotencyStore(":memory:")])
def test_owned_commit_holds_the_reservation_through_durable_action(store_factory) -> None:
    store = store_factory()
    request_hash = idempotency_request_fingerprint({"value": 1})
    args = ("/v1/results/push", "tenant-a", "source-a", "same-key")
    store.claim(
        *args,
        {"job_id": "stable-job", "committed": False},
        request_hash=request_hash,
        reservation_lease_seconds=30,
        owner_token="owner-a",
    )
    artifacts: list[str] = []

    result = store.commit_claim(
        *args,
        {"job_id": "stable-job", "committed": True},
        action=lambda: artifacts.append("durable") or "complete",
        request_hash=request_hash,
        owner_token="owner-a",
    )

    assert result == "complete"
    assert artifacts == ["durable"]
    assert store.get(*args, request_hash=request_hash) == {"job_id": "stable-job", "committed": True}


def test_sqlite_commit_claim_allows_action_to_write_shared_database(tmp_path) -> None:
    from agent_bom.api.models import ScanJob, ScanRequest
    from agent_bom.api.store import SQLiteJobStore

    db_path = tmp_path / "shared-control-plane.db"
    idempotency = SQLiteIdempotencyStore(str(db_path))
    jobs = SQLiteJobStore(str(db_path))
    request_hash = idempotency_request_fingerprint({"value": 1})
    args = ("/v1/scan", "tenant-a", "scan", "shared-db")
    idempotency.claim(
        *args,
        {"committed": False, "job_id": "shared-job"},
        request_hash=request_hash,
        reservation_lease_seconds=30,
        owner_token="owner-a",
    )
    job = ScanJob(
        job_id="shared-job",
        tenant_id="tenant-a",
        created_at="2026-09-03T00:00:00+00:00",
        request=ScanRequest(images=["redis:7"]),
    )

    result = idempotency.commit_claim(
        *args,
        {"committed": True, "job_id": job.job_id},
        action=lambda: jobs.put(job),
        request_hash=request_hash,
        owner_token="owner-a",
    )

    assert result is None
    assert jobs.get(job.job_id, tenant_id="tenant-a") is not None
    assert idempotency.get(*args, request_hash=request_hash) == {"committed": True, "job_id": job.job_id}


def test_sqlite_commit_claim_fences_expired_takeover_across_processes(tmp_path) -> None:
    """A second process cannot execute the same effect while commit is live."""

    db_path = str(tmp_path / "cross-process-idempotency.db")
    effects_path = str(tmp_path / "effects.txt")
    request_hash = idempotency_request_fingerprint({"value": 1})
    args = ("/v1/results/push", "tenant-a", "source-a", "cross-process-key")
    store = SQLiteIdempotencyStore(db_path)
    _receipt, acquired = store.claim(
        *args,
        {"job_id": "stable", "committed": False},
        request_hash=request_hash,
        reservation_lease_seconds=1,
        owner_token="owner-a",
    )
    assert acquired is True

    context = multiprocessing.get_context("spawn")
    started = context.Event()
    attempting = context.Event()
    release = context.Event()
    outcomes = context.Queue()
    owner = context.Process(
        target=_sqlite_commit_owner_process,
        args=(db_path, effects_path, request_hash, started, release, outcomes),
    )
    rival = context.Process(
        target=_sqlite_commit_rival_process,
        args=(db_path, effects_path, request_hash, started, attempting, outcomes),
    )
    owner.start()
    rival.start()
    assert attempting.wait(5), "rival never attempted takeover"
    # Let the rival cross the expired lease while the first callback remains
    # live. The per-key process fence must block it until owner-a finalizes.
    time.sleep(0.2)
    release.set()
    owner.join(5)
    rival.join(5)
    assert owner.exitcode == 0
    assert rival.exitcode == 0

    observed = {outcomes.get(timeout=1) for _ in range(2)}
    assert observed == {("owner-a", "committed"), ("owner-b", False)}
    assert Path(effects_path).read_text(encoding="utf-8").splitlines() == ["owner-a"]
    assert store.get(*args, request_hash=request_hash) == {"job_id": "stable", "committed": True}


@pytest.mark.parametrize("store_factory", [InMemoryIdempotencyStore])
def test_idempotency_claim_rejects_same_key_with_different_payload(store_factory):
    store = store_factory()
    store.claim(
        "/v1/scan",
        "tenant-a",
        "source-a",
        "same-key",
        {"job_id": "stable-job"},
        request_hash=idempotency_request_fingerprint({"value": 1}),
    )

    with pytest.raises(IdempotencyConflictError):
        store.claim(
            "/v1/scan",
            "tenant-a",
            "source-a",
            "same-key",
            {"job_id": "other-job"},
            request_hash=idempotency_request_fingerprint({"value": 2}),
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
