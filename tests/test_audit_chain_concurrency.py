"""Concurrency regression tests for the tamper-evident audit hash chain.

A hash chain forks when two concurrent appends read the same chain head
(``prev_signature``), sign against it, and both insert — producing two rows that
share one predecessor. ``_verify_audit_chain`` walks the chain chronologically
requiring ``entry.prev_signature == previous.hmac_signature``, so every forked
sibling is scored ``tampered`` and a forged entry can hide among the benign
forks.

These tests drive many threads appending to the SAME tenant and assert the chain
never forks: no two rows share a ``prev_signature`` and ``verify_integrity``
reports the chain intact.
"""

from __future__ import annotations

import os
import sqlite3
import sys
import threading

import pytest

from agent_bom.api.audit_log import AuditEntry, InMemoryAuditLog, SQLiteAuditLog


def _append_concurrently(log: object, tenant: str, n: int) -> list[Exception]:
    """Fire ``n`` threads that each append one entry to ``tenant`` at once.

    A barrier aligns every thread on the read of the chain head, and the GIL
    switch interval is shortened so an unserialized read-modify-write forks
    reliably rather than by luck.
    """
    barrier = threading.Barrier(n)
    errors: list[Exception] = []

    def worker(i: int) -> None:
        try:
            barrier.wait()
            log.append(  # type: ignore[attr-defined]
                AuditEntry(
                    action="scan",
                    actor="worker",
                    resource=f"pkg-{i}",
                    details={"tenant_id": tenant},
                )
            )
        except Exception as exc:  # noqa: BLE001 - surfaced to the assertion
            errors.append(exc)

    original_interval = sys.getswitchinterval()
    sys.setswitchinterval(1e-6)
    try:
        threads = [threading.Thread(target=worker, args=(i,)) for i in range(n)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
    finally:
        sys.setswitchinterval(original_interval)
    return errors


def test_inmemory_concurrent_append_does_not_fork_chain() -> None:
    log = InMemoryAuditLog()
    tenant = "tenant-alpha"
    n = 24

    errors = _append_concurrently(log, tenant, n)
    assert not errors, f"append raised under concurrency: {errors!r}"

    entries = log.list_entries(limit=1000, tenant_id=tenant)
    assert len(entries) == n

    prevs = [e.prev_signature for e in entries]
    duplicates = len(prevs) - len(set(prevs))
    assert duplicates == 0, f"chain forked: {duplicates} rows share a prev_signature"

    verified, tampered = log.verify_integrity(tenant_id=tenant)
    assert tampered == 0, f"verify_integrity reported {tampered} tampered rows"
    assert verified == n


def test_sqlite_concurrent_append_does_not_fork_chain(tmp_path) -> None:
    db = str(tmp_path / "audit.db")
    log = SQLiteAuditLog(db)
    tenant = "tenant-alpha"
    n = 16

    errors = _append_concurrently(log, tenant, n)
    assert not errors, f"append raised under concurrency: {errors!r}"

    entries = log.list_entries(limit=1000, tenant_id=tenant)
    assert len(entries) == n

    prevs = [e.prev_signature for e in entries]
    duplicates = len(prevs) - len(set(prevs))
    assert duplicates == 0, f"chain forked: {duplicates} rows share a prev_signature"

    verified, tampered = log.verify_integrity(tenant_id=tenant)
    assert tampered == 0, f"verify_integrity reported {tampered} tampered rows"
    assert verified == n


def test_sqlite_fork_guard_rejects_second_row_on_same_head(tmp_path) -> None:
    """A cross-connection writer that links to an already-used head is rejected.

    Emulates two uvicorn workers (separate connections) that both link to the
    same predecessor: once one row links to a head, the DB unique guard on
    ``(tenant_id, prev_signature)`` must reject a second row sharing that
    predecessor rather than persist a fork.
    """
    db = str(tmp_path / "audit.db")
    log = SQLiteAuditLog(db)
    tenant = "tenant-alpha"
    log.append(AuditEntry(action="scan", actor="w", resource="genesis", details={"tenant_id": tenant}))
    genesis_head = log._latest_signature_for_tenant(tenant)
    # A legitimate second append links to the genesis head.
    log.append(AuditEntry(action="scan", actor="w", resource="pkg-b", details={"tenant_id": tenant}))

    # A second, independent connection forges a row that links to the SAME
    # predecessor the legitimate entry already used — a fork of genesis_head.
    raw = sqlite3.connect(db)
    try:
        forged = AuditEntry(action="scan", actor="attacker", resource="forged", details={"tenant_id": tenant})
        forged.prev_signature = genesis_head
        forged.sign()
        try:
            raw.execute(
                "INSERT INTO audit_log"
                " (entry_id, timestamp, action, actor, resource,"
                " details, prev_signature, hmac_signature, tenant_id)"
                " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    forged.entry_id,
                    forged.timestamp,
                    forged.action,
                    forged.actor,
                    forged.resource,
                    "{}",
                    forged.prev_signature,
                    forged.hmac_signature,
                    tenant,
                ),
            )
            raw.commit()
            forged_inserted = True
        except sqlite3.IntegrityError:
            forged_inserted = False
    finally:
        raw.close()

    assert not forged_inserted, "fork guard missing: a second row linked to the same head was accepted"

    # The legitimate next append still succeeds, linking to the real head.
    log.append(AuditEntry(action="scan", actor="w", resource="pkg-c", details={"tenant_id": tenant}))
    verified, tampered = log.verify_integrity(tenant_id=tenant)
    assert tampered == 0
    assert verified == 3


def test_chain_fork_conflict_detector_matches_only_fork_violations() -> None:
    """The Postgres retry only fires on a fork-guard unique violation."""
    from agent_bom.api.postgres_audit import _AUDIT_FORK_GUARD_INDEX, _is_chain_fork_conflict

    class _Diag:
        def __init__(self, name):
            self.constraint_name = name

    class _FakeDbError(Exception):
        def __init__(self, sqlstate, constraint):
            super().__init__("boom")
            self.sqlstate = sqlstate
            self.diag = _Diag(constraint)

    # Unique violation on the fork-guard index → retry.
    assert _is_chain_fork_conflict(_FakeDbError("23505", _AUDIT_FORK_GUARD_INDEX)) is True
    # Unique violation with no surfaced constraint name → treat as a fork race.
    assert _is_chain_fork_conflict(_FakeDbError("23505", None)) is True
    # Unique violation on some unrelated constraint → do not retry.
    assert _is_chain_fork_conflict(_FakeDbError("23505", "some_other_constraint")) is False
    # Non-unique-violation SQLSTATE (e.g. serialization failure) → do not retry.
    assert _is_chain_fork_conflict(_FakeDbError("40001", _AUDIT_FORK_GUARD_INDEX)) is False
    # A plain exception with no sqlstate → do not retry.
    assert _is_chain_fork_conflict(ValueError("nope")) is False


@pytest.mark.skipif(
    not os.environ.get("AGENT_BOM_POSTGRES_URL"),
    reason="requires a live PostgreSQL (AGENT_BOM_POSTGRES_URL) — mock pool cannot enforce the unique fork guard",
)
def test_postgres_head_read_is_chain_ordered_not_timestamp_ordered() -> None:
    """A retried/clock-skewed append must not poison the head and livelock (#4284).

    Regression for the audit-chain livelock: the chain head was selected by
    ``ORDER BY timestamp DESC``, but ``AuditEntry.timestamp`` is stamped at entry
    creation. A writer that loses the fork race re-signs against the advanced
    head yet commits *later* with its *original, older* timestamp, so timestamp
    order diverges from chain order. The head read then returns a non-tip row
    whose successor slot is already taken — every subsequent append re-links to
    that stale head, hits the fork-guard UNIQUE violation, re-reads the same
    stale head, and retries to exhaustion: the tenant can never append again.

    This reproduces the skew deterministically (no threads): a genesis row with a
    *later* wall-clock timestamp than its own successor. The head must still be
    the true chain tip (the last-committed row), and a further append must
    succeed and link to it.
    """
    import uuid

    from agent_bom.api.postgres_common import _current_tenant, set_current_tenant
    from agent_bom.api.postgres_store import PostgresAuditLog

    store = PostgresAuditLog()
    tenant = f"tenant-skew-{uuid.uuid4().hex[:12]}"
    token = set_current_tenant(tenant)
    try:
        # Genesis carries a LATER timestamp than its successor — the exact skew a
        # retried append produces (commit order != timestamp order).
        genesis = AuditEntry(
            action="scan",
            actor="w",
            resource="genesis",
            details={"tenant_id": tenant},
            timestamp="2020-01-01T00:00:09+00:00",
        )
        store.append(genesis)
        genesis_sig = genesis.hmac_signature

        successor = AuditEntry(
            action="scan",
            actor="w",
            resource="successor",
            details={"tenant_id": tenant},
            timestamp="2020-01-01T00:00:01+00:00",
        )
        store.append(successor)
        true_tip_sig = successor.hmac_signature

        # The genesis has the max timestamp but its successor slot is already
        # taken; the true chain tip is the last-committed row (`successor`).
        head = store._latest_signature_for_tenant(tenant)
        assert head == true_tip_sig, (
            "head read returned a non-tip row — timestamp-ordered head selection "
            f"poisons the chain (#4284): got {head!r}, expected tip {true_tip_sig!r}, "
            f"genesis was {genesis_sig!r}"
        )

        # A further append must link to the true tip and succeed — on the buggy
        # code this exhausts every fork-guard retry and raises (livelock).
        third = AuditEntry(
            action="scan",
            actor="w",
            resource="third",
            details={"tenant_id": tenant},
        )
        store.append(third)
        assert third.prev_signature == true_tip_sig

        entries = store.list_entries(limit=1000, tenant_id=tenant)
        prevs = [e.prev_signature for e in entries]
        assert len(prevs) == len(set(prevs)), "chain forked: rows share a prev_signature"

        verified, tampered = store.verify_integrity(tenant_id=tenant)
        assert tampered == 0, f"verify_integrity reported {tampered} tampered rows"
        assert verified == 3
    finally:
        _current_tenant.reset(token)


@pytest.mark.skipif(
    not os.environ.get("AGENT_BOM_POSTGRES_URL"),
    reason="requires a live PostgreSQL (AGENT_BOM_POSTGRES_URL) — mock pool cannot enforce the unique fork guard",
)
def test_postgres_concurrent_append_does_not_fork_chain() -> None:
    """Cross-thread appends against a live Postgres store must not fork the chain.

    Runs only with a real database (the fork guard is a DB-enforced UNIQUE
    constraint). Each thread opens its own pooled connection, so this also
    exercises the multi-connection path that a multi-worker deployment hits.
    """
    from agent_bom.api.postgres_common import set_current_tenant
    from agent_bom.api.postgres_store import PostgresAuditLog

    store = PostgresAuditLog()
    tenant = "tenant-concurrency-probe"
    n = 16

    barrier = threading.Barrier(n)
    errors: list[Exception] = []

    def worker(i: int) -> None:
        token = set_current_tenant(tenant)
        try:
            barrier.wait()
            store.append(
                AuditEntry(
                    action="scan",
                    actor="worker",
                    resource=f"pkg-{i}",
                    details={"tenant_id": tenant},
                )
            )
        except Exception as exc:  # noqa: BLE001
            errors.append(exc)
        finally:
            from agent_bom.api.postgres_common import _current_tenant

            _current_tenant.reset(token)

    original_interval = sys.getswitchinterval()
    sys.setswitchinterval(1e-6)
    try:
        threads = [threading.Thread(target=worker, args=(i,)) for i in range(n)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
    finally:
        sys.setswitchinterval(original_interval)

    assert not errors, f"append raised under concurrency: {errors!r}"

    entries = store.list_entries(limit=1000, tenant_id=tenant)
    fresh = [e for e in entries if e.resource.startswith("pkg-")]
    prevs = [e.prev_signature for e in fresh]
    duplicates = len(prevs) - len(set(prevs))
    assert duplicates == 0, f"chain forked: {duplicates} rows share a prev_signature"

    verified, tampered = store.verify_integrity(tenant_id=tenant)
    assert tampered == 0, f"verify_integrity reported {tampered} tampered rows"
