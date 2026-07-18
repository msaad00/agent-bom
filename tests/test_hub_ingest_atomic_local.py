"""Batch-ingest atomicity for the SQLite + in-memory hub stores (wave-2 #1).

The Postgres backend already commits ledger append + current upsert (+ reconcile)
in ONE transaction (``ingest_batch_atomic``). The SQLite and in-memory backends
previously exposed only ``add`` / ``upsert_current_batch`` /
``reconcile_current_absent`` — three separately-committed writes. A failure
between the ledger commit and the current-state upsert left ``tenant_total``
inflated while the findings never appeared in any list.

These tests pin the fix on the non-Postgres backends: a mid-batch failure rolls
back the ledger too (no inflated count, no partial current-state); the happy
path commits both; an idempotent resend stays exact; and reconcile runs inside
the same transaction.
"""

from __future__ import annotations

from typing import Any

import pytest

from agent_bom.api.compliance_hub_store import (
    InMemoryComplianceHubStore,
    SQLiteComplianceHubStore,
)


def _payload(idx: int, *, severity: str = "high", source: str = "connector") -> dict[str, Any]:
    return {
        "id": f"f-{idx}",
        "canonical_id": f"c-{idx}",
        "severity": severity,
        "source": source,
        "cvss_score": 7.5,
    }


def _sqlite_store(tmp_path) -> SQLiteComplianceHubStore:
    return SQLiteComplianceHubStore(str(tmp_path / "hub.db"))


# ── SQLite: single-transaction atomicity ─────────────────────────────────────


def test_sqlite_atomic_rolls_back_ledger_when_upsert_fails(tmp_path):
    store = _sqlite_store(tmp_path)
    tenant = "atomic-sqlite"

    def _explode(*_a: Any, **_k: Any) -> None:
        raise RuntimeError("injected upsert failure")

    store._upsert_current_no_commit = _explode  # type: ignore[method-assign]

    with pytest.raises(RuntimeError):
        store.ingest_batch_atomic(
            tenant,
            [_payload(1), _payload(2)],
            observed_at="2026-07-18T00:00:00Z",
            batch_id="batch-1",
            source="connector",
            reconcile_absent=False,
            present_canonical_ids=set(),
        )

    # Ledger append rolled back with the failed upsert: no inflated count.
    assert store.count(tenant) == 0
    assert store.list_current_page(tenant, limit=50)[0] == []


def test_sqlite_atomic_rolls_back_when_reconcile_fails(tmp_path):
    store = _sqlite_store(tmp_path)
    tenant = "atomic-sqlite-recon"

    def _explode(*_a: Any, **_k: Any) -> int:
        raise RuntimeError("injected reconcile failure")

    store._reconcile_current_absent_no_commit = _explode  # type: ignore[method-assign]

    with pytest.raises(RuntimeError):
        store.ingest_batch_atomic(
            tenant,
            [_payload(1), _payload(2)],
            observed_at="2026-07-18T00:00:00Z",
            batch_id="batch-1",
            source="connector",
            reconcile_absent=True,
            present_canonical_ids={"c-1", "c-2"},
        )

    assert store.count(tenant) == 0
    assert store.list_current_page(tenant, limit=50)[0] == []


def test_sqlite_atomic_happy_path_commits_both_and_is_idempotent(tmp_path):
    store = _sqlite_store(tmp_path)
    tenant = "atomic-sqlite-ok"
    payloads = [_payload(1), _payload(2), _payload(3)]

    total, reconciled = store.ingest_batch_atomic(
        tenant,
        payloads,
        observed_at="2026-07-18T00:00:00Z",
        batch_id="batch-1",
        source="connector",
        reconcile_absent=False,
        present_canonical_ids=set(),
    )
    assert total == 3
    assert reconciled == 0
    assert store.count(tenant) == 3
    current, current_total, _ = store.list_current_page(tenant, limit=50)
    assert len(current) == 3
    assert current_total == 3

    # Idempotent resend: no new ledger or current rows.
    total2, _ = store.ingest_batch_atomic(
        tenant,
        payloads,
        observed_at="2026-07-18T00:00:00Z",
        batch_id="batch-1",
        source="connector",
        reconcile_absent=False,
        present_canonical_ids=set(),
    )
    assert total2 == 3
    assert store.count(tenant) == 3
    assert store.list_current_page(tenant, limit=50)[1] == 3


def test_sqlite_atomic_reconcile_resolves_absent_in_same_txn(tmp_path):
    store = _sqlite_store(tmp_path)
    tenant = "atomic-sqlite-reconcile"

    store.ingest_batch_atomic(
        tenant,
        [_payload(1), _payload(2), _payload(3)],
        observed_at="2026-07-18T00:00:00Z",
        batch_id="batch-1",
        source="connector",
        reconcile_absent=False,
        present_canonical_ids=set(),
    )

    # The store keys current-state on the resolved canonical id (the finding id
    # here). Second batch is present only for the first two; reconcile_absent
    # must resolve the third — in the SAME transaction as the ledger/current
    # writes.
    _total, reconciled = store.ingest_batch_atomic(
        tenant,
        [_payload(1), _payload(2)],
        observed_at="2026-07-18T01:00:00Z",
        batch_id="batch-2",
        source="connector",
        reconcile_absent=True,
        present_canonical_ids={"f-1", "f-2"},
    )
    assert reconciled == 1
    open_rows, _total2, _ = store.list_current_page(tenant, limit=50)
    statuses = {str(r.get("canonical_id") or r.get("id")): r.get("status") for r in open_rows}
    assert statuses.get("f-3") == "resolved"


# ── In-memory: rollback under a single lock acquisition ──────────────────────


def test_inmemory_atomic_rolls_back_when_reconcile_fails():
    store = InMemoryComplianceHubStore()
    tenant = "atomic-mem"

    def _explode(*_a: Any, **_k: Any) -> int:
        raise RuntimeError("injected reconcile failure")

    store._reconcile_locked = _explode  # type: ignore[method-assign]

    with pytest.raises(RuntimeError):
        store.ingest_batch_atomic(
            tenant,
            [_payload(1), _payload(2)],
            observed_at="2026-07-18T00:00:00Z",
            batch_id="batch-1",
            source="connector",
            reconcile_absent=True,
            present_canonical_ids={"c-1", "c-2"},
        )

    # Ledger + current-state restored: nothing partially applied.
    assert store.count(tenant) == 0
    assert store.list_current_page(tenant, limit=50)[0] == []


def test_inmemory_atomic_happy_path_commits_both_and_is_idempotent():
    store = InMemoryComplianceHubStore()
    tenant = "atomic-mem-ok"
    payloads = [_payload(1), _payload(2), _payload(3)]

    total, reconciled = store.ingest_batch_atomic(
        tenant,
        payloads,
        observed_at="2026-07-18T00:00:00Z",
        batch_id="batch-1",
        source="connector",
        reconcile_absent=False,
        present_canonical_ids=set(),
    )
    assert total == 3
    assert reconciled == 0
    assert store.count(tenant) == 3
    assert store.list_current_page(tenant, limit=50)[1] == 3

    total2, _ = store.ingest_batch_atomic(
        tenant,
        payloads,
        observed_at="2026-07-18T00:00:00Z",
        batch_id="batch-1",
        source="connector",
        reconcile_absent=False,
        present_canonical_ids=set(),
    )
    assert total2 == 3
    assert store.count(tenant) == 3
