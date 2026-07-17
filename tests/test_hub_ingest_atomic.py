"""Batch atomicity for the Compliance-Hub ingest write path (wave-2 residual #1).

``/v1/findings/bulk`` and ``/v1/compliance/ingest`` append the ledger
(``hub_store.add``) and then upsert current-state (``upsert_current_batch``).
On the Postgres backend each method opened its OWN tenant connection and
committed independently, so a failure between them left the ledger committed but
current-state not — the ledger inflated while the findings stayed invisible.

These tests pin the fix: the ledger append + current upsert (+ reconcile) run in
a SINGLE transaction. A mid-batch failure rolls back BOTH; the happy path is
unchanged; an idempotent re-ingest is still exact.

The live-Postgres tests are opt-in (``AGENT_BOM_POSTGRES_URL``); the routing
test runs everywhere against a fake store.
"""

from __future__ import annotations

import os
from contextlib import contextmanager
from typing import Any
from uuid import uuid4

import pytest

pg_only = pytest.mark.skipif(
    not os.environ.get("AGENT_BOM_POSTGRES_URL"),
    reason="AGENT_BOM_POSTGRES_URL is required for real Postgres atomicity tests",
)


@pytest.fixture(autouse=True)
def _reset_postgres_pool():
    if not os.environ.get("AGENT_BOM_POSTGRES_URL"):
        yield
        return
    from agent_bom.api import postgres_common

    postgres_common.reset_pool()
    yield
    pool = postgres_common._pool
    if pool is not None:
        pool.close()
    postgres_common.reset_pool()


def _payload(idx: int, *, severity: str = "high", source: str = "connector") -> dict[str, Any]:
    return {
        "id": f"f-{idx}",
        "canonical_id": f"c-{idx}",
        "severity": severity,
        "source": source,
        "cvss_score": 7.5,
    }


# ── Live Postgres: single-transaction atomicity ──────────────────────────────


@pg_only
def test_atomic_ingest_rolls_back_ledger_when_upsert_fails():
    """A mid-batch upsert failure leaves NEITHER ledger nor current rows."""
    from agent_bom.api.postgres_common import reset_current_tenant, set_current_tenant
    from agent_bom.api.postgres_compliance_hub import PostgresComplianceHubStore

    tenant = f"atomic-{uuid4().hex}"
    token = set_current_tenant(tenant)
    try:
        store = PostgresComplianceHubStore()
        payloads = [_payload(1), _payload(2)]

        boom = RuntimeError("injected upsert failure")

        def _explode(*_a: Any, **_k: Any) -> None:
            raise boom

        # Fail the current-state write AFTER the ledger insert has run on the
        # shared connection. If they share one transaction the ledger insert
        # must roll back too.
        store._write_current_batch = _explode  # type: ignore[method-assign]

        with pytest.raises(RuntimeError):
            store.ingest_batch_atomic(
                tenant,
                payloads,
                observed_at="2026-07-16T00:00:00Z",
                batch_id="batch-1",
                source="connector",
                reconcile_absent=False,
                present_canonical_ids=set(),
            )

        # DB truth (fresh connection, committed state only): both empty.
        assert store.count(tenant) == 0
        assert store.list_current_page(tenant, limit=50)[0] == []
    finally:
        reset_current_tenant(token)


@pg_only
def test_atomic_ingest_happy_path_commits_both_and_is_idempotent():
    """Clean ingest commits ledger + current; a resend is exact (idempotent)."""
    from agent_bom.api.postgres_common import reset_current_tenant, set_current_tenant
    from agent_bom.api.postgres_compliance_hub import PostgresComplianceHubStore

    tenant = f"atomic-{uuid4().hex}"
    token = set_current_tenant(tenant)
    try:
        store = PostgresComplianceHubStore()
        payloads = [_payload(1), _payload(2), _payload(3)]

        total, reconciled = store.ingest_batch_atomic(
            tenant,
            payloads,
            observed_at="2026-07-16T00:00:00Z",
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

        # Idempotent resend of the identical batch: no new ledger or current rows.
        total2, _ = store.ingest_batch_atomic(
            tenant,
            payloads,
            observed_at="2026-07-16T00:00:00Z",
            batch_id="batch-1",
            source="connector",
            reconcile_absent=False,
            present_canonical_ids=set(),
        )
        assert total2 == 3
        assert store.count(tenant) == 3
        assert store.list_current_page(tenant, limit=50)[1] == 3
    finally:
        reset_current_tenant(token)


@pg_only
def test_atomic_ingest_matches_sequential_add_plus_upsert():
    """The atomic path yields the same rows as the legacy add + upsert calls."""
    from agent_bom.api.postgres_common import reset_current_tenant, set_current_tenant
    from agent_bom.api.postgres_compliance_hub import PostgresComplianceHubStore

    store = PostgresComplianceHubStore()
    payloads = [_payload(1), _payload(2)]

    tenant_seq = f"seq-{uuid4().hex}"
    tok = set_current_tenant(tenant_seq)
    try:
        store.add(tenant_seq, payloads)
        store.upsert_current_batch(tenant_seq, payloads, observed_at="2026-07-16T00:00:00Z", batch_id="b", source="connector")
        seq_count = store.count(tenant_seq)
        seq_current = store.list_current_page(tenant_seq, limit=50)[1]
    finally:
        reset_current_tenant(tok)

    tenant_atomic = f"atm-{uuid4().hex}"
    tok = set_current_tenant(tenant_atomic)
    try:
        store.ingest_batch_atomic(
            tenant_atomic,
            payloads,
            observed_at="2026-07-16T00:00:00Z",
            batch_id="b",
            source="connector",
            reconcile_absent=False,
            present_canonical_ids=set(),
        )
        atomic_count = store.count(tenant_atomic)
        atomic_current = store.list_current_page(tenant_atomic, limit=50)[1]
    finally:
        reset_current_tenant(tok)

    assert seq_count == atomic_count == 2
    assert seq_current == atomic_current == 2


# ── Backend-agnostic: shared body routes through the atomic seam ─────────────


class _FakeAtomicStore:
    """Records that the shared ingest body used the atomic single-call seam."""

    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []

    def ingest_batch_atomic(
        self,
        tenant_id: str,
        findings: list[dict[str, Any]],
        *,
        observed_at: str,
        batch_id: str,
        source: str,
        reconcile_absent: bool,
        present_canonical_ids: set[str],
    ) -> tuple[int, int]:
        self.calls.append(
            {
                "tenant_id": tenant_id,
                "count": len(findings),
                "batch_id": batch_id,
                "reconcile_absent": reconcile_absent,
                "present": set(present_canonical_ids),
            }
        )
        return len(findings), 0

    # Present so ``add``/``upsert_current_batch`` MUST NOT be called on the
    # happy path; if the body falls back to them the test asserts they went
    # unused.
    def add(self, *_a: Any, **_k: Any) -> int:  # pragma: no cover - must not run
        raise AssertionError("shared body must route through ingest_batch_atomic")

    def upsert_current_batch(self, *_a: Any, **_k: Any) -> None:  # pragma: no cover
        raise AssertionError("shared body must route through ingest_batch_atomic")

    def reconcile_current_absent(self, *_a: Any, **_k: Any) -> int:  # pragma: no cover
        raise AssertionError("shared body must route through ingest_batch_atomic")


def test_shared_body_uses_atomic_seam_when_available():
    from agent_bom.api.hub_ingest import hub_ingest_store_writes

    # Delta emission is off by default (no AGENT_BOM_DELTA_STREAM_ENABLED), so
    # the body never reads the store — it must route the writes through the
    # atomic single-call seam.
    store = _FakeAtomicStore()
    payloads = [_payload(1), _payload(2)]
    result = hub_ingest_store_writes(
        store,
        "tenant-x",
        payloads,
        observed_at="2026-07-16T00:00:00Z",
        batch_id="batch-9",
        source="connector",
        reconcile_absent=False,
    )
    assert result["new_total"] == 2
    assert result["reconciled"] == 0
    assert store.calls and store.calls[0]["batch_id"] == "batch-9"
    assert store.calls[0]["reconcile_absent"] is False


def test_postgres_atomic_store_invalidates_cached_finding_totals(monkeypatch):
    """The atomic write seam invalidates the same tenant cache as split writes."""
    from agent_bom.api import postgres_compliance_hub as module
    from agent_bom.api.findings_count_cache import (
        cache_key,
        get_cached_total,
        reset_findings_count_cache,
        set_cached_total,
    )

    class _Connection:
        def commit(self) -> None:
            return None

    @contextmanager
    def _connection(_pool):
        yield _Connection()

    store = module.PostgresComplianceHubStore.__new__(module.PostgresComplianceHubStore)
    store._pool = object()
    monkeypatch.setattr(module, "_tenant_connection", _connection)
    monkeypatch.setattr(store, "_write_ledger_batch", lambda *_a, **_k: 1)
    monkeypatch.setattr(store, "_write_current_batch", lambda *_a, **_k: None)
    monkeypatch.setattr(store, "_bump_tenant_total", lambda *_a, **_k: 2)

    key = cache_key(
        tenant_id="tenant-cache",
        severity=None,
        scan_id=None,
        origin="bulk_ingest",
        window_days=90,
    )
    reset_findings_count_cache()
    set_cached_total(key, 1)

    total, reconciled = store.ingest_batch_atomic(
        "tenant-cache",
        [_payload(2)],
        observed_at="2026-07-17T00:00:00Z",
        batch_id="batch-2",
        source="connector",
        reconcile_absent=False,
        present_canonical_ids={"c-2"},
    )

    assert (total, reconciled) == (2, 0)
    assert get_cached_total(key) is None


@pg_only
def test_live_postgres_atomic_ingest_invalidates_cached_finding_totals():
    """A committed live write drops every cached filter/window for its tenant."""
    from agent_bom.api.findings_count_cache import (
        cache_key,
        get_cached_total,
        reset_findings_count_cache,
        set_cached_total,
    )
    from agent_bom.api.postgres_common import reset_current_tenant, set_current_tenant
    from agent_bom.api.postgres_compliance_hub import PostgresComplianceHubStore

    tenant = f"atomic-cache-{uuid4().hex}"
    token = set_current_tenant(tenant)
    key = cache_key(
        tenant_id=tenant,
        severity="critical",
        scan_id=None,
        origin="bulk_ingest",
        window_days=90,
    )
    try:
        reset_findings_count_cache()
        set_cached_total(key, 1)
        store = PostgresComplianceHubStore()
        store.ingest_batch_atomic(
            tenant,
            [_payload(1, severity="critical")],
            observed_at="2026-07-17T00:00:00Z",
            batch_id="batch-live-cache",
            source="connector",
            reconcile_absent=False,
            present_canonical_ids={"c-1"},
        )
        assert get_cached_total(key) is None
    finally:
        reset_findings_count_cache()
        reset_current_tenant(token)
