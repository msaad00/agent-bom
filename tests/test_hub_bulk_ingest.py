"""Bulk (COPY/executemany) Compliance-Hub ingest — correctness + throughput.

Wave-2 residual #2: the Postgres ledger append and current-state upsert were
per-row round-trips (~1-2k rows/s), too slow for a connector initial-sync of
millions. The write path now batches both (``executemany`` with pipelined
round-trips) while preserving EXACT semantics: idempotent ON CONFLICT, tenant
scope, lifecycle merge, and the observation dedup.

The correctness gate feeds identical batch sequences to the Postgres store and
the in-memory store (the shared lifecycle reference) and asserts the resulting
current-state is field-for-field identical. A lenient throughput smoke pins that
the batched path is no longer a per-row crawl.
"""

from __future__ import annotations

import os
import time
from typing import Any
from uuid import uuid4

import pytest

pg_only = pytest.mark.skipif(
    not os.environ.get("AGENT_BOM_POSTGRES_URL"),
    reason="AGENT_BOM_POSTGRES_URL is required for real Postgres bulk-ingest tests",
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


def _f(idx: int, *, severity: str = "high", cvss: float = 7.5) -> dict[str, Any]:
    return {
        "id": f"f-{idx}",
        "canonical_id": f"c-{idx}",
        "severity": severity,
        "source": "connector",
        "cvss_score": cvss,
        "title": f"Finding {idx}",
    }


def _current_snapshot(store: Any, tenant: str) -> dict[str, dict[str, Any]]:
    """Canonical -> comparable current-state fields (order-independent)."""
    page, _total, _cursor = store.list_current_page(tenant, limit=10000, sort="ordinal")
    out: dict[str, dict[str, Any]] = {}
    for row in page:
        cid = str(row.get("canonical_id") or row.get("id"))
        out[cid] = {
            "severity": row.get("severity"),
            "status": row.get("status"),
            "scan_count": row.get("scan_count"),
            "first_seen": row.get("first_seen"),
            "last_seen": row.get("last_seen"),
        }
    return out


def _ingest(store: Any, tenant: str, batch: list[dict[str, Any]], *, observed_at: str, batch_id: str) -> None:
    store.add(tenant, batch)
    store.upsert_current_batch(tenant, batch, observed_at=observed_at, batch_id=batch_id, source="connector")


# ── Correctness: Postgres bulk path matches the in-memory reference ──────────


@pg_only
def test_bulk_ingest_matches_in_memory_reference_across_lifecycle():
    from agent_bom.api.compliance_hub_store import InMemoryComplianceHubStore
    from agent_bom.api.postgres_common import reset_current_tenant, set_current_tenant
    from agent_bom.api.postgres_compliance_hub import PostgresComplianceHubStore

    pg = PostgresComplianceHubStore()
    mem = InMemoryComplianceHubStore()

    # A sequence exercising: fresh insert, re-observe (merge first/last_seen +
    # scan_count), a NEW finding in a later batch, an in-batch duplicate
    # canonical, and idempotent replay of a batch_id.
    batch1 = [_f(1, severity="high"), _f(2, severity="medium"), _f(3, severity="low")]
    batch2 = [
        _f(1, severity="critical", cvss=9.8),  # re-observe c-1, escalated
        _f(4, severity="high"),  # brand new
        _f(4, severity="high"),  # in-batch duplicate canonical -> deduped
    ]

    pg_tenant = f"pgbulk-{uuid4().hex}"
    tok = set_current_tenant(pg_tenant)
    try:
        _ingest(pg, pg_tenant, batch1, observed_at="2026-07-14T00:00:00Z", batch_id="b1")
        _ingest(pg, pg_tenant, batch2, observed_at="2026-07-16T00:00:00Z", batch_id="b2")
        # Idempotent replay of b2 changes nothing.
        _ingest(pg, pg_tenant, batch2, observed_at="2026-07-16T00:00:00Z", batch_id="b2")
        pg_snap = _current_snapshot(pg, pg_tenant)
        pg_count = pg.count(pg_tenant)
    finally:
        reset_current_tenant(tok)

    mem_tenant = "membulk"
    _ingest(mem, mem_tenant, batch1, observed_at="2026-07-14T00:00:00Z", batch_id="b1")
    _ingest(mem, mem_tenant, batch2, observed_at="2026-07-16T00:00:00Z", batch_id="b2")
    _ingest(mem, mem_tenant, batch2, observed_at="2026-07-16T00:00:00Z", batch_id="b2")
    mem_snap = _current_snapshot(mem, mem_tenant)

    # Canonical id derives from the finding ``id`` (f-N).
    assert set(pg_snap) == set(mem_snap) == {"f-1", "f-2", "f-3", "f-4"}
    assert pg_snap == mem_snap, f"pg={pg_snap}\nmem={mem_snap}"
    # c-1 re-observed twice -> scan_count 2, escalated to critical, first_seen
    # kept at the earliest, last_seen advanced.
    assert pg_snap["f-1"]["scan_count"] == 2
    assert pg_snap["f-1"]["severity"] == "critical"
    assert pg_snap["f-1"]["first_seen"] == "2026-07-14T00:00:00Z"
    assert pg_snap["f-1"]["last_seen"] == "2026-07-16T00:00:00Z"
    # Ledger is idempotent: 4 distinct finding_ids (f-1..f-4), replay adds none.
    assert pg_count == 4


@pg_only
def test_bulk_ingest_reconcile_absent_matches_reference():
    from agent_bom.api.compliance_hub_store import InMemoryComplianceHubStore
    from agent_bom.api.postgres_common import reset_current_tenant, set_current_tenant
    from agent_bom.api.postgres_compliance_hub import PostgresComplianceHubStore

    pg = PostgresComplianceHubStore()
    mem = InMemoryComplianceHubStore()

    first = [_f(1), _f(2), _f(3)]
    # Second scan of the same source omits c-2 and c-3 -> they resolve.
    second = [_f(1)]

    def run(store: Any, tenant: str) -> dict[str, dict[str, Any]]:
        _ingest(store, tenant, first, observed_at="2026-07-14T00:00:00Z", batch_id="b1")
        store.add(tenant, second)
        store.upsert_current_batch(tenant, second, observed_at="2026-07-16T00:00:00Z", batch_id="b2", source="connector")
        store.reconcile_current_absent(
            tenant, present_canonical_ids={"f-1"}, observed_at="2026-07-16T00:00:00Z", scope_source="connector"
        )
        return _current_snapshot(store, tenant)

    pg_tenant = f"pgrec-{uuid4().hex}"
    tok = set_current_tenant(pg_tenant)
    try:
        pg_snap = run(pg, pg_tenant)
    finally:
        reset_current_tenant(tok)
    mem_snap = run(mem, "memrec")

    assert pg_snap == mem_snap
    assert pg_snap["f-1"]["status"] == "open"
    assert pg_snap["f-2"]["status"] == "resolved"
    assert pg_snap["f-3"]["status"] == "resolved"


# ── Throughput: batched path is no longer a per-row crawl ────────────────────


@pg_only
def test_bulk_ingest_throughput_is_not_per_row_crawl():
    from agent_bom.api.postgres_common import reset_current_tenant, set_current_tenant
    from agent_bom.api.postgres_compliance_hub import PostgresComplianceHubStore

    store = PostgresComplianceHubStore()
    n = 10_000
    batch = [_f(i) for i in range(n)]
    tenant = f"pgtput-{uuid4().hex}"
    tok = set_current_tenant(tenant)
    try:
        start = time.perf_counter()
        store.add(tenant, batch)
        store.upsert_current_batch(tenant, batch, observed_at="2026-07-16T00:00:00Z", batch_id="b1", source="connector")
        elapsed = time.perf_counter() - start
        rows_per_s = n / elapsed
        # The per-row baseline was ~1-2k rows/s combined; a generous 5k floor
        # proves the batched path without being machine-flaky.
        assert rows_per_s > 5000, f"bulk ingest only {rows_per_s:.0f} rows/s (elapsed {elapsed:.2f}s)"
        assert store.count(tenant) == n
        assert store.list_current_page(tenant, limit=1, include_total=True)[1] == n
    finally:
        reset_current_tenant(tok)
