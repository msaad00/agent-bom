"""Sub-linear hub severity snapshot for /v1/overview (wave-2 residual #3).

``_hub_severity_snapshot`` fed the overview headline AND the cache fingerprint,
so its O(rows) ``severity_breakdown`` GROUP BY ran on every request. It is now
memoised per tenant and invalidated on every hub-ledger mutation (ingest /
clear), so repeated overview reads stay O(1) while the counts remain identical
to the store's live ``severity_breakdown`` truth.
"""

from __future__ import annotations

import os
import time
from types import SimpleNamespace
from uuid import uuid4

import pytest

from agent_bom.api import hub_overview_cache
from agent_bom.api.routes import overview


@pytest.fixture(autouse=True)
def _clean():
    hub_overview_cache.reset_hub_overview_cache()
    yield
    hub_overview_cache.reset_hub_overview_cache()


class _CountingStore:
    def __init__(self, counts: dict[str, int]) -> None:
        self.counts = counts
        self.calls = 0

    def severity_breakdown(self, tenant_id: str) -> dict[str, int]:
        self.calls += 1
        return dict(self.counts)


def _request(tenant: str) -> SimpleNamespace:
    return SimpleNamespace(tenant=tenant)


def test_snapshot_memoised_and_counts_match_store(monkeypatch):
    store = _CountingStore({"critical": 3, "high": 5, "medium": 0, "low": 0, "info": 0, "unknown": 1})
    monkeypatch.setattr(overview, "_tenant_id", lambda request: "acme")
    monkeypatch.setattr(
        "agent_bom.api.compliance_hub_store.get_compliance_hub_store", lambda: store
    )

    first = overview._hub_severity_snapshot(_request("acme"))
    second = overview._hub_severity_snapshot(_request("acme"))

    # Second read is a cache hit — the O(n) GROUP BY ran once.
    assert store.calls == 1
    # Counts identical to the store truth, both reads.
    assert first == second
    assert first["critical"] == 3
    assert first["high"] == 5
    assert first["unknown"] == 1


def test_ingest_invalidates_snapshot(monkeypatch):
    store = _CountingStore({"critical": 1, "high": 0, "medium": 0, "low": 0, "info": 0, "unknown": 0})
    monkeypatch.setattr(overview, "_tenant_id", lambda request: "acme")
    monkeypatch.setattr(
        "agent_bom.api.compliance_hub_store.get_compliance_hub_store", lambda: store
    )

    overview._hub_severity_snapshot(_request("acme"))
    assert store.calls == 1

    # A hub-ledger mutation invalidates the cache; the next read recomputes.
    store.counts = {"critical": 9, "high": 0, "medium": 0, "low": 0, "info": 0, "unknown": 0}
    hub_overview_cache.invalidate_tenant("acme")
    refreshed = overview._hub_severity_snapshot(_request("acme"))
    assert store.calls == 2
    assert refreshed["critical"] == 9


def test_ttl_zero_disables_cache(monkeypatch):
    monkeypatch.setenv("AGENT_BOM_HUB_OVERVIEW_CACHE_TTL_SECONDS", "0")
    store = _CountingStore({"critical": 1, "high": 0, "medium": 0, "low": 0, "info": 0, "unknown": 0})
    monkeypatch.setattr(overview, "_tenant_id", lambda request: "acme")
    monkeypatch.setattr(
        "agent_bom.api.compliance_hub_store.get_compliance_hub_store", lambda: store
    )
    overview._hub_severity_snapshot(_request("acme"))
    overview._hub_severity_snapshot(_request("acme"))
    # TTL<=0 disables memoisation entirely (every read recomputes).
    assert store.calls == 2


def test_store_add_and_clear_invalidate_overview_cache():
    """A hub-ledger mutation via ANY store path drops the cached histogram so the
    next overview read reflects the change (honest counts). Invalidation lives at
    the store layer so it holds regardless of the caller (ingest route, shared
    body, or a direct store call)."""
    from agent_bom.api.compliance_hub_store import InMemoryComplianceHubStore

    store = InMemoryComplianceHubStore()
    seed = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "unknown": 0}

    hub_overview_cache.set_cached_severity("acme", dict(seed))
    store.add("acme", [{"id": "f-1", "severity": "critical", "source": "connector"}])
    assert hub_overview_cache.get_cached_severity("acme") is None

    hub_overview_cache.set_cached_severity("acme", dict(seed))
    store.clear("acme")
    assert hub_overview_cache.get_cached_severity("acme") is None


# ── Live Postgres: cache-hit latency is bounded as rows grow ─────────────────

pg_only = pytest.mark.skipif(
    not os.environ.get("AGENT_BOM_POSTGRES_URL"),
    reason="AGENT_BOM_POSTGRES_URL is required for the live overview-latency test",
)


@pg_only
def test_overview_severity_cache_hit_bounded_and_exact():
    from agent_bom.api import postgres_common
    from agent_bom.api.postgres_common import _tenant_connection, reset_current_tenant, set_current_tenant
    from agent_bom.api.postgres_compliance_hub import PostgresComplianceHubStore

    postgres_common.reset_pool()
    store = PostgresComplianceHubStore()
    monkey_tenant = f"ovc-{uuid4().hex}"
    sevs = ["critical", "high", "medium", "low", "info"]

    def chunk(base: int, n: int):
        return [{"id": f"f-{base + i}", "severity": sevs[(base + i) % 5], "source": "connector"} for i in range(n)]

    tok = set_current_tenant(monkey_tenant)
    try:
        loaded = 0
        target = 300_000
        while loaded < target:
            step = min(50_000, target - loaded)
            with _tenant_connection(store._pool) as conn:
                store._write_ledger_batch(conn, monkey_tenant, chunk(loaded, step))
                conn.commit()
            loaded += step

        truth = store.severity_breakdown(monkey_tenant)

        # Prime the cache (one O(n) scan), then a warm read must be O(1).
        hub_overview_cache.reset_hub_overview_cache()
        hub_overview_cache.set_cached_severity(monkey_tenant, truth)

        start = time.perf_counter()
        for _ in range(50):
            cached = hub_overview_cache.get_cached_severity(monkey_tenant)
        warm_ms = (time.perf_counter() - start) / 50 * 1000

        assert cached == truth  # identical to SQL truth
        # A cache hit is a dict copy — sub-millisecond regardless of row count,
        # versus a ~360ms GROUP BY at this scale.
        assert warm_ms < 5.0, f"cache-hit read {warm_ms:.3f} ms is not O(1)"
    finally:
        reset_current_tenant(tok)
        postgres_common.reset_pool()
