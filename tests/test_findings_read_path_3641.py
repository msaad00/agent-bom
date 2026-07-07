"""Read-path perf regressions for #3641.

Covers the three QA-@500k defects:
1. cvss-sorted current-page reads must ride the cvss index (no temp B-tree
   filesort from a ``COALESCE`` wrapper).
2. the exact ``COUNT(*)`` for an origin filter must ride the
   ``(tenant_id, origin, …)`` index prefix, not scan every row through
   ``json_extract(payload, '$.origin')``.
3. ``approximate_total=true`` on ``offset=0`` must reuse the cached/approximate
   total (with a ``total_approximate`` flag) instead of forcing the O(table)
   exact count on every first page.
"""

from __future__ import annotations

import uuid

from starlette.testclient import TestClient

from agent_bom.api.compliance_hub_store import (
    InMemoryComplianceHubStore,
    SQLiteComplianceHubStore,
    set_compliance_hub_store,
)
from agent_bom.api.server import app
from tests.auth_helpers import disable_trusted_proxy_env, enable_trusted_proxy_env, proxy_headers


def _findings(count: int, *, batch_id: str, origin: str = "bulk_ingest") -> list[dict]:
    rows: list[dict] = []
    for ordinal in range(1, count + 1):
        rows.append(
            {
                "id": f"{origin}:{batch_id}:{ordinal}",
                "title": f"Finding {ordinal}",
                "severity": ("critical", "high", "medium", "low")[ordinal % 4],
                "cvss_score": float(ordinal % 10),
                "origin": origin,
                "source": "test_3641",
                "batch_id": batch_id,
                "bulk_ordinal": ordinal,
            }
        )
    return rows


def _seed_sqlite(tmp_path, *, bulk: int = 400, other: int = 100) -> SQLiteComplianceHubStore:
    store = SQLiteComplianceHubStore(str(tmp_path / "hub.db"))
    tenant = "t-3641"
    bulk_rows = _findings(bulk, batch_id="b1", origin="bulk_ingest")
    other_rows = _findings(other, batch_id="b2", origin="scan")
    store.add(tenant, bulk_rows + other_rows)
    store.upsert_current_batch(tenant, bulk_rows + other_rows, observed_at="2026-07-06T00:00:00Z", batch_id="b1", source="test_3641")
    return store


# ── Defect 1: cvss ORDER BY rides the index (no filesort) ────────────────────


def test_cvss_current_page_uses_index_no_temp_btree(tmp_path) -> None:
    store = _seed_sqlite(tmp_path)
    conn = store._conn
    order_sql = "ORDER BY cvss_score DESC, last_seen DESC, canonical_id ASC"
    plan = conn.execute(
        "EXPLAIN QUERY PLAN "
        f"SELECT canonical_id FROM hub_findings_current WHERE tenant_id=? AND origin=? {order_sql} LIMIT 51",
        ("t-3641", "bulk_ingest"),
    ).fetchall()
    detail = " | ".join(row[3] for row in plan)
    assert "TEMP B-TREE" not in detail.upper(), detail
    assert "idx_hub_findings_current_tenant_origin_cvss" in detail, detail

    # The COALESCE wrapper (the old ORDER BY) still forces a temp B-tree — proves
    # the wrapper is what defeated the index.
    old_plan = conn.execute(
        "EXPLAIN QUERY PLAN "
        "SELECT canonical_id FROM hub_findings_current WHERE tenant_id=? AND origin=? "
        "ORDER BY COALESCE(cvss_score,0) DESC, last_seen DESC, canonical_id ASC LIMIT 51",
        ("t-3641", "bulk_ingest"),
    ).fetchall()
    old_detail = " | ".join(row[3] for row in old_plan).upper()
    assert "TEMP B-TREE" in old_detail, old_detail


def test_cvss_current_page_sorted_descending(tmp_path) -> None:
    store = _seed_sqlite(tmp_path)
    rows, total, _ = store.list_current_page("t-3641", limit=25, sort="cvss", origin="bulk_ingest")
    scores = [r.get("cvss_score") for r in rows]
    assert scores == sorted(scores, reverse=True)
    assert total == 400


def test_cvss_column_is_not_null_default_zero(tmp_path) -> None:
    store = _seed_sqlite(tmp_path)
    cols = {r[1]: r for r in store._conn.execute("PRAGMA table_info(hub_findings_current)").fetchall()}
    assert cols["cvss_score"][3] == 1, "cvss_score must be NOT NULL"  # notnull flag
    nulls = store._conn.execute("SELECT COUNT(*) FROM hub_findings_current WHERE cvss_score IS NULL").fetchone()[0]
    assert nulls == 0


# ── Defect 2: origin is a real, backfilled, indexed column ───────────────────


def test_origin_count_uses_index_not_json_scan(tmp_path) -> None:
    store = _seed_sqlite(tmp_path)
    conn = store._conn
    plan = conn.execute(
        "EXPLAIN QUERY PLAN SELECT COUNT(*) FROM hub_findings_current WHERE tenant_id=? AND origin=?",
        ("t-3641", "bulk_ingest"),
    ).fetchall()
    detail = " | ".join(row[3] for row in plan)
    assert "USING" in detail.upper() and "INDEX" in detail.upper(), detail
    assert "SCAN hub_findings_current" not in detail, detail
    count = conn.execute(
        "SELECT COUNT(*) FROM hub_findings_current WHERE tenant_id=? AND origin=?", ("t-3641", "bulk_ingest")
    ).fetchone()[0]
    assert count == 400


def test_origin_filter_returns_only_matching(tmp_path) -> None:
    store = _seed_sqlite(tmp_path)
    bulk, total_bulk, _ = store.list_current_page("t-3641", limit=1000, sort="cvss", origin="bulk_ingest")
    scan, total_scan, _ = store.list_current_page("t-3641", limit=1000, sort="cvss", origin="scan")
    assert total_bulk == 400 and total_scan == 100
    assert all(r.get("origin") == "bulk_ingest" for r in bulk)
    assert all(r.get("origin") == "scan" for r in scan)


def test_origin_column_backfilled_for_preexisting_rows(tmp_path) -> None:
    """A DB whose current table predates the origin column is migrated + backfilled."""
    import sqlite3

    db = str(tmp_path / "legacy.db")
    conn = sqlite3.connect(db)
    # Old-schema current table: no origin column, nullable cvss.
    conn.executescript(
        """
        CREATE TABLE hub_findings_current (
            tenant_id TEXT NOT NULL, canonical_id TEXT NOT NULL,
            first_seen TEXT NOT NULL, last_seen TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'open', severity TEXT NOT NULL DEFAULT '',
            severity_rank INTEGER NOT NULL DEFAULT 0, cvss_score REAL,
            effective_reach_score REAL NOT NULL DEFAULT 0, scan_count INTEGER NOT NULL DEFAULT 1,
            resolved_at TEXT, reopened_at TEXT, updated_at TEXT NOT NULL, payload TEXT NOT NULL,
            PRIMARY KEY (tenant_id, canonical_id)
        );
        """
    )
    conn.execute(
        "INSERT INTO hub_findings_current (tenant_id, canonical_id, first_seen, last_seen, updated_at, payload, cvss_score) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        ("t", "c1", "2026-01-01T00:00:00Z", "2026-01-01T00:00:00Z", "2026-01-01T00:00:00Z", '{"origin": "bulk_ingest"}', None),
    )
    conn.commit()
    conn.close()

    store = SQLiteComplianceHubStore(db)
    conn2 = store._conn
    cols = {r[1] for r in conn2.execute("PRAGMA table_info(hub_findings_current)").fetchall()}
    assert "origin" in cols
    row = conn2.execute("SELECT origin, cvss_score FROM hub_findings_current WHERE canonical_id='c1'").fetchone()
    assert row[0] == "bulk_ingest"  # backfilled from payload
    assert row[1] == 0  # NULL cvss backfilled to 0


# ── Defect 3: approximate_total honors cache, does not force COUNT ───────────


def setup_module() -> None:
    enable_trusted_proxy_env()


def teardown_module() -> None:
    disable_trusted_proxy_env()


def setup_function() -> None:
    from agent_bom.api.findings_count_cache import reset_findings_count_cache

    reset_findings_count_cache()


def test_approximate_total_offset0_warm_cache_reuses_cached_total() -> None:
    tenant_id = f"approx-{uuid.uuid4().hex}"
    batch_id = f"batch-{uuid.uuid4().hex}"
    store = InMemoryComplianceHubStore()
    set_compliance_hub_store(store)
    findings = _findings(300, batch_id=batch_id)
    store.add(tenant_id, findings)
    store.upsert_current_batch(tenant_id, findings, observed_at="2026-07-06T00:00:00Z", batch_id=batch_id, source="test_3641")

    # Count how many times the store is asked for an exact total.
    real_list = store.list_current_page
    include_total_calls: list[bool] = []

    def _spy(tenant, **kwargs):  # type: ignore[no-untyped-def]
        include_total_calls.append(bool(kwargs.get("include_total")))
        return real_list(tenant, **kwargs)

    store.list_current_page = _spy  # type: ignore[assignment]

    client = TestClient(app)
    headers = proxy_headers(role="viewer", tenant=tenant_id)

    # First offset=0 request warms the cache (exact count once).
    first = client.get("/v1/findings", params={"limit": 50, "offset": 0, "approximate_total": "true"}, headers=headers)
    assert first.status_code == 200, first.text
    assert first.json()["total"] == 300
    assert any(include_total_calls), "first cold call should compute the exact total once"

    include_total_calls.clear()

    # Second offset=0 request with a warm cache must NOT recompute the exact
    # count (the pre-#3641 bug forced it on every offset=0) and must flag the
    # total as approximate.
    warm = client.get("/v1/findings", params={"limit": 50, "offset": 0, "approximate_total": "true"}, headers=headers)
    assert warm.status_code == 200, warm.text
    warm_body = warm.json()
    assert warm_body["total"] == 300
    assert warm_body.get("total_approximate") is True
    assert not any(include_total_calls), "warm offset=0 approximate_total must not force an exact COUNT"
