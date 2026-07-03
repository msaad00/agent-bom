"""Server-side pagination for the Compliance Hub store (P1-A PR1).

Regression coverage for the O(n) ``GET /v1/findings`` read path: the audit
measured 7.3s p50 at 1M rows even with ``limit=1`` because the store loaded
the whole tenant before Python sort/paginate. ``list_page`` pushes
``ORDER BY`` / ``LIMIT`` / ``OFFSET`` (and severity/scan_id/origin filters)
into the backend, backed by the ``effective_reach_score`` column + index.

These tests exercise the in-memory and SQLite backends directly; the Postgres
backend shares the same helpers and SQL shape but requires a live database
(covered by the Postgres contract suite when ``AGENT_BOM_POSTGRES_URL`` is set).
"""

from __future__ import annotations

import json
import sqlite3
from typing import Any

import pytest

from agent_bom.api.compliance_hub_store import (
    InMemoryComplianceHubStore,
    SQLiteComplianceHubStore,
    compute_effective_reach_score,
)

_SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1}

_SEEDED = 1200


def _finding(i: int) -> dict[str, Any]:
    # Deterministic, spread-out reach + cvss so ordering is unambiguous.
    return {
        "id": f"f-{i:05d}",
        "source": "external-agent",
        "origin": "bulk_ingest",
        "severity": ["low", "medium", "high", "critical"][i % 4],
        "cvss_score": round((i % 100) / 10.0, 1),
        "effective_reach_score": float(i % 500),
        "scan_id": "scan-a" if i % 2 == 0 else "scan-b",
    }


def _make_store(kind: str, tmp_path):
    if kind == "memory":
        return InMemoryComplianceHubStore()
    return SQLiteComplianceHubStore(str(tmp_path / "hub.db"))


@pytest.fixture(params=["memory", "sqlite"])
def seeded_store(request, tmp_path):
    store = _make_store(request.param, tmp_path)
    tenant = "tenant-scale"
    # Batch the insert so SQLite does one transaction for 1200 rows.
    store.add(tenant, [_finding(i) for i in range(_SEEDED)])
    return store, tenant


def test_list_page_limits_rows_and_reports_total(seeded_store) -> None:
    store, tenant = seeded_store
    rows, total = store.list_page(tenant, limit=10, offset=0)
    assert len(rows) == 10, "limit must be honored server-side"
    assert total == _SEEDED, "total must count all matching rows, not just the page"


def test_list_page_can_skip_total_count(seeded_store) -> None:
    store, tenant = seeded_store
    rows, total = store.list_page(tenant, limit=10, offset=5, include_total=False)
    assert len(rows) == 10
    assert total is None


def test_severity_breakdown_and_framework_counts(seeded_store) -> None:
    store, tenant = seeded_store
    breakdown = store.severity_breakdown(tenant)
    assert sum(breakdown.values()) == _SEEDED
    framework_counts = store.framework_slug_counts(tenant)
    assert framework_counts == {}


def test_list_page_effective_reach_sort_is_descending(seeded_store) -> None:
    store, tenant = seeded_store
    rows, total = store.list_page(tenant, limit=25, offset=0, sort="effective_reach")
    assert total == _SEEDED
    scores = [compute_effective_reach_score(r) for r in rows]
    assert scores == sorted(scores, reverse=True), "default sort must be effective_reach DESC"
    # Highest possible reach in the seed is 499; top page must start there.
    assert scores[0] == 499.0


def test_list_page_offset_walks_without_overlap(seeded_store) -> None:
    store, tenant = seeded_store
    first, _ = store.list_page(tenant, limit=20, offset=0, sort="effective_reach")
    second, _ = store.list_page(tenant, limit=20, offset=20, sort="effective_reach")
    ids_first = {r["id"] for r in first}
    ids_second = {r["id"] for r in second}
    assert not (ids_first & ids_second), "adjacent pages must not overlap"
    # Reach is non-increasing across the page boundary.
    assert compute_effective_reach_score(first[-1]) >= compute_effective_reach_score(second[0])


def test_list_page_ordinal_sort_preserves_ingest_order(seeded_store) -> None:
    store, tenant = seeded_store
    rows, _ = store.list_page(tenant, limit=5, offset=0, sort="ordinal")
    assert [r["id"] for r in rows] == [f"f-{i:05d}" for i in range(5)]


def test_list_page_severity_filter_pushed_down(seeded_store) -> None:
    store, tenant = seeded_store
    rows, total = store.list_page(tenant, limit=1000, offset=0, severity="critical")
    assert total == _SEEDED // 4
    assert all(r["severity"] == "critical" for r in rows)


def test_list_page_scan_id_filter_pushed_down(seeded_store) -> None:
    store, tenant = seeded_store
    rows, total = store.list_page(tenant, limit=1000, offset=0, scan_id="scan-a")
    assert total == _SEEDED // 2
    assert all(r["scan_id"] == "scan-a" for r in rows)


def test_list_page_origin_filter_excludes_non_bulk(tmp_path) -> None:
    store = SQLiteComplianceHubStore(str(tmp_path / "hub.db"))
    tenant = "tenant-mixed"
    store.add(tenant, [_finding(i) for i in range(50)])
    store.add(tenant, [{"id": "compliance-1", "source": "sarif", "origin": "native_scan", "severity": "high"}])
    rows, total = store.list_page(tenant, limit=1000, offset=0, origin="bulk_ingest")
    assert total == 50
    assert all(r.get("origin") == "bulk_ingest" for r in rows)


def test_list_page_cvss_sort_is_descending(seeded_store) -> None:
    store, tenant = seeded_store
    rows, _ = store.list_page(tenant, limit=15, offset=0, sort="cvss")
    scores = [float(r.get("cvss_score") or 0.0) for r in rows]
    assert scores == sorted(scores, reverse=True)


def test_list_page_severity_sort_is_rank_descending(seeded_store) -> None:
    """Severity sort must order by band rank (critical>high>medium>low), not
    the alphabetical text — the numeric ``severity_rank`` column preserves this
    after the move off ``json_extract`` (#3192)."""
    store, tenant = seeded_store
    rows, _ = store.list_page(tenant, limit=40, offset=0, sort="severity")
    ranks = [_SEVERITY_RANK.get(str(r.get("severity", "")).lower(), 0) for r in rows]
    assert ranks == sorted(ranks, reverse=True), "severity sort must be rank DESC"
    # The seed spreads all four bands; the top page must start at critical.
    assert rows[0]["severity"] == "critical"


def test_sqlite_severity_sort_uses_index(tmp_path) -> None:
    """Filtered severity sort must ride the composite severity index, not a
    temp-B-tree filesort over json_extract (#3192)."""
    store = SQLiteComplianceHubStore(str(tmp_path / "hub.db"))
    tenant = "tenant-plan"
    store.add(tenant, [_finding(i) for i in range(200)])
    plan = store._conn.execute(  # noqa: SLF001 - inspecting query plan in-test
        "EXPLAIN QUERY PLAN SELECT payload FROM compliance_hub_findings "
        "WHERE tenant_id = ? AND origin = ? ORDER BY severity_rank DESC, ordinal LIMIT 10 OFFSET 0",
        (tenant, "bulk_ingest"),
    ).fetchall()
    text = " ".join(str(row[-1]) for row in plan)
    assert "USING" in text and "INDEX" in text and "severity" in text, text
    assert "USE TEMP B-TREE FOR ORDER BY" not in text, text
    assert "SCAN compliance_hub_findings" not in text, text


def test_sqlite_cvss_sort_uses_index(tmp_path) -> None:
    """Filtered cvss sort must ride the composite cvss index, not a
    temp-B-tree filesort over json_extract (#3192)."""
    store = SQLiteComplianceHubStore(str(tmp_path / "hub.db"))
    tenant = "tenant-plan"
    store.add(tenant, [_finding(i) for i in range(200)])
    plan = store._conn.execute(  # noqa: SLF001 - inspecting query plan in-test
        "EXPLAIN QUERY PLAN SELECT payload FROM compliance_hub_findings "
        "WHERE tenant_id = ? AND origin = ? ORDER BY cvss_score DESC, ordinal LIMIT 10 OFFSET 0",
        (tenant, "bulk_ingest"),
    ).fetchall()
    text = " ".join(str(row[-1]) for row in plan)
    assert "USING" in text and "INDEX" in text and "cvss" in text, text
    assert "USE TEMP B-TREE FOR ORDER BY" not in text, text
    assert "SCAN compliance_hub_findings" not in text, text


def test_sqlite_migration_backfills_sort_columns(tmp_path) -> None:
    """A pre-#3192 table (no severity/cvss columns) must be migrated in place:
    the columns are added and backfilled from the stored payload so legacy rows
    sort correctly without a rewrite."""
    db_path = str(tmp_path / "legacy.db")
    conn = sqlite3.connect(db_path)
    conn.execute(
        """
        CREATE TABLE compliance_hub_findings (
            tenant_id TEXT NOT NULL,
            finding_id TEXT NOT NULL,
            ingested_at TEXT NOT NULL,
            source TEXT NOT NULL,
            applicable_frameworks_csv TEXT NOT NULL DEFAULT '',
            payload TEXT NOT NULL,
            ordinal INTEGER NOT NULL,
            PRIMARY KEY (tenant_id, finding_id, ordinal)
        )
        """
    )
    payload = {"id": "legacy-1", "severity": "critical", "cvss_score": 9.8, "origin": "bulk_ingest"}
    conn.execute(
        "INSERT INTO compliance_hub_findings (tenant_id, finding_id, ingested_at, source, payload, ordinal) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        ("tenant-legacy", "legacy-1", "2026-01-01T00:00:00Z", "sarif", json.dumps(payload), 1),
    )
    conn.commit()
    conn.close()

    # Re-opening through the store must migrate + backfill the new columns.
    store = SQLiteComplianceHubStore(db_path)
    row = store._conn.execute(  # noqa: SLF001 - verifying backfilled columns
        "SELECT severity, severity_rank, cvss_score FROM compliance_hub_findings WHERE finding_id = ?",
        ("legacy-1",),
    ).fetchone()
    assert row == ("critical", 4, 9.8)

    rows, _ = store.list_page("tenant-legacy", limit=5, sort="severity")
    assert rows[0]["id"] == "legacy-1"


def test_sqlite_effective_reach_sort_uses_index(tmp_path) -> None:
    """The default sort must be an index-backed scan, not a full-table sort —
    that is the whole point of the ``effective_reach_score`` column + index."""
    store = SQLiteComplianceHubStore(str(tmp_path / "hub.db"))
    tenant = "tenant-plan"
    store.add(tenant, [_finding(i) for i in range(200)])
    # Mirror the real read-path query: tenant + origin filter, reach-ordered.
    page_plan = store._conn.execute(  # noqa: SLF001 - inspecting query plan in-test
        "EXPLAIN QUERY PLAN SELECT payload FROM compliance_hub_findings "
        "WHERE tenant_id = ? AND origin = ? ORDER BY effective_reach_score DESC, ordinal LIMIT 10 OFFSET 0",
        (tenant, "bulk_ingest"),
    ).fetchall()
    page_text = " ".join(str(row[-1]) for row in page_plan)
    # The reach-ordered page must ride a hub read index, not sort in a temp tree.
    assert "USING" in page_text and "INDEX" in page_text and "reach" in page_text, page_text
    assert "USE TEMP B-TREE FOR ORDER BY" not in page_text, page_text

    # The COUNT for total must also ride an index prefix, not a full scan.
    count_plan = store._conn.execute(  # noqa: SLF001 - inspecting query plan in-test
        "EXPLAIN QUERY PLAN SELECT COUNT(*) FROM compliance_hub_findings WHERE tenant_id = ? AND origin = ?",
        (tenant, "bulk_ingest"),
    ).fetchall()
    count_text = " ".join(str(row[-1]) for row in count_plan)
    assert "USING" in count_text and "INDEX" in count_text, count_text
    assert "SCAN compliance_hub_findings" not in count_text, count_text
