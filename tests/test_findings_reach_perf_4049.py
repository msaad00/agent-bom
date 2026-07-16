"""Read-path perf regressions for #4049.

The unfiltered default (``effective_reach``) findings sort was the slowest 1M-row
read on the hot path — ~20x the ``cvss`` sort. Two independent causes:

1. In-memory backend re-derived ``symbol_reachability_from_payload`` for every
   row on every read (``compute_effective_reach_score`` in the sort comparator),
   even though the composite is already materialised at ingest.
2. SQL backends only had origin-scoped ``(tenant_id, origin, <col> DESC, ordinal)``
   sort indexes, so the *unfiltered* ``ORDER BY <col> DESC, ordinal`` fell back to
   a temp-B-tree filesort (``origin`` is an unconstrained middle column).

These tests pin: the in-memory read trusts the materialised score (no per-row
re-derivation) with byte-identical ordering, and the SQL unfiltered default sorts
ride a non-origin index range scan (no filesort) while the origin-scoped indexes
still serve the filtered reads.
"""

from __future__ import annotations

import sys

from agent_bom.api import compliance_hub_store as chs
from agent_bom.api.compliance_hub_store import (
    InMemoryComplianceHubStore,
    SQLiteComplianceHubStore,
    compute_effective_reach_score,
)

SYMS = (None, "reachable", "unreachable", "unknown")


def _findings(count: int, *, origin: str = "bulk_ingest") -> list[dict]:
    rows: list[dict] = []
    for i in range(count):
        sym = SYMS[i % len(SYMS)]
        base = float((i * 7) % 90)
        row: dict = {
            "id": f"{origin}:{i}",
            "title": f"Finding {i}",
            "severity": ("critical", "high", "medium", "low")[i % 4],
            "cvss_score": float(i % 10),
            "origin": origin,
            "source": "test_4049",
            "effective_reach_score": base,
            "effective_reach": {"composite": base, "band": "med"},
        }
        if sym is not None:
            row["symbol_reachability"] = sym
        rows.append(row)
    return rows


# ── In-memory: trust the materialised score, no per-row re-derivation ─────────


def test_inmemory_read_does_not_rederive_reach_per_row(monkeypatch) -> None:
    store = InMemoryComplianceHubStore()
    store.add("t", _findings(500))

    calls = {"n": 0}
    real = chs.compute_effective_reach_score

    def _counting(payload):
        calls["n"] += 1
        return real(payload)

    monkeypatch.setattr(chs, "compute_effective_reach_score", _counting)

    calls["n"] = 0
    store.list_page("t", limit=50, sort="effective_reach")
    # The read path must not re-derive the composite per row: the score is
    # materialised at ingest and trusted on read.
    assert calls["n"] == 0, f"read re-derived reach {calls['n']} times"


def test_inmemory_reach_ordering_unchanged() -> None:
    """Ordering is byte-identical to sorting by compute_effective_reach_score."""
    store = InMemoryComplianceHubStore()
    findings = _findings(400)
    store.add("t", findings)

    rows, total = store.list_page("t", limit=400, sort="effective_reach")
    got = [r["id"] for r in rows]
    assert total == 400

    # Reference order: descending composite, stable on ingest order (ordinal ASC).
    reference = sorted(
        enumerate(findings),
        key=lambda pair: (-compute_effective_reach_score(pair[1]), pair[0]),
    )
    expected = [f["id"] for _, f in reference]
    assert got == expected


def test_inmemory_read_does_not_leak_sort_scalar() -> None:
    store = InMemoryComplianceHubStore()
    store.add("t", _findings(20))
    rows, _ = store.list_page("t", limit=20, sort="effective_reach")
    for row in rows:
        assert chs._REACH_SORT_KEY not in row, row.keys()
    # ``list`` must not leak it either.
    for row in store.list("t"):
        assert chs._REACH_SORT_KEY not in row


def test_inmemory_reach_matches_after_idempotent_refresh() -> None:
    """A resend of the same finding refreshes the materialised score in place."""
    store = InMemoryComplianceHubStore()
    store.add("t", [{"id": "x", "origin": "bulk_ingest", "effective_reach_score": 10.0, "effective_reach": {"composite": 10.0}}])
    store.add("t", [{"id": "x", "origin": "bulk_ingest", "effective_reach_score": 90.0, "effective_reach": {"composite": 90.0}}])
    store.add("t", [{"id": "y", "origin": "bulk_ingest", "effective_reach_score": 50.0, "effective_reach": {"composite": 50.0}}])
    rows, _ = store.list_page("t", limit=10, sort="effective_reach")
    assert [r["id"] for r in rows] == ["x", "y"]  # x refreshed to 90 > y 50


# ── SQLite: unfiltered default sorts ride a non-origin index (no filesort) ────


def _seed_sqlite(tmp_path) -> SQLiteComplianceHubStore:
    store = SQLiteComplianceHubStore(str(tmp_path / "hub.db"))
    store.add("t", _findings(600, origin="bulk_ingest") + _findings(120, origin="scan"))
    return store


def _plan(conn, sql, params) -> str:
    rows = conn.execute("EXPLAIN QUERY PLAN " + sql, params).fetchall()
    return " | ".join(r[3] for r in rows)


def test_sqlite_unfiltered_reach_uses_index_no_filesort(tmp_path) -> None:
    store = _seed_sqlite(tmp_path)
    detail = _plan(
        store._conn,
        "SELECT payload FROM compliance_hub_findings WHERE tenant_id=? "
        "ORDER BY effective_reach_score DESC, ordinal ASC LIMIT 51",
        ("t",),
    )
    assert "TEMP B-TREE" not in detail.upper(), detail
    assert "idx_hub_findings_tenant_reach_all" in detail, detail


def test_sqlite_unfiltered_cvss_uses_index_no_filesort(tmp_path) -> None:
    store = _seed_sqlite(tmp_path)
    detail = _plan(
        store._conn,
        "SELECT payload FROM compliance_hub_findings WHERE tenant_id=? "
        "ORDER BY cvss_score DESC, ordinal ASC LIMIT 51",
        ("t",),
    )
    assert "TEMP B-TREE" not in detail.upper(), detail
    assert "idx_hub_findings_tenant_cvss_all" in detail, detail


def test_sqlite_unfiltered_severity_uses_index_no_filesort(tmp_path) -> None:
    store = _seed_sqlite(tmp_path)
    detail = _plan(
        store._conn,
        "SELECT payload FROM compliance_hub_findings WHERE tenant_id=? "
        "ORDER BY severity_rank DESC, ordinal ASC LIMIT 51",
        ("t",),
    )
    assert "TEMP B-TREE" not in detail.upper(), detail
    assert "idx_hub_findings_tenant_severity_all" in detail, detail


def test_sqlite_origin_filtered_reach_still_uses_origin_index(tmp_path) -> None:
    """Adding the non-origin index must NOT regress the filtered read plan."""
    store = _seed_sqlite(tmp_path)
    detail = _plan(
        store._conn,
        "SELECT payload FROM compliance_hub_findings WHERE tenant_id=? AND origin=? "
        "ORDER BY effective_reach_score DESC, ordinal ASC LIMIT 51",
        ("t", "bulk_ingest"),
    )
    assert "TEMP B-TREE" not in detail.upper(), detail
    assert "idx_hub_findings_tenant_origin_reach" in detail, detail


def test_sqlite_origin_scoped_scan_filter_not_shadowed(tmp_path) -> None:
    """Production reads always scope by origin — the new non-origin covering
    index must not steal the origin+scan filtered plan (it still rides an
    origin-scoped index, not ``idx_hub_findings_tenant_reach_all``)."""
    store = _seed_sqlite(tmp_path)
    detail = _plan(
        store._conn,
        "SELECT payload FROM compliance_hub_findings WHERE tenant_id=? AND origin=? "
        "AND scan_id=? AND scan_id!='' ORDER BY effective_reach_score DESC, ordinal ASC LIMIT 51",
        ("t", "bulk_ingest", "s1"),
    )
    assert "idx_hub_findings_tenant_reach_all" not in detail, detail
    assert "origin" in detail, detail


def test_sqlite_new_indexes_exist(tmp_path) -> None:
    store = _seed_sqlite(tmp_path)
    names = {r[0] for r in store._conn.execute("SELECT name FROM sqlite_master WHERE type='index'").fetchall()}
    assert {
        "idx_hub_findings_tenant_reach_all",
        "idx_hub_findings_tenant_cvss_all",
        "idx_hub_findings_tenant_severity_all",
    } <= names
    # The origin-scoped indexes are retained for filtered reads.
    assert "idx_hub_findings_tenant_origin_reach" in names


def test_sqlite_unfiltered_reach_ordering_matches_reference(tmp_path) -> None:
    findings = _findings(300)
    sqlite_store = SQLiteComplianceHubStore(str(tmp_path / "o.db"))
    sqlite_store.add("t", findings)
    rows, _ = sqlite_store.list_page("t", limit=300, sort="effective_reach")
    got = [r["id"] for r in rows]
    reference = sorted(
        enumerate(findings),
        key=lambda pair: (-compute_effective_reach_score(pair[1]), pair[0]),
    )
    assert got == [f["id"] for _, f in reference]


# ── Postgres: mirror the non-origin indexes (mock pool, no live PG) ───────────


def test_postgres_creates_non_origin_sort_indexes() -> None:
    sys.path.insert(0, "tests")
    from test_postgres_store import MockPool  # noqa: PLC0415

    from agent_bom.api.postgres_compliance_hub import PostgresComplianceHubStore  # noqa: PLC0415

    pool = MockPool()
    PostgresComplianceHubStore(pool=pool)
    issued = " ".join(" ".join(sql.split()) for sql, _ in pool._conn.executed)
    assert "idx_hub_findings_tenant_reach_all ON compliance_hub_findings(tenant_id, effective_reach_score DESC, ordinal)" in issued
    assert "idx_hub_findings_tenant_cvss_all ON compliance_hub_findings(tenant_id, cvss_score DESC, ordinal)" in issued
    assert "idx_hub_findings_tenant_severity_all ON compliance_hub_findings(tenant_id, severity_rank DESC, ordinal)" in issued
