"""Scale-tail fixes for ``hub_findings_current`` reads (#3984).

Two regressions this pins:

1. ``sort=ordinal`` used a per-row correlated subquery against the ledger to
   recover ingest order — a full scan + temp-B-tree filesort at scale. The
   ingest ordinal is now materialised into a ``ledger_ordinal`` column at
   upsert time, so the order clause is a bare ``ORDER BY ledger_ordinal`` that
   rides ``idx_hub_findings_current_tenant_ordinal`` as an ordered range scan.

2. Severity-filtered + reach/cvss-ordered pages could not ride one index: the
   ``LOWER(severity)`` partial index was equality-only (no sort key). New
   composites ``(tenant_id, LOWER(severity), <sort_key> DESC, …)`` back the
   filter *and* the sort with a single index (no filesort).

The EXPLAIN assertions mirror the existing sargability suite
(``test_findings_current_sargable_3926``).
"""

from __future__ import annotations

import sqlite3

from agent_bom.api.compliance_hub_store import (
    _LEDGER_ORDINAL_SENTINEL,
    SQLiteComplianceHubStore,
    _sqlite_current_order_clause,
)


def _findings(count: int, *, batch_id: str, severity: str = "high") -> list[dict]:
    return [
        {
            "id": f"{batch_id}:{ordinal}",
            "title": f"Finding {ordinal}",
            "severity": severity,
            "cvss_score": float(ordinal % 10),
            "effective_reach_score": float(ordinal % 7),
            "origin": "bulk_ingest",
            "source": "test_3984",
            "batch_id": batch_id,
        }
        for ordinal in range(1, count + 1)
    ]


def _seed(tmp_path, *, a: int = 40, b: int = 60) -> SQLiteComplianceHubStore:
    store = SQLiteComplianceHubStore(str(tmp_path / "hub.db"))
    tenant = "t-3984"
    rows_a = _findings(a, batch_id="scan-a", severity="critical")
    rows_b = _findings(b, batch_id="scan-b", severity="medium")
    store.add(tenant, rows_a + rows_b)
    store.upsert_current_batch(tenant, rows_a, observed_at="2026-07-06T00:00:00Z", batch_id="scan-a", source="test_3984")
    store.upsert_current_batch(tenant, rows_b, observed_at="2026-07-06T01:00:00Z", batch_id="scan-b", source="test_3984")
    return store


# ── ordinal order clause: no correlated subquery, materialised column ─────────


def test_ordinal_order_clause_has_no_correlated_subquery() -> None:
    clause = _sqlite_current_order_clause("ordinal")
    assert clause == "ORDER BY ledger_ordinal ASC, first_seen ASC, canonical_id ASC"
    # The old per-row ledger subquery is gone.
    assert "SELECT" not in clause.upper()
    assert "compliance_hub_findings" not in clause


def test_ordinal_read_rides_ordinal_index_not_a_subquery(tmp_path) -> None:
    store = _seed(tmp_path)
    conn = store._conn
    clause = _sqlite_current_order_clause("ordinal")
    plan = conn.execute(
        f"EXPLAIN QUERY PLAN SELECT canonical_id FROM hub_findings_current "
        f"WHERE tenant_id=? {clause} LIMIT 20",
        ("t-3984",),
    ).fetchall()
    detail = " | ".join(row[3] for row in plan)
    assert "idx_hub_findings_current_tenant_ordinal" in detail, detail
    assert "CORRELATED" not in detail.upper(), detail
    assert "USE TEMP B-TREE" not in detail.upper(), detail
    # No join back to the ledger table on the read path.
    assert "compliance_hub_findings" not in detail, detail


# ── ledger_ordinal is materialised + preserves ingest order ───────────────────


def test_ledger_ordinal_materialised_from_ledger(tmp_path) -> None:
    store = _seed(tmp_path, a=5, b=5)
    conn = store._conn
    got = dict(
        conn.execute(
            "SELECT ledger_finding_id, ledger_ordinal FROM hub_findings_current WHERE tenant_id=?",
            ("t-3984",),
        ).fetchall()
    )
    # Every current row points at a ledger row, so none carry the sentinel.
    assert got, got
    assert all(v != _LEDGER_ORDINAL_SENTINEL for v in got.values()), got
    # The materialised ordinal equals the ledger's own ordinal for that id.
    for finding_id, ordinal in got.items():
        ledger = conn.execute(
            "SELECT ordinal FROM compliance_hub_findings WHERE tenant_id=? AND finding_id=?",
            ("t-3984", finding_id),
        ).fetchone()
        assert ledger is not None and int(ledger[0]) == ordinal


def test_ordinal_sort_preserves_ingest_order(tmp_path) -> None:
    store = _seed(tmp_path, a=30, b=0)
    page, total, _ = store.list_current_page("t-3984", limit=100, sort="ordinal")
    assert total == 30
    ids = [row.get("id") for row in page]
    assert ids == [f"scan-a:{i}" for i in range(1, 31)]


def test_row_without_ledger_pointer_sorts_last_via_sentinel(tmp_path) -> None:
    """A current row with no ledger pointer carries the sort sentinel so it sorts
    after every ledger-backed row (parity with the old COALESCE fallback)."""
    store = SQLiteComplianceHubStore(str(tmp_path / "hub.db"))
    ledgered = _findings(3, batch_id="scan-a")
    store.add("t", ledgered)
    store.upsert_current_batch("t", ledgered, observed_at="2026-07-06T00:00:00Z", batch_id="scan-a", source="test_3984")
    # Upsert a finding that was never added to the ledger.
    orphan = {"id": "orphan:1", "title": "Orphan", "severity": "low", "origin": "bulk_ingest", "source": "test_3984"}
    store.upsert_current_batch("t", [orphan], observed_at="2026-07-06T02:00:00Z", batch_id="scan-b", source="test_3984")
    conn = store._conn
    orphan_ordinal = conn.execute(
        "SELECT ledger_ordinal FROM hub_findings_current WHERE tenant_id=? AND payload LIKE '%orphan:1%'",
        ("t",),
    ).fetchone()
    assert orphan_ordinal is not None and int(orphan_ordinal[0]) == _LEDGER_ORDINAL_SENTINEL
    page, _, _ = store.list_current_page("t", limit=100, sort="ordinal")
    assert page[-1].get("id") == "orphan:1"


# ── severity-filtered + sorted rides one composite index (no filesort) ────────


def test_severity_filter_reach_sort_uses_composite(tmp_path) -> None:
    store = _seed(tmp_path)
    conn = store._conn
    plan = conn.execute(
        "EXPLAIN QUERY PLAN SELECT canonical_id FROM hub_findings_current "
        "WHERE tenant_id=? AND severity != '' AND LOWER(severity)=? "
        "ORDER BY effective_reach_score DESC, last_seen DESC, canonical_id ASC LIMIT 20",
        ("t-3984", "critical"),
    ).fetchall()
    detail = " | ".join(row[3] for row in plan)
    assert "idx_hub_findings_current_tenant_severity_reach" in detail, detail
    assert "USE TEMP B-TREE" not in detail.upper(), detail


def test_severity_filter_cvss_sort_uses_composite(tmp_path) -> None:
    store = _seed(tmp_path)
    conn = store._conn
    plan = conn.execute(
        "EXPLAIN QUERY PLAN SELECT canonical_id FROM hub_findings_current "
        "WHERE tenant_id=? AND severity != '' AND LOWER(severity)=? "
        "ORDER BY cvss_score DESC, last_seen DESC, canonical_id ASC LIMIT 20",
        ("t-3984", "medium"),
    ).fetchall()
    detail = " | ".join(row[3] for row in plan)
    assert "idx_hub_findings_current_tenant_severity_cvss" in detail, detail
    assert "USE TEMP B-TREE" not in detail.upper(), detail


def test_severity_filtered_sorted_results_are_correct(tmp_path) -> None:
    """The composite must not change results: severity filter still exact +
    case-insensitive, ordering still reach-desc."""
    store = _seed(tmp_path)
    rows, total, _ = store.list_current_page("t-3984", limit=1000, sort="effective_reach", severity="CRITICAL")
    assert total == 40
    assert all(str(r.get("severity")).lower() == "critical" for r in rows)
    reach = [float(r.get("effective_reach_score") or 0.0) for r in rows]
    assert reach == sorted(reach, reverse=True)


# ── migration: pre-existing table backfilled + idempotent + empty-safe ────────


def _legacy_current_ddl() -> str:
    # hub_findings_current shape *before* ledger_ordinal — but with the
    # ledger_finding_id pointer the backfill reads from.
    return """
    CREATE TABLE hub_findings_current (
        tenant_id TEXT NOT NULL, canonical_id TEXT NOT NULL,
        first_seen TEXT NOT NULL, last_seen TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'open', severity TEXT NOT NULL DEFAULT '',
        severity_rank INTEGER NOT NULL DEFAULT 0, cvss_score REAL,
        effective_reach_score REAL NOT NULL DEFAULT 0, scan_count INTEGER NOT NULL DEFAULT 1,
        resolved_at TEXT, reopened_at TEXT, updated_at TEXT NOT NULL, payload TEXT NOT NULL,
        ledger_finding_id TEXT, origin TEXT NOT NULL DEFAULT '', scan_id TEXT NOT NULL DEFAULT '',
        PRIMARY KEY (tenant_id, canonical_id)
    );
    CREATE TABLE compliance_hub_findings (
        tenant_id TEXT NOT NULL, finding_id TEXT NOT NULL, ingested_at TEXT NOT NULL,
        source TEXT NOT NULL, applicable_frameworks_csv TEXT NOT NULL DEFAULT '',
        payload TEXT NOT NULL, ordinal INTEGER NOT NULL,
        effective_reach_score REAL NOT NULL DEFAULT 0, origin TEXT NOT NULL DEFAULT '',
        severity TEXT NOT NULL DEFAULT '', severity_rank INTEGER NOT NULL DEFAULT 0,
        cvss_score REAL NOT NULL DEFAULT 0, scan_id TEXT NOT NULL DEFAULT '',
        PRIMARY KEY (tenant_id, finding_id)
    );
    """


def test_migration_backfills_ledger_ordinal_for_preexisting_rows(tmp_path) -> None:
    db = str(tmp_path / "legacy.db")
    conn = sqlite3.connect(db)
    conn.executescript(_legacy_current_ddl())
    conn.executemany(
        "INSERT INTO compliance_hub_findings (tenant_id, finding_id, ingested_at, source, payload, ordinal) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        [
            ("t", "f-a", "2026-01-01T00:00:00Z", "s", "{}", 7),
            ("t", "f-b", "2026-01-01T00:00:00Z", "s", "{}", 12),
        ],
    )
    conn.executemany(
        "INSERT INTO hub_findings_current "
        "(tenant_id, canonical_id, first_seen, last_seen, updated_at, payload, ledger_finding_id) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        [
            ("t", "c-a", "2026-01-01T00:00:00Z", "2026-01-01T00:00:00Z", "2026-01-01T00:00:00Z", "{}", "f-a"),
            ("t", "c-b", "2026-01-01T00:00:00Z", "2026-01-01T00:00:00Z", "2026-01-01T00:00:00Z", "{}", "f-b"),
            # No ledger pointer -> keeps the sentinel.
            ("t", "c-orphan", "2026-01-01T00:00:00Z", "2026-01-01T00:00:00Z", "2026-01-01T00:00:00Z", "{}", None),
        ],
    )
    conn.commit()
    conn.close()

    store = SQLiteComplianceHubStore(db)
    conn2 = store._conn
    cols = {r[1] for r in conn2.execute("PRAGMA table_info(hub_findings_current)").fetchall()}
    assert "ledger_ordinal" in cols
    got = dict(conn2.execute("SELECT canonical_id, ledger_ordinal FROM hub_findings_current").fetchall())
    assert got["c-a"] == 7
    assert got["c-b"] == 12
    assert got["c-orphan"] == _LEDGER_ORDINAL_SENTINEL


def test_migration_is_idempotent_and_empty_safe(tmp_path) -> None:
    db = str(tmp_path / "empty.db")
    # First init creates the schema on an empty DB (no rows to backfill).
    store = SQLiteComplianceHubStore(db)
    cols = {r[1] for r in store._conn.execute("PRAGMA table_info(hub_findings_current)").fetchall()}
    assert "ledger_ordinal" in cols
    # Re-opening the same DB re-runs the guarded migration with no error and no
    # duplicate column.
    store2 = SQLiteComplianceHubStore(db)
    cols2 = [r[1] for r in store2._conn.execute("PRAGMA table_info(hub_findings_current)").fetchall()]
    assert cols2.count("ledger_ordinal") == 1


# ── Postgres parity: DDL constants, migration SQL, resolver ───────────────────


def test_postgres_ddl_declares_ledger_ordinal_and_indexes() -> None:
    from agent_bom.api.finding_lifecycle import (
        _CURRENT_LIFECYCLE_POSTGRES_DDL,
        _CURRENT_LIFECYCLE_SORT_INDEXES_POSTGRES,
    )

    assert "ledger_ordinal BIGINT NOT NULL DEFAULT 9223372036854775807" in _CURRENT_LIFECYCLE_POSTGRES_DDL
    joined = " ".join(_CURRENT_LIFECYCLE_SORT_INDEXES_POSTGRES)
    assert "idx_hub_findings_current_tenant_ordinal" in joined
    assert "idx_hub_findings_current_tenant_severity_reach" in joined
    assert "idx_hub_findings_current_tenant_severity_cvss" in joined
    # ordinal index orders by the materialised column, not a subquery.
    assert "ledger_ordinal ASC, first_seen ASC, canonical_id ASC" in joined


class _ConnSpy:
    def __init__(self, row=None):
        self.executed: list[str] = []
        self._row = row

    def execute(self, sql, params=None):
        self.executed.append(" ".join(sql.split()))
        self._last_params = params
        return self

    def fetchone(self):
        return self._row


def test_postgres_ledger_ordinal_migration_is_guarded_alter_plus_backfill() -> None:
    from agent_bom.api.postgres_compliance_hub import _migrate_current_ledger_ordinal_postgres

    spy = _ConnSpy()
    _migrate_current_ledger_ordinal_postgres(spy)
    sql = " ".join(spy.executed).lower()
    # Column-absence guard, additive ALTER, and one-shot backfill from ledger.
    assert "information_schema.columns" in sql
    assert "column_name = 'ledger_ordinal'" in sql
    assert "add column ledger_ordinal bigint not null default 9223372036854775807" in sql
    assert "update hub_findings_current" in sql
    assert "from compliance_hub_findings f" in sql


def test_postgres_resolver_returns_sentinel_or_ledger_ordinal() -> None:
    from agent_bom.api.postgres_compliance_hub import _resolve_current_ledger_ordinal_postgres

    # Empty pointer -> sentinel, no query issued.
    assert _resolve_current_ledger_ordinal_postgres(_ConnSpy(), "t", "") == _LEDGER_ORDINAL_SENTINEL
    # Present pointer -> ledger ordinal from the point lookup.
    assert _resolve_current_ledger_ordinal_postgres(_ConnSpy(row=(42,)), "t", "f-a") == 42
    # Missing ledger row -> sentinel fallback.
    assert _resolve_current_ledger_ordinal_postgres(_ConnSpy(row=None), "t", "f-x") == _LEDGER_ORDINAL_SENTINEL
