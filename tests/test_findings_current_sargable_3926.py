"""Sargability of the default ``/v1/findings`` (current-state) scan_id + severity
filters (#3926).

Follow-up to #3641/#3913: the ledger table already rode materialised
``scan_id``/``LOWER(severity)`` indexes, but ``hub_findings_current`` — the
default reach read — still filtered ``scan_id`` via
``json_extract(payload,'$.batch_id'/'$.scan_id')`` and severity via an
unindexed ``LOWER(severity)``. These regressions assert the current-state path
now rides the new partial indexes and preserves the exact filter semantics.
"""

from __future__ import annotations

import sqlite3

from agent_bom.api.compliance_hub_store import SQLiteComplianceHubStore


def _findings(count: int, *, batch_id: str, severity: str = "high") -> list[dict]:
    return [
        {
            "id": f"{batch_id}:{ordinal}",
            "title": f"Finding {ordinal}",
            "severity": severity,
            "cvss_score": float(ordinal % 10),
            "origin": "bulk_ingest",
            "source": "test_3926",
            "batch_id": batch_id,
            "bulk_ordinal": ordinal,
        }
        for ordinal in range(1, count + 1)
    ]


def _seed(tmp_path, *, a: int = 40, b: int = 60) -> SQLiteComplianceHubStore:
    store = SQLiteComplianceHubStore(str(tmp_path / "hub.db"))
    tenant = "t-3926"
    rows_a = _findings(a, batch_id="scan-a", severity="critical")
    rows_b = _findings(b, batch_id="scan-b", severity="Medium")
    store.add(tenant, rows_a + rows_b)
    store.upsert_current_batch(tenant, rows_a, observed_at="2026-07-06T00:00:00Z", batch_id="scan-a", source="test_3926")
    store.upsert_current_batch(tenant, rows_b, observed_at="2026-07-06T01:00:00Z", batch_id="scan-b", source="test_3926")
    return store


# ── scan_id is a real, backfilled, indexed column ────────────────────────────


def test_scan_id_count_uses_index_not_json_scan(tmp_path) -> None:
    store = _seed(tmp_path)
    conn = store._conn
    plan = conn.execute(
        "EXPLAIN QUERY PLAN SELECT COUNT(*) FROM hub_findings_current WHERE tenant_id=? AND scan_id=? AND scan_id != ''",
        ("t-3926", "scan-a"),
    ).fetchall()
    detail = " | ".join(row[3] for row in plan)
    assert "idx_hub_findings_current_tenant_scan" in detail, detail
    assert "SCAN hub_findings_current" not in detail, detail


def test_scan_id_filter_returns_only_matching_batch(tmp_path) -> None:
    store = _seed(tmp_path)
    a_rows, a_total, _ = store.list_current_page("t-3926", limit=1000, scan_id="scan-a")
    b_rows, b_total, _ = store.list_current_page("t-3926", limit=1000, scan_id="scan-b")
    assert a_total == 40 and b_total == 60
    assert all(r.get("batch_id") == "scan-a" for r in a_rows)
    assert all(r.get("batch_id") == "scan-b" for r in b_rows)
    # An unknown scan id matches nothing.
    _, none_total, _ = store.list_current_page("t-3926", limit=1000, scan_id="scan-x")
    assert none_total == 0


def test_scan_id_falls_back_to_payload_scan_id_when_no_batch_id(tmp_path) -> None:
    """Parity with the old ``batch_id OR scan_id`` filter: a payload carrying only
    ``scan_id`` (no batch_id) is still matched via the materialised column."""
    store = SQLiteComplianceHubStore(str(tmp_path / "hub2.db"))
    payload = {
        "id": "only-scan:1",
        "title": "Finding",
        "severity": "high",
        "origin": "bulk_ingest",
        "source": "test_3926",
        "scan_id": "sc-only",
    }
    store.add("t", [payload])
    store.upsert_current_batch("t", [payload], observed_at="2026-07-06T00:00:00Z", batch_id="sc-only", source="test_3926")
    rows, total, _ = store.list_current_page("t", limit=10, scan_id="sc-only")
    assert total == 1 and rows[0]["id"] == "only-scan:1"


# ── LOWER(severity) rides the partial expression index ───────────────────────


def test_severity_count_uses_expression_index(tmp_path) -> None:
    store = _seed(tmp_path)
    conn = store._conn
    plan = conn.execute(
        "EXPLAIN QUERY PLAN SELECT COUNT(*) FROM hub_findings_current "
        "WHERE tenant_id=? AND severity != '' AND LOWER(severity)=?",
        ("t-3926", "critical"),
    ).fetchall()
    detail = " | ".join(row[3] for row in plan)
    assert "idx_hub_findings_current_tenant_severity_ci" in detail, detail
    assert "SCAN hub_findings_current" not in detail, detail


def test_severity_filter_is_case_insensitive(tmp_path) -> None:
    store = _seed(tmp_path)
    # Seed stored "Medium" (mixed case) — a lowercase filter must still match.
    rows, total, _ = store.list_current_page("t-3926", limit=1000, severity="medium")
    assert total == 60
    assert all(str(r.get("severity")).lower() == "medium" for r in rows)


# ── migration backfills the column on pre-existing tables ────────────────────


def test_scan_id_column_backfilled_for_preexisting_rows(tmp_path) -> None:
    """A DB whose current table predates the scan_id column is migrated + backfilled
    from ``batch_id`` (preferred) or ``scan_id`` (fallback)."""
    db = str(tmp_path / "legacy.db")
    conn = sqlite3.connect(db)
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
    conn.executemany(
        "INSERT INTO hub_findings_current (tenant_id, canonical_id, first_seen, last_seen, updated_at, payload) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        [
            ("t", "c1", "2026-01-01T00:00:00Z", "2026-01-01T00:00:00Z", "2026-01-01T00:00:00Z", '{"batch_id": "b-legacy"}'),
            ("t", "c2", "2026-01-01T00:00:00Z", "2026-01-01T00:00:00Z", "2026-01-01T00:00:00Z", '{"scan_id": "s-legacy"}'),
        ],
    )
    conn.commit()
    conn.close()

    store = SQLiteComplianceHubStore(db)
    conn2 = store._conn
    cols = {r[1] for r in conn2.execute("PRAGMA table_info(hub_findings_current)").fetchall()}
    assert "scan_id" in cols
    got = dict(conn2.execute("SELECT canonical_id, scan_id FROM hub_findings_current").fetchall())
    assert got["c1"] == "b-legacy"  # batch_id preferred
    assert got["c2"] == "s-legacy"  # scan_id fallback
