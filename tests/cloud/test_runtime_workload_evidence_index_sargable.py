"""The runtime workload-evidence index must match the query's ORDER BY.

P1 (2026-07-19 audit): ``list_for_tenant`` orders by
``(tenant_id, observed_at DESC, dedup_key DESC)`` but the store only created an
index on ``(tenant_id, workload_id, observed_at DESC)`` — unusable for that sort,
so at scale every tenant read fell back to a full-scan + temp-b-tree sort. This
pins the composite index to the query so the planner can satisfy the ORDER BY
from the index (no ``USE TEMP B-TREE FOR ORDER BY``).
"""

from __future__ import annotations

import sqlite3

from agent_bom.cloud.runtime_workload_evidence_store import SQLiteRuntimeWorkloadEvidenceStore


def test_list_for_tenant_query_plan_uses_index_not_temp_btree(tmp_path) -> None:
    store = SQLiteRuntimeWorkloadEvidenceStore(tmp_path / "rwe.sqlite")
    con = sqlite3.connect(str(tmp_path / "rwe.sqlite"))
    try:
        plan = con.execute(
            "EXPLAIN QUERY PLAN "
            "SELECT payload_json FROM runtime_workload_evidence WHERE tenant_id = ? "
            "ORDER BY observed_at DESC, dedup_key DESC LIMIT ?",
            ("tenant-a", 5000),
        ).fetchall()
    finally:
        con.close()
    detail = " ".join(str(row[-1]) for row in plan)
    assert "USING INDEX" in detail, detail
    # The whole point: the sort is satisfied by the index, not a temp b-tree.
    assert "USE TEMP B-TREE FOR ORDER BY" not in detail, detail
    del store


def test_stale_workload_time_index_is_dropped(tmp_path) -> None:
    store = SQLiteRuntimeWorkloadEvidenceStore(tmp_path / "rwe.sqlite")
    con = sqlite3.connect(str(tmp_path / "rwe.sqlite"))
    try:
        names = {
            row[0]
            for row in con.execute(
                "SELECT name FROM sqlite_master WHERE type='index' AND tbl_name='runtime_workload_evidence'"
            ).fetchall()
        }
    finally:
        con.close()
    assert "idx_rwe_tenant_workload_time" not in names, names
    del store
