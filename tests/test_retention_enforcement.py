"""Retention enforcement: graph snapshot purge and on-disk history cap.

Covers P1-B PR1:
- ``purge_expired_graph_snapshots`` deletes aged snapshots and cascades to
  their nodes/edges, while fail-closing on unparseable timestamps.
- ``save_graph`` runs the purge on its post-save lifecycle hook and records
  real enforcement state in ``graph_retention_policy``.
- ``history.save_report`` caps on-disk reports and prunes the oldest.
"""

from __future__ import annotations

import sqlite3
from datetime import datetime, timedelta, timezone

import pytest

# ═══════════════════════════════════════════════════════════════════════════
# Graph snapshot retention
# ═══════════════════════════════════════════════════════════════════════════


@pytest.fixture
def db():
    from agent_bom.db.graph_store import _init_db

    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    _init_db(conn)
    yield conn
    conn.close()


def _insert_snapshot(conn: sqlite3.Connection, scan_id: str, created_at: str, tenant: str = "default") -> None:
    conn.execute(
        "INSERT INTO graph_snapshots (scan_id, tenant_id, created_at, node_count, edge_count, risk_summary) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (scan_id, tenant, created_at, 1, 0, "{}"),
    )
    conn.execute(
        "INSERT INTO graph_nodes (id, entity_type, label, first_seen, last_seen, scan_id, tenant_id) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        (f"node-{scan_id}", "agent", "n", created_at, created_at, scan_id, tenant),
    )
    conn.commit()


class TestGraphSnapshotPurge:
    def test_purge_removes_expired_snapshot_and_cascades(self, db):
        from agent_bom.db.graph_store import purge_expired_graph_snapshots

        now = datetime(2026, 1, 1, tzinfo=timezone.utc)
        _insert_snapshot(db, "old", (now - timedelta(days=400)).isoformat())
        _insert_snapshot(db, "recent", (now - timedelta(days=10)).isoformat())

        result = purge_expired_graph_snapshots(db, retention_days=180, now=now)

        assert result["purged_count"] == 1
        assert result["purged_snapshots"] == [{"scan_id": "old", "tenant_id": "default"}]

        remaining = {row[0] for row in db.execute("SELECT scan_id FROM graph_snapshots")}
        assert remaining == {"recent"}
        # Cascade: aged node removed, recent node kept.
        assert db.execute("SELECT COUNT(*) FROM graph_nodes WHERE scan_id = 'old'").fetchone()[0] == 0
        assert db.execute("SELECT COUNT(*) FROM graph_nodes WHERE scan_id = 'recent'").fetchone()[0] == 1

    def test_purge_is_fail_closed_on_unparseable_timestamp(self, db):
        from agent_bom.db.graph_store import purge_expired_graph_snapshots

        now = datetime(2026, 1, 1, tzinfo=timezone.utc)
        _insert_snapshot(db, "malformed", "not-a-timestamp")

        result = purge_expired_graph_snapshots(db, retention_days=1, now=now)

        assert result["purged_count"] == 0
        remaining = {row[0] for row in db.execute("SELECT scan_id FROM graph_snapshots")}
        assert remaining == {"malformed"}

    def test_purge_can_scope_to_single_tenant(self, db):
        from agent_bom.db.graph_store import purge_expired_graph_snapshots

        now = datetime(2026, 1, 1, tzinfo=timezone.utc)
        aged = (now - timedelta(days=400)).isoformat()
        _insert_snapshot(db, "a", aged, tenant="tenant-a")
        _insert_snapshot(db, "b", aged, tenant="tenant-b")

        result = purge_expired_graph_snapshots(db, retention_days=180, now=now, tenant_id="tenant-a")

        assert result["purged_count"] == 1
        remaining = {row[0] for row in db.execute("SELECT scan_id FROM graph_snapshots")}
        assert remaining == {"b"}


class TestSaveGraphRetentionHook:
    def test_save_graph_purges_aged_snapshot_and_records_state(self, db):
        from agent_bom.db.graph_store import (
            graph_retention_policy,
            list_snapshots,
            save_graph,
        )
        from agent_bom.graph import EntityType, UnifiedGraph, UnifiedNode

        aged = UnifiedGraph(scan_id="aged", created_at="2020-01-01T00:00:00+00:00")
        aged.add_node(UnifiedNode(id="agent:x", entity_type=EntityType.AGENT, label="x"))
        save_graph(db, aged)

        # The post-save lifecycle hook purges the just-written aged snapshot.
        assert list_snapshots(db) == []

        policy = graph_retention_policy(db)
        assert policy["enforcement"] == "age_based_purge_on_save"
        assert policy["last_purge_at"]
        assert policy["last_purged_count"] == 1

    def test_save_graph_keeps_recent_snapshot(self, db):
        from agent_bom.db.graph_store import graph_retention_policy, list_snapshots, save_graph
        from agent_bom.graph import EntityType, UnifiedGraph, UnifiedNode

        recent = UnifiedGraph(scan_id="recent")  # default created_at == now
        recent.add_node(UnifiedNode(id="agent:x", entity_type=EntityType.AGENT, label="x"))
        save_graph(db, recent)

        snaps = list_snapshots(db)
        assert [s["scan_id"] for s in snaps] == ["recent"]
        assert graph_retention_policy(db)["last_purged_count"] == 0


# ═══════════════════════════════════════════════════════════════════════════
# On-disk scan history cap
# ═══════════════════════════════════════════════════════════════════════════


class TestHistoryCap:
    def test_cap_prunes_oldest_reports(self, monkeypatch, tmp_path):
        from agent_bom import history

        monkeypatch.setattr(history, "HISTORY_DIR", tmp_path / "history")
        monkeypatch.setenv("AGENT_BOM_HISTORY_MAX_REPORTS", "3")

        for i in range(6):
            history.save_report({"summary": {}, "blast_radius": []}, label=f"scan-{i:02d}")

        reports = history.list_reports()
        assert len(reports) == 3
        # Newest labels survive; oldest are pruned.
        names = "\n".join(p.name for p in reports)
        assert "scan-05" in names and "scan-04" in names and "scan-03" in names
        assert "scan-00" not in names and "scan-01" not in names and "scan-02" not in names

    def test_cap_disabled_when_non_positive(self, monkeypatch, tmp_path):
        from agent_bom import history

        monkeypatch.setattr(history, "HISTORY_DIR", tmp_path / "history")
        monkeypatch.setenv("AGENT_BOM_HISTORY_MAX_REPORTS", "0")

        for i in range(4):
            history.save_report({"summary": {}, "blast_radius": []}, label=f"scan-{i:02d}")

        assert len(history.list_reports()) == 4

    def test_prune_history_returns_deleted_count(self, monkeypatch, tmp_path):
        from agent_bom import history

        monkeypatch.setattr(history, "HISTORY_DIR", tmp_path / "history")
        monkeypatch.setenv("AGENT_BOM_HISTORY_MAX_REPORTS", "1000")

        for i in range(4):
            history.save_report({"summary": {}, "blast_radius": []}, label=f"scan-{i:02d}")

        assert history.prune_history(max_reports=2) == 2
        assert len(history.list_reports()) == 2
