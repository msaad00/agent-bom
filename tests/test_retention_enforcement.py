"""Retention enforcement: graph snapshot purge and on-disk history cap.

Covers P1-B PR1:
- ``purge_expired_graph_snapshots`` deletes aged snapshots and cascades to
  their nodes/edges, while fail-closing on unparseable timestamps.
- ``save_graph`` runs the purge on its post-save lifecycle hook and records
  real enforcement state in ``graph_retention_policy``.
- ``history.save_report`` caps on-disk reports and prunes the oldest.

Covers P1-B PR2:
- Per-tenant graph retention via env JSON map and API config store.
- Analytics cap for local analytics mirrors and runtime observations.
"""

from __future__ import annotations

import json
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
        "INSERT INTO graph_snapshots (scan_id, tenant_id, created_at, node_count, edge_count, risk_summary) VALUES (?, ?, ?, ?, ?, ?)",
        (scan_id, tenant, created_at, 1, 0, "{}"),
    )
    conn.execute(
        "INSERT INTO graph_nodes (id, entity_type, label, first_seen, last_seen, scan_id, tenant_id) VALUES (?, ?, ?, ?, ?, ?, ?)",
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


class TestPerTenantGraphRetention:
    def test_purge_applies_different_windows_per_tenant_via_env(self, db, monkeypatch):
        from agent_bom.api.stores import set_tenant_graph_retention_store
        from agent_bom.api.tenant_graph_retention_store import InMemoryTenantGraphRetentionStore
        from agent_bom.db.graph_store import purge_expired_graph_snapshots

        set_tenant_graph_retention_store(InMemoryTenantGraphRetentionStore())
        monkeypatch.setenv("AGENT_BOM_GRAPH_RETENTION_OVERRIDES", json.dumps({"tenant-a": 30, "tenant-b": 90}))

        now = datetime(2026, 1, 1, tzinfo=timezone.utc)
        _insert_snapshot(db, "a-old", (now - timedelta(days=45)).isoformat(), tenant="tenant-a")
        _insert_snapshot(db, "a-recent", (now - timedelta(days=10)).isoformat(), tenant="tenant-a")
        _insert_snapshot(db, "b-old", (now - timedelta(days=45)).isoformat(), tenant="tenant-b")
        _insert_snapshot(db, "b-recent", (now - timedelta(days=10)).isoformat(), tenant="tenant-b")

        result = purge_expired_graph_snapshots(db, now=now)

        assert result["purged_count"] == 1
        assert result["purged_snapshots"] == [{"scan_id": "a-old", "tenant_id": "tenant-a"}]
        remaining = {row[0] for row in db.execute("SELECT scan_id FROM graph_snapshots")}
        assert remaining == {"a-recent", "b-old", "b-recent"}

    def test_purge_prefers_store_override_over_env(self, db, monkeypatch):
        from agent_bom.api.stores import set_tenant_graph_retention_store
        from agent_bom.api.tenant_graph_retention import set_tenant_graph_retention_override
        from agent_bom.api.tenant_graph_retention_store import InMemoryTenantGraphRetentionStore
        from agent_bom.db.graph_store import graph_retention_policy, purge_expired_graph_snapshots

        set_tenant_graph_retention_store(InMemoryTenantGraphRetentionStore())
        monkeypatch.setenv("AGENT_BOM_GRAPH_RETENTION_OVERRIDES", json.dumps({"tenant-a": 30}))
        set_tenant_graph_retention_override("tenant-a", 90)

        now = datetime(2026, 1, 1, tzinfo=timezone.utc)
        _insert_snapshot(db, "a-borderline", (now - timedelta(days=45)).isoformat(), tenant="tenant-a")

        result = purge_expired_graph_snapshots(db, now=now)
        assert result["purged_count"] == 0

        policy = graph_retention_policy(db, tenant_id="tenant-a")
        assert policy["retention_days"] == 90
        assert policy["tenant_id"] == "tenant-a"


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


# ═══════════════════════════════════════════════════════════════════════════
# Analytics growth cap
# ═══════════════════════════════════════════════════════════════════════════


class TestAnalyticsCap:
    def test_local_analytics_prunes_oldest_scan_runs(self, monkeypatch, tmp_path):
        from agent_bom.db.local_analytics import LocalAnalyticsStore

        db_path = tmp_path / "analytics.sqlite"
        monkeypatch.setenv("AGENT_BOM_ANALYTICS_MAX_EVENTS", "2")

        store = LocalAnalyticsStore(db_path)
        for index in range(4):
            store.record_scan_report(
                {
                    "scan_id": f"scan-{index}",
                    "generated_at": f"2026-01-0{index + 1}T00:00:00+00:00",
                    "summary": {},
                },
                source="test",
            )

        runs = store.list_scan_runs(limit=10)
        assert len(runs) == 2
        assert {row["scan_id"] for row in runs} == {"scan-2", "scan-3"}

    def test_runtime_observations_prune_oldest_per_tenant(self, monkeypatch):
        from agent_bom.api.runtime_event_store import InMemoryRuntimeEventStore, RuntimeObservationRecord

        monkeypatch.setenv("AGENT_BOM_ANALYTICS_MAX_EVENTS", "2")
        store = InMemoryRuntimeEventStore()
        for index in range(4):
            store.put_observation(
                RuntimeObservationRecord(
                    tenant_id="tenant-a",
                    observation_id=f"obs-{index}",
                    session_id="sess-1",
                    observed_at=f"2026-01-0{index + 1}T00:00:00+00:00",
                    event_type="tool_call",
                    verdict="allow",
                    severity="info",
                    tool_name="read",
                )
            )

        observations = store.list_observations("tenant-a", limit=10)
        assert len(observations) == 2
        assert {row.observation_id for row in observations} == {"obs-2", "obs-3"}
