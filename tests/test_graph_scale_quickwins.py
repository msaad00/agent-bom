"""Regression tests for the bounded graph-scale quick-win fixes (Part of #3664).

Covers three defects:
  1. snapshot_stats re-scanned graph_edges on every paged /v1/graph call instead
     of reading the edge count already materialised on the snapshot row.
  2. /v1/graph/rollup emitted one top-level entry per orphan node, growing the
     body O(nodes) on a flat estate.
  3. Deep OFFSET pagination is O(offset); it must be capped in favour of keyset
     cursor= pagination.
"""

from __future__ import annotations

import sqlite3

import pytest
from starlette.testclient import TestClient

from agent_bom.api import stores as api_stores
from agent_bom.api.graph_store import MAX_NODE_PAGE_OFFSET, SQLiteGraphStore
from agent_bom.api.server import app
from agent_bom.api.stores import set_graph_store
from agent_bom.graph import EntityType, RelationshipType, UnifiedEdge, UnifiedGraph, UnifiedNode
from agent_bom.graph.rollup import _MAX_TOP_LEVEL_ORPHANS, rollup_view


def _small_graph(scan_id: str = "scale-scan") -> UnifiedGraph:
    g = UnifiedGraph(scan_id=scan_id, tenant_id="default")
    g.add_node(UnifiedNode(id="agent:a", entity_type=EntityType.AGENT, label="agent-a"))
    g.add_node(UnifiedNode(id="server:fs", entity_type=EntityType.SERVER, label="mcp-fs"))
    g.add_node(
        UnifiedNode(
            id="vuln:CVE-1",
            entity_type=EntityType.VULNERABILITY,
            label="CVE-1",
            severity="critical",
            risk_score=9.0,
        )
    )
    g.add_edge(UnifiedEdge(source="agent:a", target="server:fs", relationship=RelationshipType.USES))
    g.add_edge(UnifiedEdge(source="server:fs", target="vuln:CVE-1", relationship=RelationshipType.VULNERABLE_TO))
    return g


# ── FIX 1: snapshot_stats reads the materialised snapshot counts ──────────────


def test_snapshot_stats_reads_stored_counts(tmp_path):
    store = SQLiteGraphStore(tmp_path / "graph.db")
    store.save_graph(_small_graph())

    baseline = store.snapshot_stats(tenant_id="default", scan_id="scale-scan")
    assert baseline["total_edges"] == 2
    assert baseline["total_nodes"] == 3

    # Tamper the materialised counts. A stored-count read returns the sentinels;
    # a recompute over graph_edges/graph_nodes would ignore them.
    conn = sqlite3.connect(store._db_path)
    conn.execute("UPDATE graph_snapshots SET node_count = 777, edge_count = 999 WHERE scan_id = 'scale-scan'")
    conn.commit()
    conn.close()

    stats = store.snapshot_stats(tenant_id="default", scan_id="scale-scan")
    assert stats["total_edges"] == 999
    assert stats["total_nodes"] == 777


def test_snapshot_stats_falls_back_when_stored_counts_null(tmp_path):
    store = SQLiteGraphStore(tmp_path / "graph.db")
    store.save_graph(_small_graph())

    conn = sqlite3.connect(store._db_path)
    conn.execute("UPDATE graph_snapshots SET node_count = NULL, edge_count = NULL WHERE scan_id = 'scale-scan'")
    conn.commit()
    conn.close()

    stats = store.snapshot_stats(tenant_id="default", scan_id="scale-scan")
    assert stats["total_edges"] == 2
    assert stats["total_nodes"] == 3


def test_snapshot_stats_filtered_recomputes_and_ignores_stored_count(tmp_path):
    store = SQLiteGraphStore(tmp_path / "graph.db")
    store.save_graph(_small_graph())

    conn = sqlite3.connect(store._db_path)
    conn.execute("UPDATE graph_snapshots SET edge_count = 999 WHERE scan_id = 'scale-scan'")
    conn.commit()
    conn.close()

    # An entity-type filter narrows the set, so the stored total must not leak
    # in: only vulnerability→vulnerability edges qualify (there are none).
    stats = store.snapshot_stats(tenant_id="default", scan_id="scale-scan", entity_types={"vulnerability"})
    assert stats["total_edges"] == 0


# ── FIX 3: deep OFFSET pagination is capped in favour of cursor= ──────────────


def test_page_nodes_rejects_deep_offset(tmp_path):
    store = SQLiteGraphStore(tmp_path / "graph.db")
    store.save_graph(_small_graph())

    with pytest.raises(ValueError, match="cursor="):
        store.page_nodes(tenant_id="default", scan_id="scale-scan", offset=MAX_NODE_PAGE_OFFSET + 1)

    # At the cap it is still served; a cursor bypasses the offset entirely.
    store.page_nodes(tenant_id="default", scan_id="scale-scan", offset=MAX_NODE_PAGE_OFFSET)


def test_graph_endpoint_deep_offset_returns_422(tmp_path):
    store = SQLiteGraphStore(tmp_path / "graph.db")
    store.save_graph(_small_graph())
    original = api_stores._graph_store
    try:
        set_graph_store(store)
        client = TestClient(app)

        rejected = client.get(f"/v1/graph?scan_id=scale-scan&offset={MAX_NODE_PAGE_OFFSET + 1}")
        assert rejected.status_code == 422
        assert "cursor=" in rejected.json()["detail"]

        allowed = client.get("/v1/graph?scan_id=scale-scan&offset=0")
        assert allowed.status_code == 200
    finally:
        set_graph_store(original)


def test_graph_agents_endpoint_deep_offset_returns_422(tmp_path):
    store = SQLiteGraphStore(tmp_path / "graph.db")
    store.save_graph(_small_graph())
    original = api_stores._graph_store
    try:
        set_graph_store(store)
        client = TestClient(app)

        rejected = client.get(f"/v1/graph/agents?scan_id=scale-scan&offset={MAX_NODE_PAGE_OFFSET + 1}")
        assert rejected.status_code == 422
    finally:
        set_graph_store(original)


# ── FIX 2: rollup bounds orphan entries and aggregates the tail ───────────────


def _flat_estate(orphan_count: int, scan_id: str = "flat-scan") -> UnifiedGraph:
    g = UnifiedGraph(scan_id=scan_id, tenant_id="default")
    for i in range(orphan_count):
        g.add_node(
            UnifiedNode(
                id=f"pkg:{i:05d}",
                entity_type=EntityType.PACKAGE,
                label=f"pkg-{i}",
                risk_score=float(orphan_count - i),
            )
        )
    return g


def test_rollup_bounds_orphans_and_aggregates_tail():
    extra = 50
    total = _MAX_TOP_LEVEL_ORPHANS + extra
    view = rollup_view(_flat_estate(total))

    # No CONTAINS tree here, so top_level is orphans-only and bounded to the cap.
    assert len(view["top_level"]) == _MAX_TOP_LEVEL_ORPHANS

    summary = view["summary"]
    assert summary["orphan_count"] == total
    assert summary["orphan_shown_count"] == _MAX_TOP_LEVEL_ORPHANS
    assert summary["orphan_truncated_count"] == extra

    orphan_summary = view["orphan_summary"]
    assert orphan_summary["total"] == total
    assert orphan_summary["shown"] == _MAX_TOP_LEVEL_ORPHANS
    assert orphan_summary["truncated"] == extra
    # Every orphan is accounted for in the aggregate, none silently dropped.
    assert sum(orphan_summary["by_type"].values()) == total
    assert orphan_summary["by_type"]["package"] == total
    # Bounded sample of the truncated tail.
    assert len(orphan_summary["sample"]) == 20


def test_rollup_surfaces_highest_severity_orphan_despite_truncation():
    g = UnifiedGraph(scan_id="flat-crit", tenant_id="default")
    # A low-risk but critical-severity finding must still surface individually,
    # not vanish into the aggregated tail.
    g.add_node(
        UnifiedNode(
            id="vuln:crit",
            entity_type=EntityType.VULNERABILITY,
            label="critical-finding",
            severity="critical",
            risk_score=0.0,
        )
    )
    for i in range(_MAX_TOP_LEVEL_ORPHANS + 50):
        g.add_node(UnifiedNode(id=f"pkg:{i:05d}", entity_type=EntityType.PACKAGE, label=f"pkg-{i}", risk_score=1.0))

    view = rollup_view(g)
    shown_ids = {entry["id"] for entry in view["top_level"]}
    assert "vuln:crit" in shown_ids
    assert view["orphan_summary"]["severity_counts"]["critical"] == 1


def test_rollup_small_estate_unchanged():
    # Small estates keep every orphan individually; the aggregate reports zero
    # truncation so existing consumers see no behavioural change.
    view = rollup_view(_flat_estate(5))
    assert len(view["top_level"]) == 5
    assert view["summary"]["orphan_truncated_count"] == 0
    assert view["orphan_summary"]["truncated"] == 0
    assert view["orphan_summary"]["sample"] == []
