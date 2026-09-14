"""Aggregate reads retain full results without decoding per-edge evidence."""

from __future__ import annotations

import pytest

from agent_bom.db import graph_store as db
from agent_bom.graph.container import UnifiedGraph
from agent_bom.graph.edge import UnifiedEdge
from agent_bom.graph.node import UnifiedNode
from agent_bom.graph.rollup import ROLLUP_RELATIONSHIPS, RollupFilters, rollup_view
from agent_bom.graph.types import EntityType, RelationshipType


@pytest.fixture
def connection(tmp_path):
    with db.open_graph_db(tmp_path / "projection.db") as conn:
        for tenant in ("default", "other"):
            graph = UnifiedGraph(scan_id="shared-snapshot", tenant_id=tenant)
            for name in ("a", "b"):
                graph.add_node(UnifiedNode(id=name, entity_type=EntityType.ACCOUNT, label=f"{tenant}-{name}"))
                graph.add_node(
                    UnifiedNode(
                        id=f"{name}-resource",
                        entity_type=EntityType.CLOUD_RESOURCE,
                        label=name,
                        severity="critical" if name == "a" else "high",
                        risk_score=8,
                        attributes={"internet_exposed": True, "toxic_exposed_sensitive": name == "b"},
                    )
                )
                graph.add_edge(UnifiedEdge(source=name, target=f"{name}-resource", relationship=RelationshipType.OWNS))
            for relationship in RelationshipType:
                graph.add_edge(
                    UnifiedEdge(
                        source="a-resource",
                        target="b-resource",
                        relationship=relationship,
                        evidence={"large_detail": "x" * 4096},
                        provenance={"source": "fixture"},
                    )
                )
            for index in range(220):
                graph.add_node(
                    UnifiedNode(
                        id=f"orphan-{index}", entity_type=EntityType.PACKAGE, label=str(index), severity="low", risk_score=index % 10
                    )
                )
            db.save_graph(conn, graph)
        conn.commit()
        yield conn


@pytest.mark.parametrize(
    "filters",
    [
        None,
        RollupFilters(min_severity="high"),
        RollupFilters(exposed_only=True),
        RollupFilters(toxic_only=True),
        RollupFilters(min_severity="critical", exposed_only=True),
    ],
)
def test_projection_equals_full_rollup_with_filters_orphans_and_cross_relationships(connection, filters):
    full = db.load_graph(connection, tenant_id="default", scan_id="shared-snapshot", relationship_types=ROLLUP_RELATIONSHIPS)
    projected = db.load_rollup_graph(connection, tenant_id="default", scan_id="shared-snapshot")
    assert rollup_view(projected, filters=filters) == rollup_view(full, filters=filters)
    assert projected.completeness.total_nodes == len(full.nodes)
    assert len(projected.edges) == len(full.edges)


def test_projection_does_not_read_or_decode_edge_evidence(connection, monkeypatch):
    queries = []
    connection.set_trace_callback(queries.append)
    original_loads = db.json.loads
    decoded = []

    def loads(raw, *args, **kwargs):
        decoded.append(raw)
        return original_loads(raw, *args, **kwargs)

    monkeypatch.setattr(db.json, "loads", loads)
    projected = db.load_rollup_graph(connection, tenant_id="default", scan_id="shared-snapshot")
    assert not any("large_detail" in raw for raw in decoded)
    edge_reads = [q.lower() for q in queries if "from graph_edges" in q.lower()]
    assert edge_reads and all("select *" not in q and "evidence" not in q and "provenance" not in q for q in edge_reads)
    assert len(projected.edges) > 0


def test_projection_scopes_latest_and_named_snapshots_by_tenant(connection):
    for tenant in ("default", "other"):
        named = db.load_rollup_graph(connection, tenant_id=tenant, scan_id="shared-snapshot")
        latest = db.load_rollup_graph(connection, tenant_id=tenant)
        assert rollup_view(named) == rollup_view(latest)
        assert named.nodes["a"].label == f"{tenant}-a"
    assert not db.load_rollup_graph(connection, tenant_id="absent", scan_id="shared-snapshot").nodes
    assert not db.load_rollup_graph(connection, tenant_id="default", scan_id="absent").nodes


def test_projection_keeps_one_snapshot_during_concurrent_refresh(connection, monkeypatch):
    from agent_bom.api.graph_store import SQLiteGraphStore

    db_path = connection.execute("PRAGMA database_list").fetchone()[2]
    store = SQLiteGraphStore(db_path)
    expected = rollup_view(store.load_rollup_graph(tenant_id="default", scan_id="shared-snapshot"))
    original_loads = db.json.loads
    refreshed = False

    def loads(raw, *args, **kwargs):
        nonlocal refreshed
        if not refreshed:
            refreshed = True
            with db.open_graph_db(db_path) as writer:
                writer.execute("DELETE FROM graph_edges WHERE tenant_id = ? AND scan_id = ?", ("default", "shared-snapshot"))
                writer.execute("UPDATE graph_nodes SET label = ? WHERE tenant_id = ? AND id = ?", ("refreshed", "default", "a"))
                writer.commit()
        return original_loads(raw, *args, **kwargs)

    monkeypatch.setattr(db.json, "loads", loads)
    assert rollup_view(store.load_rollup_graph(tenant_id="default", scan_id="shared-snapshot")) == expected
    current = store.load_rollup_graph(tenant_id="default", scan_id="shared-snapshot")
    assert not current.edges and current.nodes["a"].label == "refreshed"
