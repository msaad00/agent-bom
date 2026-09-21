"""Inventory facets retain exact results without repeated JSON expansion."""

import sqlite3

import pytest

from agent_bom.api.graph_store import SQLiteGraphStore
from agent_bom.graph import EntityType, NodeDimensions, UnifiedGraph, UnifiedNode


@pytest.mark.skipif(sqlite3.sqlite_version_info < (3, 35, 0), reason="SQLite materialization hints unavailable")
def test_inventory_facets_bound_json_decoding_work(tmp_path, monkeypatch):
    store = SQLiteGraphStore(tmp_path / "inventory.db")
    graph = UnifiedGraph(scan_id="snapshot", tenant_id="tenant-a")
    size = 120
    for index in range(size):
        graph.add_node(
            UnifiedNode(
                id=f"agent:{index:04}",
                entity_type=EntityType.AGENT,
                label=f"Agent {index:04}",
                dimensions=NodeDimensions(environment="production", cloud_provider="aws", ecosystem="python"),
                data_sources=["collector"],
                attributes={"owner": "security", "description": "x" * 1024},
            )
        )
    store.save_graph(graph)
    real_open = store._open_ro_conn
    decodes = 0

    def counted_open():
        conn = real_open()
        assert conn is not None

        def json_extract(document, path):
            nonlocal decodes
            decodes += 1
            # Delegate to SQLite itself to preserve its actual JSON semantics.
            return decoder.execute("SELECT json_extract(?, ?)", (document, path)).fetchone()[0]

        conn.create_function("json_extract", 2, json_extract, deterministic=True)
        return conn

    with sqlite3.connect(":memory:") as decoder:
        monkeypatch.setattr(store, "_open_ro_conn", counted_open)
        result = store.query_inventory(
            tenant_id="tenant-a",
            scan_id="snapshot",
            asset_entity_types={"agent"},
            environment="production",
            provider="aws",
            limit=10,
        )

    assert result["total"] == size
    assert len(result["nodes"]) == 10
    assert result["next_cursor"]
    assert result["nodes"][0].attributes["description"] == "x" * 1024
    assert result["facets"]["source"] == [{"value": "collector", "count": size}]
    assert result["facets"]["environment"] == [{"value": "production", "count": size}]
    # Work bound, not a wall-clock threshold: permits separate facet and page
    # queries, but not decoding every asset again for each individual facet.
    assert decodes <= size * 8


def test_inventory_retains_compatibility_without_materialization_hints(tmp_path, monkeypatch):
    store = SQLiteGraphStore(tmp_path / "inventory.db")
    graph = UnifiedGraph(scan_id="snapshot", tenant_id="tenant-a")
    graph.add_node(UnifiedNode(id="agent:a", entity_type=EntityType.AGENT, label="Agent"))
    store.save_graph(graph)
    monkeypatch.setattr(sqlite3, "sqlite_version_info", (3, 34, 0))
    result = store.query_inventory(tenant_id="tenant-a", scan_id="snapshot", asset_entity_types={"agent"})
    assert result["total"] == 1
    assert result["facets"]["type"] == [{"value": "agent", "count": 1}]


def test_inventory_counts_and_rows_share_read_snapshot_during_replacement(tmp_path, monkeypatch):
    store = SQLiteGraphStore(tmp_path / "inventory.db")
    graph = UnifiedGraph(scan_id="snapshot", tenant_id="tenant-a")
    for index in range(3):
        graph.add_node(UnifiedNode(id=f"agent:{index}", entity_type=EntityType.AGENT, label=f"Agent {index}"))
    store.save_graph(graph)
    replacement = UnifiedGraph(scan_id="snapshot", tenant_id="tenant-a")
    replacement.add_node(UnifiedNode(id="agent:new", entity_type=EntityType.AGENT, label="New agent"))
    real_open = store._open_ro_conn
    replaced = False

    class ReplacingConnection:
        def __init__(self, connection):
            self.connection = connection

        def execute(self, sql, *args):
            nonlocal replaced
            # A collector replaces this scan after its facets were read but
            # before the corresponding page and relationship context are read.
            if "SELECT id, entity_type, label, category_uid" in sql and not replaced:
                replaced = True
                store.save_graph(replacement)
            return self.connection.execute(sql, *args)

        def close(self):
            self.connection.close()

    monkeypatch.setattr(store, "_open_ro_conn", lambda: ReplacingConnection(real_open()))
    result = store.query_inventory(tenant_id="tenant-a", scan_id="snapshot", asset_entity_types={"agent"})
    assert replaced
    assert result["total"] == 3
    assert {node.id for node in result["nodes"]} == {"agent:0", "agent:1", "agent:2"}
    assert result["facets"]["type"] == [{"value": "agent", "count": 3}]
    current = store.query_inventory(tenant_id="tenant-a", scan_id="snapshot", asset_entity_types={"agent"})
    assert current["total"] == 1
    assert [node.id for node in current["nodes"]] == ["agent:new"]
