"""A small path page must not hydrate a high-degree node's unrelated edges."""

import json

import pytest

from agent_bom.api.graph_store import SQLiteGraphStore
from agent_bom.graph import AttackPath, EntityType, RelationshipType, UnifiedEdge, UnifiedGraph, UnifiedNode
from agent_bom.mcp_tools.graph import exposure_paths_impl


def star(scan_id: str, tenant_id: str = "default", size: int = 1_000) -> UnifiedGraph:
    graph = UnifiedGraph(scan_id=scan_id, tenant_id=tenant_id)
    graph.add_node(UnifiedNode(id="agent:hub", entity_type=EntityType.AGENT, label="Synthetic hub"))
    for index in range(size):
        target = f"resource:{index}"
        graph.add_node(UnifiedNode(id=target, entity_type=EntityType.RESOURCE, label=target))
        graph.add_edge(UnifiedEdge(source="agent:hub", target=target, relationship=RelationshipType.CAN_ACCESS))
        graph.attack_paths.append(AttackPath(source="agent:hub", target=target, hops=["agent:hub", target], edges=["can_access"]))
    return graph


@pytest.mark.asyncio
async def test_small_exposure_page_hydrates_only_its_relationships(tmp_path, monkeypatch) -> None:
    store = SQLiteGraphStore(tmp_path / "graph.db")
    store.save_graph(star("snapshot"))
    decoded = 0
    original = store._edge_from_row

    def count_decode(row):
        nonlocal decoded
        decoded += 1
        return original(row)

    monkeypatch.setattr(store, "_edge_from_row", count_decode)
    result = json.loads(await exposure_paths_impl(scan_id="snapshot", limit=2, _get_graph_store=lambda: store))
    assert result["count"] == 2 and result["total"] == 1_000
    assert decoded == 2
    assert len(result["edges"]) == 2
    assert result["pagination"]["has_more"] is True


def test_induced_query_retains_direction_and_scope_without_changing_incident_default(tmp_path) -> None:
    store = SQLiteGraphStore(tmp_path / "graph.db")
    graph = star("snapshot", size=3)
    graph.add_edge(UnifiedEdge(source="resource:0", target="agent:hub", relationship=RelationshipType.USES, direction="bidirectional"))
    store.save_graph(graph)
    store.save_graph(star("snapshot", tenant_id="other", size=4))
    store.save_graph(star("later", size=5))
    ids = {"agent:hub", "resource:0"}
    assert len(store.edges_for_node_ids(scan_id="snapshot", node_ids=ids)) == 4
    selected = store.edges_for_node_ids(scan_id="snapshot", node_ids=ids, induced_only=True)
    assert {(edge.source, edge.target, edge.direction) for edge in selected} == {
        ("agent:hub", "resource:0", "directed"),
        ("resource:0", "agent:hub", "bidirectional"),
    }
    assert store.edges_for_node_ids(tenant_id="absent", scan_id="snapshot", node_ids=ids, induced_only=True) == []
    assert store.edges_for_node_ids(scan_id="snapshot", node_ids=set(), induced_only=True) == []


@pytest.mark.asyncio
async def test_scoped_and_incident_queries_produce_identical_exposure_answers(tmp_path, monkeypatch) -> None:
    store = SQLiteGraphStore(tmp_path / "graph.db")
    graph = star("snapshot", size=100)
    graph.add_edge(UnifiedEdge(source="resource:0", target="resource:1", relationship=RelationshipType.ACCESSED))
    store.save_graph(graph)
    narrowed = await exposure_paths_impl(scan_id="snapshot", limit=3, _get_graph_store=lambda: store)
    original = store.edges_for_node_ids

    def incident_query(**kwargs):
        kwargs["induced_only"] = False
        return original(**kwargs)

    monkeypatch.setattr(store, "edges_for_node_ids", incident_query)
    legacy = await exposure_paths_impl(scan_id="snapshot", limit=3, _get_graph_store=lambda: store)
    assert json.loads(narrowed) == json.loads(legacy)


def test_postgres_receipt_restart_and_induced_query():
    import os
    from uuid import uuid4

    if not os.environ.get("AGENT_BOM_POSTGRES_URL"):
        pytest.skip("requires a migrated live PostgreSQL database")
    from agent_bom.api.postgres_common import reset_current_tenant, set_current_tenant
    from agent_bom.api.postgres_graph import PostgresGraphStore
    from agent_bom.graph.hop_evidence import exposure_hop_evidence

    scan_id = f"hop-truth-{uuid4().hex}"
    graph = star(scan_id, size=5)
    graph.attack_paths[0].hop_evidence = [
        {
            "source_node_id": "agent:hub",
            "target_node_id": "resource:0",
            "relationship": "can_access",
            "source_snapshot_ids": [scan_id],
            "runtime_observed_state": "blocked",
            "runtime_outcome": "blocked",
        }
    ]
    token = set_current_tenant("default")
    try:
        store = PostgresGraphStore()
        store.save_graph(graph)
        restored = PostgresGraphStore().load_graph(tenant_id="default", scan_id=scan_id)
        path = next(p for p in restored.attack_paths if p.target == "resource:0")
        assert exposure_hop_evidence(path)[0]["runtime_outcome"] == "blocked"
        ids = {"agent:hub", "resource:0"}
        assert len(store.edges_for_node_ids(tenant_id="default", scan_id=scan_id, node_ids=ids)) == 5
        assert len(store.edges_for_node_ids(tenant_id="default", scan_id=scan_id, node_ids=ids, induced_only=True)) == 1
        assert store.edges_for_node_ids(tenant_id="other", scan_id=scan_id, node_ids=ids, induced_only=True) == []
    finally:
        reset_current_tenant(token)
