"""High-degree pages bound SQL hydration and retain honest evidence scope."""

from __future__ import annotations

import pytest
from starlette.testclient import TestClient

from agent_bom.api.graph_store import SQLiteGraphStore
from agent_bom.api.server import app
from agent_bom.api.stores import set_graph_store
from agent_bom.graph import EntityType, RelationshipType, UnifiedEdge, UnifiedGraph, UnifiedNode
from tests.auth_helpers import disable_trusted_proxy_env, enable_trusted_proxy_env, proxy_headers


def _graph(tenant: str, count: int = 1100) -> UnifiedGraph:
    graph = UnifiedGraph(tenant_id=tenant, scan_id="estate")
    graph.add_node(UnifiedNode(id="agent:root", entity_type=EntityType.AGENT, label=f"{tenant}:root", risk_score=100))
    for index in range(count):
        node = UnifiedNode(id=f"finding:{index:05}", entity_type=EntityType.VULNERABILITY, label=f"{tenant}:finding:{index}")
        graph.add_node(node)
        graph.add_edge(UnifiedEdge(source="agent:root", target=node.id, relationship=RelationshipType.USES))
    return graph


@pytest.fixture
def store(tmp_path):
    store = SQLiteGraphStore(tmp_path / "graph.db")
    store.save_graph(_graph("tenant-a"))
    store.save_graph(_graph("tenant-b", 5))
    return store


def test_incident_query_bounds_hydration_and_deduplicates(store, monkeypatch):
    decoded = []
    original = store._edge_from_row

    def decode(row):
        decoded.append(row)
        return original(row)

    monkeypatch.setattr(store, "_edge_from_row", decode)
    edges = store.edges_for_node_ids(tenant_id="tenant-a", scan_id="estate", node_ids={"agent:root", "finding:00000"}, limit=11)
    assert len(edges) == len(decoded) == 11
    assert len({(e.source, e.target, e.relationship) for e in edges}) == 11
    assert edges == store.edges_for_node_ids(tenant_id="tenant-a", scan_id="estate", node_ids={"finding:00000", "agent:root"}, limit=11)
    assert len(store.edges_for_node_ids(tenant_id="tenant-b", scan_id="estate", node_ids={"agent:root"}, limit=11)) == 5


def test_direction_and_relationship_filters_do_not_hydrate_siblings(store):
    assert store.edges_for_node_ids(tenant_id="tenant-a", scan_id="estate", node_ids={"agent:root"}, direction="in") == []
    incoming = store.edges_for_node_ids(tenant_id="tenant-a", scan_id="estate", node_ids={"finding:00001"}, direction="in", limit=3)
    assert len(incoming) == 1 and incoming[0].target == "finding:00001"
    assert (
        store.edges_for_node_ids(tenant_id="tenant-a", scan_id="estate", node_ids={"agent:root"}, relationships={"contains"}, limit=3) == []
    )
    induced = store.edges_for_node_ids(
        tenant_id="tenant-a", scan_id="estate", node_ids={"agent:root", "finding:00001"}, induced_only=True, direction="in", limit=3
    )
    assert len(induced) == 1


@pytest.mark.parametrize("node_limit", [1, 2000])
def test_high_degree_page_discloses_edge_limit_and_allows_complete_expansion(store, node_limit):
    enable_trusted_proxy_env()
    set_graph_store(store)
    try:
        with TestClient(app, headers=proxy_headers(tenant="tenant-a")) as client:
            response = client.get("/v1/graph", params={"scan_id": "estate", "limit": node_limit})
            assert response.status_code == 200
            body = response.json()
            assert len(body["nodes"]) == min(node_limit, 1101)
            assert body["pagination"]["has_more"] is (node_limit == 1)
            assert len(body["edges"]) <= 1000
            scope = body["completeness"]
            assert scope["edges_truncated"] is True
            assert scope["complete"] is False and scope["truncated"] is True
            assert scope["edge_limit"] == 1000
            assert scope["edge_expansion_endpoint"] == "/v1/graph/incident-edges"
            params = {"scan_id": "estate", "snapshot_generation": body["snapshot_generation"], "node_id": "agent:root", "limit": 100}
            seen = set()
            while True:
                page = client.get(scope["edge_expansion_endpoint"], params=params)
                assert page.status_code == 200
                result = page.json()
                ids = {edge["id"] for edge in result["edges"]}
                assert not seen.intersection(ids)
                seen.update(ids)
                if not result["next_cursor"]:
                    break
                params["cursor"] = result["next_cursor"]
            assert len(seen) == 1100
    finally:
        set_graph_store(None)
        disable_trusted_proxy_env()


def test_omitted_incident_edge_does_not_erase_containment_parent(store):
    graph = _graph("tenant-a")
    graph.add_node(UnifiedNode(id="zz-parent", entity_type=EntityType.CLOUD_RESOURCE, label="Parent"))
    graph.add_edge(UnifiedEdge(source="zz-parent", target="agent:root", relationship=RelationshipType.CONTAINS))
    store.save_graph(graph)
    enable_trusted_proxy_env()
    set_graph_store(store)
    try:
        with TestClient(app, headers=proxy_headers(tenant="tenant-a")) as client:
            body = client.get("/v1/graph", params={"scan_id": "estate", "limit": 1}).json()
            assert {node["id"] for node in body["nodes"]} == {"agent:root", "zz-parent"}
            assert body["completeness"]["edges_truncated"] is True
            assert body["completeness"]["edge_returned"] == 1000
            assert body["completeness"]["context_nodes"] == 1
            assert any(edge["source"] == "zz-parent" and edge["target"] == "agent:root" for edge in body["edges"])
            small = client.get("/v1/graph", headers=proxy_headers(tenant="tenant-b"), params={"scan_id": "estate"}).json()
            assert small["completeness"]["edges_truncated"] is False
            assert small["completeness"]["complete"] is True
    finally:
        set_graph_store(None)
        disable_trusted_proxy_env()


def test_snapshot_relationship_counts_do_not_probe_every_endpoint_pair(store, monkeypatch):
    # Count SQLite VM work instead of elapsed time: high-degree estates must
    # inspect stored edges, not all combinations of source and target nodes.
    graph = _graph("tenant-a", 30000)
    graph.edges.clear()
    for i in range(3000):
        graph.add_node(UnifiedNode(id=f"asset:{i}", entity_type=EntityType.CLOUD_RESOURCE, label=f"asset {i}"))
    for i in range(30000):
        graph.add_edge(UnifiedEdge(source=f"asset:{i % 3000}", target=f"finding:{i:05}", relationship=RelationshipType.USES))
    store.save_graph(graph)
    conn = store._open_rw_conn()
    conn.execute("ANALYZE")
    steps = 0

    def budget():
        nonlocal steps
        steps += 1000
        return int(steps > 3_000_000)

    conn.set_progress_handler(budget, 1000)
    monkeypatch.setattr(store, "_open_ro_conn", lambda: conn)
    stats = store.snapshot_stats(tenant_id="tenant-a", scan_id="estate")
    assert stats["relationship_types"] == {"uses": 30000}
    assert stats["total_edges"] == 30000
