from __future__ import annotations

import json

import pytest

from agent_bom.api import stores as api_stores
from agent_bom.api.neptune_graph import NeptuneGraphConfig, NeptuneGraphStore, NeptuneGraphStoreConfigError
from agent_bom.graph import EntityType, RelationshipType, UnifiedEdge, UnifiedGraph, UnifiedNode


class FakeGremlinClient:
    def __init__(self) -> None:
        self.calls: list[tuple[str, dict]] = []
        self.snapshots: list[dict] = []
        self.nodes: list[dict] = []
        self.edges: list[dict] = []

    def submit(self, query: str, bindings: dict | None = None):
        bindings = bindings or {}
        self.calls.append((query, bindings))
        if "hasLabel('abom_snapshot')" in query:
            return self.snapshots[: int(bindings.get("limit", len(self.snapshots)))]
        if "hasLabel('abom_node')" in query:
            return self.nodes
        if "g.E()" in query and "valueMap()" in query:
            return self.edges
        if "project('count')" in query:
            return [{"count": [3]}]
        return []


def _node_record(node: UnifiedNode) -> dict:
    return {
        "node_id": [node.id],
        "entity_type": [node.entity_type.value],
        "label": [node.label],
        "payload_json": [json.dumps(node.to_dict())],
    }


def _edge_record(edge: UnifiedEdge) -> dict:
    return {
        "source_id": [edge.source],
        "target_id": [edge.target],
        "relationship": [edge.relationship.value],
        "valid_from": [edge.valid_from],
        "valid_to": [edge.valid_to or ""],
        "payload_json": [json.dumps(edge.to_dict())],
    }


def test_neptune_graph_store_writes_graph_with_tenant_scan_bindings() -> None:
    client = FakeGremlinClient()
    store = NeptuneGraphStore(NeptuneGraphConfig(endpoint="wss://neptune.example:8182/gremlin"), client=client)
    graph = UnifiedGraph(scan_id="scan-1", tenant_id="tenant-a", created_at="2026-05-14T00:00:00Z")
    graph.add_node(UnifiedNode(id="agent:a", entity_type=EntityType.AGENT, label="Agent A"))
    graph.add_node(UnifiedNode(id="server:a", entity_type=EntityType.SERVER, label="Server A"))
    graph.add_edge(UnifiedEdge(source="agent:a", target="server:a", relationship=RelationshipType.USES))

    store.save_graph(graph)

    assert len(client.calls) == 4
    node_call = client.calls[0][1]
    edge_call = client.calls[2][1]
    snapshot_call = client.calls[3][1]
    assert node_call["tenant_id"] == "tenant-a"
    assert node_call["scan_id"] == "scan-1"
    assert edge_call["edge_label"] == "uses"
    assert edge_call["source_key"] == "tenant-a|scan-1|agent:a"
    assert edge_call["target_key"] == "tenant-a|scan-1|server:a"
    assert snapshot_call["node_count"] == 2
    assert snapshot_call["edge_count"] == 1


def test_neptune_graph_store_reads_snapshots_graph_and_active_edges() -> None:
    client = FakeGremlinClient()
    node = UnifiedNode(id="agent:a", entity_type=EntityType.AGENT, label="Agent A")
    edge = UnifiedEdge(
        source="agent:a",
        target="server:a",
        relationship=RelationshipType.USES,
        valid_from="2026-05-14T00:00:00Z",
    )
    client.snapshots = [
        {
            "scan_id": ["scan-1"],
            "tenant_id": ["tenant-a"],
            "created_at": ["2026-05-14T00:00:00Z"],
            "node_count": [1],
            "edge_count": [1],
            "risk_summary_json": ['{"severity_counts": {}}'],
        }
    ]
    client.nodes = [_node_record(node), _node_record(UnifiedNode(id="server:a", entity_type=EntityType.SERVER, label="Server A"))]
    client.edges = [_edge_record(edge)]
    store = NeptuneGraphStore(NeptuneGraphConfig(endpoint="wss://neptune.example:8182/gremlin"), client=client)

    assert store.latest_snapshot_id(tenant_id="tenant-a") == "scan-1"
    graph = store.load_graph(tenant_id="tenant-a", scan_id="scan-1")
    active_edges = store.active_edges_at("2026-05-15T00:00:00Z", tenant_id="tenant-a")

    assert sorted(graph.nodes) == ["agent:a", "server:a"]
    assert [(item.source, item.target, item.relationship) for item in graph.edges] == [("agent:a", "server:a", RelationshipType.USES)]
    assert active_edges[0]["valid_from"] == "2026-05-14T00:00:00Z"


def test_neptune_backend_selection_is_explicit_and_fail_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    previous = api_stores._graph_store
    api_stores._graph_store = None
    monkeypatch.setenv("AGENT_BOM_GRAPH_BACKEND", "neptune")
    monkeypatch.delenv("AGENT_BOM_NEPTUNE_ENDPOINT", raising=False)
    try:
        with pytest.raises(NeptuneGraphStoreConfigError, match="AGENT_BOM_NEPTUNE_ENDPOINT"):
            api_stores._get_graph_store()
    finally:
        api_stores._graph_store = previous


def test_neptune_backend_selection_accepts_injected_client(monkeypatch: pytest.MonkeyPatch) -> None:
    previous = api_stores._graph_store
    api_stores._graph_store = None
    fake_client = FakeGremlinClient()
    monkeypatch.setenv("AGENT_BOM_GRAPH_BACKEND", "neptune")
    monkeypatch.setenv("AGENT_BOM_NEPTUNE_ENDPOINT", "wss://neptune.example:8182/gremlin")
    monkeypatch.setattr("agent_bom.api.neptune_graph._client_from_config", lambda _config: fake_client)
    try:
        store = api_stores._get_graph_store()
    finally:
        api_stores._graph_store = previous

    assert isinstance(store, NeptuneGraphStore)
    assert store.config.endpoint == "wss://neptune.example:8182/gremlin"
