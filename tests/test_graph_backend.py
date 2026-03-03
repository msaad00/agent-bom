"""Tests for graph backend — InMemory and optional NetworkX implementations."""

from __future__ import annotations

import pytest

from agent_bom.graph_backend import (
    GraphBackend,
    InMemoryBackend,
    from_context_graph,
    get_backend,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _build_triangle(backend: GraphBackend) -> GraphBackend:
    """Build a triangle graph: A -- B -- C -- A."""
    backend.add_node("A", kind="agent", label="Agent A")
    backend.add_node("B", kind="server", label="Server B")
    backend.add_node("C", kind="credential", label="Cred C")
    backend.add_edge("A", "B", kind="uses", weight=1.0)
    backend.add_edge("B", "C", kind="exposes", weight=2.0)
    backend.add_edge("C", "A", kind="shares", weight=1.5)
    return backend


def _build_chain(backend: GraphBackend) -> GraphBackend:
    """Build a chain: A -- B -- C -- D -- E."""
    for i, name in enumerate("ABCDE"):
        backend.add_node(name, kind="node", label=f"Node {name}")
    backend.add_edge("A", "B", kind="link")
    backend.add_edge("B", "C", kind="link")
    backend.add_edge("C", "D", kind="link")
    backend.add_edge("D", "E", kind="link")
    return backend


def _build_star(backend: GraphBackend) -> GraphBackend:
    """Build a star graph: center connected to 5 spokes."""
    backend.add_node("center", kind="server", label="Central Server")
    for i in range(5):
        nid = f"spoke-{i}"
        backend.add_node(nid, kind="agent", label=f"Agent {i}")
        backend.add_edge("center", nid, kind="uses")
    return backend


# ---------------------------------------------------------------------------
# TestInMemoryBackend
# ---------------------------------------------------------------------------


class TestInMemoryBackend:
    def test_add_node(self):
        g = InMemoryBackend()
        g.add_node("n1", kind="agent", label="Agent 1")
        assert g.has_node("n1")
        assert not g.has_node("n2")
        assert g.node_count() == 1

    def test_add_edge(self):
        g = InMemoryBackend()
        g.add_node("A", kind="agent", label="A")
        g.add_node("B", kind="server", label="B")
        g.add_edge("A", "B", kind="uses")
        assert g.has_edge("A", "B")
        assert g.has_edge("B", "A")  # Bidirectional
        assert g.edge_count() == 1

    def test_neighbors(self):
        g = _build_triangle(InMemoryBackend())
        neighbors_a = sorted(g.neighbors("A"))
        assert "B" in neighbors_a
        assert "C" in neighbors_a

    def test_bfs(self):
        g = _build_chain(InMemoryBackend())
        paths = g.bfs("A", max_depth=4)
        # Should find paths to B, C, D, E
        endpoints = {p[-1] for p in paths}
        assert "B" in endpoints
        assert "E" in endpoints

    def test_bfs_respects_depth(self):
        g = _build_chain(InMemoryBackend())
        paths = g.bfs("A", max_depth=2)
        endpoints = {p[-1] for p in paths}
        assert "B" in endpoints
        assert "C" in endpoints
        assert "D" not in endpoints

    def test_bfs_nonexistent_node(self):
        g = InMemoryBackend()
        assert g.bfs("nonexistent") == []

    def test_shortest_path(self):
        g = _build_chain(InMemoryBackend())
        path = g.shortest_path("A", "E")
        assert path == ["A", "B", "C", "D", "E"]

    def test_shortest_path_same_node(self):
        g = _build_chain(InMemoryBackend())
        path = g.shortest_path("A", "A")
        assert path == ["A"]

    def test_shortest_path_no_path(self):
        g = InMemoryBackend()
        g.add_node("X", kind="node", label="X")
        g.add_node("Y", kind="node", label="Y")
        path = g.shortest_path("X", "Y")
        assert path is None

    def test_shortest_path_nonexistent(self):
        g = InMemoryBackend()
        assert g.shortest_path("X", "Y") is None

    def test_to_dict(self):
        g = _build_triangle(InMemoryBackend())
        data = g.to_dict()
        assert len(data["nodes"]) == 3
        assert len(data["edges"]) == 3
        assert data["stats"]["node_count"] == 3
        assert data["stats"]["edge_count"] == 3

    def test_centrality_scores(self):
        g = _build_star(InMemoryBackend())
        scores = g.centrality_scores()
        assert "center" in scores
        # Center should have highest centrality
        assert scores["center"] == max(scores.values())

    def test_centrality_empty(self):
        g = InMemoryBackend()
        assert g.centrality_scores() == {}

    def test_bottleneck_nodes(self):
        g = _build_chain(InMemoryBackend())
        bottlenecks = g.bottleneck_nodes(top_n=3)
        assert len(bottlenecks) <= 3
        # Middle nodes (B, C, D) should be top bottlenecks
        top_ids = [n[0] for n in bottlenecks]
        assert any(n in top_ids for n in ["B", "C", "D"])

    def test_bottleneck_empty(self):
        g = InMemoryBackend()
        assert g.bottleneck_nodes() == []


# ---------------------------------------------------------------------------
# TestNetworkXBackend (skipped if not installed)
# ---------------------------------------------------------------------------


class TestNetworkXBackend:
    @pytest.fixture(autouse=True)
    def _require_networkx(self):
        pytest.importorskip("networkx")

    def _make_backend(self):
        from agent_bom.graph_backend import NetworkXBackend

        return NetworkXBackend()

    def test_add_node(self):
        g = self._make_backend()
        g.add_node("n1", kind="agent", label="Agent 1")
        assert g.has_node("n1")
        assert g.node_count() == 1

    def test_add_edge(self):
        g = self._make_backend()
        g.add_node("A", kind="agent", label="A")
        g.add_node("B", kind="server", label="B")
        g.add_edge("A", "B", kind="uses")
        assert g.has_edge("A", "B")
        assert g.has_edge("B", "A")

    def test_neighbors(self):
        g = _build_triangle(self._make_backend())
        neighbors_a = sorted(g.neighbors("A"))
        assert "B" in neighbors_a
        assert "C" in neighbors_a

    def test_bfs(self):
        g = _build_chain(self._make_backend())
        paths = g.bfs("A", max_depth=4)
        endpoints = {p[-1] for p in paths}
        assert "B" in endpoints
        assert "E" in endpoints

    def test_shortest_path(self):
        g = _build_chain(self._make_backend())
        path = g.shortest_path("A", "E")
        assert path is not None
        assert path[0] == "A"
        assert path[-1] == "E"
        assert len(path) == 5

    def test_shortest_path_no_path(self):
        g = self._make_backend()
        g.add_node("X", kind="node", label="X")
        g.add_node("Y", kind="node", label="Y")
        path = g.shortest_path("X", "Y")
        assert path is None

    def test_to_dict(self):
        g = _build_triangle(self._make_backend())
        data = g.to_dict()
        assert len(data["nodes"]) == 3
        assert data["stats"]["node_count"] == 3

    def test_centrality_pagerank(self):
        g = _build_star(self._make_backend())
        scores = g.centrality_scores()
        assert "center" in scores
        # PageRank: center should have high score
        assert scores["center"] > 0

    def test_bottleneck_betweenness(self):
        g = _build_chain(self._make_backend())
        bottlenecks = g.bottleneck_nodes(top_n=3)
        assert len(bottlenecks) <= 3
        # Middle nodes should have highest betweenness
        top_ids = [n[0] for n in bottlenecks]
        assert any(n in top_ids for n in ["B", "C", "D"])

    def test_centrality_empty(self):
        g = self._make_backend()
        assert g.centrality_scores() == {}

    def test_bottleneck_empty(self):
        g = self._make_backend()
        assert g.bottleneck_nodes() == []


# ---------------------------------------------------------------------------
# TestProtocol
# ---------------------------------------------------------------------------


class TestProtocol:
    def test_inmemory_is_graph_backend(self):
        g = InMemoryBackend()
        assert isinstance(g, GraphBackend)

    def test_networkx_is_graph_backend(self):
        pytest.importorskip("networkx")
        from agent_bom.graph_backend import NetworkXBackend

        g = NetworkXBackend()
        assert isinstance(g, GraphBackend)


# ---------------------------------------------------------------------------
# TestFactory
# ---------------------------------------------------------------------------


class TestFactory:
    def test_memory_backend(self):
        g = get_backend("memory")
        assert isinstance(g, InMemoryBackend)

    def test_auto_backend(self):
        g = get_backend("auto")
        assert isinstance(g, GraphBackend)

    def test_networkx_backend_if_available(self):
        try:
            import networkx  # noqa: F401

            g = get_backend("networkx")
            from agent_bom.graph_backend import NetworkXBackend

            assert isinstance(g, NetworkXBackend)
        except ImportError:
            pytest.skip("networkx not installed")


# ---------------------------------------------------------------------------
# TestFromContextGraph
# ---------------------------------------------------------------------------


class TestFromContextGraph:
    def test_converts_context_graph_data(self):
        data = {
            "nodes": [
                {"id": "agent:test", "kind": "agent", "label": "test"},
                {"id": "server:test:mcp", "kind": "server", "label": "mcp"},
            ],
            "edges": [
                {"source": "agent:test", "target": "server:test:mcp", "kind": "uses", "weight": 1.0},
            ],
        }
        g = from_context_graph(data, backend="memory")
        assert g.has_node("agent:test")
        assert g.has_node("server:test:mcp")
        assert g.has_edge("agent:test", "server:test:mcp")
        assert g.node_count() == 2
        assert g.edge_count() == 1

    def test_empty_context_graph(self):
        g = from_context_graph({}, backend="memory")
        assert g.node_count() == 0

    def test_centrality_on_converted_graph(self):
        data = {
            "nodes": [
                {"id": "center", "kind": "server", "label": "hub"},
                {"id": "a1", "kind": "agent", "label": "a1"},
                {"id": "a2", "kind": "agent", "label": "a2"},
                {"id": "a3", "kind": "agent", "label": "a3"},
            ],
            "edges": [
                {"source": "center", "target": "a1", "kind": "uses", "weight": 1.0},
                {"source": "center", "target": "a2", "kind": "uses", "weight": 1.0},
                {"source": "center", "target": "a3", "kind": "uses", "weight": 1.0},
            ],
        }
        g = from_context_graph(data, backend="memory")
        scores = g.centrality_scores()
        assert scores["center"] == max(scores.values())
