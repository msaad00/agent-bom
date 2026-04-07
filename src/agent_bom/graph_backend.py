"""Graph backend abstraction with optional NetworkX support.

Provides a Protocol-based graph backend that supports both a zero-dependency
in-memory implementation and an optional NetworkX-backed implementation with
centrality analysis (PageRank, betweenness centrality).

Severity constants and the canonical graph types are defined in
:mod:`graph_schema` — this module uses them for consistency.

Install NetworkX for advanced graph analytics:
    pip install 'agent-bom[graph]'
"""

from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Protocol, runtime_checkable

from agent_bom.graph import EntityType, RelationshipType, UnifiedGraph


@runtime_checkable
class GraphBackend(Protocol):
    """Protocol for graph backend implementations."""

    def add_node(self, node_id: str, kind: str, label: str, **metadata: object) -> None: ...
    def add_edge(self, source: str, target: str, kind: str, weight: float = 1.0, **metadata: object) -> None: ...
    def has_node(self, node_id: str) -> bool: ...
    def has_edge(self, source: str, target: str) -> bool: ...
    def neighbors(self, node_id: str) -> list[str]: ...
    def bfs(self, source: str, max_depth: int = 4) -> list[list[str]]: ...
    def shortest_path(self, source: str, target: str) -> list[str] | None: ...
    def node_count(self) -> int: ...
    def edge_count(self) -> int: ...
    def to_dict(self) -> dict: ...
    def centrality_scores(self) -> dict[str, float]: ...
    def bottleneck_nodes(self, top_n: int = 5) -> list[tuple[str, float]]: ...


@dataclass
class InMemoryBackend:
    """Zero-dependency in-memory graph backend using stdlib only."""

    _nodes: dict[str, dict] = field(default_factory=dict)
    _adj: dict[str, dict[str, dict]] = field(default_factory=lambda: defaultdict(dict))
    _edge_count: int = 0

    def add_node(self, node_id: str, kind: str, label: str, **metadata: object) -> None:
        self._nodes[node_id] = {"kind": kind, "label": label, **metadata}

    def add_edge(self, source: str, target: str, kind: str, weight: float = 1.0, **metadata: object) -> None:
        self._adj[source][target] = {"kind": kind, "weight": weight, **metadata}
        self._adj[target][source] = {"kind": kind, "weight": weight, **metadata}
        self._edge_count += 1

    def has_node(self, node_id: str) -> bool:
        return node_id in self._nodes

    def has_edge(self, source: str, target: str) -> bool:
        return target in self._adj.get(source, {})

    def neighbors(self, node_id: str) -> list[str]:
        return list(self._adj.get(node_id, {}).keys())

    def bfs(self, source: str, max_depth: int = 4) -> list[list[str]]:
        if source not in self._nodes:
            return []
        paths: list[list[str]] = []
        queue: deque[tuple[str, list[str]]] = deque([(source, [source])])
        visited: set[str] = {source}
        while queue:
            current, path = queue.popleft()
            if len(path) > max_depth + 1:
                continue
            if len(path) > 1:
                paths.append(path)
            for neighbor in self._adj.get(current, {}):
                if neighbor not in visited:
                    visited.add(neighbor)
                    queue.append((neighbor, path + [neighbor]))
        return paths

    def shortest_path(self, source: str, target: str) -> list[str] | None:
        if source not in self._nodes or target not in self._nodes:
            return None
        if source == target:
            return [source]
        queue: deque[tuple[str, list[str]]] = deque([(source, [source])])
        visited: set[str] = {source}
        while queue:
            current, path = queue.popleft()
            for neighbor in self._adj.get(current, {}):
                if neighbor == target:
                    return path + [neighbor]
                if neighbor not in visited:
                    visited.add(neighbor)
                    queue.append((neighbor, path + [neighbor]))
        return None

    def node_count(self) -> int:
        return len(self._nodes)

    def edge_count(self) -> int:
        return self._edge_count

    def to_dict(self) -> dict:
        return {
            "nodes": [{"id": nid, **data} for nid, data in self._nodes.items()],
            "edges": [
                {"source": src, "target": tgt, **data}
                for src, targets in self._adj.items()
                for tgt, data in targets.items()
                if src < tgt  # Avoid duplicate edges
            ],
            "stats": {"node_count": self.node_count(), "edge_count": self.edge_count()},
        }

    def centrality_scores(self) -> dict[str, float]:
        """Degree-based centrality (normalized by max possible connections)."""
        if not self._nodes:
            return {}
        max_possible = max(len(self._nodes) - 1, 1)
        return {nid: len(self._adj.get(nid, {})) / max_possible for nid in self._nodes}

    def bottleneck_nodes(self, top_n: int = 5) -> list[tuple[str, float]]:
        """Approximate betweenness centrality using BFS counting."""
        if not self._nodes:
            return []
        scores: dict[str, float] = {nid: 0.0 for nid in self._nodes}
        node_list = list(self._nodes.keys())

        # Sample a subset for performance (BFS from each node)
        sample = node_list[: min(50, len(node_list))]
        for src in sample:
            # BFS to find shortest paths
            visited: dict[str, list[str]] = {src: [src]}
            queue: deque[str] = deque([src])
            while queue:
                current = queue.popleft()
                for neighbor in self._adj.get(current, {}):
                    if neighbor not in visited:
                        visited[neighbor] = visited[current] + [neighbor]
                        queue.append(neighbor)
            # Count intermediate nodes
            for path in visited.values():
                for node in path[1:-1]:
                    scores[node] += 1.0

        # Normalize
        total = sum(scores.values()) or 1.0
        normalized = {nid: score / total for nid, score in scores.items()}
        sorted_nodes = sorted(normalized.items(), key=lambda x: x[1], reverse=True)
        return sorted_nodes[:top_n]


class NetworkXBackend:
    """NetworkX-backed graph backend with advanced analytics.

    Requires: pip install networkx
    """

    def __init__(self) -> None:
        import networkx as nx

        self._graph: nx.DiGraph = nx.DiGraph()
        self._nx = nx

    def add_node(self, node_id: str, kind: str, label: str, **metadata: object) -> None:
        self._graph.add_node(node_id, kind=kind, label=label, **metadata)

    def add_edge(self, source: str, target: str, kind: str, weight: float = 1.0, **metadata: object) -> None:
        self._graph.add_edge(source, target, kind=kind, weight=weight, **metadata)
        self._graph.add_edge(target, source, kind=kind, weight=weight, **metadata)

    def has_node(self, node_id: str) -> bool:
        return self._graph.has_node(node_id)

    def has_edge(self, source: str, target: str) -> bool:
        return self._graph.has_edge(source, target)

    def neighbors(self, node_id: str) -> list[str]:
        if not self._graph.has_node(node_id):
            return []
        return list(self._graph.neighbors(node_id))

    def bfs(self, source: str, max_depth: int = 4) -> list[list[str]]:
        if not self._graph.has_node(source):
            return []
        paths: list[list[str]] = []
        tree = self._nx.bfs_tree(self._graph, source, depth_limit=max_depth)
        for node in tree.nodes():
            if node != source:
                try:
                    path = self._nx.shortest_path(self._graph, source, node)
                    paths.append(path)
                except self._nx.NetworkXNoPath:
                    pass
        return paths

    def shortest_path(self, source: str, target: str) -> list[str] | None:
        try:
            return self._nx.shortest_path(self._graph, source, target)
        except (self._nx.NetworkXNoPath, self._nx.NodeNotFound):
            return None

    def node_count(self) -> int:
        return self._graph.number_of_nodes()

    def edge_count(self) -> int:
        return self._graph.number_of_edges() // 2  # Bidirectional

    def to_dict(self) -> dict:
        nodes = [{"id": nid, **data} for nid, data in self._graph.nodes(data=True)]
        seen: set[tuple[str, str]] = set()
        edges = []
        for src, tgt, data in self._graph.edges(data=True):
            key = (min(src, tgt), max(src, tgt))
            if key not in seen:
                seen.add(key)
                edges.append({"source": src, "target": tgt, **data})
        return {
            "nodes": nodes,
            "edges": edges,
            "stats": {"node_count": self.node_count(), "edge_count": self.edge_count()},
        }

    def centrality_scores(self) -> dict[str, float]:
        """PageRank centrality via NetworkX."""
        if self._graph.number_of_nodes() == 0:
            return {}
        return self._nx.pagerank(self._graph)

    def bottleneck_nodes(self, top_n: int = 5) -> list[tuple[str, float]]:
        """Betweenness centrality via NetworkX."""
        if self._graph.number_of_nodes() == 0:
            return []
        centrality = self._nx.betweenness_centrality(self._graph)
        sorted_nodes = sorted(centrality.items(), key=lambda x: x[1], reverse=True)
        return sorted_nodes[:top_n]


def get_backend(backend: str = "auto") -> GraphBackend:
    """Factory: create a graph backend.

    Args:
        backend: 'memory', 'networkx', or 'auto' (tries networkx, falls back to memory).
    """
    if backend == "memory":
        return InMemoryBackend()
    if backend == "networkx":
        return NetworkXBackend()
    # Auto: try networkx, fall back to memory
    try:
        return NetworkXBackend()
    except ImportError:
        return InMemoryBackend()


def from_context_graph(context_graph_data: dict, backend: str = "auto") -> GraphBackend:
    """Convert serialized context graph data into a GraphBackend for analysis."""
    graph = get_backend(backend)
    for node in context_graph_data.get("nodes", []):
        graph.add_node(
            node_id=node["id"],
            kind=node.get("kind", ""),
            label=node.get("label", ""),
        )
    for edge in context_graph_data.get("edges", []):
        graph.add_edge(
            source=edge["source"],
            target=edge["target"],
            kind=edge.get("kind", ""),
            weight=edge.get("weight", 1.0),
        )
    return graph


def from_unified_graph(ug: UnifiedGraph, backend: str = "auto") -> GraphBackend:
    """Convert a :class:`UnifiedGraph` into a GraphBackend for centrality analysis."""
    graph = get_backend(backend)
    for node in ug.nodes.values():
        et = node.entity_type.value if isinstance(node.entity_type, EntityType) else node.entity_type
        graph.add_node(
            node_id=node.id,
            kind=et,
            label=node.label,
            severity=node.severity,
            risk_score=node.risk_score,
        )
    for edge in ug.edges:
        rel = edge.relationship.value if isinstance(edge.relationship, RelationshipType) else edge.relationship
        graph.add_edge(
            source=edge.source,
            target=edge.target,
            kind=rel,
            weight=edge.weight,
        )
    return graph
