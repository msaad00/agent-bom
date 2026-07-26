"""Observed-only graph scope selection for bounded API projections."""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass
from typing import Literal

from agent_bom.graph.container import UnifiedGraph
from agent_bom.graph.edge import UnifiedEdge
from agent_bom.graph.node import UnifiedNode
from agent_bom.graph.types import RelationshipType

GraphScopeKind = Literal["estate", "account", "repository", "environment", "investigation"]

_ATTRIBUTE_KEYS: dict[str, tuple[str, ...]] = {
    "account": ("account_id", "cloud_account_id", "subscription_id", "project_id"),
    "repository": ("repository", "repository_id", "repo_full_name", "repo_url", "full_name"),
    "environment": ("environment",),
}


@dataclass(frozen=True, slots=True)
class ScopedGraph:
    graph: UnifiedGraph
    observed: bool
    basis: str
    reason: str = ""
    total_nodes: int | None = None
    total_edges: int | None = None
    node_truncated: bool = False
    edge_truncated: bool = False

    @property
    def truncated(self) -> bool:
        return self.node_truncated or self.edge_truncated


def _matches_persisted_scope(node: UnifiedNode, kind: str, scope_id: str) -> bool:
    """Match only explicit persisted dimensions/attributes, never labels or IDs."""
    expected = scope_id.strip().casefold()
    if kind == "environment" and node.dimensions.environment.strip().casefold() == expected:
        return True
    for key in _ATTRIBUTE_KEYS[kind]:
        value = node.attributes.get(key)
        if isinstance(value, str) and value.strip().casefold() == expected:
            return True
    return False


def _edge_sort_key(edge: object) -> tuple[str, str, str]:
    source = str(getattr(edge, "source", ""))
    target = str(getattr(edge, "target", ""))
    relationship = getattr(edge, "relationship", "")
    relationship_value = str(getattr(relationship, "value", relationship))
    return source, target, relationship_value


def _induced_subgraph(
    graph: UnifiedGraph,
    node_ids: set[str],
    *,
    max_edges: int,
) -> tuple[UnifiedGraph, int]:
    scoped = UnifiedGraph(
        scan_id=graph.scan_id,
        tenant_id=graph.tenant_id,
        created_at=graph.created_at,
        analysis_status=dict(graph.analysis_status),
    )
    for node_id in sorted(node_ids):
        node = graph.nodes.get(node_id)
        if node is not None:
            scoped.add_node(node)
    matching_edges = sorted(
        (
            edge
            for edge in graph.edges
            if edge.source in node_ids and edge.target in node_ids
        ),
        key=_edge_sort_key,
    )
    for edge in matching_edges[:max_edges]:
        scoped.add_edge(edge)
    return scoped, len(matching_edges)


_REPOSITORY_FORWARD_RELATIONSHIPS = frozenset(
    {
        RelationshipType.CONTAINS,
        RelationshipType.DEPENDS_ON,
    }
)


def _repository_subgraph(
    graph: UnifiedGraph,
    roots: set[str],
    *,
    max_depth: int,
    max_nodes: int,
    max_edges: int,
) -> ScopedGraph:
    """Traverse a repository from persisted overlay anchors and relationships.

    Repository trust metadata is stamped on both the repository APPLICATION and
    root DIRECTORY.  The structure overlay then supplies observed CONTAINS and
    DEPENDS_ON edges, while file/package findings point inward with AFFECTS.
    Traversal follows only those persisted relationships and never manufactures
    an APPLICATION-to-directory edge.
    """
    ordered_roots = sorted(roots)
    kept_roots = ordered_roots[:max_nodes]
    visited = set(kept_roots)
    queue: deque[tuple[str, int]] = deque((root, 0) for root in kept_roots)
    selected_edges: dict[tuple[str, str, str], UnifiedEdge] = {}
    node_truncated = len(ordered_roots) > len(kept_roots)
    edge_truncated = False
    reason = "scope_node_limit" if node_truncated else ""

    while queue:
        current, depth = queue.popleft()
        candidates: list[tuple[str, UnifiedEdge]] = []
        candidates.extend(
            (edge.target, edge)
            for edge in graph.adjacency.get(current, [])
            if edge.relationship in _REPOSITORY_FORWARD_RELATIONSHIPS
        )
        candidates.extend(
            (edge.source, edge)
            for edge in graph.reverse_adjacency.get(current, [])
            if edge.relationship == RelationshipType.AFFECTS
        )
        candidates.sort(key=lambda item: (item[0], _edge_sort_key(item[1])))

        for neighbor, edge in candidates:
            relationship = getattr(edge.relationship, "value", edge.relationship)
            edge_key = (edge.source, edge.target, str(relationship))
            if edge_key in selected_edges:
                continue

            if neighbor not in visited:
                if depth >= max_depth:
                    node_truncated = True
                    if not reason:
                        reason = "scope_traversal_limit"
                    continue
                if len(visited) >= max_nodes:
                    node_truncated = True
                    reason = "scope_node_limit"
                    continue

            if len(selected_edges) >= max_edges:
                edge_truncated = True
                if not reason:
                    reason = "scope_edge_limit"
                continue

            if neighbor not in visited:
                visited.add(neighbor)
                queue.append((neighbor, depth + 1))
            selected_edges[edge_key] = edge

    scoped = UnifiedGraph(
        scan_id=graph.scan_id,
        tenant_id=graph.tenant_id,
        created_at=graph.created_at,
        analysis_status=dict(graph.analysis_status),
    )
    for node_id in sorted(visited):
        node = graph.nodes.get(node_id)
        if node is not None:
            scoped.add_node(node)
    for edge in sorted(selected_edges.values(), key=_edge_sort_key):
        if edge.source in scoped.nodes and edge.target in scoped.nodes:
            scoped.add_edge(edge)

    incomplete = node_truncated or edge_truncated
    return ScopedGraph(
        graph=scoped,
        observed=bool(roots),
        basis="persisted_graph_traversal",
        reason=reason,
        total_nodes=None if incomplete else len(scoped.nodes),
        total_edges=None if incomplete else len(scoped.edges),
        node_truncated=node_truncated,
        edge_truncated=edge_truncated or node_truncated,
    )


def select_observed_scope(
    graph: UnifiedGraph,
    *,
    kind: GraphScopeKind,
    scope_id: str | None,
    max_depth: int,
    max_nodes: int,
    max_edges: int,
) -> ScopedGraph:
    """Return a bounded scope using only evidence persisted in ``graph``."""
    if kind == "estate":
        all_node_ids = sorted(graph.nodes)
        node_ids = set(all_node_ids[:max_nodes])
        scoped, total_edges = _induced_subgraph(graph, node_ids, max_edges=max_edges)
        node_truncated = len(all_node_ids) > len(scoped.nodes)
        edge_truncated = node_truncated or total_edges > len(scoped.edges)
        return ScopedGraph(
            graph=scoped,
            observed=bool(scoped.nodes),
            basis="persisted_graph_snapshot",
            reason="scope_node_limit" if node_truncated else "scope_edge_limit" if edge_truncated else "",
            total_nodes=len(all_node_ids),
            total_edges=None if node_truncated else total_edges,
            node_truncated=node_truncated,
            edge_truncated=edge_truncated,
        )

    if not scope_id:
        scoped, _ = _induced_subgraph(graph, set(), max_edges=max_edges)
        return ScopedGraph(
            graph=scoped,
            observed=False,
            basis="persisted_graph_traversal" if kind == "investigation" else "persisted_node_attributes",
            total_nodes=0,
            total_edges=0,
        )

    if kind == "investigation":
        scoped, _, truncated = graph.traverse_subgraph(
            [scope_id],
            direction="forward",
            max_depth=max_depth,
            max_nodes=max_nodes,
            max_edges=max_edges,
        )
        return ScopedGraph(
            graph=scoped,
            observed=scope_id in graph.nodes,
            basis="persisted_graph_traversal",
            reason="scope_traversal_limit" if truncated else "",
            total_nodes=None if truncated else len(scoped.nodes),
            total_edges=None if truncated else len(scoped.edges),
            node_truncated=truncated,
            edge_truncated=truncated,
        )

    matches = {
        node.id
        for node in graph.nodes.values()
        if _matches_persisted_scope(node, kind, scope_id)
    }
    if kind == "repository":
        return _repository_subgraph(
            graph,
            matches,
            max_depth=max_depth,
            max_nodes=max_nodes,
            max_edges=max_edges,
        )
    kept_matches = set(sorted(matches)[:max_nodes])
    scoped, total_edges = _induced_subgraph(
        graph,
        kept_matches,
        max_edges=max_edges,
    )
    node_truncated = len(matches) > len(scoped.nodes)
    edge_truncated = node_truncated or total_edges > len(scoped.edges)
    return ScopedGraph(
        graph=scoped,
        observed=bool(matches),
        basis="persisted_node_attributes",
        reason="scope_node_limit" if node_truncated else "scope_edge_limit" if edge_truncated else "",
        total_nodes=len(matches),
        total_edges=None if node_truncated else total_edges,
        node_truncated=node_truncated,
        edge_truncated=edge_truncated,
    )
