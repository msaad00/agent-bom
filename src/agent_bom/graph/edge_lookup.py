"""Shared edge indexing for ordered path projection and topology derivation."""

from __future__ import annotations

from agent_bom.graph.edge import UnifiedEdge

_EdgeLookup = dict[tuple[str, ...], UnifiedEdge]


def _rel_value(edge: UnifiedEdge) -> str:
    return edge.relationship.value if hasattr(edge.relationship, "value") else str(edge.relationship)


def _build_edge_lookup(edges: list[UnifiedEdge] | None) -> _EdgeLookup:
    """Index directed hop pairs once for a response serialization batch."""
    by_pair: _EdgeLookup = {}
    for edge in edges or []:
        by_pair.setdefault((edge.source, edge.target), edge)
        by_pair.setdefault((edge.source, edge.target, _rel_value(edge)), edge)
        if edge.is_bidirectional:
            by_pair.setdefault((edge.target, edge.source), edge)
            by_pair.setdefault((edge.target, edge.source, _rel_value(edge)), edge)
    return by_pair


def _edge_relationships_for_hops(
    hops: list[str],
    edges: list[UnifiedEdge] | None = None,
    *,
    edge_lookup: _EdgeLookup | None = None,
) -> list[str]:
    """Return relationship names for consecutive hop pairs when topology is available."""
    if len(hops) < 2:
        return []
    by_pair = edge_lookup if edge_lookup is not None else _build_edge_lookup(edges)
    relationships: list[str] = []
    for source, target in zip(hops, hops[1:], strict=False):
        edge = by_pair.get((source, target))
        if edge is not None:
            relationships.append(_rel_value(edge))
    return relationships
