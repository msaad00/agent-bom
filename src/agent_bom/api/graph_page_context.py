"""Resolve containment ancestors without reading a parent's entire estate."""

from __future__ import annotations

from typing import Any

from agent_bom.graph import UnifiedEdge, UnifiedNode
from agent_bom.graph.rollup import ROLLUP_CONTAINMENT_RELATIONSHIPS


async def containment_ancestors(
    graph_store: Any,
    *,
    scan_id: str,
    tenant_id: str,
    node_ids: set[str],
    call_store: Any,
) -> tuple[list[UnifiedNode], list[UnifiedEdge]]:
    """Follow incoming containment edges for at most five parent levels.

    Ranked findings often exclude the account/environment spine. Read that
    context separately from bounded incident evidence so an omitted relationship
    cannot erase a parent. Outgoing siblings never need to be hydrated.
    """
    ancestor_ids: set[str] = set()
    ancestor_edges: dict[tuple[str, str], UnifiedEdge] = {}
    frontier = set(node_ids)
    for _level in range(5):
        if not frontier:
            break
        edges = await call_store(
            graph_store.edges_for_node_ids,
            scan_id=scan_id,
            tenant_id=tenant_id,
            node_ids=frontier,
            direction="in",
            relationships=set(ROLLUP_CONTAINMENT_RELATIONSHIPS),
        )
        parents = set()
        for edge in edges:
            if edge.target in frontier and edge.source not in node_ids:
                parents.add(edge.source)
                ancestor_edges[(edge.source, edge.target)] = edge
        parents -= ancestor_ids
        ancestor_ids |= parents
        frontier = parents
    if not ancestor_ids:
        return [], []
    nodes = await call_store(graph_store.nodes_by_ids, scan_id=scan_id, tenant_id=tenant_id, node_ids=ancestor_ids)
    return list(nodes), list(ancestor_edges.values())


async def page_attack_context(
    graph_store: Any, *, scan_id: str, tenant_id: str, node_ids: set[str], call_store: Any
) -> tuple[list[Any], list[UnifiedNode]]:
    """Read path records and their supplemental hop nodes off the event loop."""
    paths = await call_store(graph_store.attack_paths_for_sources, scan_id=scan_id, tenant_id=tenant_id, source_ids=node_ids)
    hop_ids = {hop for path in paths for hop in path.hops}
    nodes = await call_store(graph_store.nodes_by_ids, scan_id=scan_id, tenant_id=tenant_id, node_ids=hop_ids - node_ids)
    return paths, nodes
