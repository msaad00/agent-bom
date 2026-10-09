"""Bounded traversal request and projection shared by graph investigations."""

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from agent_bom.graph.completeness import bounded_walk_reason, graph_completeness
from agent_bom.graph.container import GraphFilterOptions, UnifiedGraph
from agent_bom.graph.node import UnifiedNode
from agent_bom.graph.severity_floor import node_passes_severity_floor
from agent_bom.graph.types import RelationshipType


class GraphQueryRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    roots: list[str] = Field(..., min_length=1, description="One or more starting node IDs")
    scan_id: str = ""
    snapshot_generation: str | None = Field(None, max_length=128, description="Expected read revision; replacement returns 409")
    direction: Literal["forward", "reverse", "both"] = "forward"
    max_depth: int = Field(4, ge=1, le=10)
    max_nodes: int = Field(500, ge=1, le=5000)
    max_edges: int = Field(10_000, ge=1, le=25_000)
    timeout_ms: int = Field(2500, ge=100, le=5000)
    traversable_only: bool = False
    static_only: bool = False
    dynamic_only: bool = False
    include_roots: bool = True
    include_attack_paths: bool = False
    min_severity: str = ""
    entity_types: list[str] = Field(default_factory=list)
    relationship_types: list[str] = Field(default_factory=list)
    compliance_prefixes: list[str] = Field(default_factory=list)
    data_sources: list[str] = Field(default_factory=list)


def _node_matches_query(
    node: UnifiedNode,
    *,
    entity_types: set[str],
    min_severity_rank: int,
    compliance_prefixes: set[str],
    data_sources: set[str],
) -> bool:
    if entity_types:
        entity_type = node.entity_type.value if hasattr(node.entity_type, "value") else str(node.entity_type)
        if entity_type not in entity_types:
            return False
    # This used a local predicate that knew only two of the three rated entity
    # types, so a drift incident below the floor stayed on the page here and was
    # dropped by the stores.
    if not node_passes_severity_floor(entity_type=node.entity_type, severity=node.severity, min_severity_rank=min_severity_rank):
        return False
    if compliance_prefixes:
        prefixes = {tag.split("-")[0].upper() if "-" in tag else tag.upper() for tag in node.compliance_tags}
        if not prefixes.intersection(compliance_prefixes):
            return False
    if data_sources and not set(node.data_sources).intersection(data_sources):
        return False
    return True


def _filtered_query_graph(
    graph: UnifiedGraph,
    *,
    roots: list[str],
    entity_types: set[str],
    min_severity_rank: int,
    compliance_prefixes: set[str],
    data_sources: set[str],
) -> UnifiedGraph:
    filtered = UnifiedGraph(scan_id=graph.scan_id, tenant_id=graph.tenant_id, created_at=graph.created_at)
    keep_ids = {
        node.id
        for node in graph.nodes.values()
        if _node_matches_query(
            node,
            entity_types=entity_types,
            min_severity_rank=min_severity_rank,
            compliance_prefixes=compliance_prefixes,
            data_sources=data_sources,
        )
    }
    keep_ids.update(root for root in roots if root in graph.nodes)

    for node_id in keep_ids:
        node = graph.nodes.get(node_id)
        if node:
            filtered.add_node(node)
    for edge in graph.edges:
        if edge.source in keep_ids and edge.target in keep_ids:
            filtered.add_edge(edge)
    return filtered


def query_payload(
    body: GraphQueryRequest,
    filtered_graph: UnifiedGraph,
    depth_by_node: dict[str, int],
    truncated: bool,
    depth_limited: bool,
    attack_paths: list[dict[str, Any]],
    budget: dict[str, int],
    rel_types: set[RelationshipType] | None,
    snapshot_generation: str | None,
) -> dict[str, Any]:
    """Keep traversal limits attached to the projected investigation graph."""
    bounded = truncated or depth_limited
    return {
        "snapshot_generation": snapshot_generation,
        "scan_id": filtered_graph.scan_id,
        "tenant_id": filtered_graph.tenant_id,
        "roots": body.roots,
        "direction": body.direction,
        "max_depth": body.max_depth,
        "max_nodes": body.max_nodes,
        "max_edges": body.max_edges,
        "timeout_ms": body.timeout_ms,
        "budget": budget,
        "truncated": truncated,
        "depth_limited": depth_limited,
        "missing_roots": [],
        "depth_by_node": {node_id: depth for node_id, depth in depth_by_node.items() if node_id in filtered_graph.nodes},
        "nodes": [node.to_dict() for node in filtered_graph.nodes.values()],
        "edges": [edge.to_dict() for edge in filtered_graph.edges],
        "attack_paths": attack_paths,
        "stats": filtered_graph.stats(),
        "filters": GraphFilterOptions(
            max_depth=body.max_depth,
            min_severity=body.min_severity,
            relationship_types=rel_types or set(),
            static_only=body.static_only,
            dynamic_only=body.dynamic_only,
            include_ids=set(body.roots),
        ).to_dict(),
        # The traversal's own completeness carries a loss the `truncated` bool
        # does not: a walk that stopped at `max_depth` with reachable nodes
        # still unwalked. Reading only the bool reported such a walk as a
        # complete answer, which is how a bounded traversal comes to read as
        # "there is no attack path past here".
        "completeness": graph_completeness(
            returned=len(filtered_graph.nodes),
            total=None if bounded else filtered_graph.stats().get("node_count", len(filtered_graph.nodes)),
            truncated=bounded,
            reason=bounded_walk_reason(truncated=truncated, depth_limited=depth_limited),
        ),
    }
