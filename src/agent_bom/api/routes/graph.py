"""Graph query API — unified graph data with filters, pagination, RBAC, presets.

Endpoints:
  GET  /v1/graph                — load unified graph (filtered, paginated)
  GET  /v1/graph/diff           — diff between two scan snapshots
  GET  /v1/graph/paths          — attack paths from a source node
  GET  /v1/graph/impact         — blast radius of a node (reverse BFS)
  GET  /v1/graph/search         — full-text graph search
  GET  /v1/graph/agents         — paginated agent node selector
  POST /v1/graph/query          — programmable traversal query
  GET  /v1/graph/node/{id}      — single node detail with edges + impact
  GET  /v1/graph/snapshots      — list persisted scan snapshots
  GET  /v1/graph/legend         — entity + relationship legends
  POST /v1/graph/presets        — save a filter preset
  GET  /v1/graph/presets        — list saved presets
  DEL  /v1/graph/presets/{name} — delete a preset
"""

from __future__ import annotations

import asyncio
import logging
import os
import time
from typing import Literal, Optional

from fastapi import APIRouter, HTTPException, Query, Request
from pydantic import BaseModel, Field

from agent_bom.api.stores import _get_graph_store
from agent_bom.backpressure import BackpressureRejectedError, adaptive_backpressure
from agent_bom.graph import SEVERITY_RANK, EntityType, GraphFilterOptions, RelationshipType, UnifiedGraph
from agent_bom.security import sanitize_error

logger = logging.getLogger(__name__)
router = APIRouter()
_ALLOWED_ENTITY_TYPES = {entity_type.value for entity_type in EntityType}
_GRAPH_QUERY_ABSOLUTE_LIMITS = {
    "max_depth": 10,
    "max_nodes": 5000,
    "max_edges": 25_000,
    "timeout_ms": 5000,
}
_GRAPH_QUERY_DEFAULT_BUDGET = {
    "max_depth": 5,
    "max_nodes": 1000,
    "max_edges": 10_000,
    "timeout_ms": 2500,
}


# ═══════════════════════════════════════════════════════════════════════════
# Helpers
# ═══════════════════════════════════════════════════════════════════════════


def _get_graph_store_or_503():
    """Resolve the active graph store backend."""
    return _get_graph_store()


def _tenant(request: Request) -> str:
    """Extract tenant_id from request (set by auth middleware)."""
    return getattr(request.state, "tenant_id", "default")


def _paginate(items: list, offset: int, limit: int) -> tuple[list, dict]:
    """Apply offset/limit pagination and return (page, pagination_meta)."""
    total = len(items)
    page = items[offset : offset + limit]
    return page, {
        "total": total,
        "offset": offset,
        "limit": limit,
        "has_more": offset + limit < total,
    }


def _page_meta(total: int, offset: int, limit: int, *, cursor: str | None = None, next_cursor: str | None = None) -> dict:
    return {
        "total": total,
        "offset": offset,
        "limit": limit,
        "cursor": cursor or "",
        "next_cursor": next_cursor or "",
        "has_more": bool(next_cursor) if cursor else offset + limit < total,
    }


def _parse_entity_type_filter(raw: str | None) -> set[str] | None:
    if not raw:
        return None
    values = {value.strip() for value in raw.split(",") if value.strip()}
    invalid = sorted(values - _ALLOWED_ENTITY_TYPES)
    if invalid:
        raise HTTPException(status_code=422, detail=f"Unsupported graph entity type: {invalid[0]}")
    return values or None


def _validate_entity_type_list(values: list[str]) -> list[str]:
    cleaned = [value.strip() for value in values if value.strip()]
    invalid = sorted(set(cleaned) - _ALLOWED_ENTITY_TYPES)
    if invalid:
        raise HTTPException(status_code=422, detail=f"Unsupported graph entity type: {invalid[0]}")
    return cleaned


def _bounded_env_int(name: str, default: int, *, minimum: int, maximum: int) -> int:
    raw = os.environ.get(name)
    if raw is None:
        return default
    try:
        value = int(raw)
    except ValueError:
        return default
    return min(max(value, minimum), maximum)


def _graph_query_budget() -> dict[str, int]:
    """Return the deployer-configured graph traversal budget.

    Pydantic keeps absolute request ceilings. This budget is the lower,
    operator-tunable resource control used by the traversal endpoint.
    """
    return {
        key: _bounded_env_int(
            f"AGENT_BOM_GRAPH_QUERY_{key.upper()}",
            default,
            minimum=1 if key != "timeout_ms" else 100,
            maximum=_GRAPH_QUERY_ABSOLUTE_LIMITS[key],
        )
        for key, default in _GRAPH_QUERY_DEFAULT_BUDGET.items()
    }


def _enforce_graph_query_budget(body: GraphQueryRequest) -> dict[str, int]:
    budget = _graph_query_budget()
    requested = {
        "max_depth": body.max_depth,
        "max_nodes": body.max_nodes,
        "max_edges": body.max_edges,
        "timeout_ms": body.timeout_ms,
    }
    violations = {key: {"requested": value, "allowed": budget[key]} for key, value in requested.items() if value > budget[key]}
    if violations:
        raise HTTPException(
            status_code=422,
            detail={
                "message": "Graph query exceeds tenant query budget",
                "violations": violations,
                "budget": budget,
            },
        )
    return budget


async def _graph_store_call(fn, /, *args, **kwargs):
    """Run sync graph store methods off the event loop."""
    try:
        async with adaptive_backpressure("graph"):
            return await asyncio.to_thread(fn, *args, **kwargs)
    except BackpressureRejectedError as exc:
        raise HTTPException(status_code=429, detail=exc.to_dict(), headers={"Retry-After": str(exc.retry_after_seconds)}) from exc


# ═══════════════════════════════════════════════════════════════════════════
# Preset model
# ═══════════════════════════════════════════════════════════════════════════


class PresetCreate(BaseModel):
    name: str
    description: str = ""
    filters: dict


class GraphQueryRequest(BaseModel):
    roots: list[str] = Field(..., min_length=1, description="One or more starting node IDs")
    scan_id: str = ""
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
    node,
    *,
    entity_types: set[str],
    min_severity_rank: int,
    compliance_prefixes: set[str],
    data_sources: set[str],
) -> bool:
    from agent_bom.graph import SEVERITY_RANK

    if entity_types:
        entity_type = node.entity_type.value if hasattr(node.entity_type, "value") else str(node.entity_type)
        if entity_type not in entity_types:
            return False
    if min_severity_rank and SEVERITY_RANK.get(node.severity.lower(), 0) < min_severity_rank:
        return False
    if compliance_prefixes:
        prefixes = {tag.split("-")[0].upper() if "-" in tag else tag.upper() for tag in node.compliance_tags}
        if not prefixes.intersection(compliance_prefixes):
            return False
    if data_sources and not set(node.data_sources).intersection(data_sources):
        return False
    return True


def _filtered_query_graph(
    graph,
    *,
    roots: list[str],
    entity_types: set[str],
    min_severity_rank: int,
    compliance_prefixes: set[str],
    data_sources: set[str],
):
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


# ═══════════════════════════════════════════════════════════════════════════
# Endpoints
# ═══════════════════════════════════════════════════════════════════════════


@router.get("/v1/graph", tags=["graph"])
async def get_graph(
    request: Request,
    scan_id: Optional[str] = Query(None, description="Filter by scan ID"),
    entity_types: Optional[str] = Query(None, description="Comma-separated entity types"),
    min_severity: Optional[str] = Query(None, description="Minimum severity (critical/high/medium/low)"),
    relationships: Optional[str] = Query(None, description="Comma-separated relationship types"),
    static_only: bool = Query(False, description="Exclude runtime edges"),
    dynamic_only: bool = Query(False, description="Only runtime edges"),
    max_depth: Optional[int] = Query(None, ge=1, le=20, description="Max traversal depth"),
    cursor: Optional[str] = Query(None, description="Opaque cursor for keyset node pagination"),
    offset: int = Query(0, ge=0, description="Pagination offset for nodes"),
    limit: int = Query(500, ge=1, le=5000, description="Max nodes to return"),
) -> dict:
    """Load the unified graph with filters and pagination.

    Nodes are paginated (offset/limit). Edges are filtered to only include
    edges between returned nodes. Stats reflect the full (unpaginated) graph.
    """
    from agent_bom.graph import SEVERITY_RANK, GraphFilterOptions, RelationshipType

    tenant = _tenant(request)
    graph_store = _get_graph_store_or_503()
    requested_scan_id = scan_id or ""

    if not requested_scan_id and not await _graph_store_call(graph_store.latest_snapshot_id, tenant_id=tenant):
        raise HTTPException(status_code=503, detail="Graph snapshots not found. Run a scan first.")

    et_set = _parse_entity_type_filter(entity_types)

    min_rank = 0
    if min_severity:
        min_rank = SEVERITY_RANK.get(min_severity.lower(), 0)

    if relationships or static_only or dynamic_only:
        graph = await _graph_store_call(
            graph_store.load_graph,
            scan_id=requested_scan_id,
            tenant_id=tenant,
            entity_types=et_set,
            min_severity_rank=min_rank,
        )
        rel_set: set[RelationshipType] = set()
        if relationships:
            for r in relationships.split(","):
                r = r.strip()
                try:
                    rel_set.add(RelationshipType(r))
                except ValueError:
                    pass
        filters = GraphFilterOptions(
            relationship_types=rel_set,
            static_only=static_only,
            dynamic_only=dynamic_only,
            max_depth=max_depth or 6,
        )
        graph = graph.filtered_view(filters)

        stats = graph.stats()
        all_nodes = list(graph.nodes.values())
        paged_nodes, pagination = _paginate(all_nodes, offset, limit)
        paged_ids = {n.id for n in paged_nodes}
        paged_edges = [e for e in graph.edges if e.source in paged_ids and e.target in paged_ids]
        attack_paths = [p.to_dict() for p in graph.attack_paths if p.hops and all(hop in paged_ids for hop in p.hops)]
        interaction_risks = [
            r.to_dict() for r in graph.interaction_risks if r.agents and all(f"agent:{agent_name}" in paged_ids for agent_name in r.agents)
        ]

        return {
            "scan_id": graph.scan_id,
            "tenant_id": graph.tenant_id,
            "created_at": graph.created_at,
            "nodes": [n.to_dict() for n in paged_nodes],
            "edges": [e.to_dict() for e in paged_edges],
            "attack_paths": attack_paths,
            "interaction_risks": interaction_risks,
            "stats": stats,
            "pagination": pagination,
        }

    try:
        effective_scan_id, created_at, paged_nodes, total, next_cursor = await _graph_store_call(
            graph_store.page_nodes,
            scan_id=requested_scan_id,
            tenant_id=tenant,
            entity_types=et_set,
            min_severity_rank=min_rank,
            cursor=cursor,
            offset=offset,
            limit=limit,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=sanitize_error(exc)) from exc
    paged_ids = {n.id for n in paged_nodes}
    paged_edges = await _graph_store_call(
        graph_store.edges_for_node_ids,
        scan_id=effective_scan_id,
        tenant_id=tenant,
        node_ids=paged_ids,
    )
    return {
        "scan_id": effective_scan_id,
        "tenant_id": tenant,
        "created_at": created_at,
        "nodes": [n.to_dict() for n in paged_nodes],
        "edges": [e.to_dict() for e in paged_edges],
        "attack_paths": [],
        "interaction_risks": [],
        "stats": await _graph_store_call(
            graph_store.snapshot_stats,
            scan_id=effective_scan_id,
            tenant_id=tenant,
            entity_types=et_set,
            min_severity_rank=min_rank,
        ),
        "pagination": _page_meta(total, offset, limit, cursor=cursor, next_cursor=next_cursor),
    }


@router.get("/v1/graph/diff", tags=["graph"])
async def get_graph_diff(
    request: Request,
    old: str = Query(..., description="Old scan ID"),
    new: str = Query(..., description="New scan ID"),
) -> dict:
    """Diff two scan snapshots — nodes/edges added, removed, changed."""
    return await _graph_store_call(_get_graph_store_or_503().diff_snapshots, old, new, tenant_id=_tenant(request))


@router.get("/v1/graph/paths", tags=["graph"])
async def get_graph_paths(
    request: Request,
    source: str = Query(..., description="Source node ID (e.g. agent:claude-desktop)"),
    scan_id: Optional[str] = Query(None, description="Scan ID"),
    max_depth: int = Query(4, ge=1, le=10, description="Maximum BFS depth"),
    offset: int = Query(0, ge=0, description="Pagination offset"),
    limit: int = Query(100, ge=1, le=1000, description="Max paths"),
) -> dict:
    """Find all attack paths from a source node via BFS."""
    graph_store = _get_graph_store_or_503()
    source_nodes = await _graph_store_call(graph_store.nodes_by_ids, scan_id=scan_id or "", tenant_id=_tenant(request), node_ids={source})
    if not source_nodes:
        raise HTTPException(status_code=404, detail=f"Node '{source}' not found in graph")

    all_paths, reachable = await _graph_store_call(
        graph_store.bfs_paths,
        scan_id=scan_id or "",
        tenant_id=_tenant(request),
        source=source,
        max_depth=max_depth,
        traversable_only=True,
    )
    paged_paths, pagination = _paginate(all_paths, offset, limit)
    attack_paths = await _graph_store_call(
        graph_store.attack_paths_for_sources,
        scan_id=scan_id or "",
        tenant_id=_tenant(request),
        source_ids={source},
    )

    return {
        "source": source,
        "max_depth": max_depth,
        "reachable_count": len(reachable),
        "reachable_nodes": sorted(reachable),
        "paths": [{"target": p[-1], "hops": p, "depth": len(p) - 1} for p in paged_paths],
        "attack_paths": [ap.to_dict() for ap in attack_paths if ap.source == source],
        "pagination": pagination,
    }


@router.get("/v1/graph/impact", tags=["graph"])
async def get_graph_impact(
    request: Request,
    node: str = Query(..., description="Node ID to compute impact for"),
    scan_id: Optional[str] = Query(None, description="Scan ID"),
    max_depth: int = Query(4, ge=1, le=10, description="Maximum reverse BFS depth"),
) -> dict:
    """Compute blast radius of a node — what depends on it?"""
    impact = await _graph_store_call(
        _get_graph_store_or_503().impact_of,
        scan_id=scan_id or "",
        tenant_id=_tenant(request),
        node_id=node,
        max_depth=max_depth,
    )
    if impact is None:
        raise HTTPException(status_code=404, detail=f"Node '{node}' not found")
    return impact


@router.get("/v1/graph/search", tags=["graph"])
async def search_graph(
    request: Request,
    q: str = Query(..., min_length=1, description="Search query"),
    scan_id: Optional[str] = Query(None, description="Scan ID"),
    entity_types: Optional[str] = Query(None, description="Comma-separated entity types"),
    min_severity: Optional[str] = Query(None, description="Minimum severity (critical/high/medium/low)"),
    compliance_prefixes: Optional[str] = Query(None, description="Comma-separated compliance prefixes"),
    data_sources: Optional[str] = Query(None, description="Comma-separated data sources"),
    cursor: Optional[str] = Query(None, description="Opaque cursor for keyset search pagination"),
    offset: int = Query(0, ge=0, description="Pagination offset"),
    limit: int = Query(50, ge=1, le=500, description="Max results"),
) -> dict:
    """Search graph nodes by label, type, tags, and attributes."""
    entity_type_filters = _parse_entity_type_filter(entity_types)
    min_rank = SEVERITY_RANK.get(min_severity.lower(), 0) if min_severity else 0
    prefix_filters = {value.strip().upper() for value in compliance_prefixes.split(",") if value.strip()} if compliance_prefixes else None
    data_source_filters = {value.strip() for value in data_sources.split(",") if value.strip()} if data_sources else None
    try:
        results, total, next_cursor = await _graph_store_call(
            _get_graph_store_or_503().search_nodes,
            scan_id=scan_id or "",
            tenant_id=_tenant(request),
            query=q,
            entity_types=entity_type_filters,
            min_severity_rank=min_rank,
            compliance_prefixes=prefix_filters,
            data_sources=data_source_filters,
            cursor=cursor,
            offset=offset,
            limit=limit,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=sanitize_error(exc)) from exc
    return {
        "query": q,
        "filters": {
            "scan_id": scan_id or "",
            "entity_types": sorted(entity_type_filters) if entity_type_filters else [],
            "min_severity": min_severity or "",
            "compliance_prefixes": sorted(prefix_filters) if prefix_filters else [],
            "data_sources": sorted(data_source_filters) if data_source_filters else [],
        },
        "results": [n.to_dict() for n in results],
        "pagination": {
            "total": total,
            "offset": offset,
            "limit": limit,
            "cursor": cursor or "",
            "next_cursor": next_cursor or "",
            "has_more": bool(next_cursor) if cursor else offset + limit < total,
        },
    }


@router.get("/v1/graph/agents", tags=["graph"])
async def list_graph_agents(
    request: Request,
    q: str = Query("", description="Optional agent label/id search"),
    scan_id: Optional[str] = Query(None, description="Scan ID"),
    cursor: Optional[str] = Query(None, description="Opaque cursor for keyset pagination"),
    offset: int = Query(0, ge=0, description="Pagination offset"),
    limit: int = Query(100, ge=1, le=500, description="Max agents"),
) -> dict:
    """List agent nodes for large-graph selectors without loading the full graph."""
    graph_store = _get_graph_store_or_503()
    tenant_id = _tenant(request)
    query = q.strip()
    if query:
        agents, total, next_cursor = await _graph_store_call(
            graph_store.search_nodes,
            scan_id=scan_id or "",
            tenant_id=tenant_id,
            query=query,
            entity_types={"agent"},
            cursor=cursor,
            offset=offset,
            limit=limit,
        )
        effective_scan_id = scan_id or await _graph_store_call(graph_store.latest_snapshot_id, tenant_id=tenant_id)
        created_at = ""
    else:
        effective_scan_id, created_at, agents, total, next_cursor = await _graph_store_call(
            graph_store.page_nodes,
            scan_id=scan_id or "",
            tenant_id=tenant_id,
            entity_types={"agent"},
            cursor=cursor,
            offset=offset,
            limit=limit,
        )
    return {
        "scan_id": effective_scan_id,
        "tenant_id": tenant_id,
        "created_at": created_at,
        "agents": [
            {
                "id": node.id,
                "label": node.label,
                "risk_score": node.risk_score,
                "severity": node.severity,
                "status": node.status.value if hasattr(node.status, "value") else str(node.status),
                "data_sources": node.data_sources,
                "first_seen": node.first_seen,
                "last_seen": node.last_seen,
            }
            for node in agents
        ],
        "pagination": _page_meta(total, offset, limit, cursor=cursor, next_cursor=next_cursor),
    }


@router.post("/v1/graph/query", tags=["graph"])
async def query_graph(request: Request, body: GraphQueryRequest) -> dict:
    """Run a bounded programmable traversal over the canonical graph."""
    graph_store = _get_graph_store_or_503()
    budget = _enforce_graph_query_budget(body)
    root_nodes = await _graph_store_call(
        graph_store.nodes_by_ids,
        scan_id=body.scan_id or "",
        tenant_id=_tenant(request),
        node_ids=set(body.roots),
    )
    known_roots = {node.id for node in root_nodes}
    missing_roots = [root for root in body.roots if root not in known_roots]
    if missing_roots:
        raise HTTPException(status_code=404, detail={"message": "Root nodes not found", "missing_roots": missing_roots})

    rel_types = {RelationshipType(rel) for rel in body.relationship_types} if body.relationship_types else None
    deadline = time.monotonic() + (body.timeout_ms / 1000)
    traversal_graph, depth_by_node, truncated = await _graph_store_call(
        graph_store.traverse_subgraph,
        scan_id=body.scan_id or "",
        tenant_id=_tenant(request),
        roots=body.roots,
        direction=body.direction,
        max_depth=body.max_depth,
        max_nodes=body.max_nodes,
        max_edges=body.max_edges,
        deadline_monotonic=deadline,
        traversable_only=body.traversable_only,
        relationship_types=rel_types,
        static_only=body.static_only,
        dynamic_only=body.dynamic_only,
        include_roots=body.include_roots,
    )

    filtered_graph = _filtered_query_graph(
        traversal_graph,
        roots=body.roots,
        entity_types=set(_validate_entity_type_list(body.entity_types)),
        min_severity_rank=SEVERITY_RANK.get(body.min_severity.lower(), 0) if body.min_severity else 0,
        compliance_prefixes={prefix.upper() for prefix in body.compliance_prefixes},
        data_sources=set(body.data_sources),
    )

    attack_paths = []
    if body.include_attack_paths:
        root_attack_paths = await _graph_store_call(
            graph_store.attack_paths_for_sources,
            scan_id=body.scan_id or "",
            tenant_id=_tenant(request),
            source_ids=set(body.roots),
        )
        attack_paths = [
            ap.to_dict() for ap in root_attack_paths if ap.source in body.roots and all(hop in filtered_graph.nodes for hop in ap.hops)
        ]

    return {
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
    }


@router.get("/v1/graph/node/{node_id}", tags=["graph"])
async def get_graph_node(
    request: Request,
    node_id: str,
    scan_id: Optional[str] = Query(None, description="Scan ID"),
) -> dict:
    """Get a single node with its edges, neighbors, and impact stats."""
    node_context = await _graph_store_call(
        _get_graph_store_or_503().node_context,
        scan_id=scan_id or "",
        tenant_id=_tenant(request),
        node_id=node_id,
    )
    if node_context is None:
        raise HTTPException(status_code=404, detail=f"Node '{node_id}' not found")

    return {
        "node": node_context["node"].to_dict(),
        "edges_out": [edge.to_dict() for edge in node_context["edges_out"]],
        "edges_in": [edge.to_dict() for edge in node_context["edges_in"]],
        "neighbors": node_context["neighbors"],
        "sources": node_context["sources"],
        "impact": node_context["impact"],
    }


@router.get("/v1/graph/snapshots", tags=["graph"])
async def get_graph_snapshots(
    request: Request,
    limit: int = Query(50, ge=1, le=500, description="Max snapshots"),
) -> list[dict]:
    """List persisted scan snapshots ordered by creation time."""
    return await _graph_store_call(_get_graph_store_or_503().list_snapshots, tenant_id=_tenant(request), limit=limit)


@router.get("/v1/graph/compliance", tags=["graph"])
async def get_graph_compliance(
    request: Request,
    scan_id: Optional[str] = Query(None, description="Scan ID"),
    framework: Optional[str] = Query(None, description="Filter by framework prefix (e.g. OWASP, NIST, MITRE, CIS, SOC2)"),
) -> dict:
    """Compliance posture across all frameworks — aggregated from graph nodes.

    Returns per-framework finding counts, severity breakdown, affected entity
    counts, and the list of tagged findings. Filter by framework to drill down.
    """
    return await _graph_store_call(
        _get_graph_store_or_503().compliance_summary,
        scan_id=scan_id or "",
        tenant_id=_tenant(request),
        framework=framework or "",
    )


@router.get("/v1/graph/legend", tags=["graph"])
async def get_graph_legend() -> dict:
    """Return entity and relationship legends for UI rendering."""
    from agent_bom.graph import ENTITY_LEGEND, RELATIONSHIP_LEGEND

    return {
        "entities": [{"key": e.key, "label": e.label, "color": e.color, "shape": e.shape} for e in ENTITY_LEGEND],
        "relationships": [{"key": r.key, "label": r.label, "color": r.color} for r in RELATIONSHIP_LEGEND],
    }


# ═══════════════════════════════════════════════════════════════════════════
# Saved filter presets
# ═══════════════════════════════════════════════════════════════════════════


@router.post("/v1/graph/presets", tags=["graph"])
async def create_preset(request: Request, body: PresetCreate) -> dict:
    """Save a named graph filter preset for the current tenant."""
    from agent_bom.graph.util import _now_iso

    tenant = _tenant(request)
    await _graph_store_call(
        _get_graph_store_or_503().save_preset,
        tenant_id=tenant,
        name=body.name,
        description=body.description,
        filters=body.filters,
        created_at=_now_iso(),
    )
    return {"name": body.name, "status": "saved"}


@router.get("/v1/graph/presets", tags=["graph"])
async def list_presets(request: Request) -> list[dict]:
    """List saved filter presets for the current tenant."""
    return await _graph_store_call(_get_graph_store_or_503().list_presets, tenant_id=_tenant(request))


@router.delete("/v1/graph/presets/{name}", tags=["graph"])
async def delete_preset(request: Request, name: str) -> dict:
    """Delete a saved filter preset."""
    deleted = await _graph_store_call(_get_graph_store_or_503().delete_preset, tenant_id=_tenant(request), name=name)
    if not deleted:
        raise HTTPException(status_code=404, detail=f"Preset '{name}' not found")
    return {"name": name, "status": "deleted"}
