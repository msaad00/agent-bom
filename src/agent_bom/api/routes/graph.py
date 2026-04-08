"""Graph query API — unified graph data with filters, pagination, RBAC, presets.

Endpoints:
  GET  /v1/graph                — load unified graph (filtered, paginated)
  GET  /v1/graph/diff           — diff between two scan snapshots
  GET  /v1/graph/paths          — attack paths from a source node
  GET  /v1/graph/impact         — blast radius of a node (reverse BFS)
  GET  /v1/graph/search         — full-text graph search
  GET  /v1/graph/node/{id}      — single node detail with edges + impact
  GET  /v1/graph/snapshots      — list persisted scan snapshots
  GET  /v1/graph/legend         — entity + relationship legends
  POST /v1/graph/presets        — save a filter preset
  GET  /v1/graph/presets        — list saved presets
  DEL  /v1/graph/presets/{name} — delete a preset
"""

from __future__ import annotations

import logging
from typing import Optional

from fastapi import APIRouter, HTTPException, Query, Request
from pydantic import BaseModel

from agent_bom.api.stores import _get_graph_store

logger = logging.getLogger(__name__)
router = APIRouter()


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


# ═══════════════════════════════════════════════════════════════════════════
# Preset model
# ═══════════════════════════════════════════════════════════════════════════


class PresetCreate(BaseModel):
    name: str
    description: str = ""
    filters: dict


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

    if not requested_scan_id and not graph_store.latest_snapshot_id(tenant_id=tenant):
        raise HTTPException(status_code=503, detail="Graph snapshots not found. Run a scan first.")

    et_set: set[str] | None = None
    if entity_types:
        et_set = {t.strip() for t in entity_types.split(",") if t.strip()}

    min_rank = 0
    if min_severity:
        min_rank = SEVERITY_RANK.get(min_severity.lower(), 0)

    graph = graph_store.load_graph(
        scan_id=requested_scan_id,
        tenant_id=tenant,
        entity_types=et_set,
        min_severity_rank=min_rank,
    )

    if relationships or static_only or dynamic_only:
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


@router.get("/v1/graph/diff", tags=["graph"])
async def get_graph_diff(
    request: Request,
    old: str = Query(..., description="Old scan ID"),
    new: str = Query(..., description="New scan ID"),
) -> dict:
    """Diff two scan snapshots — nodes/edges added, removed, changed."""
    return _get_graph_store_or_503().diff_snapshots(old, new, tenant_id=_tenant(request))


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
    graph = _get_graph_store_or_503().load_graph(scan_id=scan_id or "", tenant_id=_tenant(request))
    if not graph.has_node(source):
        raise HTTPException(status_code=404, detail=f"Node '{source}' not found in graph")

    all_paths = graph.bfs(source, max_depth=max_depth, traversable_only=True)
    paged_paths, pagination = _paginate(all_paths, offset, limit)
    reachable = graph.reachable_from(source, max_depth=max_depth)

    return {
        "source": source,
        "max_depth": max_depth,
        "reachable_count": len(reachable),
        "reachable_nodes": sorted(reachable),
        "paths": [{"target": p[-1], "hops": p, "depth": len(p) - 1} for p in paged_paths],
        "attack_paths": [ap.to_dict() for ap in graph.attack_paths if ap.source == source],
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
    graph = _get_graph_store_or_503().load_graph(scan_id=scan_id or "", tenant_id=_tenant(request))
    if not graph.has_node(node):
        raise HTTPException(status_code=404, detail=f"Node '{node}' not found")
    return graph.impact_of(node, max_depth=max_depth)


@router.get("/v1/graph/search", tags=["graph"])
async def search_graph(
    request: Request,
    q: str = Query(..., min_length=1, description="Search query"),
    scan_id: Optional[str] = Query(None, description="Scan ID"),
    offset: int = Query(0, ge=0, description="Pagination offset"),
    limit: int = Query(50, ge=1, le=500, description="Max results"),
) -> dict:
    """Search graph nodes by label, entity type, severity, or compliance tag."""
    graph = _get_graph_store_or_503().load_graph(scan_id=scan_id or "", tenant_id=_tenant(request))
    all_results = graph.search_nodes(q, limit=offset + limit)
    paged, pagination = _paginate(all_results, offset, limit)
    return {
        "query": q,
        "results": [n.to_dict() for n in paged],
        "pagination": pagination,
    }


@router.get("/v1/graph/node/{node_id}", tags=["graph"])
async def get_graph_node(
    request: Request,
    node_id: str,
    scan_id: Optional[str] = Query(None, description="Scan ID"),
) -> dict:
    """Get a single node with its edges, neighbors, and impact stats."""
    graph = _get_graph_store_or_503().load_graph(scan_id=scan_id or "", tenant_id=_tenant(request))
    node = graph.get_node(node_id)
    if not node:
        raise HTTPException(status_code=404, detail=f"Node '{node_id}' not found")

    return {
        "node": node.to_dict(),
        "edges_out": [e.to_dict() for e in graph.edges_from(node_id)],
        "edges_in": [e.to_dict() for e in graph.edges_to(node_id)],
        "neighbors": graph.neighbors(node_id),
        "sources": graph.sources_of(node_id),
        "impact": graph.impact_of(node_id),
    }


@router.get("/v1/graph/snapshots", tags=["graph"])
async def get_graph_snapshots(
    request: Request,
    limit: int = Query(50, ge=1, le=500, description="Max snapshots"),
) -> list[dict]:
    """List persisted scan snapshots ordered by creation time."""
    return _get_graph_store_or_503().list_snapshots(tenant_id=_tenant(request), limit=limit)


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
    from collections import defaultdict

    graph = _get_graph_store_or_503().load_graph(scan_id=scan_id or "", tenant_id=_tenant(request))

    framework_stats: dict[str, dict] = defaultdict(
        lambda: {
            "total_findings": 0,
            "by_severity": defaultdict(int),
            "by_entity_type": defaultdict(int),
            "tags": set(),
            "node_ids": [],
        }
    )

    for node in graph.nodes.values():
        if not node.compliance_tags:
            continue
        for tag in node.compliance_tags:
            prefix = tag.split("-")[0].upper() if "-" in tag else tag.upper()
            if framework and framework.upper() != prefix:
                continue
            stats = framework_stats[prefix]
            stats["total_findings"] += 1
            stats["by_severity"][node.severity or "unknown"] += 1
            et = node.entity_type.value if hasattr(node.entity_type, "value") else node.entity_type
            stats["by_entity_type"][et] += 1
            stats["tags"].add(tag)
            if node.id not in stats["node_ids"]:
                stats["node_ids"].append(node.id)

    result = {}
    for fw, stats in sorted(framework_stats.items()):
        result[fw] = {
            "total_findings": stats["total_findings"],
            "by_severity": dict(stats["by_severity"]),
            "by_entity_type": dict(stats["by_entity_type"]),
            "tags": sorted(stats["tags"]),
            "node_count": len(stats["node_ids"]),
            "node_ids": stats["node_ids"][:100],
        }

    return {
        "scan_id": graph.scan_id,
        "framework_count": len(result),
        "total_tagged_findings": sum(s["total_findings"] for s in result.values()),
        "frameworks": result,
    }


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
    _get_graph_store_or_503().save_preset(
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
    return _get_graph_store_or_503().list_presets(tenant_id=_tenant(request))


@router.delete("/v1/graph/presets/{name}", tags=["graph"])
async def delete_preset(request: Request, name: str) -> dict:
    """Delete a saved filter preset."""
    deleted = _get_graph_store_or_503().delete_preset(tenant_id=_tenant(request), name=name)
    if not deleted:
        raise HTTPException(status_code=404, detail=f"Preset '{name}' not found")
    return {"name": name, "status": "deleted"}
