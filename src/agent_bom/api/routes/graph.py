"""Graph query API — unified graph data with filters, diffs, and attack paths.

Endpoints:
  GET /v1/graph                — load unified graph (filtered)
  GET /v1/graph/diff           — diff between two scan snapshots
  GET /v1/graph/paths          — attack paths from a source node
  GET /v1/graph/snapshots      — list persisted scan snapshots
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, HTTPException, Query

from agent_bom.db.graph_store import (
    diff_snapshots,
    list_snapshots,
    load_graph,
)

logger = logging.getLogger(__name__)
router = APIRouter()

_GRAPH_DB_PATH = Path.home() / ".agent-bom" / "db" / "graph.db"


def _get_conn():
    """Open graph DB connection. Raises 503 if not available."""
    if not _GRAPH_DB_PATH.exists():
        raise HTTPException(status_code=503, detail="Graph database not found. Run a scan first.")
    import sqlite3

    conn = sqlite3.connect(str(_GRAPH_DB_PATH), timeout=10)
    conn.row_factory = sqlite3.Row
    return conn


@router.get("/v1/graph", tags=["graph"])
async def get_graph(
    scan_id: Optional[str] = Query(None, description="Filter by scan ID"),
    entity_types: Optional[str] = Query(None, description="Comma-separated entity types (agent,server,vulnerability,...)"),
    min_severity: Optional[str] = Query(None, description="Minimum severity (critical/high/medium/low)"),
    relationships: Optional[str] = Query(None, description="Comma-separated relationship types (uses,depends_on,vulnerable_to,...)"),
    static_only: bool = Query(False, description="Exclude runtime edges"),
    dynamic_only: bool = Query(False, description="Only runtime edges"),
    max_depth: Optional[int] = Query(None, ge=1, le=20, description="Max traversal depth from any root"),
) -> dict:
    """Load the unified graph with optional filters.

    Returns the full UnifiedGraph.to_dict() shape: nodes, edges,
    attack_paths, interaction_risks, stats.

    Supports entity type, severity, relationship type, and static/dynamic
    edge filtering.
    """
    conn = _get_conn()
    try:
        from agent_bom.graph import SEVERITY_RANK, GraphFilterOptions, RelationshipType

        et_set: set[str] | None = None
        if entity_types:
            et_set = {t.strip() for t in entity_types.split(",") if t.strip()}

        min_rank = 0
        if min_severity:
            min_rank = SEVERITY_RANK.get(min_severity.lower(), 0)

        graph = load_graph(
            conn,
            scan_id=scan_id or "",
            entity_types=et_set,
            min_severity_rank=min_rank,
        )

        # Apply relationship/edge filters if any are specified
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

        return graph.to_dict()
    finally:
        conn.close()


@router.get("/v1/graph/diff", tags=["graph"])
async def get_graph_diff(
    old: str = Query(..., description="Old scan ID"),
    new: str = Query(..., description="New scan ID"),
) -> dict:
    """Diff two scan snapshots — nodes/edges added, removed, changed."""
    conn = _get_conn()
    try:
        return diff_snapshots(conn, old, new)
    finally:
        conn.close()


@router.get("/v1/graph/paths", tags=["graph"])
async def get_graph_paths(
    source: str = Query(..., description="Source node ID (e.g. agent:claude-desktop)"),
    scan_id: Optional[str] = Query(None, description="Scan ID to load graph from"),
    max_depth: int = Query(4, ge=1, le=10, description="Maximum BFS depth"),
) -> dict:
    """Find all attack paths from a source node via BFS."""
    conn = _get_conn()
    try:
        graph = load_graph(conn, scan_id=scan_id or "")
        if not graph.has_node(source):
            raise HTTPException(status_code=404, detail=f"Node '{source}' not found in graph")

        paths = graph.bfs(source, max_depth=max_depth, traversable_only=True)
        reachable = graph.reachable_from(source, max_depth=max_depth)

        return {
            "source": source,
            "max_depth": max_depth,
            "reachable_count": len(reachable),
            "reachable_nodes": sorted(reachable),
            "paths": [{"target": p[-1], "hops": p, "depth": len(p) - 1} for p in paths],
            "attack_paths": [ap.to_dict() for ap in graph.attack_paths if ap.source == source],
        }
    finally:
        conn.close()


@router.get("/v1/graph/impact", tags=["graph"])
async def get_graph_impact(
    node: str = Query(..., description="Node ID to compute impact for (e.g. vuln:CVE-2024-1234)"),
    scan_id: Optional[str] = Query(None, description="Scan ID"),
    max_depth: int = Query(4, ge=1, le=10, description="Maximum reverse traversal depth"),
) -> dict:
    """Compute blast radius / impact of a node — what depends on it?

    Follows edges in REVERSE: "if this node is compromised, what is affected?"
    Returns affected nodes grouped by entity type.
    """
    conn = _get_conn()
    try:
        graph = load_graph(conn, scan_id=scan_id or "")
        if not graph.has_node(node):
            raise HTTPException(status_code=404, detail=f"Node '{node}' not found")
        return graph.impact_of(node, max_depth=max_depth)
    finally:
        conn.close()


@router.get("/v1/graph/search", tags=["graph"])
async def search_graph(
    q: str = Query(..., min_length=1, description="Search query (label, type, severity, tag)"),
    scan_id: Optional[str] = Query(None, description="Scan ID"),
    limit: int = Query(50, ge=1, le=500, description="Max results"),
) -> list[dict]:
    """Search graph nodes by label, entity type, severity, or compliance tag."""
    conn = _get_conn()
    try:
        graph = load_graph(conn, scan_id=scan_id or "")
        results = graph.search_nodes(q, limit=limit)
        return [n.to_dict() for n in results]
    finally:
        conn.close()


@router.get("/v1/graph/node/{node_id}", tags=["graph"])
async def get_graph_node(
    node_id: str,
    scan_id: Optional[str] = Query(None, description="Scan ID"),
) -> dict:
    """Get a single node with its edges, neighbors, and impact stats."""
    conn = _get_conn()
    try:
        graph = load_graph(conn, scan_id=scan_id or "")
        node = graph.get_node(node_id)
        if not node:
            raise HTTPException(status_code=404, detail=f"Node '{node_id}' not found")

        edges_out = [e.to_dict() for e in graph.edges_from(node_id)]
        edges_in = [e.to_dict() for e in graph.edges_to(node_id)]
        impact = graph.impact_of(node_id)

        return {
            "node": node.to_dict(),
            "edges_out": edges_out,
            "edges_in": edges_in,
            "neighbors": graph.neighbors(node_id),
            "sources": graph.sources_of(node_id),
            "impact": impact,
        }
    finally:
        conn.close()


@router.get("/v1/graph/snapshots", tags=["graph"])
async def get_graph_snapshots(
    limit: int = Query(50, ge=1, le=500, description="Max snapshots to return"),
) -> list[dict]:
    """List persisted scan snapshots ordered by creation time."""
    conn = _get_conn()
    try:
        return list_snapshots(conn, limit=limit)
    finally:
        conn.close()


@router.get("/v1/graph/legend", tags=["graph"])
async def get_graph_legend() -> dict:
    """Return entity and relationship legends for UI rendering."""
    from agent_bom.graph import ENTITY_LEGEND, RELATIONSHIP_LEGEND

    return {
        "entities": [{"key": e.key, "label": e.label, "color": e.color, "shape": e.shape} for e in ENTITY_LEGEND],
        "relationships": [{"key": r.key, "label": r.label, "color": r.color} for r in RELATIONSHIP_LEGEND],
    }
