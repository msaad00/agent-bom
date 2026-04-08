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
) -> dict:
    """Load the unified graph with optional filters.

    Returns the full UnifiedGraph.to_dict() shape: nodes, edges,
    attack_paths, interaction_risks, stats.
    """
    conn = _get_conn()
    try:
        from agent_bom.graph import SEVERITY_RANK

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
