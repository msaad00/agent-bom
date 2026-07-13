"""Unified asset-inventory API — one faceted inventory across every source.

This is the serving layer for a single asset inventory spanning AI (agents, MCP
servers, models, frameworks, tools, credentials, managed identities), cloud
(cloud resources, data stores, accounts, orgs, providers, API gateways),
Snowflake (accounts, warehouses, databases, roles, users), and identity (users,
roles, policies, service accounts). All of these already coexist as OCSF-typed
nodes in the ONE tenant-scoped unified graph snapshot, so this router is a thin,
read-only projection over the existing graph store (``page_nodes`` /
``search_nodes`` / ``snapshot_stats`` / ``node_context``) — it introduces no new
data model or second store.

The graph-store projection logic lives in ``agent_bom.api.inventory_service`` so
this HTTP router and the agent-native MCP inventory tools share one
implementation over one evidence model (headless agent primitives + human
cockpit surfaces over one shared graph).

Endpoints:
  GET /v1/inventory/summary          — asset counts by type (+ group roll-up)
  GET /v1/inventory/assets           — paginated, filterable asset rows
  GET /v1/inventory/assets/{asset_id} — one asset's attributes + relationships

Findings (vulnerabilities / misconfigurations / drift) are intentionally
excluded — this is the asset inventory, not the finding queue (see /v1/findings).
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any, Optional

from fastapi import APIRouter, HTTPException, Query, Request

from agent_bom.api import inventory_service
from agent_bom.api.inventory_service import MAX_PAGE_LIMIT, InventoryError
from agent_bom.api.stores import _get_graph_store
from agent_bom.api.tenancy import require_request_tenant_id
from agent_bom.backpressure import BackpressureRejectedError, adaptive_backpressure

logger = logging.getLogger(__name__)
router = APIRouter()


async def _store_call(fn, /, *args, **kwargs):
    """Run a sync graph-store method off the event loop under graph backpressure."""
    try:
        async with adaptive_backpressure("graph"):
            return await asyncio.to_thread(fn, *args, **kwargs)
    except BackpressureRejectedError as exc:
        raise HTTPException(
            status_code=429,
            detail=exc.to_dict(),
            headers={"Retry-After": str(exc.retry_after_seconds)},
        ) from exc


def _tenant(request: Request) -> str:
    return require_request_tenant_id(request)


# ═══════════════════════════════════════════════════════════════════════════
# Summary
# ═══════════════════════════════════════════════════════════════════════════


@router.get("/inventory/summary", tags=["inventory"])
async def inventory_summary(
    request: Request,
    scan_id: Optional[str] = Query(None, description="Scan snapshot ID; latest if omitted"),
) -> dict[str, Any]:
    """Asset counts for the tenant's current graph snapshot, by type and group.

    Backed by the graph store's ``snapshot_stats`` (its ``node_types`` bucket).
    Findings are excluded — this counts assets across AI, cloud, Snowflake, and
    identity uniformly because they already coexist as typed nodes in the one
    snapshot.
    """
    tenant = _tenant(request)
    try:
        return await inventory_service.build_summary(
            store=_get_graph_store(),
            tenant_id=tenant,
            scan_id=scan_id,
            store_call=_store_call,
        )
    except InventoryError as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.detail) from exc


# ═══════════════════════════════════════════════════════════════════════════
# Faceted list
# ═══════════════════════════════════════════════════════════════════════════


@router.get("/inventory/assets", tags=["inventory"])
async def list_inventory_assets(
    request: Request,
    type: Optional[str] = Query(None, description="Comma-separated asset entity types (e.g. agent,cloud_resource)"),
    search: Optional[str] = Query(None, description="Free-text search over asset name / label / attributes"),
    environment: Optional[str] = Query(None, description="Filter by environment facet (e.g. production)"),
    provider: Optional[str] = Query(None, description="Filter by provider facet (e.g. aws, snowflake)"),
    source: Optional[str] = Query(None, description="Filter by data source / provenance facet"),
    min_severity: Optional[str] = Query(None, description="Minimum severity floor (critical/high/medium/low)"),
    scan_id: Optional[str] = Query(None, description="Scan snapshot ID; latest if omitted"),
    cursor: Optional[str] = Query(None, description="Opaque keyset cursor from a previous page's next_cursor"),
    offset: int = Query(0, ge=0, description="Pagination offset (non-cursor paging only)"),
    limit: int = Query(50, ge=1, le=MAX_PAGE_LIMIT, description="Max rows to return"),
) -> dict[str, Any]:
    """Paginated, filterable asset rows across every source in the unified graph.

    ``type`` and ``search`` and ``min_severity`` are pushed into the graph store
    (``page_nodes`` / ``search_nodes``); ``environment`` / ``provider`` /
    ``source`` are matched in-route with a keyset refill loop so a filtered page
    is never silently truncated.
    """
    tenant = _tenant(request)
    try:
        return await inventory_service.build_asset_list(
            store=_get_graph_store(),
            tenant_id=tenant,
            type=type,
            search=search,
            environment=environment,
            provider=provider,
            source=source,
            min_severity=min_severity,
            scan_id=scan_id,
            cursor=cursor,
            offset=offset,
            limit=limit,
            store_call=_store_call,
        )
    except InventoryError as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.detail) from exc


# ═══════════════════════════════════════════════════════════════════════════
# Detail
# ═══════════════════════════════════════════════════════════════════════════


@router.get("/inventory/assets/{asset_id}", tags=["inventory"])
async def get_inventory_asset(
    request: Request,
    asset_id: str,
    scan_id: Optional[str] = Query(None, description="Scan snapshot ID; latest if omitted"),
) -> dict[str, Any]:
    """One asset's full attributes plus its relationships (neighbors / edges).

    Reuses the graph store's ``node_context`` so the UI drawer can render config,
    relationships, and blast-radius impact, and link out to findings.
    """
    tenant = _tenant(request)
    try:
        detail = await inventory_service.build_asset_detail(
            store=_get_graph_store(),
            tenant_id=tenant,
            asset_id=asset_id,
            scan_id=scan_id,
            store_call=_store_call,
        )
    except InventoryError as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.detail) from exc
    if detail is None:
        raise HTTPException(status_code=404, detail=f"Asset '{asset_id}' not found")
    return detail
