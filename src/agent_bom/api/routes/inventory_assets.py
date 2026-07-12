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

from agent_bom.api.graph_store import MAX_NODE_PAGE_OFFSET
from agent_bom.api.stores import _get_graph_store
from agent_bom.api.tenancy import require_request_tenant_id
from agent_bom.backpressure import BackpressureRejectedError, adaptive_backpressure
from agent_bom.graph import SEVERITY_RANK, EntityType
from agent_bom.graph.ocsf import FINDING_ENTITY_TYPES
from agent_bom.security import sanitize_error

logger = logging.getLogger(__name__)
router = APIRouter()

# Findings are not assets. The inventory covers every non-finding entity type.
_FINDING_TYPE_VALUES: frozenset[str] = frozenset(t.value for t in FINDING_ENTITY_TYPES)
_ASSET_TYPE_VALUES: frozenset[str] = frozenset(t.value for t in EntityType) - _FINDING_TYPE_VALUES
_ALL_ENTITY_TYPE_VALUES: frozenset[str] = frozenset(t.value for t in EntityType)

# Operator-facing groupings so the summary reads as one inventory across sources
# rather than a flat list of ~40 OCSF entity types. Every non-finding entity type
# maps to exactly one group; anything unmapped falls into "other".
_TYPE_GROUPS: dict[str, tuple[str, ...]] = {
    "ai": (
        EntityType.AGENT.value,
        EntityType.SERVER.value,
        EntityType.MODEL.value,
        EntityType.FRAMEWORK.value,
        EntityType.TOOL.value,
        EntityType.TOOL_CALL.value,
        EntityType.DATASET.value,
        EntityType.APPLICATION.value,
        EntityType.CONTAINER.value,
    ),
    "cloud": (
        EntityType.CLOUD_RESOURCE.value,
        EntityType.RESOURCE.value,
        EntityType.DATA_STORE.value,
        EntityType.ACCOUNT.value,
        EntityType.ORG.value,
        EntityType.ENVIRONMENT.value,
        EntityType.PROVIDER.value,
        EntityType.API_GATEWAY.value,
        EntityType.CLUSTER.value,
        EntityType.FLEET.value,
    ),
    "identity": (
        EntityType.USER.value,
        EntityType.GROUP.value,
        EntityType.ROLE.value,
        EntityType.POLICY.value,
        EntityType.SERVICE_ACCOUNT.value,
        EntityType.SERVICE_PRINCIPAL.value,
        EntityType.FEDERATED_IDENTITY.value,
        EntityType.MANAGED_IDENTITY.value,
        EntityType.ACCESS_GRANT.value,
        EntityType.ACCESS_POLICY.value,
    ),
    "secrets": (
        EntityType.CREDENTIAL.value,
        EntityType.CREDENTIAL_REF.value,
    ),
    "code": (
        EntityType.PACKAGE.value,
        EntityType.SOURCE_FILE.value,
        EntityType.CODE_MODULE.value,
        EntityType.CONFIG_FILE.value,
        EntityType.EXTERNAL_IMPORT.value,
        EntityType.CI_JOB.value,
        EntityType.DIRECTORY.value,
    ),
}
_TYPE_TO_GROUP: dict[str, str] = {value: group for group, values in _TYPE_GROUPS.items() for value in values}

# Cap the store page pulled per request and the internal scan when a facet filter
# (environment / provider / source) that the store cannot express is active. The
# facet loop keyset-pages the store and refills so it never silently drops rows,
# but it must stay bounded — past the cap it returns a partial page + cursor so
# the caller can continue rather than forcing an unbounded scan.
_MAX_PAGE_LIMIT = 200
_MAX_FACET_SCAN_PAGES = 25


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


def _parse_types(raw: Optional[str]) -> set[str] | None:
    """Parse the ``type=`` filter into a validated set of asset entity types."""
    if not raw:
        return None
    values = {value.strip() for value in raw.split(",") if value.strip()}
    invalid = sorted(values - _ALL_ENTITY_TYPE_VALUES)
    if invalid:
        raise HTTPException(status_code=422, detail=f"Unsupported asset type: {invalid[0]}")
    findings = sorted(values & _FINDING_TYPE_VALUES)
    if findings:
        raise HTTPException(
            status_code=422,
            detail=f"'{findings[0]}' is a finding, not an asset. Use /v1/findings for findings.",
        )
    return values or None


def _node_environment(node: Any) -> str:
    return str(node.dimensions.environment or node.attributes.get("environment") or "")


def _node_provider(node: Any) -> str:
    return str(node.dimensions.cloud_provider or node.attributes.get("provider") or node.attributes.get("cloud_provider") or "")


def _entity_value(node: Any) -> str:
    return node.entity_type.value if hasattr(node.entity_type, "value") else str(node.entity_type)


def _asset_row(node: Any) -> dict[str, Any]:
    """Project a graph node into the stable inventory row shape."""
    sources = list(node.data_sources or [])
    return {
        "id": node.id,
        "type": _entity_value(node),
        "name": node.label,
        "environment": _node_environment(node),
        "provider": _node_provider(node),
        "risk": node.risk_score,
        "severity": node.severity,
        "status": node.status.value if hasattr(node.status, "value") else str(node.status),
        "source": sources[0] if sources else "",
        "sources": sources,
        "first_seen": node.first_seen,
        "last_seen": node.last_seen,
    }


def _facet_predicate(environment: str, provider: str, source: str):
    """Build an in-route predicate for the facets the store cannot filter natively.

    ``environment`` / ``provider`` / ``source`` live in the node's dimensions,
    attributes, and data_sources — not in an indexed column shared across the
    SQLite / Postgres / Neptune backends — so they are matched here. Callers pair
    this with the keyset refill loop so a filtered page still returns a full page
    (or a cursor to continue) rather than dropping matches beyond the first store
    page.
    """
    env = environment.strip().lower()
    prov = provider.strip().lower()
    src = source.strip().lower()

    def predicate(node: Any) -> bool:
        if env and _node_environment(node).lower() != env:
            return False
        if prov and _node_provider(node).lower() != prov:
            return False
        if src and src not in {str(s).lower() for s in (node.data_sources or [])}:
            return False
        return True

    return predicate


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
    stats = await _store_call(
        _get_graph_store().snapshot_stats,
        scan_id=scan_id or "",
        tenant_id=tenant,
    )
    node_types: dict[str, int] = stats.get("node_types", {}) or {}

    by_type: dict[str, int] = {}
    by_group: dict[str, int] = {group: 0 for group in _TYPE_GROUPS}
    by_group["other"] = 0
    total_assets = 0
    for entity_type, count in node_types.items():
        if entity_type in _FINDING_TYPE_VALUES:
            continue
        count = int(count or 0)
        by_type[entity_type] = count
        total_assets += count
        by_group[_TYPE_TO_GROUP.get(entity_type, "other")] += count

    return {
        "schema_version": "inventory.summary.v1",
        "tenant_id": tenant,
        "scan_id": stats.get("scan_id", scan_id or ""),
        "total_assets": total_assets,
        "by_type": dict(sorted(by_type.items(), key=lambda kv: (-kv[1], kv[0]))),
        "by_group": {group: count for group, count in by_group.items() if count or group in _TYPE_GROUPS},
        "finding_count": sum(int(node_types.get(t, 0) or 0) for t in _FINDING_TYPE_VALUES),
    }


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
    limit: int = Query(50, ge=1, le=_MAX_PAGE_LIMIT, description="Max rows to return"),
) -> dict[str, Any]:
    """Paginated, filterable asset rows across every source in the unified graph.

    ``type`` and ``search`` and ``min_severity`` are pushed into the graph store
    (``page_nodes`` / ``search_nodes``); ``environment`` / ``provider`` /
    ``source`` are matched in-route with a keyset refill loop so a filtered page
    is never silently truncated.
    """
    if not cursor and offset > MAX_NODE_PAGE_OFFSET:
        raise HTTPException(
            status_code=422,
            detail=(
                f"offset={offset} exceeds the maximum supported offset ({MAX_NODE_PAGE_OFFSET}). "
                "Use the cursor= keyset parameter (next_cursor from the previous page) for deep pagination."
            ),
        )

    tenant = _tenant(request)
    store = _get_graph_store()
    entity_types = _parse_types(type)
    # Default to every asset type so findings never leak into the inventory list.
    effective_types = entity_types if entity_types is not None else set(_ASSET_TYPE_VALUES)
    min_rank = SEVERITY_RANK.get(min_severity.lower(), 0) if min_severity else 0
    query = (search or "").strip()
    facet_active = bool((environment or "").strip() or (provider or "").strip() or (source or "").strip())
    predicate = _facet_predicate(environment or "", provider or "", source or "")

    async def _fetch(page_cursor: str | None, page_offset: int, page_limit: int):
        """Return (nodes, total, next_cursor) from the active store call."""
        if query:
            try:
                nodes, total, next_cursor = await _store_call(
                    store.search_nodes,
                    scan_id=scan_id or "",
                    tenant_id=tenant,
                    query=query,
                    entity_types=effective_types,
                    min_severity_rank=min_rank,
                    cursor=page_cursor,
                    offset=page_offset,
                    limit=page_limit,
                )
            except ValueError as exc:
                raise HTTPException(status_code=400, detail=sanitize_error(exc)) from exc
            return nodes, total, next_cursor
        try:
            _scan_id, _created_at, nodes, total, next_cursor = await _store_call(
                store.page_nodes,
                scan_id=scan_id or "",
                tenant_id=tenant,
                entity_types=effective_types,
                min_severity_rank=min_rank,
                cursor=page_cursor,
                offset=page_offset,
                limit=page_limit,
            )
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=sanitize_error(exc)) from exc
        return nodes, total, next_cursor

    if not facet_active:
        nodes, total, next_cursor = await _fetch(cursor, offset, limit)
        rows = [_asset_row(node) for node in nodes]
        return {
            "schema_version": "inventory.assets.v1",
            "tenant_id": tenant,
            "assets": rows,
            "filters": {
                "type": sorted(entity_types) if entity_types else [],
                "search": query,
                "environment": "",
                "provider": "",
                "source": "",
                "min_severity": min_severity or "",
            },
            "pagination": {
                "total": total,
                "offset": offset,
                "limit": limit,
                "cursor": cursor or "",
                "next_cursor": next_cursor or "",
                "has_more": bool(next_cursor) if cursor else offset + limit < total,
                "facet_filtered": False,
            },
        }

    # Facet filter active: keyset-page the store and refill until we have a full
    # page of matches, the store is exhausted, or the scan cap is hit. Never drops
    # matches past the first store page; total is not meaningful under an in-route
    # facet filter, so it is reported as null.
    if cursor is None and offset:
        # Offset paging is ambiguous once an in-route facet filter is applied, so
        # facet-filtered listing is cursor-only. Fall back to a fresh scan.
        offset = 0
    collected: list[dict[str, Any]] = []
    page_cursor = cursor
    exhausted = False
    for _ in range(_MAX_FACET_SCAN_PAGES):
        nodes, _total, next_cursor = await _fetch(page_cursor, 0, _MAX_PAGE_LIMIT)
        for node in nodes:
            if predicate(node):
                collected.append(_asset_row(node))
        page_cursor = next_cursor
        if not next_cursor:
            exhausted = True
            break
        if len(collected) >= limit:
            break
    page_rows = collected[:limit]
    # The continuation cursor is the store cursor after the last consumed store
    # page; the extra collected rows beyond ``limit`` are re-derived on the next
    # request, keeping the keyset stable without a private buffer.
    has_more = not exhausted or len(collected) > limit
    return {
        "schema_version": "inventory.assets.v1",
        "tenant_id": tenant,
        "assets": page_rows,
        "filters": {
            "type": sorted(entity_types) if entity_types else [],
            "search": query,
            "environment": (environment or "").strip(),
            "provider": (provider or "").strip(),
            "source": (source or "").strip(),
            "min_severity": min_severity or "",
        },
        "pagination": {
            "total": None,
            "offset": 0,
            "limit": limit,
            "cursor": cursor or "",
            "next_cursor": page_cursor or "",
            "has_more": bool(has_more and page_cursor),
            "facet_filtered": True,
        },
    }


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
    context = await _store_call(
        _get_graph_store().node_context,
        scan_id=scan_id or "",
        tenant_id=tenant,
        node_id=asset_id,
    )
    if context is None:
        raise HTTPException(status_code=404, detail=f"Asset '{asset_id}' not found")

    node = context["node"]
    return {
        "schema_version": "inventory.asset.v1",
        "tenant_id": tenant,
        "asset": _asset_row(node),
        "node": node.to_dict(),
        "edges_out": [edge.to_dict() for edge in context["edges_out"]],
        "edges_in": [edge.to_dict() for edge in context["edges_in"]],
        "neighbors": context["neighbors"],
        "sources": context["sources"],
        "impact": context["impact"],
    }
