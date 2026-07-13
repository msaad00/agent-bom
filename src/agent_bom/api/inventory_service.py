"""Shared query logic for the unified asset inventory.

Both the HTTP route (``api/routes/inventory_assets.py``) and the agent-native MCP
tools (``mcp_tools/inventory.py``) project the ONE tenant-scoped unified graph
snapshot (``snapshot_stats`` / ``page_nodes`` / ``search_nodes`` / ``node_context``)
into the same asset-inventory shape. That projection lives here so the human
cockpit and the headless agent surface share one implementation and one evidence
model — no duplicated logic, no second store.

The functions here are transport-neutral. They raise :class:`InventoryError` for
caller mistakes (bad filters, deep offsets) so each surface can map it to its own
error envelope (HTTP status vs MCP error JSON), and they take an injectable
``store_call`` so the HTTP route can wrap store access in backpressure while the
MCP path uses a plain thread hop.
"""

from __future__ import annotations

import asyncio
from typing import Any, Awaitable, Callable, Optional

from agent_bom.api.graph_store import MAX_NODE_PAGE_OFFSET, encode_graph_cursor
from agent_bom.graph import SEVERITY_RANK, EntityType
from agent_bom.graph.ocsf import FINDING_ENTITY_TYPES
from agent_bom.security import sanitize_error

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
MAX_PAGE_LIMIT = 200
MAX_FACET_SCAN_PAGES = 25

# Async callable that runs a sync graph-store method off the event loop.
StoreCall = Callable[..., Awaitable[Any]]


class InventoryError(Exception):
    """A caller-facing inventory error carrying an HTTP-style status + detail.

    Transport-neutral: the HTTP route maps ``status_code``/``detail`` onto an
    ``HTTPException`` while the MCP tools map it onto an MCP error envelope.
    """

    def __init__(self, detail: str, *, status_code: int = 422) -> None:
        super().__init__(detail)
        self.detail = detail
        self.status_code = status_code


async def default_store_call(fn: Callable[..., Any], /, *args: Any, **kwargs: Any) -> Any:
    """Run a sync graph-store method off the event loop (no backpressure)."""
    return await asyncio.to_thread(fn, *args, **kwargs)


def parse_types(raw: Optional[str]) -> set[str] | None:
    """Parse the ``type=`` filter into a validated set of asset entity types."""
    if not raw:
        return None
    values = {value.strip() for value in raw.split(",") if value.strip()}
    invalid = sorted(values - _ALL_ENTITY_TYPE_VALUES)
    if invalid:
        raise InventoryError(f"Unsupported asset type: {invalid[0]}", status_code=422)
    findings = sorted(values & _FINDING_TYPE_VALUES)
    if findings:
        raise InventoryError(
            f"'{findings[0]}' is a finding, not an asset. Use /v1/findings for findings.",
            status_code=422,
        )
    return values or None


def _node_environment(node: Any) -> str:
    return str(node.dimensions.environment or node.attributes.get("environment") or "")


def _node_provider(node: Any) -> str:
    return str(node.dimensions.cloud_provider or node.attributes.get("provider") or node.attributes.get("cloud_provider") or "")


def _entity_value(node: Any) -> str:
    return node.entity_type.value if hasattr(node.entity_type, "value") else str(node.entity_type)


def asset_row(node: Any) -> dict[str, Any]:
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


def _facet_predicate(environment: str, provider: str, source: str) -> Callable[[Any], bool]:
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


async def build_summary(
    *,
    store: Any,
    tenant_id: str,
    scan_id: Optional[str] = None,
    store_call: StoreCall = default_store_call,
) -> dict[str, Any]:
    """Asset counts for the tenant's current snapshot, by type and group.

    Backed by the graph store's ``snapshot_stats`` (its ``node_types`` bucket).
    Findings are excluded — this counts assets across AI, cloud, Snowflake, and
    identity uniformly because they already coexist as typed nodes in one snapshot.
    """
    stats = await store_call(store.snapshot_stats, scan_id=scan_id or "", tenant_id=tenant_id)
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
        "tenant_id": tenant_id,
        "scan_id": stats.get("scan_id", scan_id or ""),
        "total_assets": total_assets,
        "by_type": dict(sorted(by_type.items(), key=lambda kv: (-kv[1], kv[0]))),
        "by_group": {group: count for group, count in by_group.items() if count or group in _TYPE_GROUPS},
        "finding_count": sum(int(node_types.get(t, 0) or 0) for t in _FINDING_TYPE_VALUES),
    }


# ═══════════════════════════════════════════════════════════════════════════
# Faceted list
# ═══════════════════════════════════════════════════════════════════════════


async def build_asset_list(
    *,
    store: Any,
    tenant_id: str,
    type: Optional[str] = None,
    search: Optional[str] = None,
    environment: Optional[str] = None,
    provider: Optional[str] = None,
    source: Optional[str] = None,
    min_severity: Optional[str] = None,
    scan_id: Optional[str] = None,
    cursor: Optional[str] = None,
    offset: int = 0,
    limit: int = 50,
    store_call: StoreCall = default_store_call,
) -> dict[str, Any]:
    """Paginated, filterable asset rows across every source in the unified graph.

    ``type`` / ``search`` / ``min_severity`` are pushed into the graph store
    (``page_nodes`` / ``search_nodes``); ``environment`` / ``provider`` /
    ``source`` are matched here with a keyset refill loop so a filtered page is
    never silently truncated.
    """
    if limit < 1 or limit > MAX_PAGE_LIMIT:
        raise InventoryError(f"limit must be between 1 and {MAX_PAGE_LIMIT}", status_code=422)
    if offset < 0:
        raise InventoryError("offset must be >= 0", status_code=422)
    if not cursor and offset > MAX_NODE_PAGE_OFFSET:
        raise InventoryError(
            f"offset={offset} exceeds the maximum supported offset ({MAX_NODE_PAGE_OFFSET}). "
            "Use the cursor= keyset parameter (next_cursor from the previous page) for deep pagination.",
            status_code=422,
        )

    entity_types = parse_types(type)
    # Default to every asset type so findings never leak into the inventory list.
    effective_types = entity_types if entity_types is not None else set(_ASSET_TYPE_VALUES)
    min_rank = SEVERITY_RANK.get(min_severity.lower(), 0) if min_severity else 0
    query = (search or "").strip()
    facet_active = bool((environment or "").strip() or (provider or "").strip() or (source or "").strip())
    predicate = _facet_predicate(environment or "", provider or "", source or "")

    async def _fetch(page_cursor: str | None, page_offset: int, page_limit: int):
        """Return (nodes, total, next_cursor) from the active store call."""
        try:
            if query:
                nodes, total, next_cursor = await store_call(
                    store.search_nodes,
                    scan_id=scan_id or "",
                    tenant_id=tenant_id,
                    query=query,
                    entity_types=effective_types,
                    min_severity_rank=min_rank,
                    cursor=page_cursor,
                    offset=page_offset,
                    limit=page_limit,
                )
                return nodes, total, next_cursor
            _scan_id, _created_at, nodes, total, next_cursor = await store_call(
                store.page_nodes,
                scan_id=scan_id or "",
                tenant_id=tenant_id,
                entity_types=effective_types,
                min_severity_rank=min_rank,
                cursor=page_cursor,
                offset=page_offset,
                limit=page_limit,
            )
        except ValueError as exc:
            raise InventoryError(str(sanitize_error(exc)), status_code=400) from exc
        return nodes, total, next_cursor

    if not facet_active:
        nodes, total, next_cursor = await _fetch(cursor, offset, limit)
        rows = [asset_row(node) for node in nodes]
        return {
            "schema_version": "inventory.assets.v1",
            "tenant_id": tenant_id,
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
    collected_nodes: list[Any] = []
    collected_rows: list[dict[str, Any]] = []
    page_cursor = cursor
    exhausted = False
    for _ in range(MAX_FACET_SCAN_PAGES):
        nodes, _total, next_cursor = await _fetch(page_cursor, 0, MAX_PAGE_LIMIT)
        for node in nodes:
            if predicate(node):
                collected_nodes.append(node)
                collected_rows.append(asset_row(node))
        page_cursor = next_cursor
        if not next_cursor:
            exhausted = True
            break
        if len(collected_rows) >= limit:
            break
    page_rows = collected_rows[:limit]
    # The continuation cursor MUST resume after the last EMITTED row — not the
    # store cursor after the last consumed page, which would skip the matches
    # collected past ``limit`` within that final store page (a silent drop). When
    # more matches than ``limit`` were collected, mint the keyset cursor from the
    # boundary emitted node so the next request re-scans from exactly there;
    # otherwise everything collected was emitted, so resume from the store cursor
    # (cap hit, more to scan) or stop (store exhausted).
    if len(collected_rows) > limit:
        next_cursor_out = encode_graph_cursor(collected_nodes[limit - 1])
        has_more = True
    else:
        next_cursor_out = "" if exhausted else (page_cursor or "")
        has_more = bool(next_cursor_out)
    return {
        "schema_version": "inventory.assets.v1",
        "tenant_id": tenant_id,
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
            "next_cursor": next_cursor_out,
            "has_more": has_more,
            "facet_filtered": True,
        },
    }


# ═══════════════════════════════════════════════════════════════════════════
# Detail
# ═══════════════════════════════════════════════════════════════════════════


async def build_asset_detail(
    *,
    store: Any,
    tenant_id: str,
    asset_id: str,
    scan_id: Optional[str] = None,
    store_call: StoreCall = default_store_call,
) -> dict[str, Any] | None:
    """One asset's full attributes plus its relationships (neighbors / edges).

    Reuses the graph store's ``node_context`` so the UI drawer and headless
    agents both render config, relationships, and blast-radius impact. Returns
    ``None`` when the asset is not in the tenant's snapshot.
    """
    context = await store_call(
        store.node_context,
        scan_id=scan_id or "",
        tenant_id=tenant_id,
        node_id=asset_id,
    )
    if context is None:
        return None

    node = context["node"]
    return {
        "schema_version": "inventory.asset.v1",
        "tenant_id": tenant_id,
        "asset": asset_row(node),
        "node": node.to_dict(),
        "edges_out": [edge.to_dict() for edge in context["edges_out"]],
        "edges_in": [edge.to_dict() for edge in context["edges_in"]],
        "neighbors": context["neighbors"],
        "sources": context["sources"],
        "impact": context["impact"],
    }
