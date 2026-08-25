"""Shared query logic for the unified asset inventory.

Both the HTTP route (``api/routes/inventory_assets.py``) and the agent-native MCP
tools (``mcp_tools/inventory.py``) project the ONE tenant-scoped unified graph
snapshot (``query_inventory`` / ``node_context``)
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

from agent_bom.api.graph_store import MAX_NODE_PAGE_OFFSET
from agent_bom.graph import SEVERITY_RANK, EntityType
from agent_bom.graph.completeness import graph_completeness
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

MAX_PAGE_LIMIT = 200

_ESSENTIAL_ATTRIBUTE_KEYS = frozenset(
    {
        "account_id",
        "arn",
        "cloud_provider",
        "cluster",
        "ecosystem",
        "external_id",
        "image",
        "kind",
        "namespace",
        "organization_id",
        "owner",
        "package_name",
        "package_version",
        "path",
        "project_id",
        "purl",
        "region",
        "repository",
        "resource_id",
        "resource_kind",
        "resource_name",
        "scope",
        "subscription_id",
        "version",
    }
)

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
        "attributes": {key: value for key, value in (node.attributes or {}).items() if key in _ESSENTIAL_ATTRIBUTE_KEYS},
        "compliance_tags": list(node.compliance_tags or []),
        "ecosystem": str(node.dimensions.ecosystem or node.attributes.get("ecosystem") or ""),
        "version": str(node.attributes.get("version") or node.attributes.get("package_version") or ""),
    }


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

    Backed by the graph store's exact native inventory query. Findings are
    excluded — this counts assets across AI, cloud, Snowflake, and identity
    uniformly because they already coexist as typed nodes in one snapshot.
    """
    result = await store_call(
        store.query_inventory,
        scan_id=scan_id or "",
        tenant_id=tenant_id,
        asset_entity_types=set(_ASSET_TYPE_VALUES),
        limit=1,
    )
    type_buckets = result.get("facets", {}).get("type", [])
    node_types: dict[str, int] = {str(bucket["value"]): int(bucket["count"]) for bucket in type_buckets if bucket.get("value") is not None}

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
        "scope": "unified_graph_estate",
        "count_definition": ("typed graph nodes excluding finding entity types in the selected tenant and scan snapshot"),
        "tenant_id": tenant_id,
        "scan_id": result.get("scan_id", ""),
        "created_at": result.get("created_at", ""),
        "total_assets": total_assets,
        "by_type": dict(sorted(by_type.items(), key=lambda kv: (-kv[1], kv[0]))),
        "by_group": {group: count for group, count in by_group.items() if count or group in _TYPE_GROUPS},
        "finding_count": int(result.get("finding_count", 0)),
        "facets": {name: {"buckets": buckets} for name, buckets in result.get("facets", {}).items()},
        "facet_metadata": {
            "basis": "whole_query",
            "mode": "self_excluding",
            "exact": True,
            "scan_id": result.get("scan_id", ""),
        },
        "completeness": graph_completeness(returned=total_assets, total=total_assets),
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
    severity: Optional[str] = None,
    min_severity: Optional[str] = None,
    scan_id: Optional[str] = None,
    cursor: Optional[str] = None,
    offset: int = 0,
    limit: int = 50,
    store_call: StoreCall = default_store_call,
) -> dict[str, Any]:
    """Paginated, filterable asset rows across every source in the unified graph.

    All filters, the exact total, and self-excluding facets are evaluated by the
    selected graph store against one resolved snapshot. Severity means the
    highest directly linked finding severity, never the asset node's own rating.
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
    query = (search or "").strip()
    normalized_severity = (severity or "").strip().lower()
    if normalized_severity and normalized_severity not in SEVERITY_RANK:
        raise InventoryError(f"Unsupported severity: {normalized_severity}", status_code=422)
    min_rank = SEVERITY_RANK.get((min_severity or "").strip().lower(), 0)
    try:
        result = await store_call(
            store.query_inventory,
            scan_id=scan_id or "",
            tenant_id=tenant_id,
            asset_entity_types=set(_ASSET_TYPE_VALUES),
            entity_types=entity_types,
            search=query,
            environment=environment or "",
            provider=provider or "",
            source=source or "",
            severity=normalized_severity,
            min_severity_rank=min_rank,
            cursor=cursor,
            offset=offset,
            limit=limit,
        )
    except ValueError as exc:
        raise InventoryError(str(sanitize_error(exc)), status_code=400) from exc

    summaries = result.get("finding_summaries", {})
    relationship_counts = result.get("relationship_counts", {})
    page_rows: list[dict[str, Any]] = []
    for node in result.get("nodes", []):
        row = asset_row(node)
        row["finding_summary"] = summaries.get(node.id, {"total": 0, "by_severity": {}, "ids": [], "top_severity": ""})
        row["relationship_count"] = int(relationship_counts.get(node.id, 0))
        page_rows.append(row)
    total = int(result.get("total", 0))
    next_cursor_out = result.get("next_cursor") or ""
    has_more = bool(next_cursor_out) if cursor else offset + len(page_rows) < total
    return {
        "schema_version": "inventory.assets.v1",
        "scope": "unified_graph_estate",
        "count_definition": ("typed graph nodes excluding finding entity types in the selected tenant and scan snapshot"),
        "tenant_id": tenant_id,
        "scan_id": result.get("scan_id", ""),
        "created_at": result.get("created_at", ""),
        "assets": page_rows,
        "filters": {
            "type": sorted(entity_types) if entity_types else [],
            "search": query,
            "environment": (environment or "").strip(),
            "provider": (provider or "").strip(),
            "source": (source or "").strip(),
            "severity": normalized_severity,
            "min_severity": min_severity or "",
        },
        "pagination": {
            "total": total,
            "offset": offset,
            "limit": limit,
            "cursor": cursor or "",
            "next_cursor": next_cursor_out,
            "has_more": has_more,
            "facet_filtered": bool(
                (environment or "").strip() or (provider or "").strip() or (source or "").strip() or normalized_severity
            ),
        },
        "facets": {name: {"buckets": buckets} for name, buckets in result.get("facets", {}).items()},
        "facet_metadata": {
            "basis": "whole_query",
            "mode": "self_excluding",
            "exact": True,
            "scan_id": result.get("scan_id", ""),
        },
        "completeness": graph_completeness(
            returned=len(page_rows),
            total=total,
            truncated=has_more,
            reason="asset_page_limit" if has_more else "",
        ),
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
        "completeness": graph_completeness(returned=1, total=1),
    }
