"""Agent-native MCP tools for the unified asset inventory.

These expose the same faceted asset inventory the dashboard renders (AI, cloud,
Snowflake, and identity assets across the ONE tenant-scoped unified graph
snapshot) to headless MCP clients — Claude, Cursor, Codex, Windsurf, Cortex.
They project the graph store through ``agent_bom.api.inventory_service`` (the
same helper the ``/v1/inventory/*`` HTTP routes call), so humans and agents read
one shared evidence model with no duplicated logic and no HTTP self-call.

All three tools are read-only and tenant-scoped. Findings are excluded — this is
the asset inventory, not the finding queue.
"""

from __future__ import annotations

import json
import logging
from typing import Any, Callable, Optional

from agent_bom.mcp_errors import (
    CODE_INTERNAL_UNEXPECTED,
    CODE_NOT_FOUND_RESOURCE,
    CODE_VALIDATION_INVALID_ARGUMENT,
    mcp_error_json,
)
from agent_bom.mcp_tenant import resolve_mcp_tool_tenant_id

logger = logging.getLogger(__name__)


def _resolve_store(_get_graph_store: Optional[Callable[[], Any]]) -> Any:
    if _get_graph_store is None:
        from agent_bom.api.stores import _get_graph_store as _default_get_graph_store

        _get_graph_store = _default_get_graph_store
    return _get_graph_store()


def _encode(payload: dict[str, Any], _truncate_response: Optional[Callable[[str], str]]) -> str:
    encoded = json.dumps(payload, indent=2, default=str)
    return _truncate_response(encoded) if _truncate_response is not None else encoded


async def inventory_summary_impl(
    *,
    tenant_id: str = "default",
    scan_id: str | None = None,
    _get_graph_store: Optional[Callable[[], Any]] = None,
    _truncate_response: Optional[Callable[[str], str]] = None,
) -> str:
    """Return asset counts by type and group for the tenant's current snapshot."""
    from agent_bom.api import inventory_service

    tenant_id = resolve_mcp_tool_tenant_id(tenant_id)
    try:
        store = _resolve_store(_get_graph_store)
        payload = await inventory_service.build_summary(store=store, tenant_id=tenant_id, scan_id=scan_id)
        return _encode(payload, _truncate_response)
    except inventory_service.InventoryError as exc:
        return mcp_error_json(CODE_VALIDATION_INVALID_ARGUMENT, exc.detail)
    except Exception:
        logger.exception("MCP inventory_summary error")
        return mcp_error_json(CODE_INTERNAL_UNEXPECTED, "An internal error has occurred.")


async def inventory_list_impl(
    *,
    tenant_id: str = "default",
    type: str | None = None,
    search: str | None = None,
    environment: str | None = None,
    provider: str | None = None,
    source: str | None = None,
    min_severity: str | None = None,
    scan_id: str | None = None,
    cursor: str | None = None,
    offset: int = 0,
    limit: int = 50,
    _get_graph_store: Optional[Callable[[], Any]] = None,
    _truncate_response: Optional[Callable[[str], str]] = None,
) -> str:
    """Return a filtered, paginated page of inventory asset rows."""
    from agent_bom.api import inventory_service

    tenant_id = resolve_mcp_tool_tenant_id(tenant_id)
    try:
        store = _resolve_store(_get_graph_store)
        payload = await inventory_service.build_asset_list(
            store=store,
            tenant_id=tenant_id,
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
        )
        return _encode(payload, _truncate_response)
    except inventory_service.InventoryError as exc:
        return mcp_error_json(CODE_VALIDATION_INVALID_ARGUMENT, exc.detail)
    except Exception:
        logger.exception("MCP inventory_list error")
        return mcp_error_json(CODE_INTERNAL_UNEXPECTED, "An internal error has occurred.")


async def inventory_asset_impl(
    *,
    asset_id: str,
    tenant_id: str = "default",
    scan_id: str | None = None,
    _get_graph_store: Optional[Callable[[], Any]] = None,
    _truncate_response: Optional[Callable[[str], str]] = None,
) -> str:
    """Return one asset's attributes, relationships, and blast-radius impact."""
    from agent_bom.api import inventory_service

    asset_id = (asset_id or "").strip()
    if not asset_id:
        return mcp_error_json(
            CODE_VALIDATION_INVALID_ARGUMENT,
            "asset_id must not be empty",
            details={"argument": "asset_id"},
        )
    tenant_id = resolve_mcp_tool_tenant_id(tenant_id)
    try:
        store = _resolve_store(_get_graph_store)
        payload = await inventory_service.build_asset_detail(
            store=store,
            tenant_id=tenant_id,
            asset_id=asset_id,
            scan_id=scan_id,
        )
        if payload is None:
            return mcp_error_json(
                CODE_NOT_FOUND_RESOURCE,
                f"Asset '{asset_id}' not found in the tenant snapshot.",
                details={"asset_id": asset_id, "tenant_id": tenant_id},
            )
        return _encode(payload, _truncate_response)
    except inventory_service.InventoryError as exc:
        return mcp_error_json(CODE_VALIDATION_INVALID_ARGUMENT, exc.detail)
    except Exception:
        logger.exception("MCP inventory_asset error")
        return mcp_error_json(CODE_INTERNAL_UNEXPECTED, "An internal error has occurred.")
