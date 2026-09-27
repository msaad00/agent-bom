"""Endpoint inventory tools share the API service and authenticated tenant scope."""

from __future__ import annotations

import json
from typing import Annotated, Any

import anyio.to_thread
from pydantic import Field

from agent_bom.connectors.endpoints.models import SyncRequest
from agent_bom.connectors.endpoints.service import connection_list, device_page, sync_connection
from agent_bom.connectors.endpoints.store import EndpointStore
from agent_bom.mcp_tenant import resolve_mcp_tool_tenant_id
from agent_bom.security import sanitize_error


async def endpoint_inventory_impl(
    *, connection_id: str = "", limit: int = 100, offset: int = 0, tenant_id: str = "default", **_: Any
) -> str:
    tenant = resolve_mcp_tool_tenant_id(tenant_id)

    def read() -> dict:
        store = EndpointStore()
        if connection_id:
            return device_page(store, tenant, connection_id, limit=limit, offset=offset)
        return connection_list(store, tenant)

    try:
        return json.dumps(await anyio.to_thread.run_sync(read))
    except Exception as exc:
        return json.dumps({"error": sanitize_error(exc, generic=True)})


async def endpoint_sync_impl(
    *, connection_id: str, restart: bool = False, max_pages: int = 5, tenant_id: str = "default", _authenticated_actor: str = "", **_: Any
) -> str:
    from agent_bom.api.audit_log import log_action

    tenant = resolve_mcp_tool_tenant_id(tenant_id)

    def sync() -> dict:
        state = sync_connection(EndpointStore(), tenant, connection_id, SyncRequest(restart=restart, max_pages=max_pages))
        log_action(
            "endpoint_connector.synced",
            tenant_id=tenant,
            actor=_authenticated_actor or "mcp-operator",
            resource=f"endpoint-connector/{connection_id}",
            status=state.status,
            count=state.device_count,
            gap=state.gap,
        )
        return state.model_dump()

    try:
        return json.dumps(await anyio.to_thread.run_sync(sync))
    except Exception as exc:
        return json.dumps({"error": sanitize_error(exc, generic=True)})


def register_endpoint_tools(mcp: Any, *, read_only: Any, write_action: Any, execute_tool_async: Any) -> None:
    @mcp.tool(annotations=read_only, title="Endpoint Inventory Evidence")
    async def endpoint_inventory(
        connection_id: Annotated[str, Field(description="Stored connection ID; omit to list tenant connections.")] = "",
        limit: Annotated[int, Field(ge=1, le=500, description="Maximum device rows to return.")] = 100,
        offset: Annotated[int, Field(ge=0, description="Device offset in the current collection.")] = 0,
        tenant_id: Annotated[str, Field(description="Tenant scope; authenticated context is authoritative.")] = "default",
    ) -> str:
        """Read scoped Jamf/Falcon inventory, freshness and collection gaps. No execution or compliance inference."""
        return await execute_tool_async(
            "endpoint_inventory", endpoint_inventory_impl, connection_id=connection_id, limit=limit, offset=offset, tenant_id=tenant_id
        )

    @mcp.tool(annotations=write_action, title="Sync Endpoint Inventory")
    async def endpoint_sync(
        connection_id: Annotated[str, Field(description="Existing tenant-scoped connection ID.")],
        restart: Annotated[bool, Field(description="Start a new collection while retaining earlier evidence.")] = False,
        max_pages: Annotated[int, Field(ge=1, le=20, description="Maximum pages to collect in this bounded request.")] = 5,
        operator_role: Annotated[str, Field(description="Requested role; cannot elevate authenticated permissions.")] = "viewer",
        operator_scopes: Annotated[str, Field(description="Requested scopes; authenticated connectors:write is required.")] = "",
        reason: Annotated[str, Field(description="Operator reason recorded with the collection action.")] = "",
        tenant_id: Annotated[str, Field(description="Tenant scope; authenticated context is authoritative.")] = "default",
    ) -> str:
        """Collect read-only vendor inventory into durable evidence. Admin plus connectors:write required."""
        return await execute_tool_async(
            "endpoint_sync",
            endpoint_sync_impl,
            destructive=True,
            required_scope="connectors:write",
            connection_id=connection_id,
            restart=restart,
            max_pages=max_pages,
            operator_role=operator_role,
            operator_scopes=operator_scopes,
            reason=reason,
            tenant_id=tenant_id,
        )
