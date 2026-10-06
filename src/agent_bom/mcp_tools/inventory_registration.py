"""Asset-detail MCP registration, backed by the shared inventory service."""

from __future__ import annotations

from typing import Annotated, Any, Callable

from pydantic import Field

from agent_bom.mcp_tools.inventory import inventory_asset_impl


def register_inventory_asset_tool(
    mcp: Any, *, read_only: Any, execute_tool_async: Callable[..., Any], truncate_response: Callable[[str], str]
) -> None:
    """Register the bounded component inspection tool."""

    @mcp.tool(annotations=read_only, title="Asset Inventory Detail")
    async def inventory_asset(
        asset_id: Annotated[str, Field(description="Graph node ID of the asset to inspect, e.g. 'cloud_resource:ec2' or 'agent:a'.")],
        tenant_id: Annotated[str, Field(description="Tenant scope for the snapshot. Defaults to 'default'.")] = "default",
        scan_id: Annotated[str | None, Field(description="Optional historical scan ID. Omit for the current tenant estate.")] = None,
        limit: Annotated[int, Field(ge=1, le=100, description="Maximum recorded relationships per page.")] = 24,
        cursor: Annotated[str | None, Field(max_length=8192, description="Next-page cursor from the preceding response.")] = None,
        snapshot_generation: Annotated[str | None, Field(pattern=r"^[0-9a-f]{32}$", description="Generation from the first page.")] = None,
    ) -> str:
        """Return asset attributes and a bounded recorded relationship page.

        Reuse scan_id, snapshot_generation, and next_cursor for continuation.
        Completeness covers this page; blast-radius impact is not evaluated.
        """
        return await execute_tool_async(
            "inventory_asset",
            inventory_asset_impl,
            asset_id=asset_id,
            tenant_id=tenant_id,
            scan_id=scan_id,
            limit=limit,
            cursor=cursor,
            snapshot_generation=snapshot_generation,
            _truncate_response=truncate_response,
        )
