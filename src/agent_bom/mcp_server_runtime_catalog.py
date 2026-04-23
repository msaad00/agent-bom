"""Registration helpers for MCP runtime and inventory catalog tools."""

from __future__ import annotations

from typing import Annotated, Awaitable, Callable

from pydantic import Field


def register_runtime_catalog_tools(
    mcp,
    *,
    read_only,
    execute_tool_sync_async: Callable[..., Awaitable[str]],
    safe_path,
    truncate_response,
) -> None:
    """Attach skill, discovery, and inventory-style tools to the MCP server."""
    from agent_bom.mcp_tools.runtime import (
        inventory_impl,
        skill_scan_impl,
        skill_trust_impl,
        skill_verify_impl,
        tool_risk_assessment_impl,
        where_impl,
    )

    @mcp.tool(annotations=read_only, title="Skill Scan")
    async def skill_scan(
        path: Annotated[str, Field(description="Path to a skill/instruction file or directory to scan.")] = ".",
    ) -> str:
        """Scan skill and instruction files for trust, findings, and provenance."""
        return await execute_tool_sync_async(
            "skill_scan",
            skill_scan_impl,
            path=path,
            _safe_path=safe_path,
            _truncate_response=truncate_response,
        )

    @mcp.tool(annotations=read_only, title="Skill Provenance Verify")
    async def skill_verify(
        path: Annotated[str, Field(description="Path to a skill/instruction file or directory to verify.")] = ".",
    ) -> str:
        """Verify Sigstore provenance for skill and instruction files."""
        return await execute_tool_sync_async(
            "skill_verify",
            skill_verify_impl,
            path=path,
            _safe_path=safe_path,
            _truncate_response=truncate_response,
        )

    @mcp.tool(annotations=read_only, title="Skill Trust Assessment")
    async def skill_trust(
        skill_path: Annotated[str, Field(description="Path to a SKILL.md file (or any skill/instruction file) to assess.")],
    ) -> str:
        """Assess the trust level of a SKILL.md file using ClawHub-style categories."""
        return await execute_tool_sync_async(
            "skill_trust",
            skill_trust_impl,
            skill_path=skill_path,
            _safe_path=safe_path,
            _truncate_response=truncate_response,
        )

    @mcp.tool(annotations=read_only, title="Discovery Paths")
    async def where() -> str:
        """Show all MCP discovery paths and which config files exist."""
        return await execute_tool_sync_async("where", where_impl, _truncate_response=truncate_response)

    @mcp.tool(annotations=read_only, title="Agent Inventory")
    async def inventory(
        config_path: Annotated[str | None, Field(description="Path to MCP client config directory. Auto-discovers all if omitted.")] = None,
    ) -> str:
        """List all discovered MCP configurations and servers without CVE scanning."""
        return await execute_tool_sync_async(
            "inventory",
            inventory_impl,
            config_path=config_path,
            _truncate_response=truncate_response,
        )

    @mcp.tool(annotations=read_only, title="Tool Capability Risk")
    async def tool_risk_assessment(
        config_path: Annotated[str | None, Field(description="Path to MCP client config directory. Auto-discovers all if omitted.")] = None,
        timeout: Annotated[float, Field(description="Per-server introspection timeout in seconds.")] = 10.0,
    ) -> str:
        """Score live-introspected MCP tool capabilities and server risk."""
        return await execute_tool_sync_async(
            "tool_risk_assessment",
            tool_risk_assessment_impl,
            config_path=config_path,
            timeout=timeout,
            _truncate_response=truncate_response,
        )
