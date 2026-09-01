"""Registration helpers for MCP runtime and inventory catalog tools."""

from __future__ import annotations

from typing import Annotated, Awaitable, Callable

from pydantic import Field


def register_runtime_catalog_tools(
    mcp,
    *,
    read_only,
    runtime_introspection,
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

    @mcp.tool(annotations=runtime_introspection, title="Tool Capability Risk")
    async def tool_risk_assessment(
        config_path: Annotated[str | None, Field(description="Path to MCP client config directory. Auto-discovers all if omitted.")] = None,
        timeout: Annotated[float, Field(ge=0.1, le=60.0, description="Per-server introspection timeout in seconds.")] = 10.0,
        allow_command_execution: Annotated[
            bool,
            Field(description="Explicitly allow launching unblocked stdio server commands. False only connects to HTTP/SSE servers."),
        ] = False,
    ) -> str:
        """Live-introspect MCP servers and score each tool's capability risk.

        Discovers configured MCP clients, connects to their servers, calls
        ``tools/list``, and classifies every exposed tool by capability
        (filesystem, network, code execution, credential access) to produce a
        per-tool and per-server risk score from what the servers actually
        advertise at runtime.

        Args:
            config_path: MCP client config directory to read; auto-discovers all
                supported clients when omitted.
            timeout: Per-server introspection timeout in seconds.
            allow_command_execution: Explicit opt-in required before launching
                discovered stdio server commands.

        Returns:
            JSON with per-server tool inventories, per-tool capability classes
            and risk levels, and an aggregate server risk rating.

        Use this to assess the blast radius of MCP servers an agent can reach
        before granting or trusting their tools.
        """
        return await execute_tool_sync_async(
            "tool_risk_assessment",
            tool_risk_assessment_impl,
            config_path=config_path,
            timeout=timeout,
            allow_command_execution=allow_command_execution,
            _safe_path=safe_path,
            _truncate_response=truncate_response,
            destructive=allow_command_execution,
        )
