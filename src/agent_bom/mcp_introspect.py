"""MCP Runtime Introspection — connect to live MCP servers for tool/resource discovery.

Read-only introspection: connects to running MCP servers via the MCP protocol,
calls ``tools/list`` and ``resources/list`` to discover actual runtime capabilities,
and compares them against config-declared data to detect drift.

Requires ``mcp`` SDK.  Install with::

    pip install mcp

Security guarantees:
- **Read-only**: Only calls ``initialize``, ``tools/list``, ``resources/list``.
  Never calls ``tools/call``.
- **Timeout-guarded**: Every connection attempt has a configurable timeout.
- **Clean shutdown**: All server subprocesses are terminated on exit.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from typing import Optional

from agent_bom.models import MCPResource, MCPServer, MCPTool, TransportType

logger = logging.getLogger(__name__)

# Default timeout for connecting to an MCP server (seconds)
DEFAULT_TIMEOUT = 10.0


class IntrospectionError(Exception):
    """Raised when introspection of an MCP server fails."""


@dataclass
class ServerIntrospection:
    """Result of introspecting a single MCP server."""

    server_name: str
    success: bool
    protocol_version: Optional[str] = None
    runtime_tools: list[MCPTool] = field(default_factory=list)
    runtime_resources: list[MCPResource] = field(default_factory=list)
    error: Optional[str] = None

    # Drift analysis
    tools_added: list[str] = field(default_factory=list)
    tools_removed: list[str] = field(default_factory=list)
    resources_added: list[str] = field(default_factory=list)
    resources_removed: list[str] = field(default_factory=list)

    @property
    def has_drift(self) -> bool:
        return bool(self.tools_added or self.tools_removed or self.resources_added or self.resources_removed)

    @property
    def tool_count(self) -> int:
        return len(self.runtime_tools)

    @property
    def resource_count(self) -> int:
        return len(self.runtime_resources)


@dataclass
class IntrospectionReport:
    """Aggregate report of all MCP server introspections."""

    results: list[ServerIntrospection] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    @property
    def total_servers(self) -> int:
        return len(self.results)

    @property
    def successful(self) -> int:
        return sum(1 for r in self.results if r.success)

    @property
    def failed(self) -> int:
        return sum(1 for r in self.results if not r.success)

    @property
    def total_tools(self) -> int:
        return sum(r.tool_count for r in self.results if r.success)

    @property
    def total_resources(self) -> int:
        return sum(r.resource_count for r in self.results if r.success)

    @property
    def drift_count(self) -> int:
        return sum(1 for r in self.results if r.has_drift)


def _check_mcp_sdk() -> None:
    """Ensure the mcp SDK is available."""
    try:
        import mcp  # noqa: F401
    except ImportError:
        raise IntrospectionError(
            "mcp SDK is required for runtime introspection. "
            "Install with: pip install mcp"
        )


async def introspect_server(
    server: MCPServer,
    timeout: float = DEFAULT_TIMEOUT,
) -> ServerIntrospection:
    """Introspect a single MCP server.

    Connects via the server's configured transport, performs the MCP handshake,
    and queries tools/list + resources/list.

    Only stdio and SSE transports are supported for introspection.
    """
    _check_mcp_sdk()

    result = ServerIntrospection(server_name=server.name, success=False)

    if server.transport == TransportType.STDIO:
        if not server.command:
            result.error = "No command configured for stdio server"
            return result
        return await _introspect_stdio(server, result, timeout)

    elif server.transport in (TransportType.SSE, TransportType.STREAMABLE_HTTP):
        if not server.url:
            result.error = f"No URL configured for {server.transport.value} server"
            return result
        return await _introspect_sse(server, result, timeout)

    else:
        result.error = f"Unsupported transport: {server.transport.value}"
        return result


async def _introspect_stdio(
    server: MCPServer,
    result: ServerIntrospection,
    timeout: float,
) -> ServerIntrospection:
    """Introspect via stdio transport (subprocess)."""
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client

    params = StdioServerParameters(
        command=server.command,
        args=server.args,
        env=server.env or None,
    )

    try:
        async with asyncio.timeout(timeout):
            async with stdio_client(params) as (read, write):
                async with ClientSession(read, write) as session:
                    init_result = await session.initialize()
                    result.protocol_version = getattr(init_result, "protocolVersion", None)

                    result = await _query_capabilities(session, server, result)

    except TimeoutError:
        result.error = f"Connection timed out after {timeout}s"
    except Exception as exc:
        result.error = str(exc)

    return result


async def _introspect_sse(
    server: MCPServer,
    result: ServerIntrospection,
    timeout: float,
) -> ServerIntrospection:
    """Introspect via SSE transport (HTTP connection to running server)."""
    from mcp import ClientSession
    from mcp.client.sse import sse_client

    try:
        async with asyncio.timeout(timeout):
            async with sse_client(server.url) as (read, write):
                async with ClientSession(read, write) as session:
                    init_result = await session.initialize()
                    result.protocol_version = getattr(init_result, "protocolVersion", None)

                    result = await _query_capabilities(session, server, result)

    except TimeoutError:
        result.error = f"Connection timed out after {timeout}s"
    except Exception as exc:
        result.error = str(exc)

    return result


async def _query_capabilities(
    session,
    server: MCPServer,
    result: ServerIntrospection,
) -> ServerIntrospection:
    """Query tools/list and resources/list from an active MCP session."""

    # ── Tools ──────────────────────────────────────────────────────────
    try:
        tools_result = await session.list_tools()
        for tool in tools_result.tools:
            result.runtime_tools.append(MCPTool(
                name=tool.name,
                description=getattr(tool, "description", "") or "",
                input_schema=getattr(tool, "inputSchema", None),
            ))
    except Exception as exc:
        logger.debug("tools/list failed for %s: %s", server.name, exc)

    # ── Resources ──────────────────────────────────────────────────────
    try:
        resources_result = await session.list_resources()
        for resource in resources_result.resources:
            result.runtime_resources.append(MCPResource(
                uri=str(getattr(resource, "uri", "")),
                name=getattr(resource, "name", "") or "",
                description=getattr(resource, "description", "") or "",
                mime_type=getattr(resource, "mimeType", None),
            ))
    except Exception as exc:
        logger.debug("resources/list failed for %s: %s", server.name, exc)

    result.success = True

    # ── Drift detection ────────────────────────────────────────────────
    config_tool_names = {t.name for t in server.tools}
    runtime_tool_names = {t.name for t in result.runtime_tools}

    result.tools_added = sorted(runtime_tool_names - config_tool_names)
    result.tools_removed = sorted(config_tool_names - runtime_tool_names)

    config_resource_uris = {r.uri for r in server.resources}
    runtime_resource_uris = {r.uri for r in result.runtime_resources}

    result.resources_added = sorted(runtime_resource_uris - config_resource_uris)
    result.resources_removed = sorted(config_resource_uris - runtime_resource_uris)

    return result


async def introspect_servers(
    servers: list[MCPServer],
    timeout: float = DEFAULT_TIMEOUT,
    max_concurrent: int = 5,
) -> IntrospectionReport:
    """Introspect multiple MCP servers with concurrency control.

    Args:
        servers: List of MCP servers to introspect.
        timeout: Per-server connection timeout in seconds.
        max_concurrent: Maximum number of concurrent introspection connections.

    Returns:
        IntrospectionReport with all results and warnings.
    """
    _check_mcp_sdk()

    report = IntrospectionReport()
    semaphore = asyncio.Semaphore(max_concurrent)

    async def _introspect_with_semaphore(server: MCPServer) -> ServerIntrospection:
        async with semaphore:
            return await introspect_server(server, timeout)

    # Only introspect servers that have enough config to connect
    introspectable = []
    for server in servers:
        if server.transport == TransportType.STDIO and server.command:
            introspectable.append(server)
        elif server.transport in (TransportType.SSE, TransportType.STREAMABLE_HTTP) and server.url:
            introspectable.append(server)
        else:
            report.warnings.append(
                f"Skipping {server.name}: no command/URL for {server.transport.value} transport"
            )

    if not introspectable:
        report.warnings.append("No servers eligible for introspection")
        return report

    tasks = [_introspect_with_semaphore(s) for s in introspectable]
    results = await asyncio.gather(*tasks, return_exceptions=True)

    for i, result in enumerate(results):
        if isinstance(result, Exception):
            report.results.append(ServerIntrospection(
                server_name=introspectable[i].name,
                success=False,
                error=str(result),
            ))
        else:
            report.results.append(result)

    return report


def introspect_servers_sync(
    servers: list[MCPServer],
    timeout: float = DEFAULT_TIMEOUT,
) -> IntrospectionReport:
    """Synchronous wrapper for introspect_servers."""
    return asyncio.run(introspect_servers(servers, timeout))


def enrich_servers(
    servers: list[MCPServer],
    report: IntrospectionReport,
) -> int:
    """Enrich MCP servers with runtime-discovered tools and resources.

    For each successfully introspected server, merges runtime-discovered
    tools and resources into the server's existing data. Only adds new
    items not already present.

    Returns:
        Number of servers enriched.
    """
    enriched = 0
    result_map = {r.server_name: r for r in report.results if r.success}

    for server in servers:
        result = result_map.get(server.name)
        if not result:
            continue

        existing_tools = {t.name for t in server.tools}
        existing_resources = {r.uri for r in server.resources}
        added_any = False

        for tool in result.runtime_tools:
            if tool.name not in existing_tools:
                server.tools.append(tool)
                existing_tools.add(tool.name)
                added_any = True

        for resource in result.runtime_resources:
            if resource.uri not in existing_resources:
                server.resources.append(resource)
                existing_resources.add(resource.uri)
                added_any = True

        # Update MCP version if we got one
        if result.protocol_version and not server.mcp_version:
            server.mcp_version = result.protocol_version
            added_any = True

        if added_any:
            enriched += 1

    return enriched
