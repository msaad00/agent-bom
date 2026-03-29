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
import re
from dataclasses import dataclass, field
from typing import Optional

from agent_bom.models import MCPResource, MCPServer, MCPTool, TransportType

logger = logging.getLogger(__name__)

# Default timeout for connecting to an MCP server (seconds)
DEFAULT_TIMEOUT = 10.0
_PATH_HINT_RE = re.compile(r"(path|file|dir|cwd|workspace)", re.IGNORECASE)
_URL_HINT_RE = re.compile(r"(url|uri|endpoint|host|domain|webhook)", re.IGNORECASE)
_SHELL_HINT_RE = re.compile(r"(cmd|command|shell|exec|script)", re.IGNORECASE)
_PROMPT_HINT_RE = re.compile(r"(prompt|instruction|system|markdown|html|svg)", re.IGNORECASE)


class IntrospectionError(Exception):
    """Raised when introspection of an MCP server fails."""


@dataclass
class ServerIntrospection:
    """Result of introspecting a single MCP server."""

    server_name: str
    success: bool
    protocol_version: Optional[str] = None
    auth_mode: Optional[str] = None
    configured_fingerprint: Optional[str] = None
    runtime_fingerprint: Optional[str] = None
    configured_tool_count: int = 0
    configured_resource_count: int = 0
    runtime_tools: list[MCPTool] = field(default_factory=list)
    runtime_resources: list[MCPResource] = field(default_factory=list)
    error: Optional[str] = None
    tool_schema_findings: list[str] = field(default_factory=list)
    resource_findings: list[str] = field(default_factory=list)
    capability_risk_score: float = 0.0
    capability_risk_level: str = "low"
    capability_counts: dict[str, int] = field(default_factory=dict)
    capability_tools: dict[str, list[str]] = field(default_factory=dict)
    dangerous_combinations: list[str] = field(default_factory=list)
    risk_justification: str = ""
    tool_risk_profiles: list[dict] = field(default_factory=list)

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

    def to_dict(self, *, include_runtime_objects: bool = False) -> dict:
        payload = {
            "server_name": self.server_name,
            "success": self.success,
            "protocol_version": self.protocol_version,
            "auth_mode": self.auth_mode,
            "configured_fingerprint": self.configured_fingerprint,
            "runtime_fingerprint": self.runtime_fingerprint,
            "configured_tool_count": self.configured_tool_count,
            "configured_resource_count": self.configured_resource_count,
            "tool_count": self.tool_count,
            "resource_count": self.resource_count,
            "tools_added": self.tools_added,
            "tools_removed": self.tools_removed,
            "resources_added": self.resources_added,
            "resources_removed": self.resources_removed,
            "tool_schema_findings": self.tool_schema_findings,
            "resource_findings": self.resource_findings,
            "has_drift": self.has_drift,
            "capability_risk_score": self.capability_risk_score,
            "capability_risk_level": self.capability_risk_level,
            "capability_counts": self.capability_counts,
            "capability_tools": self.capability_tools,
            "dangerous_combinations": self.dangerous_combinations,
            "risk_justification": self.risk_justification,
            "tool_risk_profiles": self.tool_risk_profiles,
            "error": self.error,
        }
        if include_runtime_objects:
            payload["runtime_tools"] = [
                {
                    "name": t.name,
                    "description": t.description,
                    "schema_findings": t.schema_findings,
                    "risk_score": t.risk_score,
                }
                for t in self.runtime_tools
            ]
            payload["runtime_resources"] = [
                {
                    "uri": r.uri,
                    "name": r.name,
                    "description": r.description,
                    "mime_type": r.mime_type,
                    "content_findings": r.content_findings,
                    "risk_score": r.risk_score,
                }
                for r in self.runtime_resources
            ]
        return payload


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
        raise IntrospectionError("mcp SDK is required for runtime introspection. Install with: pip install mcp")


def _runtime_server_fingerprint(server: MCPServer, tools: list[MCPTool], resources: list[MCPResource]) -> str:
    """Build a deterministic fingerprint from observed runtime capabilities."""
    runtime_server = MCPServer(
        name=server.name,
        command=server.command,
        args=list(server.args),
        env=dict(server.env),
        transport=server.transport,
        url=server.url,
        tools=tools,
        resources=resources,
        registry_id=server.registry_id,
    )
    return runtime_server.fingerprint


def _lint_tool_schema(tool: MCPTool) -> list[str]:
    """Return heuristic risk findings for a tool schema."""
    findings: list[str] = []
    schema = tool.input_schema or {}
    properties = schema.get("properties", {}) if isinstance(schema, dict) else {}

    if not tool.description or len(tool.description.strip()) < 12:
        findings.append(f"{tool.name}: weak-or-missing-description")

    if not properties and schema:
        findings.append(f"{tool.name}: unstructured-input-schema")

    for prop_name, prop_schema in properties.items():
        prop_schema = prop_schema or {}
        if not isinstance(prop_schema, dict):
            continue
        prop_type = prop_schema.get("type")
        desc = (prop_schema.get("description") or "").strip()

        if prop_type == "string" and not prop_schema.get("enum") and not prop_schema.get("maxLength"):
            findings.append(f"{tool.name}.{prop_name}: unbounded-freeform-string")
        if _PATH_HINT_RE.search(prop_name):
            findings.append(f"{tool.name}.{prop_name}: filesystem-capability")
        if _URL_HINT_RE.search(prop_name):
            findings.append(f"{tool.name}.{prop_name}: network-egress-capability")
        if _SHELL_HINT_RE.search(prop_name):
            findings.append(f"{tool.name}.{prop_name}: shell-execution-capability")
        if desc and _PROMPT_HINT_RE.search(desc):
            findings.append(f"{tool.name}.{prop_name}: prompt-bearing-input")

    return sorted(set(findings))


def _lint_resource(resource: MCPResource) -> list[str]:
    """Return heuristic risk findings for a resource descriptor."""
    findings: list[str] = []
    desc = resource.description or ""
    mime = (resource.mime_type or "").lower()
    uri = resource.uri.lower()

    if _PROMPT_HINT_RE.search(resource.name) or _PROMPT_HINT_RE.search(desc):
        findings.append(f"{resource.uri}: prompt-bearing-resource")
    if any(t in mime for t in ("text/html", "image/svg", "text/markdown")):
        findings.append(f"{resource.uri}: rich-content-resource")
    if any(t in uri for t in ("template", "prompt", "instruction")):
        findings.append(f"{resource.uri}: hidden-instruction-surface")
    if "mutable" in desc.lower() or "write" in desc.lower():
        findings.append(f"{resource.uri}: mutable-resource")

    return sorted(set(findings))


def _apply_runtime_risk(server: MCPServer, result: ServerIntrospection) -> None:
    """Compute capability-aware tool/server risk from live introspection data."""
    from agent_bom.risk_analyzer import score_server_risk, score_tool_risk

    tool_profiles = [score_tool_risk(tool).to_dict() for tool in result.runtime_tools]
    tool_profiles.sort(key=lambda item: (item["risk_score"], item["tool_name"]), reverse=True)
    result.tool_risk_profiles = tool_profiles

    server_profile = score_server_risk(result.runtime_tools, credentials=server.credential_names)
    result.capability_risk_score = round(server_profile.risk_score, 2)
    result.capability_risk_level = server_profile.risk_level
    result.capability_counts = server_profile.capabilities
    result.capability_tools = server_profile.capability_tools
    result.dangerous_combinations = server_profile.dangerous_combinations
    result.risk_justification = server_profile.justification


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

    result = ServerIntrospection(
        server_name=server.name,
        success=False,
        auth_mode=server.auth_mode,
        configured_fingerprint=server.fingerprint,
        configured_tool_count=len(server.tools),
        configured_resource_count=len(server.resources),
    )

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

    if not server.url:
        result.error = "Server URL is not set"
        return result

    try:
        async with asyncio.timeout(timeout):
            async with sse_client(server.url) as (read, write):  # type: ignore[arg-type]
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
    tools_ok = False
    try:
        tools_result = await session.list_tools()
        for tool in tools_result.tools:
            runtime_tool = MCPTool(
                name=tool.name,
                description=getattr(tool, "description", "") or "",
                input_schema=getattr(tool, "inputSchema", None),
            )
            runtime_tool.schema_findings = _lint_tool_schema(runtime_tool)
            result.runtime_tools.append(runtime_tool)
        tools_ok = True
    except Exception as exc:
        logger.warning("tools/list failed for %s: %s — drift detection skipped", server.name, exc)

    # ── Resources ──────────────────────────────────────────────────────
    resources_ok = False
    try:
        resources_result = await session.list_resources()
        for resource in resources_result.resources:
            runtime_resource = MCPResource(
                uri=str(getattr(resource, "uri", "")),
                name=getattr(resource, "name", "") or "",
                description=getattr(resource, "description", "") or "",
                mime_type=getattr(resource, "mimeType", None),
            )
            runtime_resource.content_findings = _lint_resource(runtime_resource)
            result.runtime_resources.append(runtime_resource)
        resources_ok = True
    except Exception as exc:
        logger.warning("resources/list failed for %s: %s", server.name, exc)

    result.success = True

    # ── Drift detection ────────────────────────────────────────────────
    # Only compare tools if tools/list succeeded — otherwise empty runtime_tools
    # would falsely report all config tools as "removed".
    config_tool_names = {t.name for t in server.tools}
    runtime_tool_names = {t.name for t in result.runtime_tools}

    if tools_ok:
        result.tools_added = sorted(runtime_tool_names - config_tool_names)
        result.tools_removed = sorted(config_tool_names - runtime_tool_names)

    if resources_ok:
        config_resource_uris = {r.uri for r in server.resources}
        runtime_resource_uris = {r.uri for r in result.runtime_resources}

        result.resources_added = sorted(runtime_resource_uris - config_resource_uris)
        result.resources_removed = sorted(config_resource_uris - runtime_resource_uris)

    result.tool_schema_findings = sorted({finding for tool in result.runtime_tools for finding in tool.schema_findings})
    result.resource_findings = sorted({finding for resource in result.runtime_resources for finding in resource.content_findings})
    result.runtime_fingerprint = _runtime_server_fingerprint(server, result.runtime_tools, result.runtime_resources)
    _apply_runtime_risk(server, result)

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
            report.warnings.append(f"Skipping {server.name}: no command/URL for {server.transport.value} transport")

    if not introspectable:
        report.warnings.append("No servers eligible for introspection")
        return report

    tasks = [_introspect_with_semaphore(s) for s in introspectable]
    results = await asyncio.gather(*tasks, return_exceptions=True)

    for i, result in enumerate(results):
        if isinstance(result, BaseException):
            report.results.append(
                ServerIntrospection(
                    server_name=introspectable[i].name,
                    success=False,
                    error=str(result),
                )
            )
        else:
            report.results.append(result)  # type: ignore[arg-type]

    return report


def introspect_servers_sync(
    servers: list[MCPServer],
    timeout: float = DEFAULT_TIMEOUT,
) -> IntrospectionReport:
    """Synchronous wrapper for introspect_servers."""
    return asyncio.run(introspect_servers(servers, timeout))


# ── Health Checks ────────────────────────────────────────────────────────────

HEALTH_CHECK_TIMEOUT = 5.0


@dataclass
class HealthStatus:
    """Lightweight health status for a single MCP server."""

    server_name: str
    reachable: bool
    tool_count: int = 0
    protocol_version: Optional[str] = None
    latency_ms: Optional[float] = None
    error: Optional[str] = None


async def health_check_servers(
    servers: list[MCPServer],
    timeout: float = HEALTH_CHECK_TIMEOUT,
    max_concurrent: int = 10,
) -> list[HealthStatus]:
    """Lightweight health check for MCP servers.

    Faster than full introspection — uses a shorter default timeout and
    returns simple reachability + tool count without drift analysis.

    Args:
        servers: List of MCP servers to probe.
        timeout: Per-server connection timeout in seconds.
        max_concurrent: Maximum concurrent probes.

    Returns:
        List of HealthStatus, one per eligible server.
    """
    import time

    _check_mcp_sdk()

    semaphore = asyncio.Semaphore(max_concurrent)

    async def _probe(server: MCPServer) -> HealthStatus:
        async with semaphore:
            t0 = time.perf_counter()
            result = await introspect_server(server, timeout)
            elapsed_ms = round((time.perf_counter() - t0) * 1000.0, 1)
            return HealthStatus(
                server_name=result.server_name,
                reachable=result.success,
                tool_count=result.tool_count,
                protocol_version=result.protocol_version,
                latency_ms=elapsed_ms if result.success else None,
                error=result.error,
            )

    eligible = [
        s
        for s in servers
        if (s.transport == TransportType.STDIO and s.command)
        or (s.transport in (TransportType.SSE, TransportType.STREAMABLE_HTTP) and s.url)
    ]

    if not eligible:
        return []

    tasks = [_probe(s) for s in eligible]
    return list(await asyncio.gather(*tasks))


def health_check_servers_sync(
    servers: list[MCPServer],
    timeout: float = HEALTH_CHECK_TIMEOUT,
) -> list[HealthStatus]:
    """Synchronous wrapper for health_check_servers."""
    return asyncio.run(health_check_servers(servers, timeout))


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

        server.mcp_version = result.protocol_version or server.mcp_version
        existing_tools = {t.name for t in server.tools}
        existing_resources = {r.uri for r in server.resources}
        added_any = False

        for tool in result.runtime_tools:
            if tool.name not in existing_tools:
                server.tools.append(tool)
                existing_tools.add(tool.name)
                added_any = True
            else:
                existing_tool = next((t for t in server.tools if t.name == tool.name), None)
                if existing_tool and tool.schema_findings:
                    merged = sorted(set(existing_tool.schema_findings) | set(tool.schema_findings))
                    if merged != existing_tool.schema_findings:
                        existing_tool.schema_findings = merged
                        added_any = True

        for resource in result.runtime_resources:
            if resource.uri not in existing_resources:
                server.resources.append(resource)
                existing_resources.add(resource.uri)
                added_any = True
            else:
                existing_resource = next((r for r in server.resources if r.uri == resource.uri), None)
                if existing_resource and resource.content_findings:
                    merged = sorted(set(existing_resource.content_findings) | set(resource.content_findings))
                    if merged != existing_resource.content_findings:
                        existing_resource.content_findings = merged
                        added_any = True

        if added_any:
            enriched += 1

    return enriched
