"""Cross-source discovery identity collapse helpers."""

from __future__ import annotations

import os
from pathlib import Path
from urllib.parse import urlparse, urlunparse

from agent_bom.models import Agent, MCPResource, MCPServer, MCPTool, Package


def server_identity_key(server: MCPServer) -> str:
    """Return a stable identity key independent of discovery source."""
    if server.registry_id:
        return f"registry:{server.registry_id.strip().lower()}"
    if server.url:
        parsed = urlparse(server.url.strip())
        netloc = parsed.netloc.lower()
        path = parsed.path.rstrip("/")
        return f"url:{urlunparse((parsed.scheme.lower(), netloc, path, '', '', ''))}"

    command = Path(server.command or "").name.lower().strip()
    args = tuple(_normalize_arg(arg) for arg in server.args if _normalize_arg(arg))
    if command or args:
        return f"cmd:{command}:{' '.join(args)}"

    return f"name:{server.name.strip().lower()}"


def deduplicate_discovered_agents(agents: list[Agent]) -> list[Agent]:
    """Collapse duplicate MCP servers across config/process/container/k8s sources.

    The first source wins for user-facing placement. Later sources enrich the
    same server with additional tools, resources, packages, env keys, warnings,
    and provenance labels instead of creating duplicate graph nodes.
    """
    seen: dict[str, MCPServer] = {}
    merged_agents: list[Agent] = []

    for agent in agents:
        deduped_servers: list[MCPServer] = []
        for server in agent.mcp_servers:
            _record_source(server, agent)
            key = server_identity_key(server)
            existing = seen.get(key)
            if existing is None:
                seen[key] = server
                deduped_servers.append(server)
                continue
            _merge_server(existing, server)

        if deduped_servers or not agent.mcp_servers:
            agent.mcp_servers = deduped_servers
            merged_agents.append(agent)

    return merged_agents


def _normalize_arg(arg: str) -> str:
    text = str(arg).strip()
    if not text:
        return ""
    if text.startswith(("/", "~", ".")):
        try:
            return os.path.normpath(os.path.expanduser(text)).lower()
        except (OSError, ValueError):
            return text.lower()
    return text.lower()


def _record_source(server: MCPServer, agent: Agent) -> None:
    sources = _source_list(server)
    source = agent.source or agent.agent_type.value
    marker = f"{source}:{server.config_path or agent.config_path}"
    if marker not in sources:
        sources.append(marker)


def _source_list(server: MCPServer) -> list[str]:
    current = getattr(server, "discovery_sources", None)
    if isinstance(current, list):
        return current
    server.discovery_sources = []
    return server.discovery_sources


def _merge_server(target: MCPServer, incoming: MCPServer) -> None:
    target.tools = _merge_by_stable_id(target.tools, incoming.tools)
    target.resources = _merge_by_stable_id(target.resources, incoming.resources)
    target.packages = _merge_by_stable_id(target.packages, incoming.packages)
    target.env = {**incoming.env, **target.env}
    target.security_blocked = target.security_blocked or incoming.security_blocked
    target.security_warnings = _merge_strings(target.security_warnings, incoming.security_warnings)
    target.discovery_sources = _merge_strings(_source_list(target), _source_list(incoming))
    if not target.working_dir:
        target.working_dir = incoming.working_dir
    if not target.url:
        target.url = incoming.url
    if not target.registry_id:
        target.registry_id = incoming.registry_id
    target.registry_verified = target.registry_verified or incoming.registry_verified


def _merge_by_stable_id(items: list[MCPTool] | list[MCPResource] | list[Package], incoming: list) -> list:
    merged = list(items)
    seen = {getattr(item, "stable_id", repr(item)) for item in merged}
    for item in incoming:
        key = getattr(item, "stable_id", repr(item))
        if key not in seen:
            merged.append(item)
            seen.add(key)
    return merged


def _merge_strings(existing: list[str], incoming: list[str]) -> list[str]:
    merged = list(existing)
    seen = set(merged)
    for item in incoming:
        if item not in seen:
            merged.append(item)
            seen.add(item)
    return merged
