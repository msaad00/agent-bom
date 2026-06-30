"""Cross-source discovery identity collapse helpers."""

from __future__ import annotations

from agent_bom.canonical_ids import mcp_server_identity_discriminator
from agent_bom.models import Agent, MCPResource, MCPServer, MCPTool, Package


def server_identity_key(server: MCPServer) -> str:
    """Return a stable identity key independent of discovery source.

    Shares the non-registry url/command/name discriminator with
    ``canonical_mcp_server_id`` so a server's dedup identity and its served
    canonical id stay in lock-step.
    """
    if server.registry_id:
        return f"registry:{server.registry_id.strip().lower()}"
    return mcp_server_identity_discriminator(server.name, server.command, url=server.url, args=server.args)


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

    # Merging can append children and mutate command/url/registry_id, so re-scope
    # every surviving server's child identities to its final canonical id.
    for server in seen.values():
        server.stamp_child_identities()

    return merged_agents


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
    existing_intel = {
        (str(item.get("entry_id")), str(item.get("matched_value"))) for item in target.security_intelligence if isinstance(item, dict)
    }
    for item in incoming.security_intelligence:
        if not isinstance(item, dict):
            continue
        key = (str(item.get("entry_id")), str(item.get("matched_value")))
        if key not in existing_intel:
            target.security_intelligence.append(item)
            existing_intel.add(key)
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
