"""Canonical Agent BOM manifest helpers.

The manifest is the portable inventory contract for agent runtimes: which
humans/agents are present, which MCP servers and tools they can reach, and
which credential references are configured. It deliberately emits credential
names only, never values.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from agent_bom.api.fleet_store import FleetAgent
from agent_bom.api.mcp_observation_store import MCPObservation
from agent_bom.models import Agent, MCPServer, MCPTool
from agent_bom.platform_invariants import now_utc_iso
from agent_bom.security import sanitize_command_args, sanitize_security_warnings, sanitize_text, sanitize_url

AGENT_BOM_MANIFEST_SCHEMA_VERSION = "agent-bom.manifest/v1"
AGENT_BOM_GRAPH_RELATIONSHIPS = ("owns", "part_of", "uses", "provides_tool", "exposes_cred")
_RISKY_CREDENTIAL_NAME_TOKENS = ("admin", "root", "prod", "token", "key", "secret", "password")


def _value(value: object) -> str:
    if hasattr(value, "value"):
        return str(getattr(value, "value"))
    return str(value)


def _safe_path(value: object) -> str | None:
    if not value:
        return None
    return sanitize_text(str(value), max_len=300)


def _credential_refs(names: Iterable[str]) -> list[dict[str, str]]:
    return [{"name": sanitize_text(name, max_len=120), "kind": "env"} for name in sorted({name for name in names if name})]


def _credential_ref_rows(server: dict[str, object]) -> list[dict[str, object]]:
    refs = server.get("credential_refs")
    return refs if isinstance(refs, list) else []


def _tool_count(server: dict[str, object]) -> int:
    explicit = server.get("tool_count")
    if isinstance(explicit, int):
        return explicit
    tools = server.get("tools")
    return len(tools) if isinstance(tools, list) else 0


def _observed_flags(server: dict[str, object]) -> dict[str, object]:
    observed = server.get("observed")
    return observed if isinstance(observed, dict) else {}


def _security_warnings(server: dict[str, object]) -> list[str]:
    security = server.get("security")
    if not isinstance(security, dict):
        return []
    warnings = security.get("warnings")
    return [str(warning) for warning in warnings] if isinstance(warnings, list) else []


def _tool(tool: MCPTool) -> dict[str, object]:
    return {
        "name": sanitize_text(tool.name, max_len=160),
        "description": sanitize_text(tool.description, max_len=300) if tool.description else "",
    }


def _server(server: MCPServer) -> dict[str, object]:
    permission_profile = server.permission_profile
    return {
        "id": server.stable_id,
        "canonical_id": server.canonical_id,
        "fingerprint": server.fingerprint,
        "name": sanitize_text(server.name, max_len=160),
        "transport": _value(server.transport),
        "url": sanitize_url(server.url) if server.url else None,
        "command": sanitize_text(server.command, max_len=200),
        "args": sanitize_command_args(server.args),
        "config_path": _safe_path(server.config_path),
        "working_dir": _safe_path(server.working_dir),
        "auth_mode": server.auth_mode,
        "credential_refs": _credential_refs(server.credential_names),
        "tools": [_tool(tool) for tool in server.tools],
        "tool_count": len(server.tools),
        "resource_count": len(server.resources),
        "prompt_count": len(server.prompts),
        "package_count": len(server.packages),
        "registry": {
            "verified": bool(server.registry_verified),
            "id": sanitize_text(server.registry_id, max_len=200) if server.registry_id else None,
        },
        "security": {
            "blocked": bool(server.security_blocked),
            "warnings": sanitize_security_warnings(server.security_warnings),
            "privilege_level": permission_profile.privilege_level if permission_profile else "unknown",
        },
        "discovery": {
            "sources": sorted(set(server.discovery_sources)),
            "surface": sanitize_text(server.surface, max_len=80),
        },
    }


def _agent(agent: Agent) -> dict[str, object]:
    return {
        "id": agent.stable_id,
        "canonical_id": agent.canonical_id,
        "name": sanitize_text(agent.name, max_len=160),
        "agent_type": _value(agent.agent_type),
        "status": _value(agent.status),
        "source": sanitize_text(agent.source, max_len=120),
        "config_path": _safe_path(agent.config_path),
        "version": sanitize_text(agent.version, max_len=80) if agent.version else None,
        "discovered_at": agent.discovered_at,
        "last_seen": agent.last_seen,
        "mcp_server_ids": [server.stable_id for server in agent.mcp_servers],
    }


def _fleet_agent(agent: FleetAgent) -> dict[str, object]:
    return {
        "id": agent.agent_id,
        "canonical_id": agent.canonical_id,
        "name": sanitize_text(agent.name, max_len=160),
        "agent_type": sanitize_text(agent.agent_type, max_len=120),
        "status": _value(agent.lifecycle_state),
        "source_id": sanitize_text(agent.source_id, max_len=160) if agent.source_id else "",
        "owner": sanitize_text(agent.owner, max_len=160) if agent.owner else None,
        "environment": sanitize_text(agent.environment, max_len=120) if agent.environment else None,
        "tags": [sanitize_text(tag, max_len=80) for tag in agent.tags],
        "trust_score": agent.trust_score,
        "counts": {
            "mcp_servers": agent.server_count,
            "packages": agent.package_count,
            "credential_refs": agent.credential_count,
            "vulnerabilities": agent.vuln_count,
        },
        "config_path": _safe_path(agent.config_path),
        "last_discovery": agent.last_discovery,
        "last_scan": agent.last_scan,
        "updated_at": agent.updated_at,
    }


def _observed_server(observation: MCPObservation) -> dict[str, object]:
    return {
        "id": observation.server_stable_id,
        "canonical_id": observation.server_canonical_id,
        "fingerprint": observation.server_fingerprint,
        "name": sanitize_text(observation.server_name, max_len=160),
        "agent_name": sanitize_text(observation.agent_name, max_len=160),
        "transport": sanitize_text(observation.transport, max_len=80),
        "url": observation.url,
        "command": observation.command,
        "args": observation.args,
        "config_path": _safe_path(observation.config_path),
        "auth_mode": observation.auth_mode,
        "credential_refs": _credential_refs(observation.credential_env_vars),
        "security": {
            "blocked": bool(observation.security_blocked),
            "warnings": observation.security_warnings,
        },
        "observed": {
            "configured_locally": bool(observation.configured_locally),
            "fleet_present": bool(observation.fleet_present),
            "gateway_registered": bool(observation.gateway_registered),
            "runtime_observed": bool(observation.runtime_observed),
            "via": sorted(set(observation.observed_via)),
            "scopes": sorted(set(observation.observed_scopes)),
            "first_seen": observation.first_seen,
            "last_seen": observation.last_seen,
            "last_synced": observation.last_synced,
        },
    }


def _summary(agents: list[dict[str, object]], servers: list[dict[str, object]]) -> dict[str, int]:
    credential_refs = {
        str(ref.get("name")) for server in servers for ref in _credential_ref_rows(server) if isinstance(ref, dict) and ref.get("name")
    }
    runtime_observed = 0
    gateway_registered = 0
    for server in servers:
        observed = server.get("observed")
        if isinstance(observed, dict):
            runtime_observed += 1 if observed.get("runtime_observed") else 0
            gateway_registered += 1 if observed.get("gateway_registered") else 0
    return {
        "agents": len(agents),
        "mcp_servers": len(servers),
        "tools": sum(_tool_count(server) for server in servers),
        "credential_refs": len(credential_refs),
        "runtime_observed_servers": runtime_observed,
        "gateway_registered_servers": gateway_registered,
    }


def _visibility(agents: list[dict[str, object]], servers: list[dict[str, object]]) -> dict[str, object]:
    owners = {str(agent.get("owner")) for agent in agents if agent.get("owner")}
    unowned_agent_ids = [
        str(agent.get("id") or agent.get("canonical_id") or agent.get("name")) for agent in agents if not agent.get("owner")
    ]
    credential_refs = {
        str(ref.get("name")) for server in servers for ref in _credential_ref_rows(server) if isinstance(ref, dict) and ref.get("name")
    }
    risky_credential_refs = sorted(ref for ref in credential_refs if any(token in ref.lower() for token in _RISKY_CREDENTIAL_NAME_TOKENS))

    shadow_runtime_server_ids: list[str] = []
    untracked_runtime_server_ids: list[str] = []
    for server in servers:
        server_id = str(server.get("id") or server.get("canonical_id") or server.get("name") or "")
        observed = _observed_flags(server)
        runtime_observed = bool(observed.get("runtime_observed"))
        if runtime_observed and server_id and not observed.get("gateway_registered"):
            shadow_runtime_server_ids.append(server_id)
        if runtime_observed and server_id and not (observed.get("configured_locally") or observed.get("fleet_present")):
            untracked_runtime_server_ids.append(server_id)

    return {
        "owners": len(owners),
        "unowned_agents": len([agent_id for agent_id in unowned_agent_ids if agent_id]),
        "shadow_runtime_servers": len(shadow_runtime_server_ids),
        "untracked_runtime_servers": len(untracked_runtime_server_ids),
        "servers_with_warnings": sum(1 for server in servers if _security_warnings(server)),
        "risky_credential_refs": len(risky_credential_refs),
        "risk_signals": {
            "unowned_agent_ids": sorted(agent_id for agent_id in unowned_agent_ids if agent_id),
            "shadow_runtime_server_ids": sorted(shadow_runtime_server_ids),
            "untracked_runtime_server_ids": sorted(untracked_runtime_server_ids),
            "risky_credential_refs": risky_credential_refs,
        },
    }


def _blueprint_drift(agents: list[dict[str, object]], servers: list[dict[str, object]]) -> dict[str, object]:
    signals: list[dict[str, object]] = []

    for agent in agents:
        agent_id = str(agent.get("id") or agent.get("canonical_id") or agent.get("name") or "")
        if agent_id and not agent.get("owner"):
            signals.append(
                {
                    "kind": "unowned_agent",
                    "entity_id": agent_id,
                    "severity": "info",
                    "message": "Agent has no owner metadata in the current manifest.",
                }
            )

    for server in servers:
        server_id = str(server.get("id") or server.get("canonical_id") or server.get("name") or "")
        server_name = str(server.get("name") or server_id)
        observed = _observed_flags(server)
        runtime_observed = bool(observed.get("runtime_observed"))
        if runtime_observed and server_id and not observed.get("gateway_registered"):
            signals.append(
                {
                    "kind": "unregistered_runtime_server",
                    "entity_id": server_id,
                    "severity": "warning",
                    "message": f"{server_name} was observed at runtime but is not registered with the gateway.",
                }
            )
        if runtime_observed and server_id and not (observed.get("configured_locally") or observed.get("fleet_present")):
            signals.append(
                {
                    "kind": "untracked_runtime_server",
                    "entity_id": server_id,
                    "severity": "warning",
                    "message": f"{server_name} was observed at runtime without local or fleet inventory evidence.",
                }
            )
        warnings = _security_warnings(server)
        if server_id and warnings:
            signals.append(
                {
                    "kind": "server_security_warning",
                    "entity_id": server_id,
                    "severity": "warning",
                    "message": f"{server_name} has {len(warnings)} security warning(s).",
                }
            )

    warning_signals = [signal for signal in signals if signal.get("severity") != "info"]
    status = "not_observed" if not agents and not servers else "needs_review" if warning_signals else "aligned"
    return {
        "status": status,
        "mode": "observation_only",
        "fail_behavior": "report_only",
        "signal_count": len(signals),
        "signals": signals,
    }


def _node(node_id: str, entity_type: str, label: str, **attributes: object) -> dict[str, object]:
    return {
        "id": node_id,
        "entity_type": entity_type,
        "label": sanitize_text(label, max_len=180),
        "attributes": {key: value for key, value in attributes.items() if value not in (None, "", [])},
    }


def _edge(edge_id: str, source: str, target: str, relationship: str, **attributes: object) -> dict[str, object]:
    return {
        "id": edge_id,
        "source": source,
        "target": target,
        "relationship": relationship,
        "attributes": {key: value for key, value in attributes.items() if value not in (None, "", [])},
    }


def _graph(agents: list[dict[str, object]], servers: list[dict[str, object]]) -> dict[str, object]:
    nodes: dict[str, dict[str, object]] = {}
    edges: dict[str, dict[str, object]] = {}

    for agent in agents:
        agent_id = str(agent.get("id") or agent.get("canonical_id") or agent.get("name"))
        if not agent_id:
            continue
        nodes[agent_id] = _node(
            agent_id,
            "agent",
            str(agent.get("name") or agent_id),
            agent_type=agent.get("agent_type"),
            status=agent.get("status"),
            owner=agent.get("owner"),
            environment=agent.get("environment"),
        )
        if owner := agent.get("owner"):
            owner_id = f"user:{sanitize_text(str(owner), max_len=160)}"
            nodes[owner_id] = _node(owner_id, "user", str(owner), role="owner")
            edges[f"{owner_id}:owns:{agent_id}"] = _edge(
                f"{owner_id}:owns:{agent_id}",
                owner_id,
                agent_id,
                "owns",
                provenance="agent_manifest",
            )
        if environment := agent.get("environment"):
            environment_id = f"environment:{sanitize_text(str(environment), max_len=120)}"
            nodes[environment_id] = _node(environment_id, "environment", str(environment))
            edges[f"{agent_id}:part_of:{environment_id}"] = _edge(
                f"{agent_id}:part_of:{environment_id}",
                agent_id,
                environment_id,
                "part_of",
                provenance="agent_manifest",
            )

    agent_by_name = {
        str(agent.get("name")): str(agent.get("id") or agent.get("canonical_id") or agent.get("name"))
        for agent in agents
        if agent.get("name")
    }

    for server in servers:
        server_id = str(server.get("id") or server.get("canonical_id") or server.get("name"))
        if not server_id:
            continue
        nodes[server_id] = _node(
            server_id,
            "server",
            str(server.get("name") or server_id),
            transport=server.get("transport"),
            auth_mode=server.get("auth_mode"),
        )

        agent_name = str(server.get("agent_name") or "")
        linked_agent_ids: list[str] = []
        if agent_name and agent_name in agent_by_name:
            linked_agent_ids.append(agent_by_name[agent_name])
        for agent in agents:
            server_ids = agent.get("mcp_server_ids")
            if isinstance(server_ids, list) and server_id in {str(item) for item in server_ids}:
                linked_agent_ids.append(str(agent.get("id") or agent.get("canonical_id") or agent.get("name")))
        for agent_id in sorted(set(linked_agent_ids)):
            edges[f"{agent_id}:uses:{server_id}"] = _edge(f"{agent_id}:uses:{server_id}", agent_id, server_id, "uses")

        tools = server.get("tools")
        if isinstance(tools, list):
            for tool in tools:
                if not isinstance(tool, dict):
                    continue
                tool_name = str(tool.get("name") or "")
                if not tool_name:
                    continue
                tool_id = f"{server_id}:tool:{tool_name}"
                nodes[tool_id] = _node(tool_id, "tool", tool_name, server=server.get("name"))
                edges[f"{server_id}:provides_tool:{tool_id}"] = _edge(
                    f"{server_id}:provides_tool:{tool_id}",
                    server_id,
                    tool_id,
                    "provides_tool",
                )

        refs = server.get("credential_refs")
        if isinstance(refs, list):
            for ref in refs:
                if not isinstance(ref, dict):
                    continue
                ref_name = str(ref.get("name") or "")
                if not ref_name:
                    continue
                cred_id = f"credential:{ref_name}"
                nodes[cred_id] = _node(cred_id, "credential", ref_name, kind=ref.get("kind"))
                edges[f"{server_id}:exposes_cred:{cred_id}"] = _edge(
                    f"{server_id}:exposes_cred:{cred_id}",
                    server_id,
                    cred_id,
                    "exposes_cred",
                )

    return {
        "nodes": list(nodes.values()),
        "edges": list(edges.values()),
        "stats": {
            "nodes": len(nodes),
            "edges": len(edges),
            "relationships": list(AGENT_BOM_GRAPH_RELATIONSHIPS),
        },
    }


def _manifest(
    source: str,
    agents: list[dict[str, object]],
    servers: list[dict[str, object]],
    tenant_id: str | None = None,
) -> dict[str, object]:
    payload: dict[str, object] = {
        "schema_version": AGENT_BOM_MANIFEST_SCHEMA_VERSION,
        "generated_at": now_utc_iso(),
        "source": source,
        "summary": _summary(agents, servers),
        "visibility": _visibility(agents, servers),
        "blueprint_drift": _blueprint_drift(agents, servers),
        "agents": agents,
        "mcp_servers": servers,
        "graph": _graph(agents, servers),
        "boundaries": {
            "stores_credential_values": False,
            "stores_raw_prompts": False,
            "credential_value_policy": "redacted",
        },
    }
    if tenant_id is not None:
        payload["tenant_id"] = tenant_id
    return payload


def build_local_agent_manifest(
    agents: Iterable[Agent],
    *,
    source: str = "local-discovery",
    tenant_id: str | None = None,
) -> dict[str, object]:
    agent_list = list(agents)
    agent_rows = [_agent(agent) for agent in agent_list]
    server_rows = [_server(server) for agent in agent_list for server in agent.mcp_servers]
    return _manifest(source, agent_rows, server_rows, tenant_id)


def build_control_plane_agent_manifest(
    fleet_agents: Iterable[FleetAgent],
    observations: Iterable[MCPObservation],
    *,
    tenant_id: str,
) -> dict[str, object]:
    agent_rows = [_fleet_agent(agent) for agent in fleet_agents]
    server_rows = [_observed_server(observation) for observation in observations]
    return _manifest("control-plane", agent_rows, server_rows, tenant_id)


def assert_no_credential_values(payload: dict[str, Any]) -> None:
    """Guardrail used by tests and future exporters."""
    text = repr(payload).lower()
    forbidden_tokens = ("sk-", "secret=", "token=", "password=", "apikey=")
    if any(token in text for token in forbidden_tokens):
        raise ValueError("agent manifest contains credential-like values")
