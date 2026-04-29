"""Shared canonical inventory writer for operator-pull adapters."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from agent_bom.asset_provenance import sanitize_discovery_provenance
from agent_bom.cloud import provider_contracts
from agent_bom.inventory import _validate_inventory_payload
from agent_bom.mcp_blocklist import sanitize_security_intelligence_entry
from agent_bom.models import Agent, MCPServer, MCPTool, Package
from agent_bom.security import (
    sanitize_command_args,
    sanitize_env_vars,
    sanitize_security_warnings,
    sanitize_sensitive_payload,
    sanitize_text,
    sanitize_url,
)

SCHEMA_AGENT_TYPES = frozenset({"claude-desktop", "claude-code", "cursor", "windsurf", "cline", "custom"})
SCHEMA_TRANSPORTS = frozenset({"stdio", "sse", "streamable-http"})
SCHEMA_ECOSYSTEMS = frozenset({"npm", "pypi", "go", "cargo", "maven", "nuget", "hex", "pub", "unknown"})
DISCOVERY_METHODS = frozenset({"operator_pushed_inventory", "skill_invoked_pull"})


def provider_permissions_used(provider_name: str) -> list[str]:
    """Read declared provider permissions from the discovery contract."""
    try:
        providers = provider_contracts().get("providers", [])
    except Exception:  # noqa: BLE001
        return []
    provider: dict[str, Any] = next((item for item in providers if item.get("name") == provider_name), {})
    capabilities = provider.get("capabilities", {})
    permissions = capabilities.get("permissions_used", [])
    if not isinstance(permissions, list):
        return []
    return [str(permission) for permission in permissions]


def build_inventory_payload(
    agents: list[Agent],
    *,
    provider_name: str,
    source: str,
    collector: str,
    generated_at: str | None = None,
    permissions_used: list[str] | None = None,
    discovery_method: str = "operator_pushed_inventory",
) -> dict[str, Any]:
    """Build an inventory.schema.json-compatible payload from cloud agents."""
    if discovery_method not in DISCOVERY_METHODS:
        raise ValueError(f"Unsupported discovery method: {discovery_method}")
    permissions = permissions_used if permissions_used is not None else provider_permissions_used(provider_name)
    provenance = sanitize_discovery_provenance(
        {
            "source_type": discovery_method,
            "observed_via": [discovery_method, f"{provider_name}_sdk"],
            "source": source,
            "collector": collector,
            "provider": provider_name,
            "confidence": "high",
        }
    ) or {"source_type": discovery_method}
    payload = {
        "schema_version": "1",
        "source": source,
        "generated_at": generated_at or datetime.now(timezone.utc).isoformat(),
        "discovery_provenance": provenance,
        "agents": [
            _agent_to_inventory(
                agent,
                permissions_used=permissions,
                inherited_provenance=provenance,
            )
            for agent in agents
        ],
    }
    return _validate_inventory_payload(payload)


def _agent_to_inventory(
    agent: Agent,
    *,
    permissions_used: list[str],
    inherited_provenance: dict[str, Any],
) -> dict[str, Any]:
    metadata = _metadata_with_permissions(agent.metadata, permissions_used)
    provenance = _asset_provenance(getattr(agent, "discovery_provenance", None), metadata, inherited_provenance)
    agent_type = getattr(agent.agent_type, "value", str(agent.agent_type))
    if agent_type not in SCHEMA_AGENT_TYPES:
        agent_type = "custom"
    payload: dict[str, Any] = {
        "name": sanitize_text(agent.name, max_len=300),
        "agent_type": agent_type,
        "config_path": sanitize_text(agent.config_path, max_len=1000) if agent.config_path else "",
        "source": sanitize_text(agent.source or inherited_provenance.get("source") or "operator-pull", max_len=200),
        "mcp_servers": [_server_to_inventory(server, inherited_provenance=provenance) for server in agent.mcp_servers],
        "discovery_provenance": provenance,
    }
    if agent.version:
        payload["version"] = sanitize_text(agent.version, max_len=100)
    if metadata:
        payload["metadata"] = metadata
    if agent.discovered_at:
        payload["discovered_at"] = agent.discovered_at
    if agent.last_seen:
        payload["last_seen"] = agent.last_seen
    return payload


def _metadata_with_permissions(metadata: dict[str, Any], permissions_used: list[str]) -> dict[str, Any]:
    sanitized = sanitize_sensitive_payload(metadata or {})
    if not isinstance(sanitized, dict):
        sanitized = {}
    if permissions_used:
        sanitized["permissions_used"] = sorted(set(permissions_used))
    return sanitized


def _server_to_inventory(server: MCPServer, *, inherited_provenance: dict[str, Any]) -> dict[str, Any]:
    transport = getattr(server.transport, "value", str(server.transport or "stdio"))
    if transport not in SCHEMA_TRANSPORTS:
        transport = "stdio"
    provenance = sanitize_discovery_provenance(getattr(server, "discovery_provenance", None), defaults=inherited_provenance)
    payload: dict[str, Any] = {
        "name": sanitize_text(server.name, max_len=300),
        "command": sanitize_text(server.command, max_len=300),
        "args": sanitize_command_args(list(server.args or [])),
        "transport": transport,
        "env": sanitize_env_vars(dict(server.env or {})),
        "tools": [_tool_to_inventory(tool) for tool in server.tools],
        "packages": [
            _package_to_inventory(
                package,
                inherited_provenance=provenance or inherited_provenance,
            )
            for package in server.packages
        ],
        "security_blocked": bool(getattr(server, "security_blocked", False)),
        "security_warnings": sanitize_security_warnings(list(getattr(server, "security_warnings", []) or [])),
        "security_intelligence": [
            sanitize_security_intelligence_entry(item)
            for item in (getattr(server, "security_intelligence", []) or [])
            if isinstance(item, dict)
        ],
        "discovery_provenance": provenance,
    }
    if server.url:
        payload["url"] = sanitize_url(str(server.url))
    if server.mcp_version:
        payload["mcp_version"] = sanitize_text(server.mcp_version, max_len=80)
    if server.working_dir:
        payload["working_dir"] = sanitize_text(server.working_dir, max_len=1000)
    if server.config_path:
        payload["config_path"] = sanitize_text(server.config_path, max_len=1000)
    return {key: value for key, value in payload.items() if value not in (None, "", [], {})}


def _tool_to_inventory(tool: MCPTool) -> dict[str, Any]:
    payload: dict[str, Any] = {"name": sanitize_text(tool.name, max_len=300)}
    if tool.description:
        payload["description"] = sanitize_text(tool.description, max_len=1000)
    if tool.input_schema:
        sanitized_schema = sanitize_sensitive_payload(tool.input_schema)
        if isinstance(sanitized_schema, dict):
            payload["input_schema"] = sanitized_schema
    return payload


def _package_to_inventory(package: Package, *, inherited_provenance: dict[str, Any] | None = None) -> dict[str, Any]:
    payload = {
        "name": sanitize_text(package.name, max_len=300),
        "version": sanitize_text(package.version or "unknown", max_len=120) or "unknown",
    }
    ecosystem = sanitize_text(package.ecosystem or "unknown", max_len=60) or "unknown"
    if ecosystem in SCHEMA_ECOSYSTEMS:
        payload["ecosystem"] = ecosystem
    if package.purl:
        payload["purl"] = sanitize_text(package.purl, max_len=500)
    provenance = sanitize_discovery_provenance(getattr(package, "discovery_provenance", None), defaults=inherited_provenance)
    if provenance:
        payload["discovery_provenance"] = provenance
    return payload


def _asset_provenance(
    explicit: Any,
    metadata: dict[str, Any],
    inherited_provenance: dict[str, Any],
) -> dict[str, Any]:
    defaults = dict(inherited_provenance)
    cloud_origin = metadata.get("cloud_origin")
    if isinstance(cloud_origin, dict):
        defaults.update(
            {
                "provider": cloud_origin.get("provider") or defaults.get("provider"),
                "service": cloud_origin.get("service"),
                "resource_type": cloud_origin.get("resource_type"),
                "resource_id": cloud_origin.get("resource_id"),
                "resource_name": cloud_origin.get("resource_name"),
                "location": cloud_origin.get("location"),
            }
        )
    return sanitize_discovery_provenance(explicit, defaults=defaults) or inherited_provenance
