"""MCP registry, connectors, and SIEM format endpoints."""

from __future__ import annotations

import functools
import re as _re
from pathlib import Path as _Path

from fastapi import APIRouter, HTTPException

from agent_bom.security import sanitize_error

router = APIRouter()


# ─── MCP Registry helpers ────────────────────────────────────────────────────


def _derive_name(key: str) -> str:
    """Derive a human-readable name from a registry key."""
    name = _re.sub(r"^@[^/]+/", "", key)
    for prefix in ("mcp-server-", "server-", "mcp-"):
        if name.startswith(prefix):
            name = name[len(prefix) :]
            break
    return name.replace("-", " ").title()


def _infer_publisher(key: str) -> str:
    """Infer publisher from a registry key."""
    m = _re.match(r"^@([^/]+)/", key)
    if m:
        return m.group(1)
    return key.split("-")[0] if "-" in key else key


@functools.lru_cache(maxsize=1)
def _load_registry() -> list[dict]:
    """Load the bundled MCP registry JSON (cached after first load)."""
    import json as _json

    registry_path = _Path(__file__).parent.parent / "mcp_registry.json"
    if not registry_path.exists():
        return []
    try:
        raw = _json.loads(registry_path.read_text())
    except (_json.JSONDecodeError, OSError):
        return []
    servers_dict = raw.get("servers", {})
    result = []
    for key, entry in servers_dict.items():
        result.append(
            {
                "id": key,
                "name": entry.get("name", _derive_name(key)),
                "publisher": _infer_publisher(key),
                "verified": entry.get("verified", False),
                "transport": "stdio",
                "risk_level": entry.get("risk_level", "low"),
                "packages": [{"name": entry["package"], "ecosystem": entry["ecosystem"]}] if entry.get("package") else [],
                "source_url": entry.get("source_url", ""),
                "description": entry.get("description"),
                "sigstore_bundle": None,
                "tools": entry.get("tools", []),
                "credential_env_vars": entry.get("credential_env_vars", []),
                "category": entry.get("category"),
                "license": entry.get("license"),
                "latest_version": entry.get("latest_version"),
                "known_cves": entry.get("known_cves", []),
                "command_patterns": entry.get("command_patterns", []),
                "risk_justification": entry.get("risk_justification"),
            }
        )
    return result


# ─── Connectors ──────────────────────────────────────────────────────────────


@router.get("/v1/connectors", tags=["connectors"])
async def list_available_connectors() -> dict:
    """List available SaaS connectors for AI agent discovery."""
    from agent_bom.connectors import list_connectors

    return {"connectors": list_connectors()}


@router.get("/v1/connectors/{name}/health", tags=["connectors"])
async def connector_health(name: str) -> dict:
    """Check connectivity for a SaaS connector."""
    try:
        from agent_bom.connectors import check_connector_health

        status = check_connector_health(name)
        return {"connector": status.connector, "state": status.state.value, "message": status.message, "api_version": status.api_version}
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=sanitize_error(str(exc))) from exc


# ─── Registry ────────────────────────────────────────────────────────────────


@router.get("/v1/registry", tags=["registry"])
async def list_registry() -> dict:
    """List all known MCP servers from the agent-bom registry."""
    servers = _load_registry()
    return {"servers": servers, "count": len(servers)}


@router.get("/v1/registry/{server_id:path}", tags=["registry"])
async def get_registry_server(server_id: str) -> dict:
    """Get a single MCP server entry by ID."""
    servers = _load_registry()
    for server in servers:
        if server.get("id") == server_id:
            return server
    raise HTTPException(status_code=404, detail=f"Registry entry '{server_id}' not found")


# ─── SIEM Formats ────────────────────────────────────────────────────────────


@router.get("/v1/siem/formats", tags=["siem"])
async def siem_formats():
    """List supported SIEM event formats."""
    from agent_bom.siem import list_formats

    return {"formats": list_formats()}
