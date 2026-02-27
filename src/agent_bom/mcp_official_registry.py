"""Official MCP Registry integration — lookup, sync, enrichment.

Queries the canonical MCP server registry at registry.modelcontextprotocol.io.
No authentication required.

API docs: https://registry.modelcontextprotocol.io/docs
"""

from __future__ import annotations

import asyncio
import json
import logging
from dataclasses import dataclass, field
from pathlib import Path

from agent_bom.http_client import create_client, request_with_retry
from agent_bom.models import MCPServer, Package

logger = logging.getLogger(__name__)

_API_BASE = "https://registry.modelcontextprotocol.io"
_REGISTRY_PATH = Path(__file__).parent / "mcp_registry.json"


@dataclass
class OfficialRegistryServer:
    """A server entry from the Official MCP Registry."""

    qualified_name: str
    description: str = ""
    version: str = ""
    repository_url: str = ""
    packages: list[dict] = field(default_factory=list)
    status: str = "active"


@dataclass
class OfficialRegistrySearchResult:
    """Result of an Official MCP Registry search."""

    servers: list[OfficialRegistryServer] = field(default_factory=list)
    total_count: int = 0
    next_cursor: str | None = None
    error: str | None = None


@dataclass
class OfficialRegistrySyncResult:
    """Result of syncing Official MCP Registry data into local registry."""

    added: int = 0
    skipped: int = 0
    total_fetched: int = 0
    details: list[dict] = field(default_factory=list)


# ─── API Client ──────────────────────────────────────────────────────────────


async def search_official_registry(
    query: str,
    limit: int = 10,
    cursor: str | None = None,
) -> OfficialRegistrySearchResult:
    """Search the Official MCP Registry for servers.

    Args:
        query: Search term (server name, description, etc.)
        limit: Maximum results to return (1-100)
        cursor: Pagination cursor from previous response

    Returns:
        OfficialRegistrySearchResult with matching servers.
    """
    params: dict = {"search": query, "limit": min(limit, 100)}
    if cursor:
        params["cursor"] = cursor

    async with create_client(timeout=15.0) as client:
        resp = await request_with_retry(
            client,
            "GET",
            f"{_API_BASE}/v0/servers",
            params=params,
        )

        if resp is None:
            return OfficialRegistrySearchResult(error="Official MCP Registry unreachable")
        if resp.status_code != 200:
            return OfficialRegistrySearchResult(error=f"Registry API error: HTTP {resp.status_code}")

        data = resp.json()
        servers = []
        for entry in data.get("servers", []):
            s = entry.get("server", entry)
            servers.append(
                OfficialRegistryServer(
                    qualified_name=s.get("name", s.get("qualifiedName", "")),
                    description=s.get("description", ""),
                    version=s.get("version", ""),
                    repository_url=s.get("repository", {}).get("url", "") if isinstance(s.get("repository"), dict) else "",
                    packages=s.get("packages", []),
                    status=entry.get("_meta", {}).get("status", "active") if "_meta" in entry else "active",
                )
            )

        metadata = data.get("metadata", {})
        return OfficialRegistrySearchResult(
            servers=servers,
            total_count=metadata.get("count", len(servers)),
            next_cursor=metadata.get("nextCursor"),
        )


def search_official_registry_sync(
    query: str,
    limit: int = 10,
    cursor: str | None = None,
) -> OfficialRegistrySearchResult:
    """Sync wrapper for search_official_registry."""
    return asyncio.run(search_official_registry(query, limit, cursor))


# ─── Registry Fallback Lookup ────────────────────────────────────────────────


async def official_registry_lookup(
    server: MCPServer,
) -> list[Package]:
    """Look up an MCP server on the Official MCP Registry as a fallback.

    Searches by server name, then by args. Returns a Package list compatible
    with the local registry fallback format.
    """
    result = await search_official_registry(server.name, limit=5)
    if result.error or not result.servers:
        for arg in server.args:
            if arg.startswith("-"):
                continue
            result = await search_official_registry(arg, limit=5)
            if not result.error and result.servers:
                break
        else:
            return []

    best = result.servers[0]

    logger.info(
        "Official MCP Registry: resolved %s → %s (version=%s)",
        server.name,
        best.qualified_name,
        best.version,
    )

    return [
        Package(
            name=best.qualified_name,
            version=best.version or "latest",
            ecosystem="mcp-registry",
            purl=f"pkg:mcp/{best.qualified_name}@{best.version or 'latest'}",
            is_direct=True,
            resolved_from_registry=True,
            registry_version=best.version or "latest",
            version_source="registry_fallback",
            auto_risk_level="medium",
            auto_risk_justification=f"Official MCP Registry: {best.qualified_name}",
        )
    ]


def official_registry_lookup_sync(server: MCPServer) -> list[Package]:
    """Sync wrapper for official_registry_lookup."""
    return asyncio.run(official_registry_lookup(server))


# ─── Registry Sync ───────────────────────────────────────────────────────────

_GENERIC_SEGMENTS = frozenset({"server", "mcp", "main", "index", "app", "src"})


def _build_command_patterns(qualified_name: str) -> list[str]:
    """Build command_patterns for a registry entry.

    Always includes the full qualified name. If the name contains '/' and
    the last segment is specific enough, include it too.
    """
    patterns = [qualified_name]
    if "/" in qualified_name:
        last = qualified_name.split("/")[-1]
        if last.lower() not in _GENERIC_SEGMENTS and len(last) > 3:
            patterns.append(last)
    return patterns


async def sync_from_official_registry(
    max_pages: int = 10,
    page_size: int = 100,
    dry_run: bool = False,
) -> OfficialRegistrySyncResult:
    """Bulk-import Official MCP Registry servers into the local registry.

    Fetches servers and adds entries that don't already exist in the local
    mcp_registry.json. Does not overwrite existing entries.
    """
    try:
        local_data = json.loads(_REGISTRY_PATH.read_text())
    except Exception:
        local_data = {"servers": {}}

    local_servers = local_data.get("servers", {})
    local_names = {v.get("package", k).lower() for k, v in local_servers.items()}

    result = OfficialRegistrySyncResult()
    cursor = None

    async with create_client(timeout=30.0) as client:
        for _page in range(max_pages):
            params: dict = {"limit": page_size}
            if cursor:
                params["cursor"] = cursor

            resp = await request_with_retry(
                client,
                "GET",
                f"{_API_BASE}/v0/servers",
                params=params,
            )

            if resp is None or resp.status_code != 200:
                break

            data = resp.json()
            entries = data.get("servers", [])
            if not entries:
                break

            for entry in entries:
                result.total_fetched += 1
                s = entry.get("server", entry)
                qn = s.get("name", s.get("qualifiedName", ""))

                if not qn:
                    continue

                if qn.lower() in local_names:
                    result.skipped += 1
                    continue

                # Extract tools and credentials from the entry
                tools_data = s.get("tools", [])
                tool_names = [(t.get("name", "") if isinstance(t, dict) else str(t)) for t in tools_data] if tools_data else []
                cred_vars = s.get("credential_env_vars", []) or []

                # Auto-classify risk level based on tool capabilities
                from agent_bom.permissions import _infer_category, classify_risk_level

                risk = classify_risk_level(tool_names, cred_vars)
                category = _infer_category(qn, (s.get("description", "") or ""))

                reg_entry = {
                    "package": qn,
                    "ecosystem": "mcp-registry",
                    "latest_version": s.get("version", "latest"),
                    "description": (s.get("description", "") or "")[:200],
                    "name": qn,
                    "category": category,
                    "risk_level": risk,
                    "verified": True,
                    "tools": tool_names,
                    "credential_env_vars": cred_vars,
                    "command_patterns": _build_command_patterns(qn),
                    "source_url": s.get("repository", {}).get("url", "") if isinstance(s.get("repository"), dict) else "",
                    "auto_enriched": True,
                }

                if not dry_run:
                    local_servers[qn] = reg_entry

                result.added += 1
                result.details.append(
                    {
                        "server": qn,
                        "version": s.get("version", ""),
                        "status": "added",
                    }
                )

            metadata = data.get("metadata", {})
            cursor = metadata.get("nextCursor")
            if not cursor:
                break

    if not dry_run and result.added > 0:
        from datetime import datetime, timezone

        local_data["servers"] = local_servers
        local_data["_updated"] = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        local_data["_mcp_registry_sync"] = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        _REGISTRY_PATH.write_text(json.dumps(local_data, indent=2) + "\n")

    return result


def sync_from_official_registry_sync(
    max_pages: int = 10,
    page_size: int = 100,
    dry_run: bool = False,
) -> OfficialRegistrySyncResult:
    """Sync wrapper for sync_from_official_registry."""
    return asyncio.run(sync_from_official_registry(max_pages, page_size, dry_run))
