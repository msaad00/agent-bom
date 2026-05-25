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
from datetime import datetime, timezone
from pathlib import Path

from agent_bom.http_client import create_client, request_with_retry
from agent_bom.mcp_registry_text import dumps_registry_json, normalize_registry_description
from agent_bom.models import MCPServer, Package

logger = logging.getLogger(__name__)

_API_BASE = "https://registry.modelcontextprotocol.io"
_API_SERVERS_URL = f"{_API_BASE}/v0/servers"
_LEGACY_GITHUB_REGISTRY_URLS = (
    "https://raw.githubusercontent.com/modelcontextprotocol/servers/main/scripts/servers.json",
    "https://raw.githubusercontent.com/modelcontextprotocol/servers/main/servers.json",
)
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
    source: str = "mcp-official"
    source_url: str = _API_SERVERS_URL
    fallback_used: bool = False
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


def _utc_date() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")


def _utc_timestamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _load_local_registry() -> dict:
    try:
        return json.loads(_REGISTRY_PATH.read_text(encoding="utf-8"))
    except Exception as exc:  # noqa: BLE001
        logger.warning("Could not load local MCP registry %s: %s — defaulting to empty", _REGISTRY_PATH, exc)
        return {"servers": {}}


def _infer_raw_github_ecosystem(name: str) -> str:
    if name.startswith("@"):
        return "npm"
    if "/" in name and not name.startswith("io."):
        return "mcp-registry"
    if "-" in name:
        return "npm"
    return "pypi"


def _raw_registry_entries(upstream: object) -> list[dict]:
    if isinstance(upstream, list):
        return [entry for entry in upstream if isinstance(entry, dict)]
    if isinstance(upstream, dict):
        servers = upstream.get("servers", [])
        return [entry for entry in servers if isinstance(entry, dict)]
    return []


async def sync_from_official_registry(
    max_pages: int = 10,
    page_size: int = 100,
    dry_run: bool = False,
) -> OfficialRegistrySyncResult:
    """Bulk-import Official MCP Registry servers into the local registry.

    Fetches servers and adds entries that don't already exist in the local
    mcp_registry.json. Does not overwrite existing entries.
    """
    local_data = _load_local_registry()

    local_servers = local_data.get("servers", {})
    local_names = {v.get("package", k).lower() for k, v in local_servers.items()}

    result = OfficialRegistrySyncResult(source="mcp-official", source_url=_API_SERVERS_URL, fallback_used=False)
    cursor = None
    fetched_at = _utc_timestamp()

    async with create_client(timeout=30.0) as client:
        for _page in range(max_pages):
            params: dict = {"limit": page_size}
            if cursor:
                params["cursor"] = cursor

            resp = await request_with_retry(
                client,
                "GET",
                _API_SERVERS_URL,
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
                    "description": normalize_registry_description(s.get("description", "")),
                    "name": qn,
                    "category": category,
                    "risk_level": risk,
                    "verified": True,
                    "tools": tool_names,
                    "credential_env_vars": cred_vars,
                    "command_patterns": _build_command_patterns(qn),
                    "source_url": s.get("repository", {}).get("url", "") if isinstance(s.get("repository"), dict) else "",
                    "source": "mcp-official",
                    "source_fetched_at": fetched_at,
                    "registry_source_url": _API_SERVERS_URL,
                    "version_source": "official-registry",
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
        local_data["servers"] = local_servers
        local_data["_updated"] = _utc_date()
        local_data["_mcp_registry_sync"] = _utc_timestamp()
        local_data["_mcp_registry_sync_source"] = result.source
        _REGISTRY_PATH.write_text(dumps_registry_json(local_data), encoding="utf-8")

    return result


async def sync_from_legacy_github_registry(
    *,
    urls: tuple[str, ...] = _LEGACY_GITHUB_REGISTRY_URLS,
    dry_run: bool = False,
) -> OfficialRegistrySyncResult:
    """Fallback import from legacy raw GitHub MCP server lists.

    This path exists only for continuity when the Official MCP Registry API is
    unavailable. Entries are explicitly labeled as fallback-sourced so the
    bundled registry does not overclaim official API provenance.
    """
    local_data = _load_local_registry()
    local_servers = local_data.get("servers", {})
    local_names = {v.get("package", k).lower() for k, v in local_servers.items()}
    fetched_at = _utc_timestamp()
    result = OfficialRegistrySyncResult(
        source="mcp-official-github-fallback",
        source_url="",
        fallback_used=True,
    )

    async with create_client(timeout=30.0) as client:
        for url in urls:
            resp = await request_with_retry(client, "GET", url)
            if resp is None or resp.status_code != 200:
                continue

            result.source_url = url
            for entry in _raw_registry_entries(resp.json()):
                name = entry.get("package") or entry.get("name", "")
                if not name:
                    continue
                result.total_fetched += 1
                if name.lower() in local_names:
                    result.skipped += 1
                    continue

                reg_entry = {
                    "ecosystem": _infer_raw_github_ecosystem(name),
                    "package": name,
                    "description": normalize_registry_description(entry.get("description", "")),
                    "command_patterns": _build_command_patterns(name),
                    "category": entry.get("category", "uncategorized"),
                    "source": result.source,
                    "source_url": url,
                    "source_fetched_at": fetched_at,
                    "version_source": "legacy-github-fallback",
                }
                if not dry_run:
                    local_servers[name] = reg_entry
                result.added += 1
                result.details.append({"server": name, "status": "added", "source": result.source})

            break

    if not dry_run and result.added > 0:
        local_data["servers"] = local_servers
        local_data["_updated"] = _utc_date()
        local_data["_mcp_registry_sync"] = _utc_timestamp()
        local_data["_mcp_registry_sync_source"] = result.source
        _REGISTRY_PATH.write_text(dumps_registry_json(local_data), encoding="utf-8")

    return result


def sync_from_official_registry_sync(
    max_pages: int = 10,
    page_size: int = 100,
    dry_run: bool = False,
) -> OfficialRegistrySyncResult:
    """Sync wrapper for sync_from_official_registry."""
    return asyncio.run(sync_from_official_registry(max_pages, page_size, dry_run))


def sync_from_legacy_github_registry_sync(
    *,
    urls: tuple[str, ...] = _LEGACY_GITHUB_REGISTRY_URLS,
    dry_run: bool = False,
) -> OfficialRegistrySyncResult:
    """Sync wrapper for sync_from_legacy_github_registry."""
    return asyncio.run(sync_from_legacy_github_registry(urls=urls, dry_run=dry_run))
