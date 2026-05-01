"""Glama.ai registry integration — live lookup and registry sync.

Extends agent-bom's bundled MCP registry with Glama's 18,000+ MCP servers.
Used as a fallback when a discovered MCP server is not in the local registry.

API: https://glama.ai/api/mcp/v1/servers (cursor-based pagination, no auth required)
"""

from __future__ import annotations

import asyncio
import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlparse

from agent_bom.http_client import create_client, request_with_retry
from agent_bom.mcp_registry_text import dumps_registry_json, normalize_registry_description
from agent_bom.models import Package

logger = logging.getLogger(__name__)

_API_BASE = "https://glama.ai/api/mcp/v1"


def _url_host_matches(url: str, domain: str) -> bool:
    """Check if a URL's hostname matches or is a subdomain of the given domain."""
    host = urlparse(url).hostname or ""
    return host == domain or host.endswith(f".{domain}")


_REGISTRY_PATH = Path(__file__).parent / "mcp_registry.json"


@dataclass
class GlamaServer:
    """A server entry from the Glama registry."""

    id: str
    name: str
    namespace: str = ""
    slug: str = ""
    description: str = ""
    repository_url: str = ""
    license: str = ""
    tools: list[dict] = field(default_factory=list)
    attributes: list[str] = field(default_factory=list)
    url: str = ""


@dataclass
class GlamaSearchResult:
    """Result of searching Glama registry."""

    servers: list[GlamaServer] = field(default_factory=list)
    has_next_page: bool = False
    end_cursor: str = ""
    total_fetched: int = 0


@dataclass
class GlamaSyncResult:
    """Result of syncing Glama data into local registry."""

    added: int = 0
    skipped: int = 0
    total_fetched: int = 0
    details: list[dict] = field(default_factory=list)


def _parse_server(raw: dict) -> GlamaServer:
    """Parse a raw Glama API server object."""
    repo = raw.get("repository") or {}
    license_info = raw.get("spdxLicense") or {}
    return GlamaServer(
        id=raw.get("id", ""),
        name=raw.get("name", ""),
        namespace=raw.get("namespace", ""),
        slug=raw.get("slug", ""),
        description=raw.get("description", ""),
        repository_url=repo.get("url", ""),
        license=license_info.get("name", ""),
        tools=raw.get("tools") or [],
        attributes=raw.get("attributes") or [],
        url=raw.get("url", ""),
    )


async def search_glama(
    query: str = "",
    limit: int = 10,
    cursor: str | None = None,
) -> GlamaSearchResult:
    """Search Glama registry for MCP servers.

    Args:
        query: Search term (empty for all servers)
        limit: Results per page (max ~100)
        cursor: Pagination cursor from previous response

    Returns:
        GlamaSearchResult with matching servers.
    """
    params: dict = {"limit": min(limit, 100)}
    if query:
        params["query"] = query
    if cursor:
        params["cursor"] = cursor

    async with create_client(timeout=30.0) as client:
        resp = await request_with_retry(
            client,
            "GET",
            f"{_API_BASE}/servers",
            params=params,
            headers={"Accept": "application/json"},
        )

    result = GlamaSearchResult()
    if resp is None or resp.status_code != 200:
        logger.warning("Glama API returned %s", resp.status_code if resp else "no response")
        return result

    data = resp.json()
    page_info = data.get("pageInfo", {})
    result.has_next_page = page_info.get("hasNextPage", False)
    result.end_cursor = page_info.get("endCursor", "")

    for raw in data.get("servers", []):
        result.servers.append(_parse_server(raw))
        result.total_fetched += 1

    return result


async def glama_lookup(server_name: str) -> list[Package]:
    """Look up a server on Glama for fallback package resolution.

    Args:
        server_name: Server name or slug to search for.

    Returns:
        List of Package objects if found.
    """
    result = await search_glama(query=server_name, limit=5)
    packages = []

    for s in result.servers:
        if s.name.lower() == server_name.lower() or s.slug == server_name.lower():
            # Try to infer ecosystem from repository URL
            ecosystem = "npm"  # default for MCP servers
            if _url_host_matches(s.repository_url.lower(), "pypi.org") or "python" in s.description.lower():
                ecosystem = "pypi"

            pkg_name = f"{s.namespace}/{s.slug}" if s.namespace else s.slug
            packages.append(
                Package(
                    name=pkg_name,
                    version="latest",
                    ecosystem=ecosystem,
                )
            )
    return packages


async def sync_from_glama(
    max_pages: int = 10,
    page_size: int = 100,
    dry_run: bool = False,
) -> GlamaSyncResult:
    """Bulk-import Glama servers into the local MCP registry.

    Fetches servers from Glama and adds entries that don't already exist
    in the local mcp_registry.json. No authentication required.

    Args:
        max_pages: Maximum pages to fetch
        page_size: Servers per page (max 100)
        dry_run: Preview without writing

    Returns:
        GlamaSyncResult with counts.
    """
    # Load local registry
    try:
        local_data = json.loads(_REGISTRY_PATH.read_text())
    except (json.JSONDecodeError, OSError):
        local_data = {"servers": {}}

    local_servers = local_data.get("servers", {})
    local_names = {v.get("package", k).lower() for k, v in local_servers.items()}
    # Also match by slug/name
    local_names.update(k.lower() for k in local_servers)

    result = GlamaSyncResult()
    cursor = None

    async with create_client(timeout=30.0) as client:
        for page in range(max_pages):
            params: dict = {"limit": min(page_size, 100)}
            if cursor:
                params["cursor"] = cursor

            resp = await request_with_retry(
                client,
                "GET",
                f"{_API_BASE}/servers",
                params=params,
                headers={"Accept": "application/json"},
            )

            if resp is None or resp.status_code != 200:
                logger.warning("Glama API page %d failed: %s", page + 1, resp.status_code if resp else "timeout")
                break

            data = resp.json()
            servers = data.get("servers", [])
            page_info = data.get("pageInfo", {})

            if not servers:
                break

            for raw in servers:
                result.total_fetched += 1
                server = _parse_server(raw)

                if not server.name:
                    continue

                # Check if already in local registry (by name, slug, or namespace/slug)
                check_names = {
                    server.name.lower(),
                    server.slug.lower(),
                    f"{server.namespace}/{server.slug}".lower(),
                }
                if check_names & local_names:
                    result.skipped += 1
                    continue

                # Infer ecosystem from repo URL (use parsed hostname, not substring)
                ecosystem = "npm"  # default
                repo_url = server.repository_url.lower()
                if _url_host_matches(repo_url, "pypi.org") or "python" in server.description.lower()[:200]:
                    ecosystem = "pypi"
                elif _url_host_matches(repo_url, "crates.io"):
                    ecosystem = "cargo"

                # Classify risk level from tools
                risk = "medium"
                tool_names = [t.get("name", "").lower() for t in server.tools]
                dangerous_tools = {"exec", "shell", "run_command", "execute", "eval"}
                if dangerous_tools & set(tool_names):
                    risk = "high"
                elif len(server.tools) == 0:
                    risk = "medium"  # unknown tools = medium risk

                key = f"{server.namespace}/{server.slug}" if server.namespace else server.slug
                entry = {
                    "ecosystem": ecosystem,
                    "package": key,
                    "description": normalize_registry_description(server.description),
                    "risk_level": risk,
                    "tools": [t.get("name", "") for t in server.tools[:20]],
                    "repository": server.repository_url,
                    "license": server.license,
                    "source": "glama",
                    "glama_id": server.id,
                    "glama_url": server.url,
                    "auto_enriched": True,
                }

                if not dry_run:
                    local_servers[key] = entry
                    local_names.add(key.lower())

                result.added += 1
                result.details.append({"server": key, "name": server.name})

            # Cursor-based pagination
            if not page_info.get("hasNextPage", False):
                break
            cursor = page_info.get("endCursor")
            if not cursor:
                break

    # Write updated registry
    if not dry_run and result.added > 0:
        from datetime import datetime, timezone

        local_data["servers"] = local_servers
        local_data["_updated"] = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        local_data["_total_servers"] = len(local_servers)
        _REGISTRY_PATH.write_text(dumps_registry_json(local_data), encoding="utf-8")
        logger.info("Added %d Glama servers to registry", result.added)

    return result


def sync_from_glama_sync(
    max_pages: int = 10,
    page_size: int = 100,
    dry_run: bool = False,
) -> GlamaSyncResult:
    """Synchronous wrapper for sync_from_glama."""
    return asyncio.run(sync_from_glama(max_pages=max_pages, page_size=page_size, dry_run=dry_run))
