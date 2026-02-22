"""Smithery.ai registry integration — live lookup, risk enrichment, registry sync.

Extends agent-bom's bundled 112-server MCP registry with Smithery's 2,800+ servers.
Used as a fallback when a discovered MCP server is not in the local registry.

API docs: https://smithery.ai/docs/concepts/registry_search_servers
Requires: SMITHERY_API_KEY env var or --smithery-token flag.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
from dataclasses import dataclass, field
from pathlib import Path

from agent_bom.http_client import create_client, request_with_retry
from agent_bom.models import MCPServer, Package

logger = logging.getLogger(__name__)

# Smithery API endpoints
_API_BASE = "https://api.smithery.ai"
_REGISTRY_BASE = "https://registry.smithery.ai"

# Local registry path (for sync)
_REGISTRY_PATH = Path(__file__).parent / "mcp_registry.json"


def _get_token(token: str | None = None) -> str | None:
    """Resolve Smithery API token from arg or env."""
    return token or os.environ.get("SMITHERY_API_KEY")


@dataclass
class SmitheryServer:
    """A server entry from the Smithery registry."""

    qualified_name: str  # e.g. "exa/exa-search"
    display_name: str
    description: str = ""
    verified: bool = False
    use_count: int = 0
    remote: bool = False
    is_deployed: bool = False
    security_scan_passed: bool | None = None
    tools: list[dict] = field(default_factory=list)
    homepage: str = ""


@dataclass
class SmitherySearchResult:
    """Result of a Smithery registry search."""

    servers: list[SmitheryServer] = field(default_factory=list)
    total_count: int = 0
    error: str | None = None


@dataclass
class SmitherySyncResult:
    """Result of syncing Smithery data into local registry."""

    added: int = 0
    updated: int = 0
    skipped: int = 0
    total_fetched: int = 0
    details: list[dict] = field(default_factory=list)


# ─── API Client ──────────────────────────────────────────────────────────────


async def search_smithery(
    query: str,
    token: str | None = None,
    page: int = 1,
    page_size: int = 10,
) -> SmitherySearchResult:
    """Search Smithery registry for MCP servers.

    Args:
        query: Search term (server name, description, etc.)
        token: Smithery API key (falls back to SMITHERY_API_KEY env var)
        page: Page number (1-indexed)
        page_size: Results per page (1-100)

    Returns:
        SmitherySearchResult with matching servers.
    """
    api_key = _get_token(token)
    if not api_key:
        return SmitherySearchResult(error="No Smithery API key — set SMITHERY_API_KEY or use --smithery-token")

    headers = {"Authorization": f"Bearer {api_key}"}
    params = {"q": query, "page": page, "pageSize": page_size}

    async with create_client(timeout=15.0) as client:
        resp = await request_with_retry(
            client, "GET", f"{_API_BASE}/servers",
            headers=headers, params=params,
        )

        if resp is None:
            return SmitherySearchResult(error="Smithery API unreachable")
        if resp.status_code == 401:
            return SmitherySearchResult(error="Invalid Smithery API key")
        if resp.status_code != 200:
            return SmitherySearchResult(error=f"Smithery API error: HTTP {resp.status_code}")

        data = resp.json()
        servers = []
        for s in data.get("servers", []):
            servers.append(SmitheryServer(
                qualified_name=s.get("qualifiedName", ""),
                display_name=s.get("displayName", ""),
                description=s.get("description", ""),
                verified=s.get("verified", False),
                use_count=s.get("useCount", 0),
                remote=s.get("remote", False),
                is_deployed=s.get("isDeployed", False),
                homepage=s.get("homepage", ""),
            ))

        pagination = data.get("pagination", {})
        return SmitherySearchResult(
            servers=servers,
            total_count=pagination.get("totalCount", len(servers)),
        )


def search_smithery_sync(
    query: str,
    token: str | None = None,
    page: int = 1,
    page_size: int = 10,
) -> SmitherySearchResult:
    """Sync wrapper for search_smithery."""
    return asyncio.run(search_smithery(query, token, page, page_size))


async def get_smithery_server(
    qualified_name: str,
    token: str | None = None,
) -> SmitheryServer | None:
    """Get detailed info for a single Smithery server.

    Returns tools list and security scan status.
    """
    api_key = _get_token(token)
    if not api_key:
        logger.debug("No Smithery API key available")
        return None

    headers = {"Authorization": f"Bearer {api_key}"}

    async with create_client(timeout=15.0) as client:
        resp = await request_with_retry(
            client, "GET", f"{_REGISTRY_BASE}/servers/{qualified_name}",
            headers=headers,
        )

        if resp is None or resp.status_code != 200:
            return None

        data = resp.json()
        security = data.get("security", {})
        tools_raw = data.get("tools", [])

        return SmitheryServer(
            qualified_name=data.get("qualifiedName", qualified_name),
            display_name=data.get("displayName", ""),
            description=data.get("description", ""),
            verified=data.get("verified", False),
            use_count=data.get("useCount", 0),
            remote=data.get("remote", False),
            is_deployed=data.get("isDeployed", False),
            security_scan_passed=security.get("scanPassed"),
            tools=[{"name": t.get("name", ""), "description": t.get("description", "")} for t in tools_raw],
            homepage=data.get("homepage", ""),
        )


# ─── Registry Fallback Lookup ────────────────────────────────────────────────


async def smithery_lookup(
    server: MCPServer,
    token: str | None = None,
) -> list[Package]:
    """Look up an MCP server on Smithery as a registry fallback.

    Searches by server name, then enriches risk data from Smithery metadata.
    Returns a Package list compatible with the local registry fallback format.
    """
    api_key = _get_token(token)
    if not api_key:
        return []

    result = await search_smithery(server.name, token=api_key, page_size=5)
    if result.error or not result.servers:
        # Try with args too (e.g. package names in npx commands)
        for arg in server.args:
            if arg.startswith("-"):
                continue
            result = await search_smithery(arg, token=api_key, page_size=5)
            if not result.error and result.servers:
                break
        else:
            return []

    # Pick the best match
    best = result.servers[0]

    # Determine risk level from Smithery signals
    risk_level = "medium"  # default
    if best.security_scan_passed is False:
        risk_level = "critical"
    elif not best.verified:
        risk_level = "high"
    elif best.use_count > 1000 and best.verified:
        risk_level = "low"

    logger.info(
        "Smithery: resolved %s → %s (verified=%s, uses=%d)",
        server.name, best.display_name, best.verified, best.use_count,
    )

    return [Package(
        name=best.qualified_name,
        version="latest",
        ecosystem="smithery",
        purl=f"pkg:smithery/{best.qualified_name}",
        is_direct=True,
        resolved_from_registry=True,
        auto_risk_level=risk_level,
        auto_risk_justification=(
            f"Smithery: {'verified' if best.verified else 'unverified'}, "
            f"{best.use_count} installs"
            + (", security scan FAILED" if best.security_scan_passed is False else "")
        ),
    )]


def smithery_lookup_sync(
    server: MCPServer,
    token: str | None = None,
) -> list[Package]:
    """Sync wrapper for smithery_lookup."""
    return asyncio.run(smithery_lookup(server, token))


# ─── Registry Sync ───────────────────────────────────────────────────────────


async def sync_from_smithery(
    token: str | None = None,
    max_pages: int = 10,
    page_size: int = 50,
    dry_run: bool = False,
) -> SmitherySyncResult:
    """Bulk-import Smithery servers into the local MCP registry.

    Fetches servers from Smithery and adds entries that don't already exist
    in the local mcp_registry.json. Does not overwrite existing entries.

    Args:
        token: Smithery API key
        max_pages: Maximum pages to fetch
        page_size: Servers per page
        dry_run: Preview without writing

    Returns:
        SmitherySyncResult with counts.
    """
    api_key = _get_token(token)
    if not api_key:
        return SmitherySyncResult()

    # Load local registry
    try:
        local_data = json.loads(_REGISTRY_PATH.read_text())
    except Exception:
        local_data = {"servers": {}}

    local_servers = local_data.get("servers", {})
    local_names = {v.get("package", k).lower() for k, v in local_servers.items()}

    result = SmitherySyncResult()
    headers = {"Authorization": f"Bearer {api_key}"}

    async with create_client(timeout=30.0) as client:
        for page in range(1, max_pages + 1):
            resp = await request_with_retry(
                client, "GET", f"{_API_BASE}/servers",
                headers=headers,
                params={"page": page, "pageSize": page_size},
            )

            if resp is None or resp.status_code != 200:
                break

            data = resp.json()
            servers = data.get("servers", [])
            if not servers:
                break

            for s in servers:
                result.total_fetched += 1
                qn = s.get("qualifiedName", "")
                display = s.get("displayName", "")

                if not qn:
                    continue

                # Check if already in local registry
                if qn.lower() in local_names or display.lower() in local_names:
                    result.skipped += 1
                    continue

                # Map Smithery server to local registry format
                verified = s.get("verified", False)
                use_count = s.get("useCount", 0)
                remote = s.get("remote", False)

                # Infer risk level
                risk = "medium"
                if not verified:
                    risk = "high"
                elif use_count > 1000:
                    risk = "low"

                entry = {
                    "package": qn,
                    "ecosystem": "smithery",
                    "latest_version": "latest",
                    "description": s.get("description", "")[:200],
                    "name": display,
                    "category": "remote-mcp" if remote else "local-mcp",
                    "risk_level": risk,
                    "verified": verified,
                    "tools": [],
                    "credential_env_vars": [],
                    "command_patterns": [qn.split("/")[-1]] if "/" in qn else [qn],
                    "source_url": s.get("homepage", ""),
                    "smithery_use_count": use_count,
                    "smithery_remote": remote,
                    "smithery_deployed": s.get("isDeployed", False),
                }

                if not dry_run:
                    local_servers[qn] = entry

                result.added += 1
                result.details.append({
                    "server": qn,
                    "display_name": display,
                    "verified": verified,
                    "use_count": use_count,
                    "risk_level": risk,
                    "status": "added",
                })

            pagination = data.get("pagination", {})
            if page >= pagination.get("totalPages", 1):
                break

    # Write updated registry
    if not dry_run and result.added > 0:
        from datetime import datetime, timezone

        local_data["servers"] = local_servers
        local_data["_updated"] = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        local_data["_smithery_sync"] = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        _REGISTRY_PATH.write_text(json.dumps(local_data, indent=2) + "\n")

    return result


def sync_from_smithery_sync(
    token: str | None = None,
    max_pages: int = 10,
    page_size: int = 50,
    dry_run: bool = False,
) -> SmitherySyncResult:
    """Sync wrapper for sync_from_smithery."""
    return asyncio.run(sync_from_smithery(token, max_pages, page_size, dry_run))
