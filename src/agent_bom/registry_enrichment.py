"""MCP Registry Enrichment — aggregate data from Smithery, Docker Hub, GitHub.

Fetches MCP server metadata from public registries and enriches our local
registry with adoption metrics, freshness data, and cross-reference flags.

Sources:
- Smithery (registry.smithery.ai) — useCount, tools, verified status
- Docker Hub (hub.docker.com) — pull counts for official mcp/ namespace
- GitHub (api.github.com) — stars, last push, license for mcp-server repos

Usage::

    from agent_bom.registry_enrichment import enrich_registry
    stats = enrich_registry()  # updates mcp_registry.json in-place
    summary = f"Enriched {stats['total']} servers from {stats['sources']} sources"
"""

from __future__ import annotations

import json
import logging
import time
from pathlib import Path
from typing import Any

import httpx

from agent_bom.mcp_registry_text import normalize_registry_description

_logger = logging.getLogger(__name__)

# Registry file path
_REGISTRY_PATH = Path(__file__).parent / "mcp_registry.json"

# Smithery public API
_SMITHERY_API = "https://registry.smithery.ai/servers"
_SMITHERY_PAGE_SIZE = 100

# Docker Hub API (official mcp/ namespace)
_DOCKER_API = "https://hub.docker.com/v2/namespaces/mcp/repositories"

# GitHub search API
_GITHUB_SEARCH = "https://api.github.com/search/repositories"


def _fetch_smithery(max_pages: int = 40) -> dict[str, dict[str, Any]]:
    """Fetch all servers from Smithery registry API.

    Returns dict keyed by qualified name with useCount, tools, verified.
    """
    servers: dict[str, dict[str, Any]] = {}
    page = 1

    with httpx.Client(timeout=15, follow_redirects=True) as client:
        while page <= max_pages:
            try:
                resp = client.get(
                    _SMITHERY_API,
                    params={"pageSize": _SMITHERY_PAGE_SIZE, "page": page},
                )
                resp.raise_for_status()
                data = resp.json()
            except Exception as exc:
                _logger.warning("Smithery page %d failed: %s", page, exc)
                break

            items = data.get("servers") or data.get("items") or data.get("results") or []
            if isinstance(data, list):
                items = data
            if not items:
                break

            for srv in items:
                name = srv.get("qualifiedName") or srv.get("name", "")
                if not name:
                    continue
                servers[name] = {
                    "smithery_use_count": srv.get("useCount", 0),
                    "smithery_verified": srv.get("verified", False),
                    "smithery_display_name": srv.get("displayName", ""),
                    "smithery_description": normalize_registry_description(srv.get("description", "")),
                    "smithery_remote": srv.get("remote", False),
                    "smithery_homepage": srv.get("homepage", ""),
                    "smithery_created_at": srv.get("createdAt", ""),
                }

            # Check if there are more pages
            total = data.get("totalCount") or data.get("total") or 0
            if page * _SMITHERY_PAGE_SIZE >= total or len(items) < _SMITHERY_PAGE_SIZE:
                break
            page += 1
            time.sleep(0.5)  # Be respectful

    _logger.info("Smithery: fetched %d servers", len(servers))
    return servers


def _fetch_docker_hub(max_pages: int = 5) -> dict[str, dict[str, Any]]:
    """Fetch official MCP Docker images from hub.docker.com/mcp namespace.

    Returns dict keyed by image name with pull_count, last_updated.
    """
    images: dict[str, dict[str, Any]] = {}

    with httpx.Client(timeout=15, follow_redirects=True) as client:
        url: str | None = _DOCKER_API
        page = 0
        while url and page < max_pages:
            try:
                resp = client.get(url, params={"page_size": 100} if page == 0 else {})
                resp.raise_for_status()
                data = resp.json()
            except Exception as exc:
                _logger.warning("Docker Hub page %d failed: %s", page, exc)
                break

            for img in data.get("results", []):
                name = f"mcp/{img['name']}"
                images[name] = {
                    "docker_pull_count": img.get("pull_count", 0),
                    "docker_star_count": img.get("star_count", 0),
                    "docker_last_updated": img.get("last_updated", ""),
                    "docker_description": normalize_registry_description(img.get("description", "")),
                }

            url = data.get("next")
            page += 1
            time.sleep(0.3)

    _logger.info("Docker Hub: fetched %d MCP images", len(images))
    return images


def _fetch_github(max_results: int = 1000) -> dict[str, dict[str, Any]]:
    """Fetch top mcp-server repos from GitHub.

    Returns dict keyed by full_name with stars, last push, license.
    """
    repos: dict[str, dict[str, Any]] = {}
    per_page = 100
    pages = min(max_results // per_page, 10)  # GitHub limits to 1000 results

    with httpx.Client(timeout=15, follow_redirects=True) as client:
        for page in range(1, pages + 1):
            try:
                resp = client.get(
                    _GITHUB_SEARCH,
                    params={
                        "q": "topic:mcp-server",
                        "sort": "stars",
                        "order": "desc",
                        "per_page": per_page,
                        "page": page,
                    },
                    headers={"Accept": "application/vnd.github+json"},
                )
                resp.raise_for_status()
                data = resp.json()
            except Exception as exc:
                _logger.warning("GitHub page %d failed: %s", page, exc)
                break

            for repo in data.get("items", []):
                name = repo.get("full_name", "")
                repos[name] = {
                    "github_stars": repo.get("stargazers_count", 0),
                    "github_forks": repo.get("forks_count", 0),
                    "github_last_push": repo.get("pushed_at", ""),
                    "github_language": repo.get("language", ""),
                    "github_license": (repo.get("license") or {}).get("spdx_id", ""),
                    "github_description": normalize_registry_description(repo.get("description", "")),
                    "github_archived": repo.get("archived", False),
                    "github_topics": repo.get("topics", []),
                }

            if len(data.get("items", [])) < per_page:
                break
            time.sleep(2)  # GitHub search rate limit: 30/min

    _logger.info("GitHub: fetched %d mcp-server repos", len(repos))
    return repos


def _flag_risks(server: dict[str, Any]) -> list[str]:
    """Flag risk indicators for a server entry."""
    flags: list[str] = []

    # Abandoned: no GitHub push in 6+ months
    last_push = server.get("github_last_push", "")
    if last_push:
        from datetime import datetime, timezone

        try:
            push_dt = datetime.fromisoformat(last_push.replace("Z", "+00:00"))
            age_days = (datetime.now(timezone.utc) - push_dt).days
            if age_days > 180:
                flags.append(f"abandoned ({age_days}d since last push)")
        except (ValueError, TypeError):
            pass

    # Archived on GitHub
    if server.get("github_archived"):
        flags.append("archived")

    # Low adoption: <100 installs on Smithery AND <10 stars on GitHub
    use_count = server.get("smithery_use_count", 0)
    stars = server.get("github_stars", 0)
    if use_count < 100 and stars < 10:
        flags.append("low-adoption")

    # Unverified on Smithery
    if server.get("smithery_verified") is False and use_count > 0:
        flags.append("unverified")

    return flags


def enrich_registry(
    *,
    smithery: bool = True,
    docker: bool = True,
    github: bool = True,
) -> dict[str, int]:
    """Fetch from all sources and merge into mcp_registry.json.

    Returns stats dict with counts per source.
    """
    stats: dict[str, int] = {"smithery": 0, "docker": 0, "github": 0, "total": 0, "new": 0}

    # Load existing registry
    registry = json.loads(_REGISTRY_PATH.read_text(encoding="utf-8"))
    servers = registry.get("servers", {})
    existing_count = len(servers)

    # Fetch from sources
    smithery_data: dict[str, dict[str, Any]] = {}
    docker_data: dict[str, dict[str, Any]] = {}
    github_data: dict[str, dict[str, Any]] = {}

    if smithery:
        smithery_data = _fetch_smithery()
        stats["smithery"] = len(smithery_data)

    if docker:
        docker_data = _fetch_docker_hub()
        stats["docker"] = len(docker_data)

    if github:
        github_data = _fetch_github()
        stats["github"] = len(github_data)

    # Merge Smithery data into registry
    for name, meta in smithery_data.items():
        # Try to match by package name (npm packages often match Smithery qualified names)
        matched = False
        for key, srv in servers.items():
            pkg = srv.get("package", "").lower()
            if name.lower() in pkg or pkg in name.lower():
                srv.update(meta)
                matched = True
                break

        if not matched:
            # Add as new entry
            servers[name] = {
                "package": name,
                "ecosystem": "unknown",
                "name": meta.get("smithery_display_name", name),
                "description": normalize_registry_description(meta.get("smithery_description", "")),
                "source_url": meta.get("smithery_homepage", ""),
                "category": "community",
                "risk_level": "unknown",
                "verified": meta.get("smithery_verified", False),
                **meta,
            }

    # Merge Docker Hub data
    for name, meta in docker_data.items():
        short_name = name.replace("mcp/", "")
        for key, srv in servers.items():
            if short_name in key.lower() or short_name in srv.get("package", "").lower():
                srv.update(meta)
                break

    # Merge GitHub data
    for name, meta in github_data.items():
        repo_name = name.split("/")[-1].lower()
        for key, srv in servers.items():
            if repo_name in key.lower() or repo_name in srv.get("package", "").lower():
                srv.update(meta)
                break

    # Flag risks on all servers
    for srv in servers.values():
        srv["description"] = normalize_registry_description(srv.get("description", ""))
        srv["risk_flags"] = _flag_risks(srv)

    # Update metadata
    registry["servers"] = servers
    registry["_total_servers"] = len(servers)
    registry["_updated"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    registry["_enrichment_sources"] = ["smithery", "docker_hub", "github"]

    # Write back
    _REGISTRY_PATH.write_text(
        json.dumps(registry, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )

    stats["total"] = len(servers)
    stats["new"] = len(servers) - existing_count
    _logger.info(
        "Registry enriched: %d total (%d new) from Smithery=%d, Docker=%d, GitHub=%d",
        stats["total"],
        stats["new"],
        stats["smithery"],
        stats["docker"],
        stats["github"],
    )
    return stats
