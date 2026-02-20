"""MCP server registry operations: version updates, drift detection, search."""

from __future__ import annotations

import asyncio
import json
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from agent_bom.models import Package

logger = logging.getLogger(__name__)

# Path to bundled MCP registry
_REGISTRY_PATH = Path(__file__).parent / "mcp_registry.json"


@dataclass
class VersionDrift:
    """Version comparison result for a single package."""

    package: str
    ecosystem: str
    installed: str
    latest: str
    status: str  # "outdated", "current", "unknown"


@dataclass
class RegistryUpdateResult:
    """Result of a registry version refresh."""

    total: int = 0
    updated: int = 0
    failed: int = 0
    unchanged: int = 0
    details: list[dict] = field(default_factory=list)


def _load_registry() -> dict:
    """Load the bundled MCP registry JSON."""
    try:
        return json.loads(_REGISTRY_PATH.read_text()).get("servers", {})
    except Exception:
        return {}


def _load_registry_full() -> dict:
    """Load the full registry JSON (including metadata keys)."""
    try:
        return json.loads(_REGISTRY_PATH.read_text())
    except Exception:
        return {"servers": {}}


def _parse_version(version: str) -> Optional[tuple[int, ...]]:
    """Parse a version string into a comparable tuple of integers.

    Handles semver (1.2.3), calver (2025.1.14), and pre-release suffixes.
    Returns None if the version cannot be parsed.
    """
    if not version or version in ("latest", "unknown", ""):
        return None
    # Strip common prefixes and suffixes
    cleaned = re.sub(r"^[vV]", "", version)
    cleaned = re.split(r"[-+]", cleaned)[0]  # drop pre-release/build metadata
    parts = cleaned.split(".")
    try:
        return tuple(int(p) for p in parts)
    except (ValueError, TypeError):
        return None


def compare_versions(installed: str, latest: str) -> str:
    """Compare two version strings.

    Returns:
        "outdated" if installed < latest
        "current" if installed >= latest
        "unknown" if either version cannot be parsed
    """
    inst = _parse_version(installed)
    lat = _parse_version(latest)
    if inst is None or lat is None:
        return "unknown"
    if inst < lat:
        return "outdated"
    return "current"


def detect_version_drift(
    packages: list[Package],
    registry: dict | None = None,
) -> list[VersionDrift]:
    """Compare installed package versions against registry latest_version.

    Only checks packages that have resolved_from_registry=True.
    Works offline — compares against local registry JSON.
    """
    if registry is None:
        registry = _load_registry()

    results = []
    for pkg in packages:
        if not pkg.resolved_from_registry:
            continue

        # Find matching registry entry
        entry = registry.get(pkg.name)
        if not entry:
            # Try matching by package field
            for _key, ent in registry.items():
                if ent.get("package") == pkg.name:
                    entry = ent
                    break
        if not entry:
            continue

        latest = entry.get("latest_version", "")
        if not latest or latest in ("latest", "unknown"):
            continue

        status = compare_versions(pkg.version, latest)
        results.append(VersionDrift(
            package=pkg.name,
            ecosystem=pkg.ecosystem,
            installed=pkg.version,
            latest=latest,
            status=status,
        ))

    return results


def search_registry(
    query: str,
    category: str | None = None,
    risk_level: str | None = None,
    registry: dict | None = None,
) -> list[dict]:
    """Search registry by name/description substring, with optional filters."""
    if registry is None:
        registry = _load_registry()

    query_lower = query.lower()
    results = []
    for name, entry in registry.items():
        # Filter by category
        if category and entry.get("category", "").lower() != category.lower():
            continue
        # Filter by risk level
        if risk_level and entry.get("risk_level", "").lower() != risk_level.lower():
            continue
        # Match on name, package, or description
        searchable = f"{name} {entry.get('package', '')} {entry.get('description', '')}".lower()
        if query_lower in searchable:
            results.append({"name": name, **entry})
    return results


def list_registry(
    sort_by: str = "name",
    ecosystem: str | None = None,
    category: str | None = None,
    risk_level: str | None = None,
    registry: dict | None = None,
) -> list[dict]:
    """Return filtered and sorted registry entries."""
    if registry is None:
        registry = _load_registry()

    entries = []
    for name, entry in registry.items():
        if ecosystem and entry.get("ecosystem", "").lower() != ecosystem.lower():
            continue
        if category and entry.get("category", "").lower() != category.lower():
            continue
        if risk_level and entry.get("risk_level", "").lower() != risk_level.lower():
            continue
        entries.append({"name": name, **entry})

    # Sort
    if sort_by == "name":
        entries.sort(key=lambda e: e.get("name", "").lower())
    elif sort_by == "ecosystem":
        entries.sort(key=lambda e: (e.get("ecosystem", ""), e.get("name", "").lower()))
    elif sort_by == "category":
        entries.sort(key=lambda e: (e.get("category", ""), e.get("name", "").lower()))
    elif sort_by == "risk":
        risk_order = {"high": 0, "medium": 1, "low": 2}
        entries.sort(key=lambda e: (risk_order.get(e.get("risk_level", "low"), 3), e.get("name", "").lower()))

    return entries


async def update_registry_versions(
    concurrency: int = 5,
    dry_run: bool = False,
) -> RegistryUpdateResult:
    """Fetch latest versions from npm/PyPI for all servers in the registry.

    Uses asyncio.Semaphore for rate limiting.
    Reuses resolver functions for npm/PyPI lookups.
    Updates mcp_registry.json in-place (unless dry_run).
    """
    from agent_bom.http_client import create_client
    from agent_bom.resolver import resolve_npm_version, resolve_pypi_version

    data = _load_registry_full()
    servers = data.get("servers", {})
    result = RegistryUpdateResult(total=len(servers))
    sem = asyncio.Semaphore(concurrency)

    async def update_one(
        client,
        name: str,
        entry: dict,
    ) -> None:
        async with sem:
            pkg_name = entry.get("package", name)
            ecosystem = entry.get("ecosystem", "npm")
            old_version = entry.get("latest_version", "")

            try:
                if ecosystem == "npm":
                    new_version = await resolve_npm_version(pkg_name, client)
                elif ecosystem == "pypi":
                    new_version = await resolve_pypi_version(pkg_name, client)
                else:
                    new_version = None

                if new_version and new_version != old_version:
                    if not dry_run:
                        entry["latest_version"] = new_version
                    result.updated += 1
                    result.details.append({
                        "package": pkg_name,
                        "old": old_version,
                        "new": new_version,
                        "status": "updated",
                    })
                elif new_version:
                    result.unchanged += 1
                    result.details.append({
                        "package": pkg_name,
                        "old": old_version,
                        "new": old_version,
                        "status": "unchanged",
                    })
                else:
                    result.failed += 1
                    result.details.append({
                        "package": pkg_name,
                        "old": old_version,
                        "new": None,
                        "status": "failed",
                    })
            except Exception as exc:
                logger.debug("Failed to resolve %s: %s", pkg_name, exc)
                result.failed += 1
                result.details.append({
                    "package": pkg_name,
                    "old": old_version,
                    "new": None,
                    "status": "failed",
                })

    async with create_client(timeout=15.0) as client:
        tasks = [update_one(client, name, entry) for name, entry in servers.items()]
        await asyncio.gather(*tasks, return_exceptions=True)

    # Write updated registry
    if not dry_run and result.updated > 0:
        from datetime import datetime, timezone

        data["_updated"] = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        _REGISTRY_PATH.write_text(json.dumps(data, indent=2) + "\n")

    return result


def update_registry_versions_sync(
    concurrency: int = 5,
    dry_run: bool = False,
) -> RegistryUpdateResult:
    """Sync wrapper for update_registry_versions."""
    return asyncio.run(update_registry_versions(concurrency=concurrency, dry_run=dry_run))
