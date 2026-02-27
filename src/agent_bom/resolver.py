"""Resolve package versions from registries (npm, PyPI)."""

from __future__ import annotations

import asyncio
from typing import Optional

import httpx
from rich.console import Console

from agent_bom.http_client import create_client, request_with_retry
from agent_bom.models import Package

console = Console(stderr=True)

NPM_REGISTRY = "https://registry.npmjs.org"
PYPI_API = "https://pypi.org/pypi"


async def resolve_npm_metadata(
    package_name: str,
    client: httpx.AsyncClient,
) -> tuple[Optional[str], Optional[str]]:
    """Return (version, license) from npm registry."""
    encoded_name = package_name.replace("/", "%2F")
    response = await request_with_retry(
        client,
        "GET",
        f"{NPM_REGISTRY}/{encoded_name}/latest",
    )
    if response and response.status_code == 200:
        try:
            data = response.json()
            version = data.get("version")
            lic = data.get("license")
            # license can be a string or {"type": "MIT"} object
            if isinstance(lic, dict):
                lic = lic.get("type")
            return version, lic if isinstance(lic, str) else None
        except (ValueError, KeyError):
            pass
    return None, None


async def resolve_pypi_metadata(
    package_name: str,
    client: httpx.AsyncClient,
) -> tuple[Optional[str], Optional[str]]:
    """Return (version, license) from PyPI."""
    response = await request_with_retry(
        client,
        "GET",
        f"{PYPI_API}/{package_name}/json",
    )
    if response and response.status_code == 200:
        try:
            info = response.json().get("info", {})
            version = info.get("version")
            lic = info.get("license")
            # PyPI license can be empty string or "UNKNOWN"
            if lic and lic.upper() not in ("UNKNOWN", ""):
                return version, lic
            return version, None
        except (ValueError, KeyError):
            pass
    return None, None


async def resolve_package_version(pkg: Package, client: httpx.AsyncClient) -> bool:
    if pkg.version not in ("latest", "unknown", ""):
        return False
    version, lic = None, None
    if pkg.ecosystem == "npm":
        version, lic = await resolve_npm_metadata(pkg.name, client)
    elif pkg.ecosystem == "pypi":
        version, lic = await resolve_pypi_metadata(pkg.name, client)
    if version:
        pkg.version = version
        pkg.purl = f"pkg:{pkg.ecosystem}/{pkg.name}@{version}"
        if lic and not pkg.license:
            pkg.license = lic
        return True
    return False


async def enrich_licenses(packages: list[Package], client: httpx.AsyncClient) -> int:
    """Fetch license info for packages that already have a version but no license."""
    need_license = [p for p in packages if not p.license and p.version not in ("latest", "unknown", "")]
    if not need_license:
        return 0
    count = 0
    for pkg in need_license:
        _, lic = None, None
        if pkg.ecosystem == "npm":
            _, lic = await resolve_npm_metadata(pkg.name, client)
        elif pkg.ecosystem == "pypi":
            _, lic = await resolve_pypi_metadata(pkg.name, client)
        if lic:
            pkg.license = lic
            count += 1
    return count


async def resolve_all_versions(packages: list[Package]) -> int:
    unresolved = [p for p in packages if p.version in ("latest", "unknown", "")]
    if not unresolved:
        return 0
    resolved_count = 0
    async with create_client(timeout=15.0) as client:
        tasks = [resolve_package_version(pkg, client) for pkg in unresolved]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for i, result in enumerate(results):
            if result is True:
                resolved_count += 1
                lic_tag = f" ({unresolved[i].license})" if unresolved[i].license else ""
                console.print(f"  [green]✓[/green] Resolved {unresolved[i].name} → {unresolved[i].version}{lic_tag}")
            elif isinstance(result, Exception):
                console.print(f"  [yellow]⚠[/yellow] Failed to resolve {unresolved[i].name}: {result}")
        # Enrich licenses for packages that already had versions
        lic_count = await enrich_licenses(packages, client)
        if lic_count:
            console.print(f"  [green]✓[/green] Enriched {lic_count} package license(s)")
    return resolved_count


def resolve_all_versions_sync(packages: list[Package]) -> int:
    return asyncio.run(resolve_all_versions(packages))


# Backward-compatible aliases (used by registry.py)
async def resolve_npm_version(
    package_name: str,
    client: httpx.AsyncClient,
) -> Optional[str]:
    version, _ = await resolve_npm_metadata(package_name, client)
    return version


async def resolve_pypi_version(
    package_name: str,
    client: httpx.AsyncClient,
) -> Optional[str]:
    version, _ = await resolve_pypi_metadata(package_name, client)
    return version
