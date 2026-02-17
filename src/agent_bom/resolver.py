"""Resolve package versions from registries (npm, PyPI)."""

from __future__ import annotations

import asyncio
from typing import Optional

import httpx
from rich.console import Console

from agent_bom.models import Package

console = Console(stderr=True)

NPM_REGISTRY = "https://registry.npmjs.org"
PYPI_API = "https://pypi.org/pypi"


async def resolve_npm_version(package_name: str, client: httpx.AsyncClient) -> Optional[str]:
    try:
        encoded_name = package_name.replace("/", "%2F")
        response = await client.get(f"{NPM_REGISTRY}/{encoded_name}/latest", follow_redirects=True)
        if response.status_code == 200:
            data = response.json()
            return data.get("version")
    except (httpx.HTTPError, KeyError, ValueError):
        pass
    return None


async def resolve_pypi_version(package_name: str, client: httpx.AsyncClient) -> Optional[str]:
    try:
        response = await client.get(f"{PYPI_API}/{package_name}/json", follow_redirects=True)
        if response.status_code == 200:
            data = response.json()
            return data.get("info", {}).get("version")
    except (httpx.HTTPError, KeyError, ValueError):
        pass
    return None


async def resolve_package_version(pkg: Package, client: httpx.AsyncClient) -> bool:
    if pkg.version not in ("latest", "unknown", ""):
        return False
    version = None
    if pkg.ecosystem == "npm":
        version = await resolve_npm_version(pkg.name, client)
    elif pkg.ecosystem == "pypi":
        version = await resolve_pypi_version(pkg.name, client)
    if version:
        pkg.version = version
        pkg.purl = f"pkg:{pkg.ecosystem}/{pkg.name}@{version}"
        return True
    return False


async def resolve_all_versions(packages: list[Package]) -> int:
    unresolved = [p for p in packages if p.version in ("latest", "unknown", "")]
    if not unresolved:
        return 0
    resolved_count = 0
    async with httpx.AsyncClient(timeout=15.0) as client:
        tasks = [resolve_package_version(pkg, client) for pkg in unresolved]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for i, result in enumerate(results):
            if result is True:
                resolved_count += 1
                console.print(f"  [green]✓[/green] Resolved {unresolved[i].name} → {unresolved[i].version}")
            elif isinstance(result, Exception):
                console.print(f"  [yellow]⚠[/yellow] Failed to resolve {unresolved[i].name}: {result}")
    return resolved_count


def resolve_all_versions_sync(packages: list[Package]) -> int:
    return asyncio.run(resolve_all_versions(packages))
