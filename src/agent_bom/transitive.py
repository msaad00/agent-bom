"""Resolve transitive dependencies from package registries."""

from __future__ import annotations

import asyncio
import re
from typing import Optional

import httpx
from rich.console import Console

from agent_bom.models import Package

console = Console()

NPM_REGISTRY = "https://registry.npmjs.org"
PYPI_API = "https://pypi.org/pypi"

# Cache to avoid re-fetching the same package metadata
_npm_cache: dict[str, dict] = {}
_pypi_cache: dict[str, dict] = {}


async def fetch_npm_metadata(
    package_name: str,
    version: str,
    client: httpx.AsyncClient
) -> Optional[dict]:
    """Fetch package metadata from npm registry."""
    cache_key = f"{package_name}@{version}"
    if cache_key in _npm_cache:
        return _npm_cache[cache_key]

    try:
        encoded_name = package_name.replace("/", "%2F")

        # If version is 'latest' or version range, fetch the package info first
        if version in ("latest", "") or any(c in version for c in "^~>=<*"):
            response = await client.get(
                f"{NPM_REGISTRY}/{encoded_name}",
                follow_redirects=True
            )
            if response.status_code == 200:
                pkg_data = response.json()

                # Get the latest version or resolve the range
                if version == "latest" or version == "":
                    version = pkg_data.get("dist-tags", {}).get("latest", "")
                else:
                    # For version ranges, use latest (simplified - in production use semver)
                    version = pkg_data.get("dist-tags", {}).get("latest", "")

                metadata = pkg_data.get("versions", {}).get(version)
                if metadata:
                    _npm_cache[cache_key] = metadata
                    return metadata
        else:
            # Fetch specific version
            response = await client.get(
                f"{NPM_REGISTRY}/{encoded_name}/{version}",
                follow_redirects=True
            )
            if response.status_code == 200:
                metadata = response.json()
                _npm_cache[cache_key] = metadata
                return metadata

    except (httpx.HTTPError, KeyError, ValueError) as e:
        console.print(f"  [dim yellow]⚠ Failed to fetch npm metadata for {package_name}@{version}: {e}[/dim yellow]")

    return None


async def fetch_pypi_metadata(
    package_name: str,
    version: str,
    client: httpx.AsyncClient
) -> Optional[dict]:
    """Fetch package metadata from PyPI."""
    cache_key = f"{package_name}@{version}"
    if cache_key in _pypi_cache:
        return _pypi_cache[cache_key]

    try:
        if version in ("latest", ""):
            # Fetch latest version
            response = await client.get(
                f"{PYPI_API}/{package_name}/json",
                follow_redirects=True
            )
            if response.status_code == 200:
                data = response.json()
                _pypi_cache[cache_key] = data
                return data
        else:
            # Fetch specific version
            response = await client.get(
                f"{PYPI_API}/{package_name}/{version}/json",
                follow_redirects=True
            )
            if response.status_code == 200:
                data = response.json()
                _pypi_cache[cache_key] = data
                return data

    except (httpx.HTTPError, KeyError, ValueError) as e:
        console.print(f"  [dim yellow]⚠ Failed to fetch PyPI metadata for {package_name}@{version}: {e}[/dim yellow]")

    return None


async def resolve_npm_dependencies(
    package: Package,
    client: httpx.AsyncClient,
    max_depth: int = 3,
    current_depth: int = 0,
    seen: Optional[set] = None,
) -> list[Package]:
    """Recursively resolve npm package dependencies."""
    if seen is None:
        seen = set()

    if current_depth >= max_depth:
        return []

    # Avoid infinite loops
    pkg_key = f"{package.name}@{package.version}"
    if pkg_key in seen:
        return []
    seen.add(pkg_key)

    metadata = await fetch_npm_metadata(package.name, package.version, client)
    if not metadata:
        return []

    dependencies = []
    dep_dict = metadata.get("dependencies", {})

    for dep_name, dep_version in dep_dict.items():
        # Clean version spec (remove ^, ~, etc.)
        clean_version = dep_version.lstrip("^~>=<")

        transitive_pkg = Package(
            name=dep_name,
            version=clean_version,
            ecosystem="npm",
            purl=f"pkg:npm/{dep_name}@{clean_version}",
            is_direct=False,
            parent_package=package.name,
            dependency_depth=current_depth + 1,
            resolved_from_registry=True,
        )
        dependencies.append(transitive_pkg)

        # Recursively resolve this package's dependencies
        nested_deps = await resolve_npm_dependencies(
            transitive_pkg,
            client,
            max_depth,
            current_depth + 1,
            seen,
        )
        dependencies.extend(nested_deps)

    return dependencies


async def resolve_pypi_dependencies(
    package: Package,
    client: httpx.AsyncClient,
    max_depth: int = 3,
    current_depth: int = 0,
    seen: Optional[set] = None,
) -> list[Package]:
    """Recursively resolve PyPI package dependencies."""
    if seen is None:
        seen = set()

    if current_depth >= max_depth:
        return []

    # Avoid infinite loops
    pkg_key = f"{package.name}@{package.version}"
    if pkg_key in seen:
        return []
    seen.add(pkg_key)

    metadata = await fetch_pypi_metadata(package.name, package.version, client)
    if not metadata:
        return []

    dependencies = []

    # PyPI metadata has 'info' and 'requires_dist'
    info = metadata.get("info", {})
    requires_dist = info.get("requires_dist", [])

    if not requires_dist:
        return []

    for dep_spec in requires_dist:
        # Parse dependency specification (e.g., "requests>=2.28.0")
        # Skip extras and environment markers
        if ";" in dep_spec:
            dep_spec = dep_spec.split(";")[0].strip()

        if "extra ==" in dep_spec:
            continue  # Skip optional dependencies

        # Extract package name and version
        match = re.match(r'^([a-zA-Z0-9_.-]+)\s*([<>=!~]+)?\s*([a-zA-Z0-9_.*+-]+)?', dep_spec)
        if not match:
            continue

        dep_name = match.group(1)
        version_spec = match.group(3) if match.group(3) else "latest"

        transitive_pkg = Package(
            name=dep_name,
            version=version_spec,
            ecosystem="pypi",
            purl=f"pkg:pypi/{dep_name}@{version_spec}",
            is_direct=False,
            parent_package=package.name,
            dependency_depth=current_depth + 1,
            resolved_from_registry=True,
        )
        dependencies.append(transitive_pkg)

        # Recursively resolve this package's dependencies
        nested_deps = await resolve_pypi_dependencies(
            transitive_pkg,
            client,
            max_depth,
            current_depth + 1,
            seen,
        )
        dependencies.extend(nested_deps)

    return dependencies


async def resolve_transitive_dependencies(
    packages: list[Package],
    max_depth: int = 3,
) -> list[Package]:
    """Resolve transitive dependencies for a list of packages."""
    all_transitive = []

    async with httpx.AsyncClient(timeout=30.0) as client:
        tasks = []

        for pkg in packages:
            if pkg.ecosystem == "npm":
                tasks.append(resolve_npm_dependencies(pkg, client, max_depth))
            elif pkg.ecosystem == "pypi":
                tasks.append(resolve_pypi_dependencies(pkg, client, max_depth))

        if tasks:
            results = await asyncio.gather(*tasks, return_exceptions=True)

            for result in results:
                if isinstance(result, list):
                    all_transitive.extend(result)
                elif isinstance(result, Exception):
                    console.print(f"  [yellow]⚠ Error resolving transitive deps: {result}[/yellow]")

    # Deduplicate
    seen = set()
    unique = []
    for pkg in all_transitive:
        key = (pkg.name, pkg.version, pkg.ecosystem)
        if key not in seen:
            seen.add(key)
            unique.append(pkg)

    return unique


def resolve_transitive_dependencies_sync(
    packages: list[Package],
    max_depth: int = 3,
) -> list[Package]:
    """Synchronous wrapper for resolve_transitive_dependencies."""
    return asyncio.run(resolve_transitive_dependencies(packages, max_depth))
