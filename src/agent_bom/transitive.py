"""Resolve transitive dependencies from package registries."""

from __future__ import annotations

import asyncio
import re
from typing import Optional

import httpx
from rich.console import Console

from agent_bom.models import Package

console = Console(stderr=True)

NPM_REGISTRY = "https://registry.npmjs.org"
PYPI_API = "https://pypi.org/pypi"

# Cache to avoid re-fetching the same package metadata
_npm_cache: dict[str, dict] = {}
_pypi_cache: dict[str, dict] = {}


def _resolve_npm_version(version_range: str, pkg_data: dict) -> str:
    """Pick the best npm version satisfying a semver range.

    Uses a simplified semver matcher sufficient for most ^X.Y.Z / ~X.Y.Z / >=X patterns.
    Falls back to dist-tags.latest if no match found.
    """
    latest = pkg_data.get("dist-tags", {}).get("latest", "")

    if version_range in ("latest", "", "*"):
        return latest

    available = list(pkg_data.get("versions", {}).keys())
    if not available:
        return latest

    # Strip leading ^, ~, =, >, < to get the minimum version
    stripped = version_range.lstrip("^~>=<").split(" ")[0]
    try:
        # Parse minimum as tuple of ints for comparison
        min_parts = tuple(int(x) for x in stripped.split(".") if x.isdigit())
    except ValueError:
        return latest

    # Parse operator
    if version_range.startswith("^"):
        # Compatible: same major, >= minor.patch
        major = min_parts[0] if min_parts else 0
        candidates = []
        for v in available:
            try:
                parts = tuple(int(x) for x in v.split(".") if x.isdigit())
                if parts[0] == major and parts >= min_parts:
                    candidates.append((parts, v))
            except (ValueError, IndexError):
                continue
        return max(candidates)[1] if candidates else latest

    elif version_range.startswith("~"):
        # Approximately: same major.minor, >= patch
        major = min_parts[0] if len(min_parts) > 0 else 0
        minor = min_parts[1] if len(min_parts) > 1 else 0
        candidates = []
        for v in available:
            try:
                parts = tuple(int(x) for x in v.split(".") if x.isdigit())
                if len(parts) >= 2 and parts[0] == major and parts[1] == minor and parts >= min_parts:
                    candidates.append((parts, v))
            except (ValueError, IndexError):
                continue
        return max(candidates)[1] if candidates else latest

    elif ">=" in version_range:
        candidates = []
        for v in available:
            try:
                parts = tuple(int(x) for x in v.split(".") if x.isdigit())
                if parts >= min_parts:
                    candidates.append((parts, v))
            except (ValueError, IndexError):
                continue
        return max(candidates)[1] if candidates else latest

    return latest


def _resolve_pip_version(version_spec: str, releases: dict) -> str:
    """Pick the best PyPI version satisfying a PEP 440 specifier.

    Uses the `packaging` library when available, else strips operators.
    """
    if not version_spec or version_spec in ("latest", "unknown"):
        return max(releases.keys(), default="unknown") if releases else "unknown"

    try:
        from packaging.specifiers import SpecifierSet
        from packaging.version import Version

        spec = SpecifierSet(version_spec, prereleases=False)
        candidates = []
        for v in releases:
            try:
                pv = Version(v)
                if not pv.is_prerelease and spec.contains(pv):
                    candidates.append(pv)
            except Exception:
                continue
        if candidates:
            return str(max(candidates))
    except ImportError:
        pass

    # Fallback: strip operators, use the bare version
    return re.sub(r"[^0-9.]", "", version_spec.split(",")[0]) or "unknown"


async def fetch_npm_metadata(
    package_name: str,
    version: str,
    client: httpx.AsyncClient
) -> Optional[dict]:
    """Fetch package metadata from npm registry, resolving ranges to exact versions."""
    cache_key = f"{package_name}@{version}"
    if cache_key in _npm_cache:
        return _npm_cache[cache_key]

    try:
        encoded_name = package_name.replace("/", "%2F")
        is_range = version in ("latest", "") or any(c in version for c in "^~>=<*")

        if is_range:
            # Fetch full package document to resolve the range
            response = await client.get(f"{NPM_REGISTRY}/{encoded_name}", follow_redirects=True)
            if response.status_code == 200:
                pkg_data = response.json()
                resolved = _resolve_npm_version(version, pkg_data)
                metadata = pkg_data.get("versions", {}).get(resolved)
                if metadata:
                    _npm_cache[cache_key] = metadata
                    return metadata
        else:
            response = await client.get(f"{NPM_REGISTRY}/{encoded_name}/{version}", follow_redirects=True)
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
    """Fetch package metadata from PyPI, resolving version specifiers to exact versions."""
    cache_key = f"{package_name}@{version}"
    if cache_key in _pypi_cache:
        return _pypi_cache[cache_key]

    try:
        is_range = version in ("latest", "unknown", "") or any(c in version for c in "^~>=<*,!")

        if is_range:
            # Fetch all releases to resolve the specifier
            response = await client.get(f"{PYPI_API}/{package_name}/json", follow_redirects=True)
            if response.status_code == 200:
                pkg_data = response.json()
                releases = pkg_data.get("releases", {})
                resolved = _resolve_pip_version(version if version not in ("latest", "unknown", "") else "", releases)
                if resolved and resolved != "unknown":
                    version_data = await client.get(f"{PYPI_API}/{package_name}/{resolved}/json", follow_redirects=True)
                    if version_data.status_code == 200:
                        data = version_data.json()
                        _pypi_cache[cache_key] = data
                        return data
                # Fallback: return the root package data (latest)
                _pypi_cache[cache_key] = pkg_data
                return pkg_data
        else:
            response = await client.get(f"{PYPI_API}/{package_name}/{version}/json", follow_redirects=True)
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
