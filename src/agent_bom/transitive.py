"""Resolve transitive dependencies from package registries."""

from __future__ import annotations

import asyncio
import logging
import re
from typing import Optional

import httpx
from rich.console import Console

from agent_bom.http_client import create_client, request_with_retry
from agent_bom.models import Package

console = Console(stderr=True)
_logger = logging.getLogger(__name__)

NPM_REGISTRY = "https://registry.npmjs.org"
PYPI_API = "https://pypi.org/pypi"
GO_PROXY = "https://proxy.golang.org"

# Cache to avoid re-fetching the same package metadata (bounded)
_MAX_TRANSITIVE_CACHE = 5_000
_npm_cache: dict[str, dict] = {}
_pypi_cache: dict[str, dict] = {}
_go_cache: dict[str, str] = {}


def _cache_put(cache: dict[str, dict], key: str, value: dict) -> None:
    """Insert into a bounded cache, evicting oldest entries when full."""
    cache[key] = value
    if len(cache) > _MAX_TRANSITIVE_CACHE:
        for k in list(cache.keys())[: len(cache) - _MAX_TRANSITIVE_CACHE]:
            del cache[k]


def _is_prerelease(version_str: str) -> bool:
    """Check if an npm version string is a pre-release (e.g., 1.0.0-beta.1)."""
    # Semver pre-release: anything with a hyphen after the version core
    # e.g., "1.0.0-alpha", "2.1.0-rc.1", "3.0.0-beta"
    base = version_str.split("+")[0]  # strip build metadata
    return "-" in base


def _resolve_npm_version(version_range: str, pkg_data: dict) -> str:
    """Pick the best npm version satisfying a semver range.

    Uses a simplified semver matcher sufficient for most ^X.Y.Z / ~X.Y.Z / >=X patterns.
    Excludes pre-release versions (e.g., 1.0.0-beta) unless no stable match is found.
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
            if _is_prerelease(v):
                continue
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
            if _is_prerelease(v):
                continue
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
            if _is_prerelease(v):
                continue
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
            except Exception as exc:  # noqa: BLE001
                _logger.debug("Skipping unparseable version %r for transitive dep: %s", v, exc)
                continue
        if candidates:
            return str(max(candidates))
    except ImportError:
        pass

    # Fallback: strip operators, use the bare version
    return re.sub(r"[^0-9.]", "", version_spec.split(",")[0]) or "unknown"


async def fetch_npm_metadata(package_name: str, version: str, client: httpx.AsyncClient) -> Optional[dict]:
    """Fetch package metadata from npm registry, resolving ranges to exact versions."""
    cache_key = f"{package_name}@{version}"
    if cache_key in _npm_cache:
        return _npm_cache[cache_key]

    encoded_name = package_name.replace("/", "%2F")
    is_range = version in ("latest", "") or any(c in version for c in "^~>=<*")

    if is_range:
        response = await request_with_retry(
            client,
            "GET",
            f"{NPM_REGISTRY}/{encoded_name}",
        )
        if response and response.status_code == 200:
            try:
                pkg_data = response.json()
                resolved = _resolve_npm_version(version, pkg_data)
                metadata = pkg_data.get("versions", {}).get(resolved)
                if metadata:
                    _cache_put(_npm_cache, cache_key, metadata)
                    return metadata
            except (ValueError, KeyError) as exc:
                _logger.warning("Failed to parse npm metadata for %s@%s: %s", package_name, version, exc)
    else:
        response = await request_with_retry(
            client,
            "GET",
            f"{NPM_REGISTRY}/{encoded_name}/{version}",
        )
        if response and response.status_code == 200:
            try:
                metadata = response.json()
                _cache_put(_npm_cache, cache_key, metadata)
                return metadata
            except (ValueError, KeyError) as exc:
                _logger.warning("Failed to parse npm metadata for %s@%s: %s", package_name, version, exc)

    return None


async def fetch_pypi_metadata(package_name: str, version: str, client: httpx.AsyncClient) -> Optional[dict]:
    """Fetch package metadata from PyPI, resolving version specifiers to exact versions."""
    cache_key = f"{package_name}@{version}"
    if cache_key in _pypi_cache:
        return _pypi_cache[cache_key]

    is_range = version in ("latest", "unknown", "") or any(c in version for c in "^~>=<*,!")

    if is_range:
        response = await request_with_retry(
            client,
            "GET",
            f"{PYPI_API}/{package_name}/json",
        )
        if response and response.status_code == 200:
            try:
                pkg_data = response.json()
                releases = pkg_data.get("releases", {})
                resolved = _resolve_pip_version(version if version not in ("latest", "unknown", "") else "", releases)
                if resolved and resolved != "unknown":
                    version_data = await request_with_retry(
                        client,
                        "GET",
                        f"{PYPI_API}/{package_name}/{resolved}/json",
                    )
                    if version_data and version_data.status_code == 200:
                        data = version_data.json()
                        _cache_put(_pypi_cache, cache_key, data)
                        return data
                _cache_put(_pypi_cache, cache_key, pkg_data)
                return pkg_data
            except (ValueError, KeyError) as exc:
                _logger.warning("Failed to parse PyPI metadata for %s@%s: %s", package_name, version, exc)
    else:
        response = await request_with_retry(
            client,
            "GET",
            f"{PYPI_API}/{package_name}/{version}/json",
        )
        if response and response.status_code == 200:
            try:
                data = response.json()
                _cache_put(_pypi_cache, cache_key, data)
                return data
            except (ValueError, KeyError) as exc:
                _logger.warning("Failed to parse PyPI metadata for %s@%s: %s", package_name, version, exc)

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
    dependency_sections = (
        ("dependencies", "runtime", "runtime_dependency", True),
        ("optionalDependencies", "optional", "declaration_only", False),
        ("peerDependencies", "peer", "declaration_only", False),
    )

    for section, dependency_scope, reachability_evidence, recurse in dependency_sections:
        dep_dict = metadata.get(section, {}) or {}
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
                dependency_scope=dependency_scope,
                reachability_evidence=reachability_evidence,
                resolved_from_registry=True,
            )
            dependencies.append(transitive_pkg)

            if not recurse:
                continue

            # Recursively resolve this package's runtime dependencies. Optional
            # and peer declarations are surfaced as evidence, but not expanded
            # as confirmed runtime paths.
            nested_deps = await resolve_npm_dependencies(
                transitive_pkg,
                client,
                max_depth,
                current_depth + 1,
                seen,
            )
            dependencies.extend(nested_deps)

    return dependencies


def _split_requires_dist_marker(dep_spec: str) -> tuple[str, str]:
    """Return the requirement body and optional PEP 508 marker."""
    if ";" not in dep_spec:
        return dep_spec.strip(), ""
    requirement, marker = dep_spec.split(";", 1)
    return requirement.strip(), marker.strip()


def _scope_for_pypi_marker(marker: str) -> tuple[str, str]:
    """Classify PyPI dependency markers without evaluating the local runtime."""
    normalized = marker.lower().replace('"', "'")
    if "extra ==" in normalized:
        return "extra", "declaration_only"
    if marker:
        return "conditional", "declaration_only"
    return "runtime", "runtime_dependency"


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
        dep_spec, marker = _split_requires_dist_marker(dep_spec)
        dependency_scope, reachability_evidence = _scope_for_pypi_marker(marker)

        # Extract package name and version
        match = re.match(r"^([a-zA-Z0-9_.-]+)\s*([<>=!~]+)?\s*([a-zA-Z0-9_.*+-]+)?", dep_spec)
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
            dependency_scope=dependency_scope,
            reachability_evidence=reachability_evidence,
            resolved_from_registry=True,
        )
        dependencies.append(transitive_pkg)

        if reachability_evidence == "declaration_only":
            continue

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


def _go_encode_module(module: str) -> str:
    """Encode a Go module path for proxy.golang.org.

    The Go module proxy uses case-encoding: uppercase letters become
    ``!`` + lowercase (e.g., ``GitHub.com`` → ``!github.com``).
    Forward slashes are kept as literal path separators in the URL.
    """
    parts: list[str] = []
    for ch in module:
        if ch.isupper():
            parts.append("!")
            parts.append(ch.lower())
        else:
            parts.append(ch)
    return "".join(parts)


def _parse_go_mod_requires(go_mod_text: str) -> list[tuple[str, str]]:
    """Parse ``require`` directives from go.mod content.

    Handles both single-line (``require module version``) and
    block-style (``require ( ... )``) forms.  Lines ending with
    ``// indirect`` are included — callers decide what to do with them.

    Returns a list of ``(module, version)`` tuples.
    """
    requires: list[tuple[str, str]] = []
    in_block = False
    for raw_line in go_mod_text.splitlines():
        line = raw_line.strip()
        # Strip inline comments
        if "//" in line:
            line = line[: line.index("//")].strip()
        if not line:
            continue
        if line.startswith("require ("):
            in_block = True
            continue
        if in_block:
            if line == ")":
                in_block = False
                continue
            parts = line.split()
            if len(parts) >= 2:
                requires.append((parts[0], parts[1]))
        elif line.startswith("require "):
            parts = line[len("require ") :].split()
            if len(parts) >= 2:
                requires.append((parts[0], parts[1]))
    return requires


async def fetch_go_mod(module: str, version: str, client: httpx.AsyncClient) -> Optional[str]:
    """Fetch the go.mod file for a specific Go module version from the module proxy.

    Returns the raw go.mod text on success, or ``None`` on any failure.
    """
    cache_key = f"{module}@{version}"
    if cache_key in _go_cache:
        return _go_cache[cache_key]

    encoded = _go_encode_module(module)
    url = f"{GO_PROXY}/{encoded}/@v/{version}.mod"
    response = await request_with_retry(client, "GET", url)
    if response and response.status_code == 200:
        text = response.text
        _cache_put(_go_cache, cache_key, text)  # type: ignore[arg-type]
        return text
    return None


async def resolve_go_dependencies(
    package: Package,
    client: httpx.AsyncClient,
    max_depth: int = 3,
    current_depth: int = 0,
    seen: Optional[set] = None,
) -> list[Package]:
    """Recursively resolve Go module dependencies via proxy.golang.org."""
    if seen is None:
        seen = set()

    if current_depth >= max_depth:
        return []

    pkg_key = f"{package.name}@{package.version}"
    if pkg_key in seen:
        return []
    seen.add(pkg_key)

    go_mod_text = await fetch_go_mod(package.name, package.version, client)
    if not go_mod_text:
        return []

    dependencies: list[Package] = []
    for dep_module, dep_version in _parse_go_mod_requires(go_mod_text):
        transitive_pkg = Package(
            name=dep_module,
            version=dep_version,
            ecosystem="go",
            purl=f"pkg:golang/{dep_module}@{dep_version}",
            is_direct=False,
            parent_package=package.name,
            dependency_depth=current_depth + 1,
            resolved_from_registry=True,
        )
        dependencies.append(transitive_pkg)

        nested_deps = await resolve_go_dependencies(
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

    async with create_client(timeout=30.0) as client:
        tasks = []

        unsupported_logged: set[str] = set()
        for pkg in packages:
            if pkg.ecosystem == "npm":
                tasks.append(resolve_npm_dependencies(pkg, client, max_depth))
            elif pkg.ecosystem == "pypi":
                tasks.append(resolve_pypi_dependencies(pkg, client, max_depth))
            elif pkg.ecosystem in ("go", "golang"):
                tasks.append(resolve_go_dependencies(pkg, client, max_depth))
            elif pkg.ecosystem not in unsupported_logged:
                _logger.debug(
                    "Transitive resolution not available for ecosystem %r — skipping %s",
                    pkg.ecosystem,
                    pkg.name,
                )
                unsupported_logged.add(pkg.ecosystem)

        if tasks:
            results = await asyncio.gather(*tasks, return_exceptions=True)

            for result in results:
                if isinstance(result, list):
                    all_transitive.extend(result)
                elif isinstance(result, Exception):
                    _logger.warning("Error resolving transitive deps: %s", result)
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
