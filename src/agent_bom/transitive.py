"""Resolve transitive dependencies from package registries."""

from __future__ import annotations

import asyncio
import logging
from typing import Optional

import httpx
from packaging.requirements import InvalidRequirement, Requirement
from rich.console import Console

from agent_bom.http_client import create_client, request_with_retry
from agent_bom.models import Package
from agent_bom.npm_semver import classify_npm_spec, npm_exact_version, resolve_npm_spec
from agent_bom.package_utils import synthesize_purl

console = Console(stderr=True)
_logger = logging.getLogger(__name__)

NPM_REGISTRY = "https://registry.npmjs.org"
PYPI_API = "https://pypi.org/pypi"
GO_PROXY = "https://proxy.golang.org"

# Cache to avoid re-fetching the same package metadata (bounded)
_MAX_TRANSITIVE_CACHE = 5_000
_npm_cache: dict[str, dict] = {}
_npm_packument_cache: dict[str, dict] = {}
_pypi_cache: dict[str, dict] = {}
_go_cache: dict[str, str] = {}


def _cache_put(cache: dict[str, dict], key: str, value: dict) -> None:
    """Insert into a bounded cache, evicting oldest entries when full."""
    cache[key] = value
    if len(cache) > _MAX_TRANSITIVE_CACHE:
        for k in list(cache.keys())[: len(cache) - _MAX_TRANSITIVE_CACHE]:
            del cache[k]


def _declared_dependency_package(*, name: str, ecosystem: str, declared: str, resolved: Optional[str], exact: bool) -> Package:
    """Build a registry-declared dependency without ever reporting a range bound as its version.

    An exact pin is the version. A range/tag resolved against the registry
    reports the version a fresh install selects and keeps the declared spec. A
    spec the registry cannot satisfy stays ``unknown`` with no purl, so no
    advisory is matched against a version nobody installed.
    """
    if resolved:
        pkg = Package(
            name=name,
            version=resolved,
            ecosystem=ecosystem,
            purl=synthesize_purl(name, resolved, ecosystem),
            declared_version=declared,
            resolved_version=resolved,
            resolved_from_registry=True,
        )
        if not exact:
            pkg.floating_reference = True
            pkg.floating_reference_reason = (
                f"declared as a version range ({declared}); resolved to the version a fresh install selects from the registry"
            )
            pkg.version_confidence = "low"
        return pkg
    return Package(
        name=name,
        version="unknown",
        ecosystem=ecosystem,
        declared_version=declared,
        resolved_from_registry=True,
        floating_reference=True,
        floating_reference_reason=(
            f"declared as {declared or 'an empty spec'} — no published registry version satisfies it or it is not a registry reference"
        ),
        version_confidence="low",
    )


def _pypi_exact_pin(requirement: Requirement) -> Optional[str]:
    specs = list(requirement.specifier)
    if len(specs) == 1 and specs[0].operator in ("==", "===") and "*" not in specs[0].version:
        return specs[0].version
    return None


def _is_prerelease(version_str: str) -> bool:
    """Check if an npm version string is a pre-release (e.g., 1.0.0-beta.1)."""
    # Semver pre-release: anything with a hyphen after the version core
    # e.g., "1.0.0-alpha", "2.1.0-rc.1", "3.0.0-beta"
    base = version_str.split("+")[0]  # strip build metadata
    return "-" in base


def _semver_tuple(version_str: str) -> tuple[int, int, int] | None:
    """Parse an npm version core into a (major, minor, patch) tuple, or None.

    Strips pre-release / build metadata and pads to three components so
    comparisons are well-defined (``1.2`` → ``(1, 2, 0)``).
    """
    base = version_str.split("+")[0].split("-")[0].strip()
    parts = base.split(".")
    try:
        nums = [int(p) for p in parts[:3]]
    except ValueError:
        return None
    if not nums:
        return None
    while len(nums) < 3:
        nums.append(0)
    return (nums[0], nums[1], nums[2])


def _npm_caret_tilde_bounds(version_range: str) -> tuple[tuple[int, int, int], tuple[int, int, int]] | None:
    """Return ``(lo_inclusive, hi_exclusive)`` for an npm ``^``/``~`` range.

    Implements npm's real caret/tilde semantics, including the 0.x special
    cases the previous matcher got wrong:

    - ``^1.2.3`` → ``>=1.2.3 <2.0.0``
    - ``^0.2.3`` → ``>=0.2.3 <0.3.0``   (caret pins minor when major is 0)
    - ``^0.0.3`` → ``>=0.0.3 <0.0.4``   (caret pins patch when major.minor are 0)
    - ``~1.2.3`` / ``~1.2`` → ``>=… <1.3.0``
    - ``~1``     → ``>=1.0.0 <2.0.0``
    """
    if not version_range or version_range[0] not in "^~":
        return None
    op = version_range[0]
    body = version_range[1:].split(" ")[0]
    comps = body.split(".")
    try:
        nums = [int(x) for x in comps if x.lstrip("-").isdigit()]
    except ValueError:
        return None
    if not nums:
        return None
    major = nums[0]
    minor = nums[1] if len(nums) > 1 else 0
    patch = nums[2] if len(nums) > 2 else 0
    lo = (major, minor, patch)
    if op == "^":
        if major > 0:
            hi = (major + 1, 0, 0)
        elif minor > 0:
            hi = (0, minor + 1, 0)
        else:
            hi = (0, 0, patch + 1)
    else:  # "~": ~X.Y[.Z] pins the minor; bare ~X pins the major.
        hi = (major, minor + 1, 0) if len(nums) >= 2 else (major + 1, 0, 0)
    return lo, hi


def _resolve_npm_version(version_range: str, pkg_data: dict) -> str:
    """Pick the npm version a fresh install of *version_range* would select.

    Follows node-semver range semantics and npm-pick-manifest's selection
    (``latest`` when it satisfies, else the highest satisfying version).
    Returns ``""`` when nothing satisfies — never a version the range excludes.
    """
    return resolve_npm_spec(version_range, pkg_data) or ""


def _resolve_pip_version(version_spec: str, releases: dict) -> str:
    """Pick the best PyPI version satisfying a PEP 440 specifier.

    Returns ``"unknown"`` when the specifier is unparseable or no published
    release satisfies it — a bound is never reported as the installed version.
    """
    if not version_spec or version_spec in ("latest", "unknown"):
        return max(releases.keys(), default="unknown") if releases else "unknown"

    from packaging.specifiers import InvalidSpecifier, SpecifierSet
    from packaging.version import InvalidVersion, Version

    try:
        spec = SpecifierSet(version_spec, prereleases=False)
    except InvalidSpecifier:
        return "unknown"
    candidates = []
    for v in releases:
        try:
            pv = Version(v)
        except InvalidVersion as exc:
            _logger.debug("Skipping unparseable version %r for transitive dep: %s", v, exc)
            continue
        if not pv.is_prerelease and spec.contains(pv):
            candidates.append(pv)
    return str(max(candidates)) if candidates else "unknown"


async def fetch_npm_packument(package_name: str, client: httpx.AsyncClient) -> Optional[dict]:
    """Return ``{"dist-tags", "versions"}`` for an npm package (cached, version bodies dropped)."""
    if package_name in _npm_packument_cache:
        return _npm_packument_cache[package_name]
    encoded_name = package_name.replace("/", "%2F")
    response = await request_with_retry(client, "GET", f"{NPM_REGISTRY}/{encoded_name}")
    if not response or response.status_code != 200:
        return None
    try:
        data = response.json()
    except ValueError as exc:
        _logger.warning("Failed to parse npm packument for %s: %s", package_name, exc)
        return None
    if not isinstance(data, dict):
        return None
    raw_tags = data.get("dist-tags")
    raw_versions = data.get("versions")
    dist_tags: dict = raw_tags if isinstance(raw_tags, dict) else {}
    versions: dict = raw_versions if isinstance(raw_versions, dict) else {}
    slim = {"dist-tags": dict(dist_tags), "versions": {v: {} for v in versions}}
    _cache_put(_npm_packument_cache, package_name, slim)
    return slim


async def resolve_npm_range_version(package_name: str, spec: str, client: httpx.AsyncClient) -> Optional[str]:
    """Resolve a registry range/tag *spec* to the version a fresh install selects, or ``None``."""
    if classify_npm_spec(spec) not in ("range", "tag"):
        return npm_exact_version(spec)
    packument = await fetch_npm_packument(package_name, client)
    if not packument:
        return None
    return resolve_npm_spec(spec, packument)


async def fetch_pypi_releases(package_name: str, client: httpx.AsyncClient) -> Optional[dict]:
    """Return the PyPI ``releases`` map for a package, or ``None`` when unavailable."""
    response = await request_with_retry(client, "GET", f"{PYPI_API}/{package_name}/json")
    if not response or response.status_code != 200:
        return None
    try:
        data = response.json()
    except ValueError as exc:
        _logger.warning("Failed to parse PyPI metadata for %s: %s", package_name, exc)
        return None
    releases = data.get("releases") if isinstance(data, dict) else None
    return releases if isinstance(releases, dict) else None


async def resolve_pypi_spec_version(package_name: str, spec: str, client: httpx.AsyncClient) -> Optional[str]:
    """Resolve a PEP 440 specifier to the highest satisfying release, or ``None``."""
    releases = await fetch_pypi_releases(package_name, client)
    if not releases:
        return None
    resolved = _resolve_pip_version(spec, releases)
    return None if resolved == "unknown" else resolved


async def fetch_npm_metadata(package_name: str, version: str, client: httpx.AsyncClient) -> Optional[dict]:
    """Fetch package metadata from npm registry, resolving ranges to exact versions."""
    cache_key = f"{package_name}@{version}"
    if cache_key in _npm_cache:
        return _npm_cache[cache_key]

    encoded_name = package_name.replace("/", "%2F")
    is_range = classify_npm_spec(version) != "exact"

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
                metadata = pkg_data.get("versions", {}).get(resolved) if resolved else None
                if metadata:
                    _cache_put(_npm_cache, cache_key, metadata)
                    return metadata
            except (ValueError, KeyError, AttributeError) as exc:
                _logger.warning("Failed to parse npm metadata for %s@%s: %s", package_name, version, exc)
    else:
        response = await request_with_retry(
            client,
            "GET",
            f"{NPM_REGISTRY}/{encoded_name}/{npm_exact_version(version) or version}",
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
            declared = str(dep_version or "").strip()
            resolved = await resolve_npm_range_version(dep_name, declared, client)
            transitive_pkg = _declared_dependency_package(
                name=dep_name,
                ecosystem="npm",
                declared=declared,
                resolved=resolved,
                exact=classify_npm_spec(declared) == "exact",
            )
            transitive_pkg.is_direct = False
            transitive_pkg.parent_package = package.name
            transitive_pkg.dependency_depth = current_depth + 1
            transitive_pkg.dependency_scope = dependency_scope
            transitive_pkg.reachability_evidence = reachability_evidence
            dependencies.append(transitive_pkg)

            if not recurse or not resolved:
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

        try:
            requirement = Requirement(dep_spec)
        except InvalidRequirement:
            _logger.debug("Skipping unparseable requirement %r of %s", dep_spec, package.name)
            continue

        dep_name = requirement.name
        specifier = str(requirement.specifier)
        exact = _pypi_exact_pin(requirement)
        if not specifier:
            transitive_pkg = Package(name=dep_name, version="latest", ecosystem="pypi", resolved_from_registry=True)
            resolved: Optional[str] = "latest"
        else:
            resolved = exact or await resolve_pypi_spec_version(dep_name, specifier, client)
            transitive_pkg = _declared_dependency_package(
                name=dep_name,
                ecosystem="pypi",
                declared=specifier,
                resolved=resolved,
                exact=exact is not None,
            )
        transitive_pkg.is_direct = False
        transitive_pkg.parent_package = package.name
        transitive_pkg.dependency_depth = current_depth + 1
        transitive_pkg.dependency_scope = dependency_scope
        transitive_pkg.reachability_evidence = reachability_evidence
        dependencies.append(transitive_pkg)

        if reachability_evidence == "declaration_only" or not resolved:
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
