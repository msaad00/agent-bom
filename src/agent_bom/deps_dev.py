"""deps.dev API client for transitive dependency resolution and license enrichment.

Google's deps.dev provides dependency graphs for 50M+ packages across npm, PyPI, Go,
Cargo, Maven, and NuGet ecosystems. Free, no authentication required.

API docs: https://docs.deps.dev/api/v3alpha/
"""

from __future__ import annotations

import asyncio
import logging

import httpx

from agent_bom.http_client import create_client, request_with_retry
from agent_bom.models import Package

logger = logging.getLogger(__name__)

DEPS_DEV_BASE = "https://api.deps.dev/v3alpha"

# Map our ecosystem names to deps.dev system names
ECOSYSTEM_MAP: dict[str, str] = {
    "npm": "npm",
    "pypi": "pypi",
    "go": "go",
    "cargo": "cargo",
    "maven": "maven",
    "nuget": "nuget",
}

# Rate limiting
MAX_CONCURRENT = 10
BATCH_DELAY = 0.3  # seconds between batches

# Cache to avoid re-fetching (bounded)
_MAX_CACHE = 5_000
_info_cache: dict[str, dict] = {}
_deps_cache: dict[str, list[dict]] = {}


def _cache_put(cache: dict, key: str, value: object) -> None:
    """Insert into a bounded cache, evicting oldest entries when full."""
    cache[key] = value
    if len(cache) > _MAX_CACHE:
        for k in list(cache.keys())[: len(cache) - _MAX_CACHE]:
            del cache[k]


def _encode_package_name(name: str, system: str) -> str:
    """URL-encode a package name for deps.dev API paths.

    npm scoped packages use %2F for /, Go modules use %2F for /.
    """
    return name.replace("/", "%2F")


async def get_package_info(
    ecosystem: str,
    name: str,
    version: str,
    client: httpx.AsyncClient,
) -> dict | None:
    """Fetch package version info from deps.dev.

    Returns dict with keys: versionKey, licenses, links, advisoryKeys, etc.
    Returns None if package/version not found or ecosystem not supported.
    """
    system = ECOSYSTEM_MAP.get(ecosystem)
    if not system:
        return None

    cache_key = f"{system}:{name}@{version}"
    if cache_key in _info_cache:
        return _info_cache[cache_key]

    encoded = _encode_package_name(name, system)
    url = f"{DEPS_DEV_BASE}/systems/{system}/packages/{encoded}/versions/{version}"

    response = await request_with_retry(client, "GET", url)
    if response and response.status_code == 200:
        try:
            data = response.json()
            _cache_put(_info_cache, cache_key, data)
            return data
        except (ValueError, KeyError):
            pass

    return None


async def get_dependencies(
    ecosystem: str,
    name: str,
    version: str,
    client: httpx.AsyncClient,
) -> list[dict]:
    """Fetch dependency graph for a package version from deps.dev.

    Returns list of dicts: [{name, version, ecosystem, relation, ...}]
    where relation is "SELF", "DIRECT", or "INDIRECT".
    """
    system = ECOSYSTEM_MAP.get(ecosystem)
    if not system:
        return []

    cache_key = f"{system}:{name}@{version}:deps"
    if cache_key in _deps_cache:
        return _deps_cache[cache_key]

    encoded = _encode_package_name(name, system)
    url = f"{DEPS_DEV_BASE}/systems/{system}/packages/{encoded}/versions/{version}:dependencies"

    response = await request_with_retry(client, "GET", url)
    if response and response.status_code == 200:
        try:
            data = response.json()
            nodes = data.get("nodes", [])
            deps = []
            for node in nodes:
                vk = node.get("versionKey", {})
                relation = node.get("relation", "")
                if relation == "SELF":
                    continue
                deps.append(
                    {
                        "name": vk.get("name", ""),
                        "version": vk.get("version", ""),
                        "system": vk.get("system", ""),
                        "relation": relation,
                    }
                )
            _cache_put(_deps_cache, cache_key, deps)
            return deps
        except (ValueError, KeyError):
            pass

    return []


def _system_to_ecosystem(system: str) -> str:
    """Convert deps.dev system name back to our ecosystem name."""
    reverse = {v: k for k, v in ECOSYSTEM_MAP.items()}
    return reverse.get(system.lower(), system.lower())


async def _resolve_one_package(
    pkg: Package,
    client: httpx.AsyncClient,
    max_depth: int,
    seen: set[str],
) -> list[Package]:
    """Resolve transitive dependencies for a single package via deps.dev."""
    if pkg.version in ("latest", "unknown", ""):
        return []

    system = ECOSYSTEM_MAP.get(pkg.ecosystem)
    if not system:
        return []

    pkg_key = f"{pkg.ecosystem}:{pkg.name}@{pkg.version}"
    if pkg_key in seen:
        return []
    seen.add(pkg_key)

    deps = await get_dependencies(pkg.ecosystem, pkg.name, pkg.version, client)
    if not deps:
        return []

    results = []
    for dep in deps:
        dep_name = dep["name"]
        dep_version = dep["version"]
        dep_eco = _system_to_ecosystem(dep["system"])
        relation = dep.get("relation", "INDIRECT")

        dep_key = f"{dep_eco}:{dep_name}@{dep_version}"
        if dep_key in seen:
            continue
        seen.add(dep_key)

        depth = 1 if relation == "DIRECT" else 2
        if depth > max_depth:
            continue

        transitive_pkg = Package(
            name=dep_name,
            version=dep_version,
            ecosystem=dep_eco,
            purl=f"pkg:{dep_eco}/{dep_name}@{dep_version}",
            is_direct=False,
            parent_package=pkg.name,
            dependency_depth=depth,
            resolved_from_registry=True,
            deps_dev_resolved=True,
        )
        results.append(transitive_pkg)

    return results


async def resolve_transitive_deps_dev(
    packages: list[Package],
    max_depth: int = 3,
) -> list[Package]:
    """Resolve transitive dependencies for a list of packages via deps.dev.

    Only resolves packages that have a concrete version (not "latest"/"unknown").
    Deduplicates by (name, version, ecosystem).

    Returns list of transitive Package objects (is_direct=False).
    """
    # Filter to packages with concrete versions in supported ecosystems
    eligible = [
        p
        for p in packages
        if p.ecosystem in ECOSYSTEM_MAP
        and p.version not in ("latest", "unknown", "")
        and p.is_direct  # only resolve direct deps' transitive trees
    ]

    if not eligible:
        return []

    all_transitive: list[Package] = []
    seen: set[str] = set()
    semaphore = asyncio.Semaphore(MAX_CONCURRENT)

    async def _bounded(pkg: Package) -> list[Package]:
        async with semaphore:
            return await _resolve_one_package(pkg, client, max_depth, seen)

    async with create_client(timeout=30.0) as client:
        # Process in batches to respect rate limits
        batch_size = MAX_CONCURRENT * 2
        for i in range(0, len(eligible), batch_size):
            batch = eligible[i : i + batch_size]
            tasks = [_bounded(pkg) for pkg in batch]
            results = await asyncio.gather(*tasks, return_exceptions=True)

            for result in results:
                if isinstance(result, list):
                    all_transitive.extend(result)
                elif isinstance(result, Exception):
                    logger.warning("deps.dev resolution error: %s", result)

            if i + batch_size < len(eligible):
                await asyncio.sleep(BATCH_DELAY)

    # Final deduplication (seen set handles most, but belt-and-suspenders)
    final_seen: set[tuple[str, str, str]] = set()
    unique: list[Package] = []
    for pkg in all_transitive:
        key = (pkg.name, pkg.version, pkg.ecosystem)
        if key not in final_seen:
            final_seen.add(key)
            unique.append(pkg)

    return unique


async def enrich_licenses_deps_dev(
    packages: list[Package],
) -> int:
    """Enrich license fields for packages missing license info via deps.dev.

    deps.dev returns SPDX license expressions (e.g., "MIT", "Apache-2.0 OR MIT").
    Updates both `license` (simple identifier) and `license_expression` (full expression).

    Returns count of packages enriched.
    """
    need_license = [p for p in packages if not p.license and p.version not in ("latest", "unknown", "") and p.ecosystem in ECOSYSTEM_MAP]

    if not need_license:
        return 0

    count = 0
    semaphore = asyncio.Semaphore(MAX_CONCURRENT)

    async def _enrich_one(pkg: Package, client: httpx.AsyncClient) -> bool:
        async with semaphore:
            info = await get_package_info(pkg.ecosystem, pkg.name, pkg.version, client)
            if not info:
                return False

            enriched = False

            # License enrichment
            licenses = info.get("licenses", [])
            spdx_ids = [lic for lic in licenses if isinstance(lic, str) and lic]
            if spdx_ids and not pkg.license:
                pkg.license = spdx_ids[0]
                pkg.license_expression = " AND ".join(spdx_ids) if len(spdx_ids) > 1 else spdx_ids[0]
                enriched = True

            # Supply chain metadata from deps.dev links
            links = info.get("links", [])
            for link in links:
                label = (link.get("label") or "").lower()
                url = link.get("url") or ""
                if not url:
                    continue
                if "homepage" in label and not pkg.homepage:
                    pkg.homepage = url
                elif "source" in label or "repo" in label and not pkg.repository_url:
                    pkg.repository_url = url

            # Description from deps.dev (if available)
            if not pkg.description:
                desc = info.get("description")
                if desc:
                    pkg.description = desc[:300]

            return enriched

    async with create_client(timeout=15.0) as client:
        batch_size = MAX_CONCURRENT * 2
        for i in range(0, len(need_license), batch_size):
            batch = need_license[i : i + batch_size]
            tasks = [_enrich_one(pkg, client) for pkg in batch]
            results = await asyncio.gather(*tasks, return_exceptions=True)

            for result in results:
                if result is True:
                    count += 1

            if i + batch_size < len(need_license):
                await asyncio.sleep(BATCH_DELAY)

    return count


def resolve_transitive_deps_dev_sync(
    packages: list[Package],
    max_depth: int = 3,
) -> list[Package]:
    """Synchronous wrapper for resolve_transitive_deps_dev."""
    return asyncio.run(resolve_transitive_deps_dev(packages, max_depth))


def enrich_licenses_deps_dev_sync(packages: list[Package]) -> int:
    """Synchronous wrapper for enrich_licenses_deps_dev."""
    return asyncio.run(enrich_licenses_deps_dev(packages))
