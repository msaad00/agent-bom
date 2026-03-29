"""Resolve package versions from registries (npm, PyPI)."""

from __future__ import annotations

import asyncio
import logging
from collections import defaultdict
from typing import Optional

import httpx
from rich.console import Console

from agent_bom.http_client import create_client, request_with_retry
from agent_bom.models import Package

console = Console(stderr=True)
_logger = logging.getLogger(__name__)

NPM_REGISTRY = "https://registry.npmjs.org"
PYPI_API = "https://pypi.org/pypi"
_INVALID_VERSIONS = {"latest", "unknown", "", "{{VERSION}}"}
_RESOLVE_CONCURRENCY = 8
_NPM_LATEST_CACHE: dict[str, dict | None] = {}
_PYPI_INFO_CACHE: dict[str, dict | None] = {}


def _apply_registry_version_fallback(pkg: Package) -> bool:
    """Use bundled registry metadata when live resolution is unavailable.

    This preserves scan continuity under registry pressure instead of leaving
    versionless packages to silently degrade or be skipped downstream.
    """
    fallback_version = getattr(pkg, "registry_version", None)
    if not fallback_version or fallback_version in _INVALID_VERSIONS:
        return False
    pkg.version = fallback_version
    pkg.purl = f"pkg:{pkg.ecosystem}/{pkg.name}@{fallback_version}"
    pkg.version_source = "registry_fallback"
    return True


def _resolution_key(pkg: Package) -> tuple[str, str]:
    """Stable key for deduping identical registry lookups within one run."""
    return (pkg.ecosystem.lower(), pkg.name.lower())


def _copy_resolution_fields(source: Package, target: Package) -> bool:
    """Copy resolved version metadata from *source* to *target*."""
    if source.version in _INVALID_VERSIONS:
        return False
    target.version = source.version
    target.purl = source.purl
    if source.license and not target.license:
        target.license = source.license
    if source.version_source == "registry_fallback":
        target.version_source = "registry_fallback"
    return True


async def _get_npm_latest_doc(package_name: str, client: httpx.AsyncClient) -> dict | None:
    """Return cached npm `/latest` JSON for a package."""
    cache_key = package_name.lower()
    if cache_key in _NPM_LATEST_CACHE:
        return _NPM_LATEST_CACHE[cache_key]

    encoded_name = package_name.replace("/", "%2F")
    response = await request_with_retry(
        client,
        "GET",
        f"{NPM_REGISTRY}/{encoded_name}/latest",
    )
    data: dict | None = None
    if response and response.status_code == 200:
        try:
            parsed = response.json()
            if isinstance(parsed, dict):
                data = parsed
        except ValueError as exc:
            _logger.debug("Failed to parse npm metadata for %s: %s", package_name, exc)
    _NPM_LATEST_CACHE[cache_key] = data
    return data


async def _get_pypi_info_doc(package_name: str, client: httpx.AsyncClient) -> dict | None:
    """Return cached PyPI `info` JSON for a package."""
    cache_key = package_name.lower()
    if cache_key in _PYPI_INFO_CACHE:
        return _PYPI_INFO_CACHE[cache_key]

    response = await request_with_retry(
        client,
        "GET",
        f"{PYPI_API}/{package_name}/json",
    )
    info: dict | None = None
    if response and response.status_code == 200:
        try:
            parsed = response.json()
            maybe_info = parsed.get("info", {}) if isinstance(parsed, dict) else {}
            if isinstance(maybe_info, dict):
                info = maybe_info
        except ValueError as exc:
            _logger.debug("Failed to parse PyPI metadata for %s: %s", package_name, exc)
    _PYPI_INFO_CACHE[cache_key] = info
    return info


async def resolve_npm_metadata(
    package_name: str,
    client: httpx.AsyncClient,
) -> tuple[Optional[str], Optional[str]]:
    """Return (version, license) from npm registry."""
    data = await _get_npm_latest_doc(package_name, client)
    if data:
        version = data.get("version")
        lic = data.get("license")
        # license can be a string or {"type": "MIT"} object
        if isinstance(lic, dict):
            lic = lic.get("type")
        return version, lic if isinstance(lic, str) else None
    return None, None


async def resolve_npm_supply_chain(
    pkg: Package,
    client: httpx.AsyncClient,
) -> None:
    """Enrich a Package with npm registry supply chain metadata."""
    data = await _get_npm_latest_doc(pkg.name, client)
    if not data:
        return
    try:
        if not pkg.description:
            pkg.description = (data.get("description") or "")[:300] or None
        if not pkg.homepage:
            pkg.homepage = data.get("homepage") or None
        if not pkg.repository_url:
            repo = data.get("repository")
            if isinstance(repo, dict):
                pkg.repository_url = repo.get("url")
            elif isinstance(repo, str):
                pkg.repository_url = repo
        if not pkg.author:
            author = data.get("author")
            if isinstance(author, dict):
                pkg.author = author.get("name")
            elif isinstance(author, str):
                pkg.author = author
    except (ValueError, KeyError) as exc:
        _logger.debug("Failed to parse npm supply chain metadata for %s: %s", pkg.name, exc)


async def resolve_pypi_metadata(
    package_name: str,
    client: httpx.AsyncClient,
) -> tuple[Optional[str], Optional[str]]:
    """Return (version, license) from PyPI."""
    info = await _get_pypi_info_doc(package_name, client)
    if info:
        version = info.get("version")
        lic = info.get("license")
        # PyPI license can be empty string, "UNKNOWN", or full license text.
        # Prefer the SPDX classifier; fall back to first line of license field.
        if lic and lic.upper() not in ("UNKNOWN", ""):
            # If license field is multi-line (full text), extract SPDX from classifiers
            if "\n" in lic or len(lic) > 120:
                classifiers = info.get("classifiers") or []
                for c in classifiers:
                    if c.startswith("License :: OSI Approved :: "):
                        lic = c.split(" :: ")[-1]
                        break
                else:
                    # No classifier — take first line, capped
                    lic = lic.split("\n", 1)[0][:80]
            return version, lic
        return version, None
    return None, None


async def resolve_pypi_supply_chain(
    pkg: Package,
    client: httpx.AsyncClient,
) -> None:
    """Enrich a Package with PyPI supply chain metadata."""
    info = await _get_pypi_info_doc(pkg.name, client)
    if not info:
        return
    try:
        if not pkg.description:
            pkg.description = (info.get("summary") or "")[:300] or None
        if not pkg.homepage:
            pkg.homepage = info.get("home_page") or info.get("project_url") or None
            # Fall back to project_urls
            if not pkg.homepage:
                urls = info.get("project_urls") or {}
                pkg.homepage = urls.get("Homepage") or urls.get("Home") or None
        if not pkg.repository_url:
            urls = info.get("project_urls") or {}
            pkg.repository_url = urls.get("Repository") or urls.get("Source") or urls.get("Source Code") or urls.get("GitHub") or None
        if not pkg.author:
            pkg.author = info.get("author") or info.get("author_email") or None
        if not pkg.supplier:
            pkg.supplier = info.get("maintainer") or None
    except (ValueError, KeyError) as exc:
        _logger.debug("Failed to parse PyPI supply chain metadata for %s: %s", pkg.name, exc)


async def resolve_package_version(pkg: Package, client: httpx.AsyncClient) -> bool:
    if pkg.version not in _INVALID_VERSIONS - {"{{VERSION}}"}:
        return False
    version, lic = None, None
    if pkg.ecosystem == "npm":
        version, lic = await resolve_npm_metadata(pkg.name, client)
    elif pkg.ecosystem == "pypi":
        version, lic = await resolve_pypi_metadata(pkg.name, client)
    elif pkg.ecosystem == "go":
        from agent_bom.version_utils import resolve_go_metadata

        version, lic = await resolve_go_metadata(pkg.name, client)
    elif pkg.ecosystem == "cargo":
        from agent_bom.version_utils import resolve_cargo_metadata

        version, lic = await resolve_cargo_metadata(pkg.name, client)
    elif pkg.ecosystem == "conda":
        # Conda packages often have PyPI equivalents — try PyPI resolution
        version, lic = await resolve_pypi_metadata(pkg.name, client)
    elif pkg.ecosystem == "maven" and ":" in pkg.name:
        from agent_bom.version_utils import resolve_maven_metadata

        group, artifact = pkg.name.split(":", 1)
        version, lic = await resolve_maven_metadata(group, artifact, client)
    if version:
        pkg.version = version
        pkg.purl = f"pkg:{pkg.ecosystem}/{pkg.name}@{version}"
        if lic and not pkg.license:
            pkg.license = lic
        return True
    return _apply_registry_version_fallback(pkg)


async def enrich_licenses(packages: list[Package], client: httpx.AsyncClient) -> int:
    """Fetch license info for packages that already have a version but no license.

    Tries npm/PyPI registries first, then falls back to deps.dev for other ecosystems.
    """
    need_license = [p for p in packages if not p.license and p.version not in ("latest", "unknown", "")]
    if not need_license:
        return 0
    count = 0
    deps_dev_batch = []
    for pkg in need_license:
        _, lic = None, None
        if pkg.ecosystem == "npm":
            _, lic = await resolve_npm_metadata(pkg.name, client)
        elif pkg.ecosystem == "pypi":
            _, lic = await resolve_pypi_metadata(pkg.name, client)
        else:
            # Queue for deps.dev fallback (go, cargo, maven, nuget)
            deps_dev_batch.append(pkg)
            continue
        if lic:
            pkg.license = lic
            count += 1

    # deps.dev fallback for non-npm/non-pypi ecosystems
    if deps_dev_batch:
        try:
            from agent_bom.deps_dev import get_package_info

            for pkg in deps_dev_batch:
                info = await get_package_info(pkg.ecosystem, pkg.name, pkg.version, client)
                if info:
                    licenses = info.get("licenses", [])
                    spdx_ids = [lic for lic in licenses if isinstance(lic, str) and lic]
                    if spdx_ids:
                        pkg.license = spdx_ids[0]
                        if len(spdx_ids) > 1:
                            pkg.license_expression = " AND ".join(spdx_ids)
                        else:
                            pkg.license_expression = spdx_ids[0]
                        count += 1
        except ImportError:
            pass  # deps_dev module not available — skip gracefully

    return count


async def enrich_supply_chain_metadata(
    packages: list[Package],
    client: httpx.AsyncClient,
) -> int:
    """Enrich packages with supply chain metadata (description, homepage, repo, author).

    Fetches from npm/PyPI registries for those ecosystems; skips packages that
    already have metadata populated (e.g., from SBOM ingestion).

    Returns count of packages enriched.
    """
    need_meta = [p for p in packages if not p.description and p.version not in ("latest", "unknown", "") and p.ecosystem in ("npm", "pypi")]
    if not need_meta:
        return 0

    count = 0
    for pkg in need_meta:
        try:
            if pkg.ecosystem == "npm":
                await resolve_npm_supply_chain(pkg, client)
            elif pkg.ecosystem == "pypi":
                await resolve_pypi_supply_chain(pkg, client)
            if pkg.description or pkg.homepage or pkg.repository_url:
                count += 1
        except Exception as exc:  # noqa: BLE001
            _logger.warning("Failed to enrich supply chain metadata for %s@%s: %s", pkg.name, pkg.version, exc)
            continue
    return count


async def resolve_all_versions(
    packages: list[Package],
    *,
    quiet: bool = False,
    global_timeout: float = 30.0,
) -> int:
    """Resolve unresolved package versions from registries.

    Args:
        packages: Packages to resolve.
        quiet: Suppress console output.
        global_timeout: Max total seconds for all resolution (prevents hangs).
    """
    unresolved = [p for p in packages if p.version in ("latest", "unknown", "")]
    if not unresolved:
        return 0
    resolved_count = 0
    groups: dict[tuple[str, str], list[Package]] = defaultdict(list)
    for pkg in unresolved:
        groups[_resolution_key(pkg)].append(pkg)
    representatives = [members[0] for members in groups.values()]
    try:
        async with create_client(timeout=10.0) as client:
            semaphore = asyncio.Semaphore(_RESOLVE_CONCURRENCY)

            async def _resolve_with_limit(pkg: Package) -> bool:
                async with semaphore:
                    return await resolve_package_version(pkg, client)

            tasks = {asyncio.create_task(_resolve_with_limit(pkg)): pkg for pkg in representatives}
            done, pending = await asyncio.wait(tasks.keys(), timeout=global_timeout)

            for task in done:
                pkg = tasks[task]
                peers = groups[_resolution_key(pkg)]
                result: bool | Exception
                try:
                    result = task.result()
                except Exception as exc:  # noqa: BLE001
                    result = exc
                if result is True:
                    peer_resolved = 0
                    for peer in peers:
                        if peer is pkg:
                            peer_resolved += 1
                            continue
                        if _copy_resolution_fields(pkg, peer):
                            peer_resolved += 1
                    resolved_count += peer_resolved
                    if not quiet:
                        lic_tag = ""
                        if pkg.license:
                            short_lic = (pkg.license or "").split("\n", 1)[0][:60]
                            lic_tag = f" ({short_lic})"
                        icon = "[green]✓[/green]"
                        note = ""
                        if pkg.version_source == "registry_fallback":
                            icon = "[yellow]↺[/yellow]"
                            note = " [dim](bundled registry fallback)[/dim]"
                        peer_note = f" [dim](applied to {len(peers)} package entries)[/dim]" if len(peers) > 1 else ""
                        console.print(f"  {icon} Resolved {pkg.name} → {pkg.version}{lic_tag}{note}{peer_note}")
                elif isinstance(result, Exception):
                    if not quiet:
                        console.print(f"  [yellow]⚠[/yellow] Failed to resolve {pkg.name}: {result}")
                elif not quiet:
                    console.print(f"  [yellow]⚠[/yellow] Could not resolve {pkg.name} from live registries")

            for task in pending:
                pkg = tasks[task]
                peers = groups[_resolution_key(pkg)]
                task.cancel()
                group_fallbacks = 0
                if _apply_registry_version_fallback(pkg):
                    group_fallbacks += 1
                for peer in peers:
                    if peer is pkg:
                        continue
                    if not _copy_resolution_fields(pkg, peer):
                        if _apply_registry_version_fallback(peer):
                            group_fallbacks += 1
                    else:
                        group_fallbacks += 1
                if group_fallbacks:
                    resolved_count += group_fallbacks
                    if not quiet:
                        console.print(
                            f"  [yellow]↺[/yellow] Resolved {pkg.name} → {pkg.version} "
                            f"[dim](bundled registry fallback after timeout"
                            f"{'; applied to ' + str(len(peers)) + ' package entries' if len(peers) > 1 else ''})[/dim]"
                        )
            if pending:
                await asyncio.gather(*pending, return_exceptions=True)

            # Enrich licenses for packages that already had versions
            lic_count = await enrich_licenses(packages, client)
            if lic_count and not quiet:
                console.print(f"  [green]✓[/green] Enriched {lic_count} package license(s)")

            unresolved_after = [p for p in unresolved if p.version in ("latest", "unknown", "")]
            if unresolved_after and not quiet:
                fallback_count = sum(1 for p in unresolved if p.version_source == "registry_fallback")
                console.print(
                    "  [yellow]⚠[/yellow] Some package versions remain unresolved "
                    f"({len(unresolved_after)} package(s)); scan continues with explicit partial coverage"
                )
                if fallback_count:
                    console.print(
                        f"  [yellow]↺[/yellow] Preserved scan continuity for {fallback_count} package(s) using bundled registry versions"
                    )
    except asyncio.TimeoutError:
        _logger.warning(
            "Version resolution timed out after %.0fs (%d/%d resolved)",
            global_timeout,
            resolved_count,
            len(unresolved),
        )
        if not quiet:
            n_done, n_total = resolved_count, len(unresolved)
            console.print(
                f"  [yellow]⚠[/yellow] Version resolution timed out ({n_done}/{n_total} resolved) — scanning with available versions"
            )
    return resolved_count


def resolve_all_versions_sync(packages: list[Package], *, quiet: bool = False) -> int:
    return asyncio.run(resolve_all_versions(packages, quiet=quiet))


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
