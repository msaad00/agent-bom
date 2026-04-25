"""OSV query and advisory helpers for scanner workflows."""

from __future__ import annotations

import asyncio
import logging
from typing import Any, Awaitable, Callable, Optional

import httpx
from rich.console import Console

from agent_bom.config import SCANNER_BATCH_DELAY as BATCH_DELAY_SECONDS
from agent_bom.config import SCANNER_BATCH_SIZE as _BATCH_SIZE
from agent_bom.enrichment_posture import enrichment_source_available, record_enrichment_source
from agent_bom.http_client import OfflineModeError, create_client, request_with_retry
from agent_bom.models import Package
from agent_bom.package_utils import normalize_package_name

_logger = logging.getLogger(__name__)

OSV_API_URL = "https://api.osv.dev/v1"
OSV_BATCH_URL = f"{OSV_API_URL}/querybatch"
# Max pipeline-level pause when OSV returns persistent 429 after all per-request retries.
# Separate from per-request exponential backoff (http_client.py) — this pauses the
# whole batch queue so subsequent batches don't immediately hammer a throttled API.
_PIPELINE_429_BACKOFF = 60.0


def candidate_package_names(package_name: str, ecosystem: str = "", source_package: str | None = None) -> set[str]:
    """Normalized candidate package names for matching advisories."""
    names = {normalize_package_name(package_name, ecosystem)}
    if source_package:
        source_norm = normalize_package_name(source_package, ecosystem)
        if source_norm:
            names.add(source_norm)
    return names


def is_valid_fix_version(version: str) -> bool:
    """Check if a string looks like a usable package version."""
    if not version or not any(c.isdigit() for c in version):
        return False
    stripped = version.lstrip("v")
    if len(stripped) == 40 and all(c in "0123456789abcdef" for c in stripped):
        return False
    if 7 <= len(stripped) <= 12 and all(c in "0123456789abcdef" for c in stripped):
        return False
    return True


def package_lookup_names(pkg: Package) -> list[str]:
    """Lookup names for a package, preserving the primary package name first."""
    ordered: list[str] = []
    seen: set[str] = set()
    for name in pkg.lookup_names:
        norm = normalize_package_name(name, pkg.ecosystem)
        if norm and norm not in seen:
            ordered.append(norm)
            seen.add(norm)
    return ordered


def parse_fixed_version(
    vuln_data: dict,
    package_name: str,
    ecosystem: str = "",
    current_version: str = "",
    source_package: str | None = None,
    allow_prerelease: bool = False,
) -> Optional[str]:
    """Extract fixed version from OSV affected data."""
    from agent_bom.version_utils import compare_version_order, is_prerelease_version

    norm_inputs = candidate_package_names(package_name, ecosystem, source_package)
    prerelease_candidate: Optional[str] = None

    for affected in vuln_data.get("affected", []):
        pkg = affected.get("package", {})
        pkg_name = pkg.get("name", "")
        if not pkg_name:
            _logger.debug("Skipping affected entry with empty package name in %s", vuln_data.get("id", "?"))
            continue
        osv_eco = pkg.get("ecosystem", ecosystem)
        osv_norm = normalize_package_name(pkg_name, osv_eco)
        if osv_norm in norm_inputs:
            for rng in affected.get("ranges", []):
                for event in rng.get("events", []):
                    if "fixed" not in event:
                        continue
                    fixed = event["fixed"]
                    if not is_valid_fix_version(fixed):
                        continue
                    try:
                        if current_version and current_version not in ("unknown", "latest", ""):
                            current_cmp = compare_version_order(current_version, fixed, ecosystem)
                            if current_cmp is not None and current_cmp > 0:
                                _logger.debug(
                                    "Skipping fix %s < current %s for %s",
                                    fixed,
                                    current_version,
                                    package_name,
                                )
                                continue
                        if not is_prerelease_version(fixed, ecosystem):
                            return fixed
                        if prerelease_candidate is None:
                            prerelease_candidate = fixed
                    except Exception as exc:  # noqa: BLE001
                        _logger.debug("Version parse failed for %r: %s", fixed, exc)
                        if current_version and current_version not in ("unknown", "latest", ""):
                            current_cmp = compare_version_order(current_version, fixed, ecosystem)
                            if current_cmp is not None and current_cmp > 0:
                                continue
                        if not is_prerelease_version(fixed, ecosystem):
                            return fixed
    if allow_prerelease:
        return prerelease_candidate
    if prerelease_candidate:
        _logger.debug("Suppressing prerelease-only fix %s for %s", prerelease_candidate, package_name)
    return None


async def enrich_vuln_details(
    client: httpx.AsyncClient,
    vuln_ids: list[str],
    *,
    request_with_retry_fn: Callable[..., Awaitable[Any]] = request_with_retry,
) -> dict[str, dict]:
    """Fetch full vulnerability details from OSV /v1/vulns/{id}."""
    if not vuln_ids:
        return {}

    sem = asyncio.Semaphore(10)

    async def _fetch_one(vid: str) -> tuple[str, dict]:
        async with sem:
            resp = await request_with_retry_fn(client, "GET", f"{OSV_API_URL}/vulns/{vid}")
            if resp and resp.status_code == 200:
                try:
                    return vid, resp.json()
                except (ValueError, KeyError):
                    pass
        return vid, {}

    pairs = await asyncio.gather(*[_fetch_one(vid) for vid in vuln_ids])
    return dict(pairs)


async def enrich_results_if_needed(
    results: dict[str, list[dict]],
    *,
    console: Console,
    record_scan_warning: Callable[[str], None],
    create_client_fn: Callable[..., Any] = create_client,
    request_with_retry_fn: Callable[..., Awaitable[Any]] = request_with_retry,
) -> dict[str, list[dict]]:
    """Enrich minimal OSV batch results with full vuln details where missing."""
    if not results:
        return results
    all_vuln_ids: list[str] = []
    for vuln_list in results.values():
        for vuln in vuln_list:
            if "summary" not in vuln and vuln.get("id"):
                all_vuln_ids.append(vuln["id"])
    unique_ids = list(dict.fromkeys(all_vuln_ids))
    if not unique_ids:
        return results
    try:
        async with create_client_fn(timeout=20.0) as detail_client:
            details_map = await enrich_vuln_details(
                detail_client,
                unique_ids,
                request_with_retry_fn=request_with_retry_fn,
            )
        for key, vuln_list in results.items():
            results[key] = [{**v, **details_map.get(v.get("id", ""), {})} for v in vuln_list]
    except Exception as exc:  # noqa: BLE001
        _logger.warning("OSV detail enrichment skipped (vulnerability summaries may be incomplete): %s", exc)
        console.print(
            "  [yellow]⚠[/yellow] OSV detail enrichment skipped — vulnerability summaries may be incomplete."
            " [dim]Use --verbose for details.[/dim]"
        )
        record_scan_warning("OSV detail enrichment skipped")
    return results


async def query_osv_batch_impl(
    packages: list[Package],
    *,
    console: Console,
    get_scan_cache: Callable[[], Any],
    get_api_semaphore: Callable[[], asyncio.Semaphore],
    bump_scan_perf: Callable[[str, int], None],
    enrich_results_if_needed_fn: Callable[[dict[str, list[dict]]], Awaitable[dict[str, list[dict]]]],
    record_scan_warning: Callable[[str], None],
    osv_ecosystems_for_package: Callable[[Package], list[str]],
    non_osv_ecosystems: frozenset[str],
    create_client_fn: Callable[..., Any] = create_client,
    request_with_retry_fn: Callable[..., Awaitable[Any]] = request_with_retry,
) -> dict[str, list[dict]]:
    """Query OSV API for vulnerabilities in batch."""
    if not packages:
        return {}

    cache = get_scan_cache()
    results: dict[str, list[dict]] = {}
    packages_to_query: list[Package] = []
    skipped_versions = 0
    skipped_ecosystems: dict[str, int] = {}

    for pkg in packages:
        eco_key = pkg.ecosystem.lower()
        osv_ecosystems = osv_ecosystems_for_package(pkg)
        if not osv_ecosystems:
            if eco_key in non_osv_ecosystems:
                _logger.debug(
                    "Skipping package %s/%s: ecosystem %r is not OSV-queryable (handled by other pipeline)",
                    pkg.ecosystem,
                    pkg.name,
                    pkg.ecosystem,
                )
            else:
                _logger.warning(
                    "Skipping package %s/%s: unknown ecosystem %r — add to ECOSYSTEM_MAP or _NON_OSV_ECOSYSTEMS",
                    pkg.ecosystem,
                    pkg.name,
                    pkg.ecosystem,
                )
            skipped_ecosystems[eco_key] = skipped_ecosystems.get(eco_key, 0) + 1
            bump_scan_perf("skipped_non_osv_ecosystems", 1)
            continue
        if not pkg.version or pkg.version in ("unknown", "latest"):
            _logger.warning(
                "Skipping package %s/%s: unresolvable version %r",
                pkg.ecosystem,
                pkg.name,
                pkg.version,
            )
            skipped_versions += 1
            bump_scan_perf("skipped_unresolvable_versions", 1)
            continue
        norm_name = normalize_package_name(pkg.name, eco_key)
        cache_key_eco = eco_key if len(osv_ecosystems) == 1 else f"{eco_key}|{'|'.join(osv_ecosystems)}"
        if cache:
            cached = cache.get(cache_key_eco, norm_name, pkg.version)
            if cached is not None:
                bump_scan_perf("osv_cache_hits", 1)
                if cached:
                    key = f"{eco_key}:{norm_name}@{pkg.version}"
                    results[key] = cached
                    bump_scan_perf("osv_cache_hits_with_vulns", 1)
                else:
                    bump_scan_perf("osv_cache_hits_clean", 1)
                continue
        bump_scan_perf("osv_cache_misses", 1)
        packages_to_query.append(pkg)

    if not packages_to_query:
        total_skipped_eco = sum(skipped_ecosystems.values())
        scanned = len(packages) - skipped_versions - total_skipped_eco
        if skipped_versions or skipped_ecosystems:
            _logger.info(
                "Scan complete: %d packages scanned, %d skipped (unresolvable versions), %d skipped (non-OSV ecosystem)",
                scanned,
                skipped_versions,
                total_skipped_eco,
            )
        if skipped_ecosystems:
            parts = ", ".join(f"{eco}: {cnt}" for eco, cnt in sorted(skipped_ecosystems.items()))
            console.print(f"  [dim]Skipped {total_skipped_eco} packages not in OSV database ({parts})[/dim]")
        return await enrich_results_if_needed_fn(results)

    queries = []
    pkg_index: dict[int, tuple[Package, str]] = {}

    for pkg in packages_to_query:
        eco_key = pkg.ecosystem.lower()
        osv_ecosystems = osv_ecosystems_for_package(pkg)
        if not osv_ecosystems or pkg.version in ("unknown", "latest"):
            continue

        osv_version = f"v{pkg.version}" if eco_key == "go" and not pkg.version.startswith("v") else pkg.version
        for osv_ecosystem in osv_ecosystems:
            for norm_name in package_lookup_names(pkg):
                queries.append(
                    {
                        "version": osv_version,
                        "package": {
                            "name": norm_name,
                            "ecosystem": osv_ecosystem,
                        },
                    }
                )
                pkg_index[len(queries) - 1] = (pkg, norm_name)

    if not queries:
        return await enrich_results_if_needed_fn(results)
    bump_scan_perf("osv_packages_queried", len(packages_to_query))
    bump_scan_perf("osv_queries_sent", len(queries))

    if not enrichment_source_available("osv"):
        _logger.warning("OSV enrichment circuit is open; skipping %d remote query item(s)", len(queries))
        console.print("  [yellow]⚠[/yellow] OSV enrichment circuit open — using cache/local data only")
        record_scan_warning("OSV enrichment circuit open")
        return await enrich_results_if_needed_fn(results)

    lookup_errors: list[tuple[str, str, str]] = []
    batch_size = min(_BATCH_SIZE, 1000)
    semaphore = get_api_semaphore()
    try:
        client_ctx = create_client_fn(timeout=30.0)
    except OfflineModeError:
        record_enrichment_source("osv", "failure", error="offline mode")
        _logger.info("Offline mode: skipping OSV batch query for %d packages", len(queries))
        console.print("  [yellow]⚠[/yellow] Offline mode — CVE scanning skipped. Use local DB or remove --offline.")
        record_scan_warning("offline mode skipped remote CVE lookups")
        bump_scan_perf("offline_skips", len(packages_to_query))
        return results

    async with client_ctx as client:
        for batch_start in range(0, len(queries), batch_size):
            batch = queries[batch_start : batch_start + batch_size]
            bump_scan_perf("osv_batches", 1)

            async with semaphore:
                response = await request_with_retry_fn(client, "POST", OSV_BATCH_URL, json={"queries": batch})

                if response and response.status_code == 200:
                    try:
                        data = response.json()
                        record_enrichment_source("osv", "success")
                        osv_results = data.get("results", [])
                        if len(osv_results) != len(batch):
                            _logger.warning(
                                "OSV batch response length mismatch: sent %d queries, got %d results. "
                                "Some packages may have missed vulnerability detection.",
                                len(batch),
                                len(osv_results),
                            )
                            console.print(
                                f"  [yellow]⚠[/yellow] OSV batch response length mismatch:"
                                f" sent {len(batch)} queries, got {len(osv_results)} results."
                                f" [dim]Some packages may have missed vulnerability detection.[/dim]"
                            )
                        for index, result in enumerate(osv_results):
                            if index >= len(batch):
                                break
                            vulns = result.get("vulns", [])
                            if not vulns:
                                continue
                            actual_idx = batch_start + index
                            pkg_match = pkg_index.get(actual_idx)
                            if not pkg_match:
                                continue
                            pkg_obj, _queried_name = pkg_match
                            norm = normalize_package_name(pkg_obj.name, pkg_obj.ecosystem)
                            key = f"{pkg_obj.ecosystem.lower()}:{norm}@{pkg_obj.version}"
                            existing = results.setdefault(key, [])
                            seen_ids = {item.get("id") for item in existing}
                            for vuln in vulns:
                                if vuln.get("id") not in seen_ids:
                                    existing.append(vuln)
                                    seen_ids.add(vuln.get("id"))
                    except (ValueError, KeyError) as exc:
                        record_enrichment_source("osv", "failure", error=f"parse error: {exc}")
                        console.print(f"  [red]✗[/red] OSV response parse error: {exc}")
                        for idx in range(batch_start, min(batch_start + len(batch), len(queries))):
                            pkg_err = pkg_index.get(idx)
                            if pkg_err:
                                lookup_errors.append((pkg_err[0].name, pkg_err[0].ecosystem, f"parse error: {exc}"))
                elif response and response.status_code == 429:
                    record_enrichment_source("osv", "failure", error="HTTP 429 rate limited")
                    retry_after_hdr = response.headers.get("Retry-After")
                    pipeline_wait = _PIPELINE_429_BACKOFF
                    if retry_after_hdr:
                        try:
                            pipeline_wait = min(float(retry_after_hdr), _PIPELINE_429_BACKOFF)
                        except ValueError:
                            pass
                    console.print(f"  [yellow]⚠[/yellow] OSV rate limit (429) — pausing {pipeline_wait:.0f}s before next batch")
                    _logger.warning("OSV rate limit hit after all retries; pausing pipeline %.0fs", pipeline_wait)
                    await asyncio.sleep(pipeline_wait)
                elif response:
                    record_enrichment_source("osv", "failure", error=f"HTTP {response.status_code}")
                    console.print(f"  [red]✗[/red] OSV API error: HTTP {response.status_code}")
                    for idx in range(batch_start, min(batch_start + len(batch), len(queries))):
                        pkg_err = pkg_index.get(idx)
                        if pkg_err:
                            lookup_errors.append((pkg_err[0].name, pkg_err[0].ecosystem, f"HTTP {response.status_code}"))
                else:
                    record_enrichment_source("osv", "failure", error="unreachable after retries")
                    console.print("  [red]✗[/red] OSV API unreachable after retries")
                    for idx in range(batch_start, min(batch_start + len(batch), len(queries))):
                        pkg_err = pkg_index.get(idx)
                        if pkg_err:
                            lookup_errors.append((pkg_err[0].name, pkg_err[0].ecosystem, "unreachable"))

            if batch_start + batch_size < len(queries):
                await asyncio.sleep(BATCH_DELAY_SECONDS)

    await enrich_results_if_needed_fn(results)

    if cache:
        cache_writes = [
            (
                pkg.ecosystem.lower()
                if len(osv_ecosystems_for_package(pkg)) == 1
                else f"{pkg.ecosystem.lower()}|{'|'.join(osv_ecosystems_for_package(pkg))}",
                normalize_package_name(pkg.name, pkg.ecosystem),
                pkg.version,
                results.get(f"{pkg.ecosystem.lower()}:{normalize_package_name(pkg.name, pkg.ecosystem)}@{pkg.version}", []),
            )
            for pkg in packages_to_query
        ]
        await asyncio.to_thread(cache.put_many, cache_writes)

    total_skipped_eco = sum(skipped_ecosystems.values())
    scanned = len(packages) - skipped_versions - total_skipped_eco
    if skipped_versions or skipped_ecosystems:
        _logger.info(
            "Scan complete: %d packages scanned, %d skipped (unresolvable versions), %d skipped (non-OSV ecosystem)",
            scanned,
            skipped_versions,
            total_skipped_eco,
        )
    if skipped_ecosystems:
        parts = ", ".join(f"{eco}: {cnt}" for eco, cnt in sorted(skipped_ecosystems.items()))
        console.print(f"  [dim]Skipped {total_skipped_eco} packages not in OSV database ({parts})[/dim]")
    if lookup_errors:
        bump_scan_perf("osv_lookup_errors", len(lookup_errors))
        _logger.warning(
            "%d packages had CVE lookup errors — vulnerability detection may be incomplete",
            len(lookup_errors),
        )
        console.print(f"  [yellow]⚠[/yellow] {len(lookup_errors)} packages had lookup errors [dim](use --verbose for details)[/dim]")
        record_scan_warning(f"{len(lookup_errors)} package lookup error(s)")
        for pkg_name, eco, err in lookup_errors:
            _logger.info("  Lookup error: %s/%s — %s", eco, pkg_name, err)
    return results
