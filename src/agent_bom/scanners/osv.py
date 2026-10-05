"""OSV query and advisory helpers for scanner workflows."""

from __future__ import annotations

import asyncio
import logging
from typing import Any, Awaitable, Callable, Optional

from rich.console import Console

from agent_bom.config import SCANNER_BATCH_SIZE as _BATCH_SIZE
from agent_bom.config import SCANNER_OSV_BATCH_CONCURRENCY as OSV_BATCH_CONCURRENCY
from agent_bom.core.errors import (
    UpstreamError,
    UpstreamInvalidResponseError,
    UpstreamRateLimitedError,
)
from agent_bom.enrichment_posture import enrichment_source_available, record_enrichment_source
from agent_bom.http_client import OfflineModeError, create_client, request_with_retry
from agent_bom.models import Package
from agent_bom.package_utils import normalize_package_name
from agent_bom.scanners.osv_details import OSV_API_URL as OSV_API_URL
from agent_bom.scanners.osv_details import enrich_results_if_needed as enrich_results_if_needed
from agent_bom.scanners.osv_details import enrich_vuln_details as enrich_vuln_details
from agent_bom.scanners.osv_details import vuln_needs_enrichment as vuln_needs_enrichment
from agent_bom.scanners.upstream import upstream_request

_logger = logging.getLogger(__name__)

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


def ecosystem_matches(osv_ecosystem: str, query_ecosystem: str) -> bool:
    """Whether an OSV ``affected[].package.ecosystem`` matches the queried ecosystem.

    OSV advisories are frequently shared across ecosystems (a single GHSA can
    list npm, PyPI, NuGet, Maven … affected entries). When resolving a fix or
    matching an installed version we must only consider entries from the same
    ecosystem, otherwise a fix version from a different ecosystem's entry can
    bleed in (e.g. jQuery's npm ``3.4.0`` being reported as Django's PyPI fix).

    Returns True when either side is unknown (nothing to disqualify on), and
    compares on the base ecosystem so OSV release-suffixed ecosystems such as
    ``Debian:11`` or ``Alpine:v3.16`` still match their bare form.
    """
    if not osv_ecosystem or not query_ecosystem:
        return True
    osv_base = osv_ecosystem.split(":", 1)[0].strip().lower()
    query_base = query_ecosystem.split(":", 1)[0].strip().lower()
    if osv_base == query_base:
        return True
    # The queried ecosystem is often the internal code ("deb", "rpm", "conda")
    # while OSV uses its own name ("Debian:11", "Linux", "PyPI"). Map the query
    # code to its OSV ecosystem and compare on that base too.
    from agent_bom.scanners import ECOSYSTEM_MAP  # lazy: avoids import cycle

    mapped = ECOSYSTEM_MAP.get(query_base)
    if mapped and mapped.split(":", 1)[0].strip().lower() == osv_base:
        return True
    return False


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
    from agent_bom.version_utils import (
        compare_version_order,
        is_prerelease_version,
        version_in_range,
    )

    norm_inputs = candidate_package_names(package_name, ecosystem, source_package)
    prerelease_candidate: Optional[str] = None
    # ``same_branch_fix`` is the fix from the affected branch that actually
    # CONTAINS the installed version (introduced <= current < fixed); it is
    # preferred so a multi-branch advisory never advises a cross-branch jump
    # (e.g. urllib3 1.26.4 -> 1.26.18, not the 2.x fix 2.0.7). ``fallback_fix``
    # (earliest valid fix) is used only when no branch contains the version.
    same_branch_fix: Optional[str] = None
    fallback_fix: Optional[str] = None
    has_current = bool(current_version and current_version not in ("unknown", "latest", ""))

    def _consider_fallback(candidate: str) -> None:
        nonlocal fallback_fix
        if fallback_fix is None:
            fallback_fix = candidate
            return
        order = compare_version_order(candidate, fallback_fix, ecosystem)
        if order is not None and order < 0:
            fallback_fix = candidate

    for affected in vuln_data.get("affected", []):
        pkg = affected.get("package", {})
        pkg_name = pkg.get("name", "")
        if not pkg_name:
            _logger.debug("Skipping affected entry with empty package name in %s", vuln_data.get("id", "?"))
            continue
        osv_eco = pkg.get("ecosystem", ecosystem)
        if not ecosystem_matches(osv_eco, ecosystem):
            _logger.debug(
                "Skipping cross-ecosystem affected entry %s/%s (want %s) in %s",
                osv_eco,
                pkg_name,
                ecosystem,
                vuln_data.get("id", "?"),
            )
            continue
        osv_norm = normalize_package_name(pkg_name, osv_eco)
        if osv_norm not in norm_inputs:
            continue
        for rng in affected.get("ranges", []):
            introduced: Optional[str] = None
            for event in rng.get("events", []):
                if "introduced" in event:
                    introduced = event.get("introduced") or None
                    continue
                if "fixed" not in event:
                    continue
                fixed = event["fixed"]
                if not is_valid_fix_version(fixed):
                    continue
                try:
                    if has_current:
                        current_cmp = compare_version_order(current_version, fixed, ecosystem)
                        if current_cmp is not None and current_cmp > 0:
                            _logger.debug(
                                "Skipping fix %s < current %s for %s",
                                fixed,
                                current_version,
                                package_name,
                            )
                            continue
                    prerelease = is_prerelease_version(fixed, ecosystem)
                except Exception as exc:  # noqa: BLE001  # broad-except: per-ecosystem version grammars raise heterogeneous errors; falls back to plain ordering
                    _logger.debug("Version parse failed for %r: %s", fixed, exc)
                    if has_current:
                        current_cmp = compare_version_order(current_version, fixed, ecosystem)
                        if current_cmp is not None and current_cmp > 0:
                            continue
                    prerelease = False

                if prerelease:
                    if prerelease_candidate is None:
                        prerelease_candidate = fixed
                    continue

                if has_current and same_branch_fix is None and version_in_range(current_version, introduced, fixed, None, ecosystem):
                    same_branch_fix = fixed
                _consider_fallback(fixed)

    if same_branch_fix is not None:
        return same_branch_fix
    if fallback_fix is not None:
        return fallback_fix
    if allow_prerelease:
        return prerelease_candidate
    if prerelease_candidate:
        _logger.debug("Suppressing prerelease-only fix %s for %s", prerelease_candidate, package_name)
    return None


def _collect_batch_vulns(
    data: Any,
    batch_start: int,
    batch_len: int,
    pkg_index: dict[int, tuple[Package, str]],
    partial: dict[str, list[dict]],
    console: Console,
) -> None:
    """Merge one ``/v1/querybatch`` payload into ``partial``; raise on a malformed shape."""
    if not isinstance(data, dict):
        raise ValueError(f"unexpected payload type: {type(data).__name__}")
    osv_results = data.get("results")
    if not isinstance(osv_results, list):
        raise ValueError("OSV results must be an array")
    if len(osv_results) != batch_len:
        _logger.warning(
            "OSV batch response length mismatch: sent %d queries, got %d results. Some packages may have missed vulnerability detection.",
            batch_len,
            len(osv_results),
        )
        console.print(
            f"  [yellow]⚠[/yellow] OSV batch response length mismatch:"
            f" sent {batch_len} queries, got {len(osv_results)} results."
            f" [dim]Some packages may have missed vulnerability detection.[/dim]"
        )
    incomplete = len(osv_results) != batch_len
    for index, result in enumerate(osv_results[:batch_len]):
        if not isinstance(result, dict):
            raise ValueError("OSV result must be an object")
        if result.get("error") or result.get("next_page_token"):
            incomplete = True
        vulns = result.get("vulns", [])
        if not isinstance(vulns, list) or any(
            not isinstance(vuln, dict) or not isinstance(vuln.get("id"), str) or not vuln["id"].strip() for vuln in vulns
        ):
            raise ValueError("OSV vulnerabilities must contain advisory identifiers")
        pkg_match = pkg_index.get(batch_start + index)
        if not vulns or not pkg_match:
            continue
        pkg_obj = pkg_match[0]
        key = f"{pkg_obj.ecosystem.lower()}:{normalize_package_name(pkg_obj.name, pkg_obj.ecosystem)}@{pkg_obj.version}"
        existing = partial.setdefault(key, [])
        seen_ids = {item.get("id") for item in existing}
        for vuln in vulns:
            if vuln.get("id") not in seen_ids:
                existing.append(vuln)
                seen_ids.add(vuln.get("id"))
    if incomplete:
        # Retain observed findings, but never cache this incomplete batch.
        raise ValueError("OSV batch response is incomplete")


async def _cache_complete_results(
    cache: Any,
    packages_to_query: list[Package],
    results: dict[str, list[dict]],
    pkg_index: dict[int, tuple[Package, str]],
    completed_queries: set[int],
    osv_ecosystems_for_package: Callable[[Package], list[str]],
) -> None:
    """Cache a package only when every contributing query completed."""
    incomplete_packages = {
        (pkg.ecosystem.lower(), normalize_package_name(pkg.name, pkg.ecosystem), pkg.version)
        for index, (pkg, _name) in pkg_index.items()
        if index not in completed_queries
    }
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
        if (pkg.ecosystem.lower(), normalize_package_name(pkg.name, pkg.ecosystem), pkg.version) not in incomplete_packages
    ]
    await asyncio.to_thread(cache.put_many, cache_writes)


def _record_unavailable_osv(packages: list[Package], reason: str) -> None:
    """A skipped remote lookup must reach the same verdict gate as a failure."""
    from agent_bom.scanners.state import record_coverage_warning

    record_coverage_warning(
        {
            "kind": "remote_lookup_error",
            "release": "remote:osv",
            "ecosystems": sorted({pkg.ecosystem.lower() for pkg in packages}),
            "package_count": len(packages),
            "reasons": [reason],
        }
    )


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
        _record_unavailable_osv(packages_to_query, "circuit_open")
        return await enrich_results_if_needed_fn(results)

    lookup_errors: list[tuple[str, str, UpstreamError]] = []
    completed_queries: set[int] = set()
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
        batch_starts = list(range(0, len(queries), batch_size))
        batch_concurrency = max(1, min(OSV_BATCH_CONCURRENCY, len(batch_starts)))

        # Pipeline-wide rate-limit gate: a 429 in any batch closes it so every
        # other in-flight/queued batch pauses before its next request instead of
        # piling on while one batch backs off.
        rate_gate = asyncio.Event()
        rate_gate.set()

        async def _handle_batch_failure(failure: UpstreamError) -> None:
            record_enrichment_source("osv", "failure", error=failure.detail)
            if not isinstance(failure, UpstreamRateLimitedError):
                console.print(f"  [red]✗[/red] OSV API error: {failure.detail}")
                return
            pipeline_wait = min(failure.retry_after, _PIPELINE_429_BACKOFF) if failure.retry_after is not None else _PIPELINE_429_BACKOFF
            # Close the gate so every other batch holds before its next request;
            # only the first batch to hit 429 owns the sleep, concurrent 429s
            # just wait the pause out. The batch itself stays unenriched and is
            # reported as a lookup error, never silently dropped.
            if rate_gate.is_set():
                rate_gate.clear()
                console.print(f"  [yellow]⚠[/yellow] OSV rate limit (429) — pausing the OSV pipeline {pipeline_wait:.0f}s")
                _logger.warning("OSV rate limit hit after all retries; pausing pipeline %.0fs", pipeline_wait)
                try:
                    await asyncio.sleep(pipeline_wait)
                finally:
                    rate_gate.set()
            else:
                await rate_gate.wait()

        async def _process_batch(batch_start: int) -> tuple[dict[str, list[dict]], list[tuple[str, str, UpstreamError]]]:
            batch = queries[batch_start : batch_start + batch_size]
            partial: dict[str, list[dict]] = {}
            batch_errors: list[tuple[str, str, UpstreamError]] = []
            bump_scan_perf("osv_batches", 1)

            def _fail_batch(failure: UpstreamError) -> None:
                for idx in range(batch_start, min(batch_start + len(batch), len(queries))):
                    pkg_err = pkg_index.get(idx)
                    if pkg_err:
                        batch_errors.append((pkg_err[0].name, pkg_err[0].ecosystem, failure))

            async with semaphore:
                await rate_gate.wait()
                try:
                    response = await upstream_request("osv", request_with_retry_fn, client, "POST", OSV_BATCH_URL, json={"queries": batch})
                except UpstreamError as failure:
                    await _handle_batch_failure(failure)
                    _fail_batch(failure)
                    return partial, batch_errors

                try:
                    _collect_batch_vulns(response.json(), batch_start, len(batch), pkg_index, partial, console)
                    completed_queries.update(range(batch_start, batch_start + len(batch)))
                    record_enrichment_source("osv", "success")
                except (ValueError, KeyError, AttributeError, TypeError) as exc:
                    record_enrichment_source("osv", "failure", error=f"parse error: {type(exc).__name__}")
                    console.print("  [red]✗[/red] OSV returned an invalid or incomplete response")
                    _fail_batch(UpstreamInvalidResponseError("osv", f"parse error: {type(exc).__name__}"))
            return partial, batch_errors

        batch_sem = asyncio.Semaphore(batch_concurrency)

        async def _guarded_batch(batch_start: int) -> tuple[dict[str, list[dict]], list[tuple[str, str, UpstreamError]]]:
            async with batch_sem:
                return await _process_batch(batch_start)

        outcomes = await asyncio.gather(*(_guarded_batch(batch_start) for batch_start in batch_starts))
        for partial, batch_errors in outcomes:
            for key, vulns in partial.items():
                existing = results.setdefault(key, [])
                seen_ids = {item.get("id") for item in existing}
                for vuln in vulns:
                    if vuln.get("id") not in seen_ids:
                        existing.append(vuln)
                        seen_ids.add(vuln.get("id"))
            lookup_errors.extend(batch_errors)

        if batch_concurrency > 1 and len(batch_starts) > 1:
            bump_scan_perf("osv_parallel_batch_groups", len(batch_starts))

    await enrich_results_if_needed_fn(results)

    if cache:
        await _cache_complete_results(cache, packages_to_query, results, pkg_index, completed_queries, osv_ecosystems_for_package)

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
        # Structured signal so a caller can fail closed deterministically
        # instead of string-matching the warning above. A zero-vuln result for
        # a package whose remote lookup ERRORED is not evidence of anything.
        from agent_bom.scanners.state import record_coverage_warning

        record_coverage_warning(
            {
                "kind": "remote_lookup_error",
                "release": "remote:osv",
                "ecosystems": sorted({eco.lower() for _name, eco, _err in lookup_errors if eco}),
                "package_count": len(lookup_errors),
                "reasons": sorted({err.kind for _name, _eco, err in lookup_errors}),
            }
        )
        for pkg_name, eco, err in lookup_errors:
            _logger.info("  Lookup error: %s/%s — %s", eco, pkg_name, err.detail)
    return results
