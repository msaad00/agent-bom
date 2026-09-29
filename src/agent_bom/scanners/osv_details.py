"""OSV advisory-detail enrichment: fill querybatch stubs from ``/v1/vulns/{id}``."""

from __future__ import annotations

import asyncio
import logging
from typing import Any, Awaitable, Callable

import httpx
from rich.console import Console

from agent_bom.core.errors import DegradedCoverage, UpstreamError, UpstreamInvalidResponseError
from agent_bom.http_client import OfflineModeError, create_client, request_with_retry
from agent_bom.scanners.upstream import upstream_request

_logger = logging.getLogger(__name__)

OSV_API_URL = "https://api.osv.dev/v1"


async def enrich_vuln_details(
    client: httpx.AsyncClient,
    vuln_ids: list[str],
    *,
    request_with_retry_fn: Callable[..., Awaitable[Any]] = request_with_retry,
    errors: list[UpstreamError] | None = None,
) -> dict[str, dict]:
    """Fetch full vulnerability details from OSV /v1/vulns/{id}.

    A record that could not be fetched maps to ``{}``; when ``errors`` is given
    the typed cause of each such gap is appended to it. HTTP 404 is an answer
    (withdrawn advisory), not a gap.
    """
    if not vuln_ids:
        return {}

    sem = asyncio.Semaphore(10)
    failures: list[UpstreamError] = [] if errors is None else errors

    async def _fetch_one(vid: str) -> tuple[str, dict]:
        async with sem:
            try:
                resp = await upstream_request(
                    "osv", request_with_retry_fn, client, "GET", f"{OSV_API_URL}/vulns/{vid}", ok_statuses=frozenset({200, 404})
                )
                payload = resp.json() if resp.status_code == 200 else {}
            except UpstreamError as failure:
                failures.append(failure)
                return vid, {}
            except ValueError:
                payload = None
            if isinstance(payload, dict):
                return vid, payload
            failures.append(UpstreamInvalidResponseError("osv", "advisory detail is not a JSON object"))
        return vid, {}

    pairs = await asyncio.gather(*[_fetch_one(vid) for vid in vuln_ids])
    return dict(pairs)


def vuln_needs_enrichment(vuln: dict) -> bool:
    """Whether an OSV record must be enriched before fix/version resolution.

    The OSV ``/v1/querybatch`` endpoint returns minimal ``{id, modified}``
    stubs, and a partially-enriched record (e.g. one carrying only a
    ``summary`` from a prior run) can still be missing the ``affected`` block.
    Both ``parse_fixed_version`` and version-range matching need ``affected``
    with at least one ranges/versions entry, so gate enrichment on the presence
    of that resolution data rather than on the ``summary`` field. Keying off
    ``summary`` alone dropped fixes for records that had a summary but no
    ``affected`` and, because ``summary``-less advisories (e.g. PYSEC) were
    re-fetched every run, made the null-fix count nondeterministic across
    cache-cold and cache-warm runs.
    """
    if not vuln.get("id"):
        return False
    affected = vuln.get("affected")
    if not affected:
        return True
    return not any(isinstance(entry, dict) and (entry.get("ranges") or entry.get("versions")) for entry in affected)


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
            if vuln_needs_enrichment(vuln):
                all_vuln_ids.append(vuln["id"])
    # Deterministic order/dedup: the same set of ids is enriched regardless of
    # cache-cold vs cache-warm runs, so fix-version resolution is reproducible.
    unique_ids = sorted(dict.fromkeys(all_vuln_ids))
    if not unique_ids:
        return results
    detail_errors: list[UpstreamError] = []
    try:
        async with create_client_fn(timeout=20.0) as detail_client:
            details_map = await enrich_vuln_details(
                detail_client,
                unique_ids,
                request_with_retry_fn=request_with_retry_fn,
                errors=detail_errors,
            )
        for key, vuln_list in results.items():
            results[key] = [{**v, **details_map.get(v.get("id", ""), {})} for v in vuln_list]
    except (OfflineModeError, httpx.HTTPError, OSError) as exc:
        _logger.warning("OSV detail enrichment skipped (vulnerability summaries may be incomplete): %s", type(exc).__name__)
        console.print(
            "  [yellow]⚠[/yellow] OSV detail enrichment skipped — vulnerability summaries may be incomplete."
            " [dim]Use --verbose for details.[/dim]"
        )
        record_scan_warning("OSV detail enrichment skipped")
        return results
    degraded = DegradedCoverage.from_errors(
        "OSV advisory details",
        detail_errors,
        requested=len(unique_ids),
        missing=len(detail_errors),
        unit="advisory record(s)",
    )
    if degraded is not None:
        _logger.warning("%s", degraded.message())
        console.print(f"  [yellow]⚠[/yellow] {degraded.message()} — fix versions and summaries may be missing.")
        record_scan_warning(degraded.message())
    return results
