"""Enrich vulnerabilities with NVD, EPSS, and CISA KEV data."""

from __future__ import annotations

import asyncio
import json
import logging
import time
from datetime import datetime
from pathlib import Path
from typing import Optional

import httpx
from rich.console import Console

from agent_bom.http_client import create_client, request_with_retry
from agent_bom.models import Vulnerability

console = Console(stderr=True)
_logger = logging.getLogger(__name__)

# API Endpoints
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
EPSS_API_URL = "https://api.first.org/data/v1/epss"
CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

# Cache for CISA KEV catalog (refresh daily)
_kev_cache: Optional[dict] = None
_kev_cache_time: Optional[datetime] = None

# ─── Persistent enrichment cache (NVD + EPSS) ──────────────────────────────

_ENRICHMENT_CACHE_DIR = Path.home() / ".agent-bom"
_ENRICHMENT_TTL = 604_800  # 7 days

# Module-level in-memory mirrors (loaded lazily from disk)
_nvd_file_cache: dict[str, dict] = {}
_epss_file_cache: dict[str, dict] = {}
_enrichment_cache_loaded = False


def _load_enrichment_cache() -> None:
    """Load NVD + EPSS caches from disk (once)."""
    global _nvd_file_cache, _epss_file_cache, _enrichment_cache_loaded  # noqa: PLW0603
    if _enrichment_cache_loaded:
        return
    _enrichment_cache_loaded = True
    now = time.time()
    for name, target in [("nvd_cache.json", "_nvd"), ("epss_cache.json", "_epss")]:
        path = _ENRICHMENT_CACHE_DIR / name
        if not path.exists():
            continue
        try:
            raw = json.loads(path.read_text())
            # Expire entries older than TTL
            fresh = {k: v for k, v in raw.items() if isinstance(v, dict) and (now - v.get("_cached_at", 0)) < _ENRICHMENT_TTL}
            if target == "_nvd":
                _nvd_file_cache.update(fresh)
            else:
                _epss_file_cache.update(fresh)
        except Exception:  # noqa: BLE001
            pass


def _save_enrichment_cache() -> None:
    """Persist NVD + EPSS caches to disk."""
    _ENRICHMENT_CACHE_DIR.mkdir(parents=True, exist_ok=True)
    for name, data in [("nvd_cache.json", _nvd_file_cache), ("epss_cache.json", _epss_file_cache)]:
        try:
            (_ENRICHMENT_CACHE_DIR / name).write_text(json.dumps(data))
        except Exception:  # noqa: BLE001
            _logger.debug("Failed to save %s cache", name)


async def fetch_nvd_data(cve_id: str, client: httpx.AsyncClient, api_key: Optional[str] = None) -> Optional[dict]:
    """Fetch CVE data from NVD API (with persistent file cache).

    Args:
        cve_id: CVE identifier (e.g., "CVE-2024-1234")
        client: HTTP client
        api_key: Optional NVD API key (recommended for higher rate limits)

    Returns:
        NVD vulnerability data or None if not found
    """
    _load_enrichment_cache()

    # Check persistent cache
    if cve_id in _nvd_file_cache:
        cached = _nvd_file_cache[cve_id]
        data = {k: v for k, v in cached.items() if k != "_cached_at"}
        return data if data else None

    headers = {}
    if api_key:
        headers["apiKey"] = api_key

    response = await request_with_retry(
        client,
        "GET",
        NVD_API_URL,
        params={"cveId": cve_id},
        headers=headers,
    )

    if response and response.status_code == 200:
        try:
            data = response.json()
            vulnerabilities = data.get("vulnerabilities", [])
            if vulnerabilities:
                result = vulnerabilities[0].get("cve", {})
                # Store in persistent cache
                _nvd_file_cache[cve_id] = {**result, "_cached_at": time.time()}
                return result
        except (ValueError, KeyError) as e:
            console.print(f"  [dim yellow]NVD parse error for {cve_id}: {e}[/dim yellow]")

    return None


async def fetch_epss_scores(cve_ids: list[str], client: httpx.AsyncClient) -> dict[str, dict]:
    """Fetch EPSS scores for multiple CVEs (with persistent file cache).

    EPSS (Exploit Prediction Scoring System) provides probability that a CVE
    will be exploited in the wild within the next 30 days.

    Args:
        cve_ids: List of CVE identifiers
        client: HTTP client

    Returns:
        Dictionary mapping CVE ID to EPSS data
    """
    if not cve_ids:
        return {}

    _load_enrichment_cache()

    scores: dict[str, dict] = {}
    uncached: list[str] = []

    # Check persistent cache first
    for cve_id in cve_ids:
        if cve_id in _epss_file_cache:
            cached = _epss_file_cache[cve_id]
            scores[cve_id] = {k: v for k, v in cached.items() if k != "_cached_at"}
        else:
            uncached.append(cve_id)

    if not uncached:
        return scores

    # EPSS API accepts comma-separated CVE list
    cve_param = ",".join(uncached[:100])  # Limit to 100 per request

    response = await request_with_retry(
        client,
        "GET",
        EPSS_API_URL,
        params={"cve": cve_param},
    )

    if response and response.status_code == 200:
        try:
            data = response.json()
            for item in data.get("data", []):
                cve = item.get("cve")
                if cve:
                    entry = {
                        "score": float(item.get("epss", 0.0)),
                        "percentile": float(item.get("percentile", 0.0)),
                        "date": item.get("date"),
                    }
                    scores[cve] = entry
                    _epss_file_cache[cve] = {**entry, "_cached_at": time.time()}
        except (ValueError, KeyError) as e:
            console.print(f"  [dim yellow]EPSS parse error: {e}[/dim yellow]")

    return scores


async def fetch_cisa_kev_catalog(client: httpx.AsyncClient) -> dict:
    """Fetch CISA Known Exploited Vulnerabilities catalog.

    CISA maintains a catalog of CVEs known to be actively exploited.
    These represent the highest priority vulnerabilities.

    Args:
        client: HTTP client

    Returns:
        Dictionary of KEV data indexed by CVE ID
    """
    global _kev_cache, _kev_cache_time

    # Use cache if less than 24 hours old
    if _kev_cache and _kev_cache_time:
        age = datetime.now() - _kev_cache_time
        if age.total_seconds() < 86400:  # 24 hours
            return _kev_cache

    response = await request_with_retry(client, "GET", CISA_KEV_URL)

    if response and response.status_code == 200:
        try:
            data = response.json()
            kev_dict = {}

            for vuln in data.get("vulnerabilities", []):
                cve_id = vuln.get("cveID")
                if cve_id:
                    kev_dict[cve_id] = {
                        "date_added": vuln.get("dateAdded"),
                        "due_date": vuln.get("dueDate"),
                        "short_description": vuln.get("shortDescription"),
                        "required_action": vuln.get("requiredAction"),
                        "vendor_project": vuln.get("vendorProject"),
                        "product": vuln.get("product"),
                    }

            _kev_cache = kev_dict
            _kev_cache_time = datetime.now()
            return kev_dict
        except (ValueError, KeyError) as e:
            console.print(f"  [dim yellow]CISA KEV parse error: {e}[/dim yellow]")

    return {}


def extract_cve_ids(vulnerabilities: list[Vulnerability]) -> list[str]:
    """Extract CVE IDs from vulnerability list (including aliases)."""
    cve_ids: set[str] = set()
    for vuln in vulnerabilities:
        if vuln.id.startswith("CVE-"):
            cve_ids.add(vuln.id)
        for alias in vuln.aliases:
            if alias.startswith("CVE-"):
                cve_ids.add(alias)
    return list(cve_ids)


def calculate_exploitability(epss_score: Optional[float]) -> Optional[str]:
    """Calculate exploitability level from EPSS score."""
    if epss_score is None:
        return None

    if epss_score >= 0.7:
        return "HIGH"
    elif epss_score >= 0.3:
        return "MEDIUM"
    else:
        return "LOW"


async def enrich_vulnerabilities(
    vulnerabilities: list[Vulnerability],
    nvd_api_key: Optional[str] = None,
    enable_nvd: bool = True,
    enable_epss: bool = True,
    enable_kev: bool = True,
) -> int:
    """Enrich vulnerabilities with NVD, EPSS, and CISA KEV data.

    Args:
        vulnerabilities: List of vulnerabilities to enrich
        nvd_api_key: Optional NVD API key for higher rate limits
        enable_nvd: Fetch NVD data (CWE, dates)
        enable_epss: Fetch EPSS exploit prediction scores
        enable_kev: Check CISA Known Exploited Vulnerabilities

    Returns:
        Number of vulnerabilities enriched
    """
    if not vulnerabilities:
        return 0

    cve_ids = extract_cve_ids(vulnerabilities)
    if not cve_ids:
        return 0

    console.print(f"\n[bold blue]🔬 Enriching {len(cve_ids)} CVE(s) with external data...[/bold blue]\n")

    enriched_count = 0

    async with create_client(timeout=30.0) as client:
        # Fetch EPSS scores (batch)
        epss_data = {}
        if enable_epss:
            console.print("  [cyan]→[/cyan] Fetching EPSS exploit prediction scores...")
            epss_data = await fetch_epss_scores(cve_ids, client)
            if epss_data:
                console.print(f"  [green]✓[/green] Retrieved EPSS data for {len(epss_data)} CVE(s)")

        # Fetch CISA KEV catalog (cached)
        kev_data = {}
        if enable_kev:
            console.print("  [cyan]→[/cyan] Checking CISA Known Exploited Vulnerabilities...")
            kev_data = await fetch_cisa_kev_catalog(client)
            kev_count = sum(1 for vuln in vulnerabilities if vuln.id in kev_data)
            if kev_count:
                console.print(f"  [red]⚠[/red] Found {kev_count} actively exploited CVE(s) in CISA KEV!")
            else:
                console.print("  [green]✓[/green] No CVEs in CISA KEV catalog")

        # Fetch NVD data — all CVEs with proper rate limiting
        # Limits: 5 req/30s without API key, 50 req/30s with API key
        nvd_data: dict[str, dict] = {}
        if enable_nvd and cve_ids:
            console.print(f"  [cyan]→[/cyan] Fetching NVD metadata for {len(cve_ids)} CVE(s)...")
            batch_size = 50 if nvd_api_key else 5
            sleep_secs = 1.0 if nvd_api_key else 6.0

            for batch_start in range(0, len(cve_ids), batch_size):
                batch = cve_ids[batch_start : batch_start + batch_size]
                tasks = [fetch_nvd_data(cve_id, client, nvd_api_key) for cve_id in batch]
                results = await asyncio.gather(*tasks, return_exceptions=True)
                for cve_id, result in zip(batch, results):
                    if result and not isinstance(result, Exception):
                        nvd_data[cve_id] = result
                if batch_start + batch_size < len(cve_ids):
                    await asyncio.sleep(sleep_secs)

            if nvd_data:
                console.print(f"  [green]✓[/green] Retrieved NVD data for {len(nvd_data)}/{len(cve_ids)} CVE(s)")

        # Enrich each vulnerability — match by primary ID or CVE aliases
        for vuln in vulnerabilities:
            # Collect all CVE IDs this vuln maps to (primary + aliases)
            vuln_cve_ids = []
            if vuln.id.startswith("CVE-"):
                vuln_cve_ids.append(vuln.id)
            for alias in vuln.aliases:
                if alias.startswith("CVE-"):
                    vuln_cve_ids.append(alias)

            if not vuln_cve_ids:
                continue

            # Apply EPSS data (use first matching CVE)
            for cve in vuln_cve_ids:
                if cve in epss_data:
                    epss = epss_data[cve]
                    vuln.epss_score = epss["score"]
                    vuln.epss_percentile = epss["percentile"]
                    vuln.exploitability = calculate_exploitability(epss["score"])
                    enriched_count += 1
                    break

            # Apply CISA KEV data
            for cve in vuln_cve_ids:
                if cve in kev_data:
                    kev = kev_data[cve]
                    vuln.is_kev = True
                    vuln.kev_date_added = kev["date_added"]
                    vuln.kev_due_date = kev["due_date"]
                    enriched_count += 1
                    break

            # Apply NVD data
            if enable_nvd:
                for cve in vuln_cve_ids:
                    if cve in nvd_data:
                        nvd = nvd_data[cve]

                        # Extract CWE IDs
                        weaknesses = nvd.get("weaknesses", [])
                        for weakness in weaknesses:
                            for desc in weakness.get("description", []):
                                if desc.get("value", "").startswith("CWE-"):
                                    vuln.cwe_ids.append(desc["value"])

                        # Extract dates
                        vuln.nvd_published = nvd.get("published")
                        vuln.nvd_modified = nvd.get("lastModified")
                        enriched_count += 1
                        break

    # Persist enrichment caches to disk
    _save_enrichment_cache()

    console.print(f"\n  [bold]Enriched {enriched_count} vulnerability data points.[/bold]")
    return enriched_count


def enrich_vulnerabilities_sync(
    vulnerabilities: list[Vulnerability],
    nvd_api_key: Optional[str] = None,
    enable_nvd: bool = True,
    enable_epss: bool = True,
    enable_kev: bool = True,
) -> int:
    """Synchronous wrapper for enrich_vulnerabilities."""
    return asyncio.run(
        enrich_vulnerabilities(
            vulnerabilities,
            nvd_api_key,
            enable_nvd,
            enable_epss,
            enable_kev,
        )
    )
