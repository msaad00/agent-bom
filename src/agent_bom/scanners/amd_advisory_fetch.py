"""AMD PSIRT live-feed fetcher.

Scrapes the AMD product-security bulletin page and parses the structured
advisory data into the same ``_AMD_ADVISORY_SEED`` format consumed by
``amd_advisory.check_amd_advisories``.  Designed to refresh the static
seed without changing the scanner interface.

Usage (CLI / maintenance script)::

    python -m agent_bom.scanners.amd_advisory_fetch

This will print a refreshed ``_AMD_ADVISORY_SEED`` tuple to stdout that
can be pasted back into ``amd_advisory.py``.

AMD does not publish a CSAF 2.0 feed (unlike NVIDIA).  The source is the
JSON embedded in the advisory listing page at:
  https://www.amd.com/en/resources/product-security.html

The page loads bulletins from a public JSON endpoint that backs their
React table.  We fetch that endpoint and map it to our seed schema.
"""

from __future__ import annotations

import logging
import re
from typing import Any

logger = logging.getLogger(__name__)

# AMD PSIRT bulletin API — the web page fetches from this endpoint.
# Returns a JSON list of bulletin objects.
_AMD_PSIRT_JSON = "https://www.amd.com/en/resources/product-security.json"

# Fallback: AMD ROCm GitHub security advisories GraphQL endpoint
_ROCM_GHSA_URL = "https://api.github.com/repos/ROCm/ROCm/security-advisories"

# CVSS severity buckets matching AMD's own wording
_AMD_SEVERITY_MAP: dict[str, str] = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "moderate": "medium",
    "low": "low",
    "informational": "low",
}

# ROCm product → our product key (matches _AMD_PRODUCT_MAP in amd_advisory.py)
_PRODUCT_KEYWORD_MAP: dict[str, str] = {
    "rocm": "rocm",
    "hip": "hip runtime",
    "miopen": "miopen",
    "rocblas": "rocblas",
    "rocsolver": "rocsolver",
    "rccl": "rccl",
    "rocprim": "rocprim",
    "rocthrust": "rocthrust",
    "rocrand": "rocrand",
    "composable": "composablekernel",
    "triton": "pytorch-triton-rocm",
    "torch": "torch-rocm",
    "pytorch": "torch-rocm",
    "tensorflow": "tensorflow-rocm",
    "jax": "jax-rocm",
    "amd instinct": "rocm",
    "radeon": "rocm",
    "gpu": "rocm",
}

_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)


def _classify_products(title: str, description: str) -> list[str]:
    """Map bulletin title/description to our product keys."""
    text = (title + " " + description).lower()
    products: list[str] = []
    seen: set[str] = set()
    for keyword, product_key in _PRODUCT_KEYWORD_MAP.items():
        if keyword in text and product_key not in seen:
            products.append(product_key)
            seen.add(product_key)
    return products or ["rocm"]  # default to rocm if we can't classify


def _cvss_to_severity(cvss: float | None, label: str) -> str:
    if label:
        mapped = _AMD_SEVERITY_MAP.get(label.lower().strip())
        if mapped:
            return mapped
    if cvss is None:
        return "medium"
    if cvss >= 9.0:
        return "critical"
    if cvss >= 7.0:
        return "high"
    if cvss >= 4.0:
        return "medium"
    return "low"


def _fetch_amd_psirt_json(timeout: int = 15) -> list[dict]:
    """Fetch AMD PSIRT bulletin listing JSON.

    Returns a list of raw bulletin dicts.  Returns [] on any network or
    parse error so the caller can fall back to the static seed.
    """
    try:
        import httpx
    except ImportError:
        logger.debug("httpx not available — AMD live feed skipped")
        return []

    try:
        with httpx.Client(timeout=timeout, follow_redirects=True) as client:
            resp = client.get(_AMD_PSIRT_JSON)
            if resp.status_code != 200:
                logger.debug("AMD PSIRT JSON returned HTTP %d", resp.status_code)
                return []
            return resp.json() if isinstance(resp.json(), list) else resp.json().get("data", [])
    except Exception as exc:
        logger.debug("AMD PSIRT fetch error: %s", exc)
        return []


def _fetch_rocm_ghsa(token: str | None = None, timeout: int = 15) -> list[dict]:
    """Fetch ROCm GitHub security advisories as a supplement."""
    try:
        import httpx
    except ImportError:
        return []

    headers: dict[str, str] = {"Accept": "application/vnd.github+json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    try:
        with httpx.Client(timeout=timeout) as client:
            resp = client.get(_ROCM_GHSA_URL, headers=headers)
            if resp.status_code != 200:
                return []
            return resp.json() if isinstance(resp.json(), list) else []
    except Exception as exc:
        logger.debug("ROCm GHSA fetch error: %s", exc)
        return []


def _parse_psirt_bulletin(raw: dict[str, Any]) -> tuple | None:
    """Convert one AMD PSIRT bulletin to seed tuple format.

    Returns (cve_id, summary, severity_str, cvss_score, affected_products,
             fixed_version, references) or None if the bulletin lacks a CVE ID.
    """
    # AMD page uses varying key names — normalise
    title = str(raw.get("title", raw.get("bulletinTitle", ""))).strip()
    description = str(raw.get("description", raw.get("bulletinDescription", ""))).strip()
    severity_lbl = str(raw.get("severity", raw.get("bulletinSeverity", ""))).strip()
    cvss_raw = raw.get("cvssScore", raw.get("cvss_score", raw.get("baseScore")))
    cve_raw = str(raw.get("cveId", raw.get("cve_id", raw.get("id", "")))).strip()
    ref_url = str(raw.get("url", raw.get("link", raw.get("bulletinUrl", "")))).strip()
    fixed_ver = str(raw.get("fixedVersion", raw.get("fixed_version", ""))).strip() or None

    # Extract CVE ID from various fields
    cve_id = cve_raw if _CVE_RE.match(cve_raw) else None
    if not cve_id:
        found = _CVE_RE.search(title + " " + description)
        cve_id = found.group(0).upper() if found else None
    if not cve_id:
        return None

    cvss_score: float | None = None
    try:
        cvss_score = float(cvss_raw) if cvss_raw is not None else None
    except (TypeError, ValueError):
        pass

    severity_str = _cvss_to_severity(cvss_score, severity_lbl)
    products = _classify_products(title, description)
    refs = [ref_url] if ref_url else ["https://www.amd.com/en/resources/product-security.html"]

    return (cve_id, description or title, severity_str, cvss_score, products, fixed_ver, refs)


def _parse_ghsa(raw: dict[str, Any]) -> tuple | None:
    """Convert one GitHub GHSA advisory to seed tuple format."""
    ghsa_id = raw.get("ghsa_id", "")
    summary = raw.get("summary", "")
    severity = raw.get("severity", "medium")
    cve_id_raw = raw.get("cve_id", "")
    refs = [raw.get("html_url", f"https://github.com/advisories/{ghsa_id}")]
    cvss_raw = (raw.get("cvss", {}) or {}).get("score")
    cvss_score: float | None = float(cvss_raw) if cvss_raw else None

    cve_id = cve_id_raw if cve_id_raw and _CVE_RE.match(cve_id_raw) else None
    if not cve_id:
        found = _CVE_RE.search(summary)
        cve_id = found.group(0).upper() if found else None

    identifier = cve_id or ghsa_id
    if not identifier:
        return None

    products = _classify_products(summary, "")
    severity_str = _AMD_SEVERITY_MAP.get(severity.lower(), "medium")
    return (identifier, summary, severity_str, cvss_score, products, None, refs)


def fetch_live_advisories(github_token: str | None = None) -> list[tuple]:
    """Fetch AMD PSIRT + ROCm GHSA advisories and return as seed tuples.

    Merges both sources, deduplicates by CVE/GHSA ID, and returns a list
    compatible with ``_AMD_ADVISORY_SEED`` in ``amd_advisory.py``.

    Returns [] on failure so callers can fall back to the static seed.
    """
    results: dict[str, tuple] = {}

    for raw in _fetch_amd_psirt_json():
        entry = _parse_psirt_bulletin(raw)
        if entry and entry[0] not in results:
            results[entry[0]] = entry

    for raw in _fetch_rocm_ghsa(token=github_token):
        entry = _parse_ghsa(raw)
        if entry and entry[0] not in results:
            results[entry[0]] = entry

    advisories = list(results.values())
    if advisories:
        logger.info("AMD live feed: fetched %d advisory entries", len(advisories))
    return advisories


def merge_with_seed(
    live: list[tuple],
    seed: list[tuple],
) -> list[tuple]:
    """Merge live advisories into the static seed.

    Live entries override seed entries with the same CVE ID; seed entries
    not present in the live feed are preserved (offline / air-gapped safety).
    """
    live_ids = {entry[0] for entry in live}
    merged = list(live)
    for entry in seed:
        if entry[0] not in live_ids:
            merged.append(entry)
    return merged


if __name__ == "__main__":
    import json
    import sys

    advisories = fetch_live_advisories()
    sys.stdout.write(json.dumps(advisories, indent=2, default=str) + "\n")
    sys.stdout.write(f"\n# {len(advisories)} advisories fetched\n")
