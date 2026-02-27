"""Supplemental NVIDIA security advisory enrichment.

Fetches CSAF 2.0 advisories from NVIDIA's product-security GitHub repo and
cross-references against GPU/ML packages found in scans.  This catches
NVIDIA CVEs that may not yet be indexed by OSV.dev's PyPI advisory database.
"""

from __future__ import annotations

import logging
import re

import httpx

from agent_bom.http_client import create_client, request_with_retry
from agent_bom.models import Package, Severity, Vulnerability

logger = logging.getLogger(__name__)

# GitHub raw URL for the NVIDIA product-security repo
_GITHUB_API = "https://api.github.com/repos/NVIDIA/product-security/contents"

# Map NVIDIA product names (from CSAF) to PyPI package prefixes.
# Advisory product names are lowercased for matching.
_NVIDIA_PRODUCT_MAP: dict[str, list[str]] = {
    "cuda toolkit": [
        "cuda-python",
        "nvidia-cuda-runtime-cu11",
        "nvidia-cuda-runtime-cu12",
        "nvidia-cuda-cupti-cu11",
        "nvidia-cuda-cupti-cu12",
        "nvidia-cuda-nvrtc-cu11",
        "nvidia-cuda-nvrtc-cu12",
        "nvidia-cublas-cu11",
        "nvidia-cublas-cu12",
        "nvidia-cusolver-cu11",
        "nvidia-cusolver-cu12",
        "nvidia-cusparse-cu11",
        "nvidia-cusparse-cu12",
        "nvidia-cufft-cu11",
        "nvidia-cufft-cu12",
        "nvidia-curand-cu11",
        "nvidia-curand-cu12",
        "nvidia-nvjitlink-cu12",
    ],
    "cudnn": [
        "nvidia-cudnn-cu11",
        "nvidia-cudnn-cu12",
    ],
    "nccl": [
        "nvidia-nccl-cu11",
        "nvidia-nccl-cu12",
    ],
    "tensorrt": [
        "tensorrt",
        "nvidia-tensorrt",
    ],
    "container toolkit": [
        "nvidia-container-toolkit",
    ],
    "nvjpeg": [],  # Not typically a PyPI package, but tracked for image scans
}

# Reverse map: PyPI package name → NVIDIA product names it belongs to
_PYPI_TO_NVIDIA: dict[str, list[str]] = {}
for _product, _packages in _NVIDIA_PRODUCT_MAP.items():
    for _pkg in _packages:
        _PYPI_TO_NVIDIA.setdefault(_pkg.lower().replace("-", "_"), []).append(_product)


def _normalise(name: str) -> str:
    """Normalise package name for comparison (lowercase, underscores)."""
    return name.lower().replace("-", "_")


def get_nvidia_products_for_package(pkg_name: str) -> list[str]:
    """Return NVIDIA product names that a PyPI package maps to."""
    return _PYPI_TO_NVIDIA.get(_normalise(pkg_name), [])


def _parse_csaf_severity(scores: list[dict]) -> tuple[Severity, float | None]:
    """Extract severity and CVSS score from CSAF scores array."""
    for score_entry in scores:
        cvss = score_entry.get("cvss_v3") or score_entry.get("cvss_v4") or {}
        base_score = cvss.get("baseScore")
        if base_score is not None:
            base_score = float(base_score)
            if base_score >= 9.0:
                return Severity.CRITICAL, base_score
            elif base_score >= 7.0:
                return Severity.HIGH, base_score
            elif base_score >= 4.0:
                return Severity.MEDIUM, base_score
            else:
                return Severity.LOW, base_score
    return Severity.MEDIUM, None


def _extract_fixed_version(vuln: dict) -> str | None:
    """Extract fixed version from CSAF product_status.fixed entries."""
    fixed = vuln.get("product_status", {}).get("fixed", [])
    if fixed:
        # Product IDs often contain version info like "CUDA Toolkit 12.9 Update 1"
        for product_id in fixed:
            m = re.search(r"(\d+\.\d+[\w. ]*)", str(product_id))
            if m:
                return m.group(1).strip()
    return None


async def fetch_nvidia_advisory_index(
    years: list[str] | None = None,
    client: httpx.AsyncClient | None = None,
) -> list[dict]:
    """Fetch the list of advisory folders from NVIDIA's GitHub repo.

    Returns list of dicts with 'name' and 'path' keys.
    Only fetches recent years by default.
    """
    if years is None:
        years = ["2025", "2026"]

    close_client = False
    if client is None:
        client = httpx.AsyncClient(timeout=15.0)
        close_client = True

    advisories = []
    try:
        for year in years:
            resp = await request_with_retry(
                client,
                "GET",
                f"{_GITHUB_API}/{year}",
                headers={"Accept": "application/vnd.github.v3+json"},
            )
            if resp and resp.status_code == 200:
                for item in resp.json():
                    if item.get("type") == "dir":
                        advisories.append(
                            {
                                "id": item["name"],
                                "path": item["path"],
                                "url": f"https://raw.githubusercontent.com/NVIDIA/product-security/main/{item['path']}/{item['name']}.json",
                            }
                        )
    finally:
        if close_client:
            await client.aclose()

    return advisories


async def fetch_nvidia_csaf(
    advisory_url: str,
    client: httpx.AsyncClient,
) -> dict | None:
    """Fetch a single NVIDIA CSAF advisory JSON."""
    resp = await request_with_retry(client, "GET", advisory_url)
    if resp and resp.status_code == 200:
        try:
            return resp.json()
        except (ValueError, KeyError):
            return None
    return None


def _csaf_affects_product(csaf: dict, product_names: set[str]) -> bool:
    """Check if a CSAF advisory affects any of the given NVIDIA product names."""
    title = (csaf.get("document", {}).get("title", "") or "").lower()
    for product in product_names:
        if product in title:
            return True
    # Also check product_tree branches
    for branch in csaf.get("product_tree", {}).get("branches", []):
        _name = (branch.get("name", "") or "").lower()
        for product in product_names:
            if product in _name:
                return True
        for sub in branch.get("branches", []):
            _sname = (sub.get("name", "") or "").lower()
            for product in product_names:
                if product in _sname:
                    return True
    return False


def extract_vulns_from_csaf(csaf: dict) -> list[Vulnerability]:
    """Extract Vulnerability objects from a CSAF advisory."""
    vulns = []
    for vuln_data in csaf.get("vulnerabilities", []):
        cve_id = vuln_data.get("cve", "")
        if not cve_id:
            continue

        severity, cvss_score = _parse_csaf_severity(vuln_data.get("scores", []))
        summary = ""
        for note in vuln_data.get("notes", []):
            if note.get("category") in ("description", "summary"):
                summary = note.get("text", "")[:200]
                break

        cwe = vuln_data.get("cwe", {})
        cwe_ids = [cwe["id"]] if cwe.get("id") else []

        fixed_version = _extract_fixed_version(vuln_data)

        refs = []
        for ref in vuln_data.get("references", []):
            url = ref.get("url", "")
            if url:
                refs.append(url)

        vulns.append(
            Vulnerability(
                id=cve_id,
                summary=summary or f"NVIDIA Security Advisory ({cve_id})",
                severity=severity,
                cvss_score=cvss_score,
                fixed_version=fixed_version,
                references=refs,
                cwe_ids=cwe_ids,
            )
        )
    return vulns


async def check_nvidia_advisories(
    packages: list[Package],
    max_advisories: int = 20,
) -> int:
    """Check NVIDIA packages against NVIDIA's security advisories.

    Fetches recent CSAF advisories from NVIDIA's GitHub repo and
    cross-references against the given packages.  Only processes
    advisories relevant to the NVIDIA products matching the packages.

    Returns count of new vulnerabilities found.
    """
    # Determine which NVIDIA products are relevant
    product_names: set[str] = set()
    pkg_by_product: dict[str, list[Package]] = {}
    for pkg in packages:
        products = get_nvidia_products_for_package(pkg.name)
        for product in products:
            product_names.add(product)
            pkg_by_product.setdefault(product, []).append(pkg)

    if not product_names:
        return 0

    logger.info("NVIDIA advisory check for products: %s", product_names)

    total_new = 0
    async with create_client(timeout=15.0) as client:
        # Fetch advisory index
        advisories = await fetch_nvidia_advisory_index(client=client)
        if not advisories:
            logger.debug("No NVIDIA advisories found")
            return 0

        # Process most recent advisories first (higher ID = more recent)
        advisories.sort(key=lambda a: a["id"], reverse=True)

        checked = 0
        for adv in advisories:
            if checked >= max_advisories:
                break

            csaf = await fetch_nvidia_csaf(adv["url"], client)
            if not csaf:
                continue

            checked += 1

            if not _csaf_affects_product(csaf, product_names):
                continue

            csaf_vulns = extract_vulns_from_csaf(csaf)
            if not csaf_vulns:
                continue

            # Assign vulnerabilities to matching packages (deduplicate by CVE ID)
            for product, pkgs in pkg_by_product.items():
                if product not in product_names:
                    continue
                # Check if this advisory affects this product
                if not _csaf_affects_product(csaf, {product}):
                    continue
                for pkg in pkgs:
                    existing_ids = {v.id for v in pkg.vulnerabilities}
                    for vuln in csaf_vulns:
                        if vuln.id not in existing_ids:
                            pkg.vulnerabilities.append(vuln)
                            existing_ids.add(vuln.id)
                            total_new += 1

    if total_new:
        logger.info("NVIDIA advisories: found %d new CVE(s)", total_new)

    return total_new
