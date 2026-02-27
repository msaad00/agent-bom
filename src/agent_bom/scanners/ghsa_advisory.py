"""Supplemental GitHub Security Advisory (GHSA) enrichment.

Queries the public GitHub Advisory Database REST API to find advisories
that may not yet be indexed by OSV.dev.  Deduplicates by CVE ID against
existing package vulnerabilities.
"""

from __future__ import annotations

import asyncio
import logging

import httpx

from agent_bom.http_client import create_client, request_with_retry
from agent_bom.models import Package, Severity, Vulnerability

logger = logging.getLogger(__name__)

_GITHUB_ADVISORY_API = "https://api.github.com/advisories"

# Map internal ecosystem names to GitHub Advisory API ecosystem values
_ECOSYSTEM_MAP: dict[str, str] = {
    "pypi": "pip",
    "npm": "npm",
    "go": "go",
    "maven": "maven",
    "cargo": "rust",
    "nuget": "nuget",
    "rubygems": "rubygems",
}


def _parse_ghsa_severity(advisory: dict) -> tuple[Severity, float | None]:
    """Extract severity and CVSS score from a GHSA advisory."""
    cvss = advisory.get("cvss", {}) or {}
    score = cvss.get("score")
    sev_str = (advisory.get("severity") or "").upper()

    if score is not None:
        score = float(score)

    severity_map = {
        "CRITICAL": Severity.CRITICAL,
        "HIGH": Severity.HIGH,
        "MEDIUM": Severity.MEDIUM,
        "LOW": Severity.LOW,
    }
    severity = severity_map.get(sev_str, Severity.MEDIUM)
    return severity, score


def _extract_fixed_version(advisory: dict, package_name: str) -> str | None:
    """Extract the first patched version for a specific package."""
    for vuln in advisory.get("vulnerabilities", []):
        pkg = vuln.get("package", {})
        if pkg.get("name", "").lower() == package_name.lower():
            patched = vuln.get("patched_versions")
            if patched:
                # patched_versions is a range string like ">= 4.18.0"
                cleaned = patched.lstrip(">= ").split(",")[0].strip()
                if cleaned:
                    return cleaned
    return None


def _get_cwe_ids(advisory: dict) -> list[str]:
    """Extract CWE IDs from GHSA advisory."""
    cwes = advisory.get("cwes", []) or []
    return [c.get("cwe_id", "") for c in cwes if c.get("cwe_id")]


async def _fetch_advisories_for_package(
    pkg: Package,
    client: httpx.AsyncClient,
    semaphore: asyncio.Semaphore,
) -> list[dict]:
    """Fetch GitHub advisories for a single package."""
    eco = _ECOSYSTEM_MAP.get(pkg.ecosystem.lower(), "")
    if not eco:
        return []

    async with semaphore:
        await asyncio.sleep(1.0)  # Rate limit: stay under 60 req/hr
        resp = await request_with_retry(
            client,
            "GET",
            _GITHUB_ADVISORY_API,
            params={
                "ecosystem": eco,
                "package": pkg.name,
                "per_page": "30",
            },
            headers={"Accept": "application/vnd.github+json"},
        )
        if resp and resp.status_code == 200:
            try:
                return resp.json()
            except (ValueError, KeyError):
                return []
        return []


async def check_github_advisories(
    packages: list[Package],
    max_packages: int = 50,
) -> int:
    """Check packages against GitHub Security Advisories (GHSA).

    Queries the public GitHub Advisory Database REST API for each package,
    deduplicates by CVE ID against existing vulnerabilities, and appends
    any new findings.

    Returns count of new vulnerabilities found.
    """
    if not packages:
        return 0

    # Filter to supported ecosystems and deduplicate by name+ecosystem
    seen_keys: set[str] = set()
    queryable: list[Package] = []
    for pkg in packages:
        eco = _ECOSYSTEM_MAP.get(pkg.ecosystem.lower(), "")
        if not eco:
            continue
        key = f"{eco}:{pkg.name.lower()}"
        if key in seen_keys:
            continue
        seen_keys.add(key)
        queryable.append(pkg)

    if not queryable:
        return 0

    # Cap to avoid rate limit exhaustion
    queryable = queryable[:max_packages]

    logger.info("GHSA advisory check for %d packages", len(queryable))

    # Build a reverse lookup: all packages sharing the same name+ecosystem
    pkg_groups: dict[str, list[Package]] = {}
    for pkg in packages:
        eco = _ECOSYSTEM_MAP.get(pkg.ecosystem.lower(), "")
        if eco:
            key = f"{eco}:{pkg.name.lower()}"
            pkg_groups.setdefault(key, []).append(pkg)

    total_new = 0
    semaphore = asyncio.Semaphore(5)

    async with create_client(timeout=15.0) as client:
        tasks = [_fetch_advisories_for_package(p, client, semaphore) for p in queryable]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for i, result in enumerate(results):
            if isinstance(result, Exception):
                logger.debug("GHSA fetch failed for %s: %s", queryable[i].name, result)
                continue
            if not result:
                continue

            pkg = queryable[i]
            eco = _ECOSYSTEM_MAP.get(pkg.ecosystem.lower(), "")
            key = f"{eco}:{pkg.name.lower()}"
            target_pkgs = pkg_groups.get(key, [pkg])

            for advisory in result:
                ghsa_id = advisory.get("ghsa_id", "")
                cve_id = advisory.get("cve_id") or ""
                vuln_id = cve_id or ghsa_id
                if not vuln_id:
                    continue

                severity, cvss_score = _parse_ghsa_severity(advisory)
                summary = advisory.get("summary", "") or f"GitHub Advisory ({vuln_id})"
                cwe_ids = _get_cwe_ids(advisory)
                refs = [advisory.get("html_url", "")] if advisory.get("html_url") else []

                for target_pkg in target_pkgs:
                    # Verify this advisory actually affects the target package
                    # (GitHub API does substring matching, so "express" returns
                    # advisories for "express-session", "express-validator", etc.)
                    advisory_pkg_names = {v.get("package", {}).get("name", "").lower() for v in advisory.get("vulnerabilities", [])}
                    if target_pkg.name.lower() not in advisory_pkg_names:
                        continue

                    existing_ids = {v.id for v in target_pkg.vulnerabilities}
                    # Skip if CVE or GHSA ID already present
                    if vuln_id in existing_ids or (cve_id and cve_id in existing_ids) or (ghsa_id and ghsa_id in existing_ids):
                        continue

                    fixed = _extract_fixed_version(advisory, target_pkg.name)
                    vuln = Vulnerability(
                        id=vuln_id,
                        summary=summary[:200],
                        severity=severity,
                        cvss_score=cvss_score,
                        fixed_version=fixed,
                        references=refs,
                        cwe_ids=cwe_ids,
                    )
                    target_pkg.vulnerabilities.append(vuln)
                    total_new += 1

    if total_new:
        logger.info("GHSA advisories: found %d new CVE(s)", total_new)

    return total_new
