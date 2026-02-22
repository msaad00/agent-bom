"""Snyk vulnerability enrichment — cross-reference packages against Snyk's intelligence feed.

Adds vulnerability data from Snyk as a supplement to OSV.dev findings.
Only adds CVEs not already found by OSV to avoid duplicates.

Requires: SNYK_TOKEN env var or --snyk-token flag + SNYK_ORG_ID.
API docs: https://docs.snyk.io/snyk-api
"""

from __future__ import annotations

import asyncio
import logging
import urllib.parse
from typing import Optional

from agent_bom.http_client import create_client, request_with_retry
from agent_bom.models import Package, Severity, Vulnerability

logger = logging.getLogger(__name__)

_API_BASE = "https://api.snyk.io"
_API_VERSION = "2024-01-23"


def _purl_for_package(pkg: Package) -> str | None:
    """Build a purl string for Snyk API lookup."""
    if pkg.purl:
        return pkg.purl
    if not pkg.name or not pkg.ecosystem:
        return None
    eco_map = {
        "npm": "npm",
        "pypi": "pypi",
        "PyPI": "pypi",
        "go": "golang",
        "cargo": "cargo",
        "maven": "maven",
        "nuget": "nuget",
        "gem": "gem",
    }
    eco = eco_map.get(pkg.ecosystem)
    if not eco:
        return None
    version = pkg.version if pkg.version not in ("unknown", "latest", "") else None
    if version:
        return f"pkg:{eco}/{pkg.name}@{version}"
    return f"pkg:{eco}/{pkg.name}"


def _severity_from_snyk(sev_str: str) -> Severity:
    """Map Snyk severity string to our Severity enum."""
    mapping = {
        "critical": Severity.CRITICAL,
        "high": Severity.HIGH,
        "medium": Severity.MEDIUM,
        "low": Severity.LOW,
    }
    return mapping.get(sev_str.lower(), Severity.MEDIUM)


async def fetch_snyk_issues(
    purl: str,
    client,
    token: str,
    org_id: str,
) -> list[dict]:
    """Fetch vulnerability issues for a package from Snyk REST API.

    Args:
        purl: Package URL (e.g. "pkg:npm/express@4.17.1")
        client: httpx.AsyncClient instance
        token: Snyk API token
        org_id: Snyk organization ID

    Returns:
        List of issue dicts with id, title, severity, cvss_score, cve_ids.
    """
    encoded_purl = urllib.parse.quote(purl, safe="")
    url = f"{_API_BASE}/rest/orgs/{org_id}/packages/{encoded_purl}/issues"
    headers = {"Authorization": f"token {token}"}
    params = {"version": _API_VERSION}

    resp = await request_with_retry(
        client, "GET", url,
        headers=headers, params=params,
    )

    if resp is None or resp.status_code != 200:
        if resp and resp.status_code == 404:
            return []  # Package not in Snyk DB
        logger.debug("Snyk API error for %s: %s", purl, resp.status_code if resp else "unreachable")
        return []

    data = resp.json()
    issues = []
    for item in data.get("data", []):
        attrs = item.get("attributes", {})
        issues.append({
            "id": item.get("id", ""),
            "title": attrs.get("title", ""),
            "severity": attrs.get("effective_severity_level", attrs.get("severity", "medium")),
            "cvss_score": attrs.get("cvss_score"),
            "cve_ids": [
                slot.get("value")
                for slot in attrs.get("slots", {}).get("references", [])
                if slot.get("type") == "cve"
            ] if isinstance(attrs.get("slots"), dict) else [],
        })

    return issues


async def enrich_with_snyk(
    packages: list[Package],
    token: str | None = None,
    org_id: str | None = None,
) -> int:
    """Cross-reference packages against Snyk vulnerability database.

    Only adds Snyk findings where the CVE ID is not already present on the
    package from OSV scanning. This prevents duplicate vulnerability entries.

    Args:
        packages: List of Package objects to enrich
        token: Snyk API token
        org_id: Snyk organization ID

    Returns:
        Count of new vulnerabilities added across all packages.
    """
    if not token or not org_id:
        logger.warning("Snyk enrichment requires both SNYK_TOKEN and SNYK_ORG_ID")
        return 0

    new_vuln_count = 0

    async with create_client(timeout=15.0) as client:
        for pkg in packages:
            purl = _purl_for_package(pkg)
            if not purl:
                continue

            existing_ids = {v.id.upper() for v in pkg.vulnerabilities}

            issues = await fetch_snyk_issues(purl, client, token, org_id)
            for issue in issues:
                # Check all CVE IDs associated with this Snyk issue
                cve_ids = issue.get("cve_ids", [])
                snyk_id = issue.get("id", "")

                # If any CVE already exists, skip
                already_known = False
                for cve_id in cve_ids:
                    if cve_id and cve_id.upper() in existing_ids:
                        already_known = True
                        break
                if snyk_id.upper() in existing_ids:
                    already_known = True

                if already_known:
                    continue

                # Add as new vulnerability
                vuln_id = cve_ids[0] if cve_ids else snyk_id
                if not vuln_id:
                    continue

                pkg.vulnerabilities.append(Vulnerability(
                    id=vuln_id,
                    summary=f"[Snyk] {issue.get('title', '')}",
                    severity=_severity_from_snyk(issue.get("severity", "medium")),
                    cvss_score=issue.get("cvss_score"),
                    references=[f"https://security.snyk.io/vuln/{snyk_id}"] if snyk_id else [],
                ))
                existing_ids.add(vuln_id.upper())
                new_vuln_count += 1

    return new_vuln_count


def enrich_with_snyk_sync(
    packages: list[Package],
    token: Optional[str] = None,
    org_id: Optional[str] = None,
) -> int:
    """Sync wrapper for enrich_with_snyk."""
    return asyncio.run(enrich_with_snyk(packages, token, org_id))
