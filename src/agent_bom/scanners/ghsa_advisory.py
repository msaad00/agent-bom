"""Supplemental GitHub Security Advisory (GHSA) enrichment.

Queries the public GitHub Advisory Database REST API to find advisories
that may not yet be indexed by OSV.dev.  Deduplicates by CVE ID against
existing package vulnerabilities.
"""

from __future__ import annotations

import asyncio
import logging
import os
import time

import httpx

from agent_bom.enrichment_posture import record_enrichment_source
from agent_bom.http_client import create_client, request_with_retry
from agent_bom.models import Package, Severity, Vulnerability
from agent_bom.package_utils import normalize_package_name

logger = logging.getLogger(__name__)

_GITHUB_ADVISORY_API = "https://api.github.com/advisories"
_GHSA_PER_PAGE = 100
_GHSA_RATE_LIMIT_BACKOFF = 60.0
_GHSA_SINGLE_PACKAGE_RATE_LIMIT_BACKOFF = 0.0

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


class GHSARateLimitError(RuntimeError):
    """Raised when GitHub advisory lookups remain rate-limited after retry."""

    def __init__(self, retry_after: float) -> None:
        super().__init__("GitHub Advisory API rate limited")
        self.retry_after = retry_after


def _github_token() -> str:
    return os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN") or ""


def _ghsa_headers() -> dict[str, str]:
    headers = {"Accept": "application/vnd.github+json"}
    token = _github_token()
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def _rate_limit_retry_after(resp: httpx.Response, default: float = _GHSA_RATE_LIMIT_BACKOFF) -> float:
    retry_after = resp.headers.get("Retry-After")
    if retry_after:
        try:
            return min(float(retry_after), default)
        except ValueError:
            return default
    reset_at = resp.headers.get("X-RateLimit-Reset")
    if reset_at:
        try:
            return min(max(float(reset_at) - time.time(), 0.0), default)
        except ValueError:
            return default
    return default


def _is_rate_limited(resp: httpx.Response) -> bool:
    return resp.status_code == 429 or (resp.status_code == 403 and resp.headers.get("X-RateLimit-Remaining") == "0")


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
    severity = severity_map.get(sev_str, Severity.UNKNOWN)
    return severity, score


def _extract_fixed_version(advisory: dict, package_name: str, ecosystem: str = "") -> str | None:
    """Extract the first patched version for a specific package.

    Checks ``patched_versions`` first (older GHSA API format).  When that
    field is null (current API behaviour), falls back to
    ``vulnerable_version_range`` and extracts the exclusive upper bound for
    ``< X`` constraints (the fix version is X in that case).

    Uses PEP 503 normalization for PyPI so that mixed-separator forms like
    ``Requests_OAuthlib`` match a normalized input of ``requests-oauthlib``.
    """
    import re as _re

    norm_input = normalize_package_name(package_name, ecosystem)
    for vuln in advisory.get("vulnerabilities", []):
        pkg = vuln.get("package", {})
        pkg_eco = pkg.get("ecosystem", ecosystem)
        osv_norm = normalize_package_name(pkg.get("name", ""), pkg_eco)
        if osv_norm == norm_input:
            patched = vuln.get("patched_versions")
            if patched:
                return _parse_patched_range(patched)
            # patched_versions is null in current GHSA API responses —
            # attempt to derive the fix from an exclusive upper-bound range.
            vuln_range = vuln.get("vulnerable_version_range") or ""
            for part in vuln_range.split(","):
                part = part.strip()
                # "< X" → fix version is X (exclusive upper bound)
                if part.startswith("<") and not part.startswith("<="):
                    bound = part[1:].strip()
                    if bound and _re.match(r"\d", bound):
                        return bound
    return None


def _get_vulnerable_ranges_for_package(advisory: dict, package_name: str, ecosystem: str = "") -> list[str]:
    """Return all ``vulnerable_version_range`` strings for *package_name* in *advisory*.

    An advisory may have multiple entries for the same package covering disjoint version
    windows (e.g., "< 1.0" AND ">= 1.5, < 2.0").  All must be checked — affected if ANY
    range matches (OR semantics across entries).
    """
    norm_input = normalize_package_name(package_name, ecosystem)
    ranges: list[str] = []
    for vuln in advisory.get("vulnerabilities", []):
        pkg = vuln.get("package", {})
        pkg_eco = pkg.get("ecosystem", ecosystem)
        osv_norm = normalize_package_name(pkg.get("name", ""), pkg_eco)
        if osv_norm == norm_input:
            r = vuln.get("vulnerable_version_range")
            if r:
                ranges.append(r)
    return ranges


# Kept for backwards compatibility with any external callers.
def _get_vulnerable_range_for_package(advisory: dict, package_name: str, ecosystem: str = "") -> str | None:
    """Return the first ``vulnerable_version_range`` for *package_name*, or None."""
    ranges = _get_vulnerable_ranges_for_package(advisory, package_name, ecosystem)
    return ranges[0] if ranges else None


def _installed_version_is_affected(installed: str, vuln_range: str) -> bool:
    """Return True if *installed* falls within the GHSA vulnerable_version_range.

    Range format examples::

        '<= 1.6.8'             → affected if version <= 1.6.8
        '< 4.5.2'              → affected if version < 4.5.2
        '>= 22.0.0, < 26.0.0'  → affected if 22.0.0 <= version < 26.0.0

    Uses ``packaging.specifiers.SpecifierSet`` for full PEP 440 compliance
    (handles pre-release versions, epochs, and complex specifier combinations).
    Returns ``True`` on parse error (conservative: assume affected).
    """
    try:
        from packaging.specifiers import SpecifierSet
        from packaging.version import Version

        spec = SpecifierSet(vuln_range, prereleases=True)
        return Version(installed) in spec
    except Exception:
        return True  # unknown — conservatively assume affected


def _parse_patched_range(patched: str) -> str | None:
    """Parse a GHSA patched_versions range string to a concrete version.

    Examples:
        ">= 4.18.0"           → "4.18.0"
        ">= 4.18.0, < 5.0.0"  → "4.18.0"
        "~> 1.2.3"             → "1.2.3"
        "^1.2.3"               → "1.2.3"
    """
    import re as _re

    # Split on comma — take the lower-bound constraint (first with >= or ~>)
    for part in patched.split(","):
        part = part.strip()
        # Strip range operators: >=, >, ~>, ^, ~=, ==
        version = _re.sub(r"^[><=~^!]+\s*", "", part).strip()
        if version and _re.match(r"\d", version):
            return version
    return None


def _get_cwe_ids(advisory: dict) -> list[str]:
    """Extract CWE IDs from GHSA advisory."""
    cwes = advisory.get("cwes", []) or []
    return [c.get("cwe_id", "") for c in cwes if c.get("cwe_id")]


async def _fetch_advisories_for_package(
    pkg: Package,
    client: httpx.AsyncClient,
    semaphore: asyncio.Semaphore,
    *,
    max_pages: int = 10,
    rate_limit_backoff: float = _GHSA_RATE_LIMIT_BACKOFF,
) -> list[dict]:
    """Fetch GitHub advisories for a single package."""
    eco = _ECOSYSTEM_MAP.get(pkg.ecosystem.lower(), "")
    if not eco:
        return []

    async with semaphore:
        advisories: list[dict] = []
        for page in range(1, max_pages + 1):
            for attempt in range(2):
                resp = await request_with_retry(
                    client,
                    "GET",
                    _GITHUB_ADVISORY_API,
                    params={
                        "ecosystem": eco,
                        "package": pkg.name,
                        "per_page": str(_GHSA_PER_PAGE),
                        "page": str(page),
                    },
                    headers=_ghsa_headers(),
                )
                if resp and resp.status_code == 200:
                    try:
                        page_data = resp.json()
                    except (ValueError, KeyError):
                        return advisories
                    if not isinstance(page_data, list):
                        return advisories
                    advisories.extend(item for item in page_data if isinstance(item, dict))
                    if len(page_data) < _GHSA_PER_PAGE:
                        return advisories
                    break
                if resp and _is_rate_limited(resp):
                    wait_seconds = min(_rate_limit_retry_after(resp, rate_limit_backoff), rate_limit_backoff)
                    if attempt == 0 and wait_seconds > 0:
                        logger.warning("GHSA rate limit for %s; pausing %.0fs before retry", pkg.name, wait_seconds)
                        await asyncio.sleep(wait_seconds)
                        continue
                    raise GHSARateLimitError(wait_seconds)
                return advisories
        return advisories


async def check_github_advisories(
    packages: list[Package],
    max_packages: int | None = None,
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

    if max_packages is not None:
        queryable = queryable[:max_packages]

    logger.info("GHSA advisory check for %d packages", len(queryable))
    github_token_available = bool(_github_token())
    if not github_token_available:
        logger.warning(
            "GITHUB_TOKEN/GH_TOKEN is not set; GHSA advisory enrichment will fail fast on GitHub rate limits instead of pausing."
        )

    # Build a reverse lookup: all packages sharing the same name+ecosystem
    pkg_groups: dict[str, list[Package]] = {}
    for pkg in packages:
        eco = _ECOSYSTEM_MAP.get(pkg.ecosystem.lower(), "")
        if eco:
            key = f"{eco}:{pkg.name.lower()}"
            pkg_groups.setdefault(key, []).append(pkg)

    total_new = 0
    semaphore = asyncio.Semaphore(5)
    fetch_errors: list[str] = []
    rate_limited = False

    try:
        async with create_client(timeout=15.0) as client:
            rate_limit_backoff = _GHSA_RATE_LIMIT_BACKOFF
            if not github_token_available:
                rate_limit_backoff = _GHSA_SINGLE_PACKAGE_RATE_LIMIT_BACKOFF
            tasks = [_fetch_advisories_for_package(p, client, semaphore, rate_limit_backoff=rate_limit_backoff) for p in queryable]
            results = await asyncio.gather(*tasks, return_exceptions=True)

            for i, result in enumerate(results):
                if isinstance(result, BaseException):
                    logger.debug("GHSA fetch failed for %s: %s", queryable[i].name, result)
                    if isinstance(result, GHSARateLimitError):
                        rate_limited = True
                    fetch_errors.append(str(result))
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
                        # Use PEP 503 normalization so "Requests_OAuthlib" matches
                        # the already-normalized target name "requests-oauthlib".
                        target_eco = target_pkg.ecosystem
                        advisory_pkg_names = {
                            normalize_package_name(v.get("package", {}).get("name", ""), v.get("package", {}).get("ecosystem", target_eco))
                            for v in advisory.get("vulnerabilities", [])
                        }
                        if normalize_package_name(target_pkg.name, target_eco) not in advisory_pkg_names:
                            continue

                        existing_ids = {v.id for v in target_pkg.vulnerabilities}
                        for v in target_pkg.vulnerabilities:
                            existing_ids.update(v.aliases)
                        # Skip if CVE or GHSA ID already present (including aliases)
                        if vuln_id in existing_ids or (cve_id and cve_id in existing_ids) or (ghsa_id and ghsa_id in existing_ids):
                            continue

                        fixed = _extract_fixed_version(advisory, target_pkg.name, target_pkg.ecosystem)

                        # Skip if the installed version is already at or beyond the fix.
                        if target_pkg.version:
                            if fixed:
                                # compare_versions returns True only when fix > current
                                # (upgrade needed).  False = already patched → skip.
                                from agent_bom.version_utils import compare_versions

                                if not compare_versions(target_pkg.version, fixed, target_pkg.ecosystem):
                                    continue
                            else:
                                # patched_versions is null in current GHSA API responses.
                                # Use vulnerable_version_range to check whether the
                                # installed version actually falls in the affected range.
                                # An advisory may list MULTIPLE disjoint ranges for the same
                                # package — version is affected if it matches ANY of them.
                                vuln_ranges = _get_vulnerable_ranges_for_package(advisory, target_pkg.name, target_pkg.ecosystem)
                                if vuln_ranges and not any(_installed_version_is_affected(target_pkg.version, r) for r in vuln_ranges):
                                    continue

                        vuln = Vulnerability(
                            id=vuln_id,
                            summary=summary[:200],
                            severity=severity,
                            cvss_score=cvss_score,
                            fixed_version=fixed,
                            references=refs,
                            cwe_ids=cwe_ids,
                            advisory_sources=["ghsa"],
                        )
                        target_pkg.vulnerabilities.append(vuln)
                        total_new += 1
    except Exception as exc:
        record_enrichment_source("ghsa", "failure", error=str(exc))
        raise

    if rate_limited:
        record_enrichment_source("ghsa", "failure", error="rate_limited")
    elif fetch_errors:
        record_enrichment_source("ghsa", "failure", error=fetch_errors[0])
    else:
        record_enrichment_source("ghsa", "success")

    if total_new:
        logger.info("GHSA advisories: found %d new CVE(s)", total_new)

    return total_new
