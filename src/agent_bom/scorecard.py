"""OpenSSF Scorecard API enrichment for package security health.

Fetches scorecard data from api.securityscorecards.dev for packages
that have a known source repository. Low scorecard scores amplify
risk in blast radius calculations.

Reference: https://scorecard.dev/
API: https://api.securityscorecards.dev
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from typing import TYPE_CHECKING, Optional

from agent_bom.http_client import create_client, request_with_retry

if TYPE_CHECKING:
    from agent_bom.models import Package

logger = logging.getLogger(__name__)

SCORECARD_API_URL = "https://api.securityscorecards.dev/projects"

# Cache: repo_url -> scorecard data (or None for miss)
_scorecard_cache: dict[str, Optional[dict]] = {}

# Pattern to extract GitHub owner/repo from various URL formats
_GITHUB_REPO_PATTERN = re.compile(r"(?:https?://)?github\.com/([^/]+/[^/#?]+?)(?:\.git)?(?:[/#?]|$)")


@dataclass
class ScorecardEnrichmentStats:
    """Summary of Scorecard enrichment coverage for a package set."""

    total_packages: int = 0
    unique_packages: int = 0
    eligible_packages: int = 0
    attempted_packages: int = 0
    enriched_packages: int = 0
    unresolved_packages: int = 0
    failed_packages: int = 0

    def to_dict(self) -> dict[str, int]:
        return {
            "total_packages": self.total_packages,
            "unique_packages": self.unique_packages,
            "eligible_packages": self.eligible_packages,
            "attempted_packages": self.attempted_packages,
            "enriched_packages": self.enriched_packages,
            "unresolved_packages": self.unresolved_packages,
            "failed_packages": self.failed_packages,
        }


def extract_github_repo(url: str) -> Optional[str]:
    """Extract 'owner/repo' from a GitHub URL.

    Handles: github.com/owner/repo, github.com/owner/repo.git,
    github.com/owner/repo/tree/main, etc.
    """
    m = _GITHUB_REPO_PATTERN.search(url.strip())
    return m.group(1) if m else None


def extract_github_repo_from_purl(purl: str) -> Optional[str]:
    """Extract 'owner/repo' from a PURL that may embed a GitHub URL.

    This avoids relying on a simple substring check like
    '"github.com" in purl' by using the same robust extractor
    used for regular URLs.
    """
    if not purl:
        return None

    # Reuse the GitHub URL extraction logic; this will only return
    # a repo if a valid GitHub URL pattern is present in the PURL.
    return extract_github_repo(purl)


def _repo_url_from_package(pkg: Package) -> Optional[str]:
    """Try to determine GitHub repo URL from package metadata."""
    for candidate in (pkg.source_repo, pkg.repository_url, pkg.homepage):
        if candidate:
            repo = extract_github_repo(candidate)
            if repo:
                return repo

    if pkg.purl:
        repo = extract_github_repo_from_purl(pkg.purl)
        if repo:
            return repo

    return None


_SAFE_REPO_PATTERN = re.compile(r"^[A-Za-z0-9._-]+/[A-Za-z0-9._-]+$")


async def fetch_scorecard(repo: str) -> Optional[dict]:
    """Fetch OpenSSF Scorecard for a GitHub repository.

    Args:
        repo: GitHub owner/repo (e.g. "expressjs/express")

    Returns:
        Scorecard data dict with 'score' and 'checks', or None.
    """
    # Validate repo format to prevent SSRF via path manipulation
    if not _SAFE_REPO_PATTERN.match(repo):
        return None

    if repo in _scorecard_cache:
        return _scorecard_cache[repo]

    async with create_client(timeout=15.0) as client:
        url = f"{SCORECARD_API_URL}/github.com/{repo}"
        response = await request_with_retry(client, "GET", url, max_retries=2)

        if response and response.status_code == 200:
            try:
                data = response.json()
                result = {
                    "score": data.get("score", 0.0),
                    "date": data.get("date", ""),
                    "repo": data.get("repo", {}).get("name", repo),
                    "checks": {check["name"]: check.get("score", -1) for check in data.get("checks", [])},
                }
                _scorecard_cache[repo] = result
                return result
            except (ValueError, KeyError) as exc:
                safe_repo = repo.replace("\n", "").replace("\r", "")
                safe_exc = str(exc).replace("\n", "\\n").replace("\r", "\\r")
                logger.debug("Scorecard parse error for %s: %s", safe_repo, safe_exc)

        _scorecard_cache[repo] = None
        return None


def summarize_scorecard_coverage(packages: list[Package]) -> ScorecardEnrichmentStats:
    """Summarize Scorecard coverage using current package metadata/state."""
    stats = ScorecardEnrichmentStats(total_packages=len(packages))
    seen_keys: set[str] = set()

    for pkg in packages:
        key = f"{pkg.ecosystem.lower()}:{pkg.name.lower()}@{pkg.version}"
        if key in seen_keys:
            continue
        seen_keys.add(key)
        stats.unique_packages += 1

        repo = pkg.scorecard_repo or _repo_url_from_package(pkg)
        if repo:
            stats.eligible_packages += 1
            stats.attempted_packages += 1

        if pkg.scorecard_lookup_state == "enriched":
            stats.enriched_packages += 1
        elif pkg.scorecard_lookup_state == "failed":
            stats.failed_packages += 1
        elif pkg.scorecard_lookup_state == "unresolved" or not repo:
            stats.unresolved_packages += 1
        elif pkg.scorecard_score is not None:
            stats.enriched_packages += 1
        elif repo:
            stats.failed_packages += 1
        else:
            stats.unresolved_packages += 1

    return stats


async def enrich_packages_with_scorecard_stats(packages: list[Package]) -> ScorecardEnrichmentStats:
    """Enrich packages with OpenSSF Scorecard and return coverage stats."""
    stats = ScorecardEnrichmentStats(total_packages=len(packages))
    grouped: dict[str, list[Package]] = {}

    for pkg in packages:
        key = f"{pkg.ecosystem.lower()}:{pkg.name.lower()}@{pkg.version}"
        grouped.setdefault(key, []).append(pkg)

    stats.unique_packages = len(grouped)

    for group in grouped.values():
        leader = group[0]
        repo = _repo_url_from_package(leader)
        if not repo:
            stats.unresolved_packages += 1
            for pkg in group:
                pkg.scorecard_repo = None
                pkg.scorecard_lookup_state = "unresolved"
                pkg.scorecard_lookup_reason = "no_resolvable_github_repo"
            continue

        stats.eligible_packages += 1
        stats.attempted_packages += 1
        data = await fetch_scorecard(repo)
        if data:
            stats.enriched_packages += 1
            for pkg in group:
                pkg.scorecard_repo = repo
                pkg.scorecard_score = data["score"]
                pkg.scorecard_checks = data.get("checks", {})
                pkg.scorecard_lookup_state = "enriched"
                pkg.scorecard_lookup_reason = None
        else:
            stats.failed_packages += 1
            for pkg in group:
                pkg.scorecard_repo = repo
                pkg.scorecard_lookup_state = "failed"
                pkg.scorecard_lookup_reason = "scorecard_lookup_failed"

    return stats


async def enrich_packages_with_scorecard(packages: list[Package]) -> int:
    """Enrich packages with OpenSSF Scorecard data.

    Populates pkg.scorecard_score and pkg.scorecard_checks for
    packages that have a resolvable GitHub source repo.

    Returns the number of packages enriched.
    """
    stats = await enrich_packages_with_scorecard_stats(packages)
    return stats.enriched_packages
