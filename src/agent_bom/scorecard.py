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
from typing import TYPE_CHECKING, Optional

from agent_bom.http_client import create_client, request_with_retry

if TYPE_CHECKING:
    from agent_bom.models import Package

logger = logging.getLogger(__name__)

SCORECARD_API_URL = "https://api.securityscorecards.dev/projects"

# Cache: repo_url -> scorecard data (or None for miss)
_scorecard_cache: dict[str, Optional[dict]] = {}

# Pattern to extract GitHub owner/repo from various URL formats
_GITHUB_REPO_PATTERN = re.compile(
    r"(?:https?://)?github\.com/([^/]+/[^/#?]+?)(?:\.git)?(?:[/#?]|$)"
)


def extract_github_repo(url: str) -> Optional[str]:
    """Extract 'owner/repo' from a GitHub URL.

    Handles: github.com/owner/repo, github.com/owner/repo.git,
    github.com/owner/repo/tree/main, etc.
    """
    m = _GITHUB_REPO_PATTERN.search(url.strip())
    return m.group(1) if m else None


def _repo_url_from_package(pkg: Package) -> Optional[str]:
    """Try to determine GitHub repo URL from package metadata."""
    # Check source_repo field first (populated by registry lookup)
    if pkg.source_repo:
        repo = extract_github_repo(pkg.source_repo)
        if repo:
            return repo

    # Check PURL for hints (some PURLs include qualifiers with repo info)
    if pkg.purl and "github.com" in pkg.purl:
        repo = extract_github_repo(pkg.purl)
        if repo:
            return repo

    return None


async def fetch_scorecard(repo: str) -> Optional[dict]:
    """Fetch OpenSSF Scorecard for a GitHub repository.

    Args:
        repo: GitHub owner/repo (e.g. "expressjs/express")

    Returns:
        Scorecard data dict with 'score' and 'checks', or None.
    """
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
                    "checks": {
                        check["name"]: check.get("score", -1)
                        for check in data.get("checks", [])
                    },
                }
                _scorecard_cache[repo] = result
                return result
            except (ValueError, KeyError) as exc:
                logger.debug("Scorecard parse error for %s: %s", repo, exc)

        _scorecard_cache[repo] = None
        return None


async def enrich_packages_with_scorecard(packages: list[Package]) -> int:
    """Enrich packages with OpenSSF Scorecard data.

    Populates pkg.scorecard_score and pkg.scorecard_checks for
    packages that have a resolvable GitHub source repo.

    Returns the number of packages enriched.
    """
    enriched = 0
    for pkg in packages:
        repo = _repo_url_from_package(pkg)
        if not repo:
            continue

        data = await fetch_scorecard(repo)
        if data:
            pkg.scorecard_score = data["score"]
            pkg.scorecard_checks = data.get("checks", {})
            enriched += 1

    return enriched
