"""Auto-discovery for unknown packages — fetch metadata from npm/PyPI and generate risk profiles.

When a package isn't in the bundled MCP registry, this module queries public
package registries to fetch metadata (description, maintainers, repo URL,
license, dependency count) and auto-generates a risk profile.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Optional

from agent_bom.models import Package

logger = logging.getLogger(__name__)

# ─── npm / PyPI metadata fetchers ────────────────────────────────────────────

_NPM_URL = "https://registry.npmjs.org/{}/latest"
_PYPI_URL = "https://pypi.org/pypi/{}/json"

# Keywords that signal higher-risk capabilities
_HIGH_RISK_KEYWORDS = frozenset({
    "filesystem", "write", "execute", "shell", "database", "sql",
    "admin", "deploy", "delete", "command", "eval", "sudo",
    "credential", "password", "token", "secret",
})

_MEDIUM_RISK_KEYWORDS = frozenset({
    "read", "search", "fetch", "query", "http", "request",
    "download", "upload", "send", "post", "api",
})


async def fetch_npm_metadata(name: str, client: object) -> Optional[dict]:
    """Fetch package metadata from the npm registry."""
    try:
        resp = await client.get(_NPM_URL.format(name), timeout=10.0)  # type: ignore[union-attr]
        if resp.status_code != 200:
            return None
        data = resp.json()
        return {
            "name": data.get("name", name),
            "description": data.get("description", ""),
            "license": data.get("license", ""),
            "maintainers": len(data.get("maintainers", data.get("_npmUser", [None]))),
            "repository": (data.get("repository", {}) or {}).get("url", ""),
            "dependencies_count": len(data.get("dependencies", {})),
            "keywords": data.get("keywords", []),
            "ecosystem": "npm",
        }
    except Exception:  # noqa: BLE001
        logger.debug("Failed to fetch npm metadata for %s", name)
        return None


async def fetch_pypi_metadata(name: str, client: object) -> Optional[dict]:
    """Fetch package metadata from PyPI."""
    try:
        resp = await client.get(_PYPI_URL.format(name), timeout=10.0)  # type: ignore[union-attr]
        if resp.status_code != 200:
            return None
        data = resp.json()
        info = data.get("info", {})
        project_urls = info.get("project_urls") or {}
        source_url = (
            project_urls.get("Source")
            or project_urls.get("Repository")
            or project_urls.get("Homepage")
            or ""
        )
        requires_dist = info.get("requires_dist") or []
        # Count maintainers from author field
        author = info.get("author", "")
        maintainer_count = 1 if author else 0

        return {
            "name": info.get("name", name),
            "description": info.get("summary", ""),
            "license": info.get("license", ""),
            "maintainers": maintainer_count,
            "repository": source_url,
            "dependencies_count": len(requires_dist),
            "keywords": info.get("keywords", "").split(",") if info.get("keywords") else [],
            "ecosystem": "pypi",
        }
    except Exception:  # noqa: BLE001
        logger.debug("Failed to fetch PyPI metadata for %s", name)
        return None


# ─── Risk inference ──────────────────────────────────────────────────────────


def infer_risk_level(metadata: dict) -> str:
    """Heuristic risk scoring based on package metadata.

    Returns "high", "medium", or "low".
    """
    score = 0
    desc = (metadata.get("description", "") + " " + " ".join(metadata.get("keywords", []))).lower()

    # Capability signals from description/keywords
    if any(kw in desc for kw in _HIGH_RISK_KEYWORDS):
        score += 3
    if any(kw in desc for kw in _MEDIUM_RISK_KEYWORDS):
        score += 1

    # Trust signals
    maintainers = metadata.get("maintainers", 0)
    if maintainers <= 1:
        score += 1

    if not metadata.get("repository"):
        score += 2

    # Dependencies amplify risk
    dep_count = metadata.get("dependencies_count", 0)
    if dep_count > 20:
        score += 1
    elif dep_count > 50:
        score += 2

    if score >= 5:
        return "high"
    elif score >= 3:
        return "medium"
    return "low"


def generate_risk_justification(metadata: dict, risk_level: str) -> str:
    """Generate human-readable risk justification from metadata signals."""
    parts: list[str] = []
    desc = (metadata.get("description", "") + " " + " ".join(metadata.get("keywords", []))).lower()

    # What it does
    if metadata.get("description"):
        parts.append(metadata["description"].rstrip(".") + ".")

    # Capability signals
    high_kws = [kw for kw in _HIGH_RISK_KEYWORDS if kw in desc]
    if high_kws:
        parts.append(f"High-risk capabilities detected: {', '.join(high_kws[:3])}.")

    # Trust signals
    maintainers = metadata.get("maintainers", 0)
    if maintainers <= 1:
        parts.append("Single maintainer — limited review coverage.")

    if not metadata.get("repository"):
        parts.append("No source repository linked — provenance unclear.")

    dep_count = metadata.get("dependencies_count", 0)
    if dep_count > 20:
        parts.append(f"{dep_count} dependencies — large attack surface.")

    if not parts:
        parts.append(f"Auto-discovered package with {risk_level} risk profile.")

    return " ".join(parts)


# ─── Batch enrichment ────────────────────────────────────────────────────────


async def autodiscover_package(
    name: str,
    ecosystem: str,
    client: object,
) -> Optional[dict]:
    """Fetch metadata from npm/PyPI and generate a risk profile."""
    metadata: Optional[dict] = None
    if ecosystem == "npm":
        metadata = await fetch_npm_metadata(name, client)
    elif ecosystem in ("pypi", "PyPI"):
        metadata = await fetch_pypi_metadata(name, client)

    if not metadata:
        return None

    risk_level = infer_risk_level(metadata)
    justification = generate_risk_justification(metadata, risk_level)

    return {
        **metadata,
        "auto_risk_level": risk_level,
        "auto_risk_justification": justification,
    }


async def enrich_unknown_packages(packages: list[Package]) -> int:
    """Batch-enrich packages not found in the bundled registry.

    Updates Package objects in-place with auto_risk_level,
    auto_risk_justification, maintainer_count, and source_repo.

    Returns the number of packages successfully enriched.
    """
    from agent_bom.http_client import create_client

    # Filter to packages not already enriched
    to_enrich = [
        p for p in packages
        if not p.resolved_from_registry
        and not getattr(p, "auto_risk_level", None)
        and p.version not in ("unknown", "latest", "")
        and p.ecosystem in ("npm", "pypi", "PyPI")
    ]

    if not to_enrich:
        return 0

    enriched = 0
    async with create_client(timeout=15.0) as client:
        sem = asyncio.Semaphore(5)

        async def _enrich_one(pkg: Package) -> bool:
            async with sem:
                result = await autodiscover_package(pkg.name, pkg.ecosystem, client)
                if result:
                    pkg.auto_risk_level = result.get("auto_risk_level")
                    pkg.auto_risk_justification = result.get("auto_risk_justification")
                    pkg.maintainer_count = result.get("maintainers")
                    pkg.source_repo = result.get("repository")
                    return True
                return False

        tasks = [_enrich_one(pkg) for pkg in to_enrich]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        enriched = sum(1 for r in results if r is True)

    return enriched
