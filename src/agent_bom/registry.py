"""MCP server registry operations: version updates, drift detection, search."""

from __future__ import annotations

import asyncio
import json
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from agent_bom.models import Package

logger = logging.getLogger(__name__)

# Path to bundled MCP registry
_REGISTRY_PATH = Path(__file__).parent / "mcp_registry.json"


@dataclass
class VersionDrift:
    """Version comparison result for a single package."""

    package: str
    ecosystem: str
    installed: str
    latest: str
    status: str  # "outdated", "current", "unknown"


@dataclass
class RegistryUpdateResult:
    """Result of a registry version refresh."""

    total: int = 0
    updated: int = 0
    failed: int = 0
    unchanged: int = 0
    details: list[dict] = field(default_factory=list)


def _load_registry() -> dict:
    """Load the bundled MCP registry JSON."""
    try:
        return json.loads(_REGISTRY_PATH.read_text()).get("servers", {})
    except (json.JSONDecodeError, OSError):
        return {}


def _load_registry_full() -> dict:
    """Load the full registry JSON (including metadata keys)."""
    try:
        return json.loads(_REGISTRY_PATH.read_text())
    except (json.JSONDecodeError, OSError):
        return {"servers": {}}


def _parse_version(version: str) -> Optional[tuple[int, ...]]:
    """Parse a version string into a comparable tuple of integers.

    Handles semver (1.2.3), calver (2025.1.14), and pre-release suffixes.
    Returns None if the version cannot be parsed.
    """
    if not version or version in ("latest", "unknown", ""):
        return None
    # Strip common prefixes and suffixes
    cleaned = re.sub(r"^[vV]", "", version)
    cleaned = re.split(r"[-+]", cleaned)[0]  # drop pre-release/build metadata
    parts = cleaned.split(".")
    try:
        return tuple(int(p) for p in parts)
    except (ValueError, TypeError):
        return None


def compare_versions(installed: str, latest: str) -> str:
    """Compare two version strings.

    Returns:
        "outdated" if installed < latest
        "current" if installed >= latest
        "unknown" if either version cannot be parsed
    """
    inst = _parse_version(installed)
    lat = _parse_version(latest)
    if inst is None or lat is None:
        return "unknown"
    if inst < lat:
        return "outdated"
    return "current"


def detect_version_drift(
    packages: list[Package],
    registry: dict | None = None,
) -> list[VersionDrift]:
    """Compare installed package versions against registry latest_version.

    Only checks packages that have resolved_from_registry=True.
    Uses pkg.registry_version (if set) for comparison, otherwise falls
    back to registry lookup.  Works offline — compares against local
    registry JSON.
    """
    if registry is None:
        registry = _load_registry()

    results = []
    for pkg in packages:
        if not pkg.resolved_from_registry:
            continue

        # Prefer the registry_version stored on the Package (set during
        # lookup_mcp_registry) so we compare actual installed vs. known latest.
        latest = getattr(pkg, "registry_version", None) or ""

        if not latest or latest in ("latest", "unknown"):
            # Fall back to registry lookup
            entry = registry.get(pkg.name)
            if not entry:
                for _key, ent in registry.items():
                    if ent.get("package") == pkg.name:
                        entry = ent
                        break
            if not entry:
                continue
            latest = entry.get("latest_version", "")

        if not latest or latest in ("latest", "unknown"):
            continue

        status = compare_versions(pkg.version, latest)
        results.append(
            VersionDrift(
                package=pkg.name,
                ecosystem=pkg.ecosystem,
                installed=pkg.version,
                latest=latest,
                status=status,
            )
        )

    return results


def search_registry(
    query: str,
    category: str | None = None,
    risk_level: str | None = None,
    registry: dict | None = None,
) -> list[dict]:
    """Search registry by name/description substring, with optional filters."""
    if registry is None:
        registry = _load_registry()

    query_lower = query.lower()
    results = []
    for name, entry in registry.items():
        # Filter by category
        if category and entry.get("category", "").lower() != category.lower():
            continue
        # Filter by risk level
        if risk_level and entry.get("risk_level", "").lower() != risk_level.lower():
            continue
        # Match on name, package, or description
        searchable = f"{name} {entry.get('package', '')} {entry.get('description', '')}".lower()
        if query_lower in searchable:
            results.append({"name": name, **entry})
    return results


def list_registry(
    sort_by: str = "name",
    ecosystem: str | None = None,
    category: str | None = None,
    risk_level: str | None = None,
    registry: dict | None = None,
) -> list[dict]:
    """Return filtered and sorted registry entries."""
    if registry is None:
        registry = _load_registry()

    entries = []
    for name, entry in registry.items():
        if ecosystem and entry.get("ecosystem", "").lower() != ecosystem.lower():
            continue
        if category and entry.get("category", "").lower() != category.lower():
            continue
        if risk_level and entry.get("risk_level", "").lower() != risk_level.lower():
            continue
        entries.append({"name": name, **entry})

    # Sort
    if sort_by == "name":
        entries.sort(key=lambda e: e.get("name", "").lower())
    elif sort_by == "ecosystem":
        entries.sort(key=lambda e: (e.get("ecosystem", ""), e.get("name", "").lower()))
    elif sort_by == "category":
        entries.sort(key=lambda e: (e.get("category", ""), e.get("name", "").lower()))
    elif sort_by == "risk":
        risk_order = {"high": 0, "medium": 1, "low": 2}
        entries.sort(key=lambda e: (risk_order.get(e.get("risk_level", "low"), 3), e.get("name", "").lower()))

    return entries


async def update_registry_versions(
    concurrency: int = 5,
    dry_run: bool = False,
) -> RegistryUpdateResult:
    """Fetch latest versions from npm/PyPI for all servers in the registry.

    Uses asyncio.Semaphore for rate limiting.
    Reuses resolver functions for npm/PyPI lookups.
    Updates mcp_registry.json in-place (unless dry_run).
    """
    from agent_bom.http_client import create_client
    from agent_bom.resolver import resolve_npm_version, resolve_pypi_version

    data = _load_registry_full()
    servers = data.get("servers", {})
    result = RegistryUpdateResult(total=len(servers))
    sem = asyncio.Semaphore(concurrency)

    async def update_one(
        client,
        name: str,
        entry: dict,
    ) -> None:
        async with sem:
            pkg_name = entry.get("package", name)
            ecosystem = entry.get("ecosystem", "npm")
            old_version = entry.get("latest_version", "")

            try:
                if ecosystem == "npm":
                    new_version = await resolve_npm_version(pkg_name, client)
                elif ecosystem == "pypi":
                    new_version = await resolve_pypi_version(pkg_name, client)
                else:
                    new_version = None

                if new_version and new_version != old_version:
                    if not dry_run:
                        entry["latest_version"] = new_version
                    result.updated += 1
                    result.details.append(
                        {
                            "package": pkg_name,
                            "old": old_version,
                            "new": new_version,
                            "status": "updated",
                        }
                    )
                elif new_version:
                    result.unchanged += 1
                    result.details.append(
                        {
                            "package": pkg_name,
                            "old": old_version,
                            "new": old_version,
                            "status": "unchanged",
                        }
                    )
                else:
                    result.failed += 1
                    result.details.append(
                        {
                            "package": pkg_name,
                            "old": old_version,
                            "new": None,
                            "status": "failed",
                        }
                    )
            except Exception as exc:
                logger.debug("Failed to resolve %s: %s", pkg_name, exc)
                result.failed += 1
                result.details.append(
                    {
                        "package": pkg_name,
                        "old": old_version,
                        "new": None,
                        "status": "failed",
                    }
                )

    async with create_client(timeout=15.0) as client:
        tasks = [update_one(client, name, entry) for name, entry in servers.items()]
        await asyncio.gather(*tasks, return_exceptions=True)

    # Write updated registry
    if not dry_run and result.updated > 0:
        from datetime import datetime, timezone

        data["_updated"] = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        _REGISTRY_PATH.write_text(json.dumps(data, indent=2) + "\n")

    return result


def update_registry_versions_sync(
    concurrency: int = 5,
    dry_run: bool = False,
) -> RegistryUpdateResult:
    """Sync wrapper for update_registry_versions."""
    return asyncio.run(update_registry_versions(concurrency=concurrency, dry_run=dry_run))


# ─── Registry enrichment ─────────────────────────────────────────────────────

# Risk inference based on category keywords
_RISK_CATEGORY_MAP: dict[str, str] = {
    "filesystem": "high",
    "shell": "high",
    "exec": "high",
    "code-execution": "high",
    "database": "medium",
    "developer-tools": "medium",
    "cloud": "medium",
    "communication": "medium",
    "search": "low",
    "data": "low",
    "monitoring": "low",
    "utilities": "low",
    "ai": "low",
}

# Package name patterns → likely credential env vars
_CREDENTIAL_PATTERNS: list[tuple[list[str], list[str]]] = [
    (["github"], ["GITHUB_PERSONAL_ACCESS_TOKEN"]),
    (["gitlab"], ["GITLAB_PERSONAL_ACCESS_TOKEN"]),
    (["slack"], ["SLACK_BOT_TOKEN"]),
    (["postgres", "pg"], ["POSTGRES_CONNECTION_STRING"]),
    (["redis"], ["REDIS_URL"]),
    (["mysql", "mariadb"], ["MYSQL_CONNECTION_STRING"]),
    (["mongo"], ["MONGODB_URI"]),
    (["aws", "s3", "dynamodb", "lambda"], ["AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY"]),
    (["azure"], ["AZURE_CLIENT_ID", "AZURE_CLIENT_SECRET", "AZURE_TENANT_ID"]),
    (["gcp", "google", "firebase", "bigquery"], ["GOOGLE_APPLICATION_CREDENTIALS"]),
    (["openai"], ["OPENAI_API_KEY"]),
    (["anthropic", "claude"], ["ANTHROPIC_API_KEY"]),
    (["stripe"], ["STRIPE_SECRET_KEY"]),
    (["twilio"], ["TWILIO_ACCOUNT_SID", "TWILIO_AUTH_TOKEN"]),
    (["sendgrid"], ["SENDGRID_API_KEY"]),
    (["notion"], ["NOTION_API_KEY"]),
    (["jira", "confluence", "atlassian"], ["ATLASSIAN_API_TOKEN"]),
    (["linear"], ["LINEAR_API_KEY"]),
    (["sentry"], ["SENTRY_DSN"]),
    (["datadog"], ["DD_API_KEY"]),
    (["puppeteer", "playwright", "browser"], []),
    (["fetch", "http"], []),
]

# Package name patterns → likely risk justification
_RISK_JUSTIFICATIONS: dict[str, str] = {
    "filesystem": "Filesystem read/write access allows data exfiltration or corruption of local files.",
    "shell": "Shell command execution enables arbitrary code execution on the host.",
    "exec": "Code execution capability allows arbitrary operations on the host system.",
    "database": "Database access may expose sensitive data or allow destructive schema changes.",
    "cloud": "Cloud API access may permit resource provisioning, data access, or cost escalation.",
    "communication": "Messaging access may allow impersonation, data leakage, or spam.",
    "developer-tools": "Developer tool access may expose source code, secrets, or CI/CD pipelines.",
    "search": "Search access is generally read-only with limited blast radius.",
    "data": "Data access may expose sensitive information depending on the data source.",
    "monitoring": "Monitoring access is generally read-only with limited blast radius.",
}


@dataclass
class EnrichResult:
    """Result of a registry enrichment run."""

    total: int = 0
    enriched: int = 0
    skipped: int = 0
    details: list[dict] = field(default_factory=list)


def _infer_risk_level(name: str, entry: dict) -> str | None:
    """Infer risk level from category and package name patterns."""
    category = entry.get("category", "").lower()
    if category in _RISK_CATEGORY_MAP:
        return _RISK_CATEGORY_MAP[category]

    # Fallback: check package name for risky keywords
    pkg_lower = name.lower()
    for keyword in ("filesystem", "shell", "exec", "terminal", "bash"):
        if keyword in pkg_lower:
            return "high"
    for keyword in ("database", "postgres", "redis", "mysql", "mongo"):
        if keyword in pkg_lower:
            return "medium"
    return "low"


def _infer_credentials(name: str, entry: dict) -> list[str] | None:
    """Infer likely credential environment variables from package name."""
    pkg_lower = name.lower()
    for patterns, creds in _CREDENTIAL_PATTERNS:
        if any(pat in pkg_lower for pat in patterns):
            return creds
    return None


def _infer_risk_justification(entry: dict) -> str | None:
    """Infer risk justification from category."""
    category = entry.get("category", "").lower()
    return _RISK_JUSTIFICATIONS.get(category)


def _needs_enrichment(entry: dict) -> list[str]:
    """Return list of fields that need enrichment (empty or missing)."""
    needs: list[str] = []
    if not entry.get("risk_level"):
        needs.append("risk_level")
    if not entry.get("description"):
        needs.append("description")
    if not entry.get("risk_justification"):
        needs.append("risk_justification")
    if not entry.get("category"):
        needs.append("category")
    # tools and credential_env_vars are valid as empty arrays
    if "tools" not in entry:
        needs.append("tools")
    if "credential_env_vars" not in entry:
        needs.append("credential_env_vars")
    return needs


def enrich_registry_entries(dry_run: bool = False) -> EnrichResult:
    """Find and enrich registry entries missing key metadata fields.

    Fills in risk_level, risk_justification, and credential_env_vars
    using heuristic inference from package names and categories.
    Does not overwrite existing non-empty values.

    Args:
        dry_run: If True, preview enrichment without writing.

    Returns:
        EnrichResult with counts and per-entry details.
    """
    data = _load_registry_full()
    servers = data.get("servers", {})
    result = EnrichResult(total=len(servers))

    for name, entry in servers.items():
        needs = _needs_enrichment(entry)
        if not needs:
            result.skipped += 1
            continue

        enriched_fields: dict[str, object] = {}

        if "risk_level" in needs:
            inferred = _infer_risk_level(name, entry)
            if inferred:
                enriched_fields["risk_level"] = inferred
                if not dry_run:
                    entry["risk_level"] = inferred

        if "risk_justification" in needs:
            inferred = _infer_risk_justification(entry)
            if inferred:
                enriched_fields["risk_justification"] = inferred
                if not dry_run:
                    entry["risk_justification"] = inferred

        if "credential_env_vars" in needs:
            inferred_creds = _infer_credentials(name, entry)
            if inferred_creds is not None:
                enriched_fields["credential_env_vars"] = inferred_creds
                if not dry_run:
                    entry["credential_env_vars"] = inferred_creds

        if "tools" in needs:
            enriched_fields["tools"] = []
            if not dry_run:
                entry["tools"] = []

        if "category" in needs:
            enriched_fields["category"] = "other"
            if not dry_run:
                entry["category"] = "other"

        if "description" in needs:
            enriched_fields["description"] = f"MCP server: {name}"
            if not dry_run:
                entry["description"] = f"MCP server: {name}"

        if enriched_fields:
            result.enriched += 1
            result.details.append(
                {
                    "server": name,
                    "fields_enriched": list(enriched_fields.keys()),
                    "values": enriched_fields,
                }
            )
        else:
            result.skipped += 1

    # Write updated registry
    if not dry_run and result.enriched > 0:
        from datetime import datetime, timezone

        data["_updated"] = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        _REGISTRY_PATH.write_text(json.dumps(data, indent=2) + "\n")

    return result


# ─── CVE enrichment via OSV + EPSS + KEV ────────────────────────────────────


@dataclass
class CVEEnrichResult:
    """Result of registry CVE enrichment."""

    total: int = 0
    scannable: int = 0
    enriched: int = 0
    total_cves: int = 0
    total_critical: int = 0
    total_kev: int = 0
    details: list[dict] = field(default_factory=list)


async def enrich_registry_with_cves(
    nvd_api_key: Optional[str] = None,
    dry_run: bool = False,
) -> CVEEnrichResult:
    """Enrich registry entries with CVE data from OSV, EPSS, and CISA KEV.

    For each npm/pypi package in the registry:
    1. Query OSV batch API for known vulnerabilities
    2. Fetch EPSS exploit prediction scores
    3. Check CISA KEV (Known Exploited Vulnerabilities) catalog
    4. Store summary in registry entry

    Args:
        nvd_api_key: Optional NVD API key for higher rate limits.
        dry_run: If True, preview without writing.

    Returns:
        CVEEnrichResult with counts and per-entry details.
    """
    from agent_bom.enrichment import fetch_cisa_kev_catalog, fetch_epss_scores
    from agent_bom.http_client import create_client
    from agent_bom.models import Package
    from agent_bom.scanners import ECOSYSTEM_MAP, query_osv_batch

    data = _load_registry_full()
    servers = data.get("servers", {})
    result = CVEEnrichResult(total=len(servers))

    # Build Package objects for scannable entries (npm/pypi only)
    pkg_to_servers: dict[str, list[str]] = {}
    packages: list[Package] = []

    for name, entry in servers.items():
        ecosystem = entry.get("ecosystem", "")
        if ecosystem not in ECOSYSTEM_MAP:
            continue
        pkg_name = entry.get("package", name)
        version = entry.get("latest_version", "")
        if not version or version in ("unknown", "latest"):
            continue

        result.scannable += 1
        key = f"{ecosystem}:{pkg_name}@{version}"
        pkg_to_servers.setdefault(key, []).append(name)

        # Avoid duplicate queries for same package
        if len(pkg_to_servers[key]) == 1:
            packages.append(Package(name=pkg_name, version=version, ecosystem=ecosystem))

    if not packages:
        return result

    # 1. Query OSV for vulnerabilities
    osv_results = await query_osv_batch(packages)

    # Collect all CVE IDs for EPSS/KEV enrichment
    all_cve_ids: list[str] = []
    for vulns in osv_results.values():
        for v in vulns:
            for alias in v.get("aliases", []):
                if alias.startswith("CVE-"):
                    all_cve_ids.append(alias)
            vid = v.get("id", "")
            if vid.startswith("CVE-"):
                all_cve_ids.append(vid)
    all_cve_ids = list(set(all_cve_ids))

    # 2. Fetch EPSS scores and KEV catalog
    epss_scores: dict[str, dict] = {}
    kev_catalog: dict = {}
    if all_cve_ids:
        async with create_client(timeout=30.0) as client:
            epss_scores = await fetch_epss_scores(all_cve_ids, client)
            kev_catalog = await fetch_cisa_kev_catalog(client)

    # 3. Update registry entries
    for name, entry in servers.items():
        ecosystem = entry.get("ecosystem", "")
        if ecosystem not in ECOSYSTEM_MAP:
            continue
        pkg_name = entry.get("package", name)
        version = entry.get("latest_version", "")
        if not version or version in ("unknown", "latest"):
            continue

        key = f"{ecosystem}:{pkg_name}@{version}"
        vulns = osv_results.get(key, [])

        if not vulns:
            if not dry_run and entry.get("known_cves"):
                entry["known_cves"] = []
                entry["cve_summary"] = {}
            continue

        # Extract CVE/GHSA IDs and severity info
        cve_ids: list[str] = []
        ghsa_ids: list[str] = []
        severities: list[str] = []

        for v in vulns:
            vid = v.get("id", "")
            if vid.startswith("GHSA-"):
                ghsa_ids.append(vid)
            for alias in v.get("aliases", []):
                if alias.startswith("CVE-") and alias not in cve_ids:
                    cve_ids.append(alias)
                elif alias.startswith("GHSA-") and alias not in ghsa_ids:
                    ghsa_ids.append(alias)
            if vid.startswith("CVE-") and vid not in cve_ids:
                cve_ids.append(vid)

            for sev in v.get("severity", []):
                if "CVSS" in sev.get("type", ""):
                    try:
                        base = float(sev.get("score", "0").split("/")[0].split(":")[-1])
                        if base >= 9.0:
                            severities.append("critical")
                        elif base >= 7.0:
                            severities.append("high")
                        elif base >= 4.0:
                            severities.append("medium")
                        else:
                            severities.append("low")
                    except (ValueError, IndexError):
                        pass

        # Count EPSS high-risk and KEV entries
        critical_count = 0
        kev_count = 0
        for cve_id in cve_ids:
            epss = epss_scores.get(cve_id, {})
            is_kev = cve_id in kev_catalog
            if epss.get("score", 0.0) >= 0.7 or is_kev:
                critical_count += 1
            if is_kev:
                kev_count += 1

        # Extract fix versions from OSV affected ranges
        fix_versions: list[str] = []
        for v in vulns:
            for affected in v.get("affected", []):
                for rng in affected.get("ranges", []):
                    for event in rng.get("events", []):
                        if "fixed" in event and event["fixed"] not in fix_versions:
                            fix_versions.append(event["fixed"])

        summary = {
            "total": len(cve_ids),
            "ghsa_count": len(ghsa_ids),
            "critical": critical_count,
            "kev": kev_count,
            "severity_breakdown": {
                "critical": severities.count("critical"),
                "high": severities.count("high"),
                "medium": severities.count("medium"),
                "low": severities.count("low"),
            },
            "fix_available": len(fix_versions) > 0,
            "fix_versions": fix_versions[:5],
        }

        if not dry_run:
            entry["known_cves"] = cve_ids + [g for g in ghsa_ids if g not in cve_ids]
            entry["cve_summary"] = summary

        result.enriched += 1
        result.total_cves += len(cve_ids)
        result.total_critical += critical_count
        result.total_kev += kev_count
        result.details.append(
            {
                "server": name,
                "package": pkg_name,
                "cve_count": len(cve_ids),
                "ghsa_count": len(ghsa_ids),
                "critical": critical_count,
                "kev": kev_count,
                "cves": cve_ids[:10],
            }
        )

    # Write updated registry
    if not dry_run and result.enriched > 0:
        from datetime import datetime, timezone

        data["_cve_enriched"] = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        data["_updated"] = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        _REGISTRY_PATH.write_text(json.dumps(data, indent=2) + "\n")

    return result


def enrich_registry_with_cves_sync(
    nvd_api_key: Optional[str] = None,
    dry_run: bool = False,
) -> CVEEnrichResult:
    """Sync wrapper for enrich_registry_with_cves."""
    return asyncio.run(enrich_registry_with_cves(nvd_api_key=nvd_api_key, dry_run=dry_run))
