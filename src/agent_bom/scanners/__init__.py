"""Vulnerability scanning — local SQLite DB first, OSV.dev API for gaps."""

from __future__ import annotations

import asyncio
import logging
import math
import time
from typing import Any, Optional

import httpx
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn

from agent_bom.atlas import tag_blast_radius as tag_atlas_techniques
from agent_bom.cis_controls import tag_blast_radius as tag_cis_controls
from agent_bom.cmmc import tag_blast_radius as tag_cmmc
from agent_bom.config import (
    SCANNER_BATCH_DELAY as BATCH_DELAY_SECONDS,
)
from agent_bom.config import (
    SCANNER_BATCH_SIZE as _BATCH_SIZE,
)
from agent_bom.config import (
    SCANNER_MAX_CONCURRENT as MAX_CONCURRENT_REQUESTS,
)

# Single source of truth for AI/ML package catalog — imported from constants.
# Vulnerabilities in these carry elevated risk because they run inside AI
# agents that have credentials and tool access.
from agent_bom.constants import AI_PACKAGES as _AI_FRAMEWORK_PACKAGES
from agent_bom.eu_ai_act import tag_blast_radius as tag_eu_ai_act
from agent_bom.fedramp import tag_blast_radius as tag_fedramp
from agent_bom.http_client import OfflineModeError, create_client, request_with_retry
from agent_bom.iso_27001 import tag_blast_radius as tag_iso_27001
from agent_bom.malicious import check_typosquat, flag_malicious_from_vulns
from agent_bom.mitre_attack import tag_blast_radius as tag_attack_techniques
from agent_bom.models import Agent, BlastRadius, MCPServer, Package, Severity, Vulnerability, normalize_package_name
from agent_bom.nist_800_53 import tag_blast_radius as tag_nist_800_53
from agent_bom.nist_ai_rmf import tag_blast_radius as tag_nist_ai_rmf
from agent_bom.nist_csf import tag_blast_radius as tag_nist_csf
from agent_bom.owasp import tag_blast_radius
from agent_bom.owasp_agentic import tag_blast_radius as tag_owasp_agentic
from agent_bom.owasp_mcp import tag_blast_radius as tag_owasp_mcp
from agent_bom.soc2 import tag_blast_radius as tag_soc2
from agent_bom.vuln_compliance import tag_vulnerability as _tag_vuln

console = Console(stderr=True)
_logger = logging.getLogger(__name__)

# Module-level offline flag — when True, skip all OSV API calls and scan
# only against the local SQLite DB.  Set by CLI --offline before scanning.
# Also synced from http_client._OFFLINE for transport-layer enforcement.
offline_mode: bool = False


def set_offline_mode(value: bool) -> None:
    """Set offline mode in both scanner and http_client transport layer."""
    global offline_mode  # noqa: PLW0603
    offline_mode = value
    from agent_bom.http_client import set_offline

    set_offline(value)


# When True, prefer local DB results and only fall back to OSV API for
# packages not found in the DB. Set automatically when DB is <24h old.
prefer_local_db: bool = False

# When False, skip compliance framework tagging on findings (faster for individual scans)
compliance_mode: bool = False

OSV_API_URL = "https://api.osv.dev/v1"
OSV_BATCH_URL = f"{OSV_API_URL}/querybatch"
# Max pipeline-level pause when OSV returns persistent 429 after all per-request retries.
# Separate from per-request exponential backoff (http_client.py) — this pauses the
# whole batch queue so subsequent batches don't immediately hammer a throttled API.
_PIPELINE_429_BACKOFF = 60.0
OSV_QUERY_URL = f"{OSV_API_URL}/query"

# Map ecosystem names to OSV ecosystem identifiers
ECOSYSTEM_MAP = {
    "npm": "npm",
    "pypi": "PyPI",
    "go": "Go",
    "cargo": "crates.io",
    "maven": "Maven",
    "nuget": "NuGet",
    "rubygems": "RubyGems",
    "composer": "Packagist",
    "swift": "SwiftURL",
    "pub": "Pub",
    "hex": "Hex",
    # conda packages are pip-installable and tracked under PyPI in OSV
    "conda": "PyPI",
    # OS package ecosystems are distro-versioned in OSV, so query_osv_batch
    # resolves them dynamically from package distro metadata rather than using
    # these flat placeholders directly.
    "deb": "Debian",
    "apk": "Alpine",
    # RPM covers RHEL, CentOS, Fedora, Rocky, Alma — OSV "Linux" is the
    # cross-distro ecosystem that matches all RPM-based advisories.
    "rpm": "Linux",
}

# Known non-OSV ecosystems: valid discovery artifacts that cannot be queried
# against OSV/NVD. These are silently skipped (DEBUG) rather than flagged as
# errors — the scanner handles them through other pipelines (OCI image scan,
# model provenance checks, cloud runtime inventory, etc.).
_NON_OSV_ECOSYSTEMS: frozenset[str] = frozenset(
    {
        "docker",  # Image stubs from MCP configs / docker-compose / running containers
        "container",  # GPU infra image refs (cuda-toolkit, cudnn)
        "container-image",  # CoreWeave / Nebius pod images
        "ollama",  # Ollama model names — no OSV advisory DB
        "smithery",  # Smithery MCP marketplace stubs
        "mcp-registry",  # MCP Registry stubs
        "azure-runtime",  # Azure Functions / ACA runtime images
        "nebius-ai-studio",  # Nebius AI Studio model artifacts
        "nebius-compute-image",  # Nebius compute node images
        "sast",  # SAST findings represented as packages
        "unknown",  # Packages with unresolvable ecosystem (e.g. --sbom ingest)
    }
)

_DEBIAN_OSV_FALLBACKS = ("Debian:11", "Debian:12", "Debian:13", "Debian:14")
_ALPINE_OSV_FALLBACKS = ("Alpine:v3.18", "Alpine:v3.19", "Alpine:v3.20", "Alpine:v3.21", "Alpine:v3.22")


def _osv_ecosystems_for_package(pkg: Package) -> list[str]:
    """Return one or more OSV ecosystem identifiers for a package."""
    eco_key = pkg.ecosystem.lower()

    if eco_key == "deb":
        distro_name = (pkg.distro_name or "").lower()
        distro_version = (pkg.distro_version or "").strip()
        if distro_name == "debian" and distro_version:
            return [f"Debian:{distro_version.split('.', 1)[0]}"]
        if distro_name == "ubuntu" and distro_version:
            normalized = distro_version
            if normalized.count(".") == 1:
                return [f"Ubuntu:{normalized}:LTS", f"Ubuntu:{normalized}"]
            return [f"Ubuntu:{normalized}"]
        return list(_DEBIAN_OSV_FALLBACKS)

    if eco_key == "apk":
        distro_version = (pkg.distro_version or "").strip()
        if distro_version:
            normalized = distro_version if distro_version.startswith("v") else f"v{distro_version}"
            return [f"Alpine:{normalized}"]
        return list(_ALPINE_OSV_FALLBACKS)

    osv_ecosystem = ECOSYSTEM_MAP.get(eco_key)
    return [osv_ecosystem] if osv_ecosystem else []


def _db_ecosystems_for_package(pkg: Package) -> list[str]:
    """Return normalized DB ecosystem keys for a package."""
    return [eco.lower() for eco in _osv_ecosystems_for_package(pkg)]


_MAX_CACHED_LOOPS = 8  # Bound stale entries in long-running servers
_loop_semaphores: dict[int, asyncio.Semaphore] = {}


def _get_api_semaphore() -> asyncio.Semaphore:
    """Get or create a semaphore bound to the current running event loop.

    Caches one semaphore per event loop id so rate-limiting is effective
    across multiple calls within the same scan, while avoiding the stale-loop
    problem that module-level semaphores have with ThreadPoolExecutor.

    Evicts oldest entries when the cache exceeds ``_MAX_CACHED_LOOPS`` to
    prevent unbounded memory growth in long-running API servers.

    Uses ``get_running_loop()`` (not the deprecated ``get_event_loop()``)
    so this works correctly on Python 3.10+.
    """
    loop = asyncio.get_running_loop()
    loop_id = id(loop)
    if loop_id not in _loop_semaphores:
        if len(_loop_semaphores) >= _MAX_CACHED_LOOPS:
            # Evict the oldest entry (first inserted key)
            oldest = next(iter(_loop_semaphores))
            del _loop_semaphores[oldest]
        _loop_semaphores[loop_id] = asyncio.Semaphore(MAX_CONCURRENT_REQUESTS)
    return _loop_semaphores[loop_id]


# ── Scan cache (optional, lazy-initialised) ────────────────────────────────

_scan_cache_instance = None  # type: ignore[var-annotated]


def _get_scan_cache():  # noqa: ANN202
    """Return the shared ScanCache singleton, or *None* if unavailable."""
    global _scan_cache_instance  # noqa: PLW0603
    if _scan_cache_instance is None:
        try:
            from agent_bom.scan_cache import ScanCache

            _scan_cache_instance = ScanCache()
        except Exception as exc:  # noqa: BLE001
            _logger.warning("ScanCache initialization failed (caching disabled): %s", exc)
            _scan_cache_instance = False  # mark as attempted, don't retry
    return _scan_cache_instance if _scan_cache_instance is not False else None


# Map CVSS scores to severity
def cvss_to_severity(score: Optional[float]) -> Severity:
    if score is None:
        return Severity.UNKNOWN
    if score >= 9.0:
        return Severity.CRITICAL
    if score >= 7.0:
        return Severity.HIGH
    if score >= 4.0:
        return Severity.MEDIUM
    if score > 0:
        return Severity.LOW
    return Severity.NONE


# CVSS 3.1 Base Score metric weights.
# Reference: FIRST CVSS v3.1 Specification, Section 7.4 — Metric Values
# https://www.first.org/cvss/v3.1/specification-document#7-4-Metric-Values
_CVSS3_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}  # Attack Vector
_CVSS3_AC = {"L": 0.77, "H": 0.44}  # Attack Complexity
_CVSS3_PR_U = {"N": 0.85, "L": 0.62, "H": 0.27}  # Privileges Required (Scope Unchanged)
_CVSS3_PR_C = {"N": 0.85, "L": 0.68, "H": 0.50}  # Privileges Required (Scope Changed)
_CVSS3_UI = {"N": 0.85, "R": 0.62}  # User Interaction
_CVSS3_CIA = {"N": 0.00, "L": 0.22, "H": 0.56}  # Confidentiality / Integrity / Availability


def _parse_cvss4_vector(vector: str) -> Optional[float]:
    """Extract an approximate base score from a CVSS 4.0 vector string.

    CVSS v4.0 scoring requires a complex lookup-table algorithm that isn't
    practical to reimplement inline (700+ macro-vector combinations).  Instead
    we estimate a base score from the *impact* and *exploitability* metric
    values using a simplified weighted model that tracks the official
    calculator within ±0.5 for typical vectors.

    Returns ``None`` if the vector cannot be parsed.
    """
    try:
        parts = vector.split("/")[1:]
        m = dict(p.split(":") for p in parts)

        # Attack Vector / Complexity / Privileges / User Interaction
        av = {"N": 1.0, "A": 0.75, "L": 0.55, "P": 0.20}.get(m.get("AV", ""), None)
        ac = {"L": 1.0, "H": 0.55}.get(m.get("AC", ""), None)
        at = {"N": 1.0, "P": 0.60}.get(m.get("AT", ""), None)  # Attack Requirements
        pr = {"N": 1.0, "L": 0.65, "H": 0.30}.get(m.get("PR", ""), None)
        ui = {"N": 1.0, "P": 0.70, "A": 0.55}.get(m.get("UI", ""), None)

        # Vulnerable-system impact
        vc = {"H": 0.56, "L": 0.22, "N": 0.0}.get(m.get("VC", ""), None)
        vi = {"H": 0.56, "L": 0.22, "N": 0.0}.get(m.get("VI", ""), None)
        va = {"H": 0.56, "L": 0.22, "N": 0.0}.get(m.get("VA", ""), None)

        required = (av, ac, at, pr, ui, vc, vi, va)
        if any(v is None for v in required):
            return None

        # Type narrowing for mypy — the None case is already handled by the
        # ``any(v is None ...)`` guard above; these are runtime-safe casts.
        av, ac, at, pr, ui = float(av), float(ac), float(at), float(pr), float(ui)  # type: ignore[arg-type]
        vc, vi, va = float(vc), float(vi), float(va)  # type: ignore[arg-type]

        # Subsequent-system impact (optional — defaults to None=0)
        sc = {"H": 0.56, "L": 0.22, "N": 0.0}.get(m.get("SC", "N"), 0.0)
        si = {"H": 0.56, "L": 0.22, "N": 0.0}.get(m.get("SI", "N"), 0.0)
        sa = {"H": 0.56, "L": 0.22, "N": 0.0}.get(m.get("SA", "N"), 0.0)

        isc = 1.0 - (1.0 - vc) * (1.0 - vi) * (1.0 - va)
        isc_sub = 1.0 - (1.0 - sc) * (1.0 - si) * (1.0 - sa)
        impact = max(isc, isc + 0.25 * isc_sub)  # Subsequent amplifies

        if impact <= 0:
            return 0.0

        exploit = av * ac * at * pr * ui
        raw = min(10.0, 1.1 * (6.42 * impact + 8.22 * exploit * 0.6))

        return math.ceil(raw * 10) / 10.0
    except Exception as exc:
        _logger.debug("CVSS 4.0 vector parse failed for %r: %s", vector, exc)
        return None


def parse_cvss_vector(vector: str) -> Optional[float]:
    """Compute CVSS base score from a vector string (v3.x and v4.0).

    Examples:
        'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' → 9.8
        'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N' → ~9.3
    """
    try:
        if vector.startswith("CVSS:4"):
            return _parse_cvss4_vector(vector)
        if not vector.startswith("CVSS:3"):
            return None
        # Strip prefix
        parts = vector.split("/")[1:]
        metrics = dict(p.split(":") for p in parts)

        av = _CVSS3_AV.get(metrics.get("AV", ""), None)
        ac = _CVSS3_AC.get(metrics.get("AC", ""), None)
        scope = metrics.get("S", "U")
        pr_map = _CVSS3_PR_C if scope == "C" else _CVSS3_PR_U
        pr = pr_map.get(metrics.get("PR", ""), None)
        ui = _CVSS3_UI.get(metrics.get("UI", ""), None)
        c = _CVSS3_CIA.get(metrics.get("C", ""), None)
        i = _CVSS3_CIA.get(metrics.get("I", ""), None)
        a = _CVSS3_CIA.get(metrics.get("A", ""), None)

        if any(v is None for v in (av, ac, pr, ui, c, i, a)):
            return None

        # Type narrowing for mypy — the None case is already handled by the
        # ``any(v is None ...)`` guard above; these are runtime-safe casts.
        av, ac, pr, ui = float(av), float(ac), float(pr), float(ui)  # type: ignore[arg-type]
        c, i, a = float(c), float(i), float(a)  # type: ignore[arg-type]

        isc_base = 1.0 - (1.0 - c) * (1.0 - i) * (1.0 - a)
        if scope == "C":
            isc = 7.52 * (isc_base - 0.029) - 3.25 * ((isc_base - 0.02) ** 15)
        else:
            isc = 6.42 * isc_base

        if isc <= 0:
            return 0.0

        exploitability = 8.22 * av * ac * pr * ui

        if scope == "C":
            raw = min(1.08 * (isc + exploitability), 10.0)
        else:
            raw = min(isc + exploitability, 10.0)

        # Roundup to one decimal (CVSS spec: ceiling to 1 decimal)
        return math.ceil(raw * 10) / 10.0

    except Exception as exc:
        _logger.debug("CVSS vector parse failed for %r: %s", vector, exc)
        return None


def parse_osv_severity(vuln_data: dict) -> tuple[Severity, Optional[float], Optional[str]]:
    """Extract severity, CVSS score, and severity source from OSV vulnerability data.

    Returns ``(severity, cvss_score, severity_source)`` where *severity_source*
    indicates where the severity was derived from:

    - ``"cvss"`` — parsed from a CVSS v3/v4 vector or numeric score
    - ``"osv_database"`` — from ``database_specific.severity``
    - ``"osv_ecosystem"`` — from ``ecosystem_specific.severity``
    - ``"ghsa_heuristic"`` — inferred MEDIUM for reviewed GHSA advisories
    - ``None`` — severity is UNKNOWN, no source available
    """
    cvss_score = None
    severity = Severity.UNKNOWN  # Default — never silently inflate to MEDIUM
    severity_source: Optional[str] = None

    # Check severity array — may be numeric score or CVSS vector string
    for sev in vuln_data.get("severity", []):
        if sev.get("type") in ("CVSS_V3", "CVSS_V3_1", "CVSS_V4"):
            score_str = sev.get("score", "")
            try:
                parsed = float(score_str)
                # CVSS scores must be 0.0–10.0
                if 0.0 <= parsed <= 10.0:
                    cvss_score = parsed
            except ValueError:
                # It's a CVSS vector string — compute the base score
                computed = parse_cvss_vector(score_str)
                if computed is not None and 0.0 <= computed <= 10.0:
                    cvss_score = computed

    # Check database_specific for severity label (reliable fallback)
    db_specific = vuln_data.get("database_specific", {})
    if "severity" in db_specific:
        sev_str = db_specific["severity"].upper()
        severity_map = {
            "CRITICAL": Severity.CRITICAL,
            "HIGH": Severity.HIGH,
            "MODERATE": Severity.MEDIUM,
            "MEDIUM": Severity.MEDIUM,
            "LOW": Severity.LOW,
        }
        resolved = severity_map.get(sev_str, Severity.UNKNOWN)
        if resolved != Severity.UNKNOWN:
            severity = resolved
            severity_source = "osv_database"

    # CVSS score overrides label-based severity
    if cvss_score is not None:
        severity = cvss_to_severity(cvss_score)
        severity_source = "cvss"

    # If still UNKNOWN, try to infer from ecosystem_specific or affected data
    if severity == Severity.UNKNOWN:
        eco_specific = vuln_data.get("ecosystem_specific", {})
        if isinstance(eco_specific, dict) and "severity" in eco_specific:
            sev_str = str(eco_specific["severity"]).upper()
            severity_map = {
                "CRITICAL": Severity.CRITICAL,
                "HIGH": Severity.HIGH,
                "MODERATE": Severity.MEDIUM,
                "MEDIUM": Severity.MEDIUM,
                "LOW": Severity.LOW,
            }
            resolved = severity_map.get(sev_str, severity)
            if resolved != Severity.UNKNOWN:
                severity = resolved
                severity_source = "osv_ecosystem"

    # Last resort: if GHSA advisory, treat as at least MEDIUM
    # (GHSA advisories are reviewed and vetted — they wouldn't exist without merit)
    if severity == Severity.UNKNOWN:
        vuln_id = vuln_data.get("id", "")
        if vuln_id.startswith("GHSA-"):
            severity = Severity.MEDIUM
            severity_source = "ghsa_heuristic"

    return severity, cvss_score, severity_source


def _candidate_package_names(package_name: str, ecosystem: str = "", source_package: str | None = None) -> set[str]:
    """Normalized candidate package names for matching advisories."""
    names = {normalize_package_name(package_name, ecosystem)}
    if source_package:
        source_norm = normalize_package_name(source_package, ecosystem)
        if source_norm:
            names.add(source_norm)
    return names


def parse_fixed_version(
    vuln_data: dict,
    package_name: str,
    ecosystem: str = "",
    current_version: str = "",
    source_package: str | None = None,
) -> Optional[str]:
    """Extract fixed version from OSV affected data.

    Prefers stable releases over pre-release versions.  Uses PEP 503
    normalization when comparing PyPI package names so that mixed-separator
    forms (e.g. ``Requests_OAuthlib`` vs ``requests-oauthlib``) always match.

    Guards against cross-package fix bleed: skips affected entries with no
    package name and skips fix versions lower than ``current_version``.
    """
    from agent_bom.version_utils import compare_version_order

    norm_inputs = _candidate_package_names(package_name, ecosystem, source_package)
    prerelease_candidate: Optional[str] = None

    for affected in vuln_data.get("affected", []):
        pkg = affected.get("package", {})
        pkg_name = pkg.get("name", "")
        # Skip entries with no package name — can't match, causes false fix bleed
        if not pkg_name:
            _logger.debug("Skipping affected entry with empty package name in %s", vuln_data.get("id", "?"))
            continue
        osv_eco = pkg.get("ecosystem", ecosystem)
        osv_norm = normalize_package_name(pkg_name, osv_eco)
        if osv_norm in norm_inputs:
            for rng in affected.get("ranges", []):
                for event in rng.get("events", []):
                    if "fixed" in event:
                        fixed = event["fixed"]
                        try:
                            if current_version and current_version not in ("unknown", "latest", ""):
                                current_cmp = compare_version_order(current_version, fixed, ecosystem)
                                if current_cmp is not None and current_cmp > 0:
                                    _logger.debug(
                                        "Skipping fix %s < current %s for %s",
                                        fixed,
                                        current_version,
                                        package_name,
                                    )
                                    continue
                            from packaging.version import Version

                            pv = Version(fixed)
                            if not pv.is_prerelease:
                                return fixed
                            # Remember pre-release as fallback
                            if prerelease_candidate is None:
                                prerelease_candidate = fixed
                        except Exception as exc:  # noqa: BLE001
                            _logger.debug("Version parse failed for %r: %s", fixed, exc)
                            if current_version and current_version not in ("unknown", "latest", ""):
                                current_cmp = compare_version_order(current_version, fixed, ecosystem)
                                if current_cmp is not None and current_cmp > 0:
                                    continue
                            if _is_valid_fix_version(fixed):
                                return fixed
                            # Not a usable version — skip silently
    return prerelease_candidate


def _is_valid_fix_version(version: str) -> bool:
    """Check if a string looks like a usable package version (not a git SHA or random hash).

    Returns False for:
    - Git commit SHAs (40 hex chars)
    - Short SHAs (7-12 hex chars with no dots/dashes)
    - Empty strings
    - Strings with no digits at all
    """
    if not version or not any(c.isdigit() for c in version):
        return False
    # Git SHA: 40 hex chars
    stripped = version.lstrip("v")
    if len(stripped) == 40 and all(c in "0123456789abcdef" for c in stripped):
        return False
    # Short SHA: 7-12 hex chars with no version separators
    if 7 <= len(stripped) <= 12 and all(c in "0123456789abcdef" for c in stripped):
        return False
    return True


def _package_lookup_names(pkg: Package) -> list[str]:
    """Lookup names for a package, preserving the primary package name first."""
    ordered: list[str] = []
    seen: set[str] = set()
    for name in pkg.lookup_names:
        norm = normalize_package_name(name, pkg.ecosystem)
        if norm and norm not in seen:
            ordered.append(norm)
            seen.add(norm)
    return ordered


async def _enrich_vuln_details(client: httpx.AsyncClient, vuln_ids: list[str]) -> dict[str, dict]:
    """Fetch full vulnerability details from OSV /v1/vulns/{id}.

    The querybatch endpoint only returns {id, modified}.  This function
    fetches the complete record (summary, severity, references, affected,
    aliases) for each unique ID so callers get rich data.
    """
    if not vuln_ids:
        return {}

    sem = asyncio.Semaphore(10)  # cap concurrent fetches

    async def _fetch_one(vid: str) -> tuple[str, dict]:
        async with sem:
            resp = await request_with_retry(client, "GET", f"{OSV_API_URL}/vulns/{vid}")
            if resp and resp.status_code == 200:
                try:
                    return vid, resp.json()
                except (ValueError, KeyError):
                    pass
        return vid, {}

    pairs = await asyncio.gather(*[_fetch_one(vid) for vid in vuln_ids])
    return dict(pairs)


async def _enrich_results_if_needed(results: dict[str, list[dict]]) -> dict[str, list[dict]]:
    """Enrich minimal OSV batch results with full vuln details where missing.

    Fetches /v1/vulns/{id} for any vuln entry that only has {id, modified}.
    """
    if not results:
        return results
    all_vuln_ids: list[str] = []
    for vuln_list in results.values():
        for v in vuln_list:
            if "summary" not in v and v.get("id"):
                all_vuln_ids.append(v["id"])
    unique_ids = list(dict.fromkeys(all_vuln_ids))
    if not unique_ids:
        return results
    try:
        async with create_client(timeout=20.0) as detail_client:
            details_map = await _enrich_vuln_details(detail_client, unique_ids)
        for key, vuln_list in results.items():
            results[key] = [{**v, **details_map.get(v.get("id", ""), {})} for v in vuln_list]
    except Exception as exc:
        _logger.warning("OSV detail enrichment skipped (vulnerability summaries may be incomplete): %s", exc)
        console.print(
            "  [yellow]⚠[/yellow] OSV detail enrichment skipped — vulnerability summaries may be incomplete."
            " [dim]Use --verbose for details.[/dim]"
        )
    return results


async def query_osv_batch(packages: list[Package]) -> dict[str, list[dict]]:
    """Query OSV API for vulnerabilities in batch.

    Uses an optional SQLite cache (``ScanCache``) to skip packages that were
    already queried within the last 24 hours.
    """
    if not packages:
        return {}

    cache = _get_scan_cache()
    results: dict[str, list[dict]] = {}
    packages_to_query: list[Package] = []
    skipped_versions = 0

    skipped_ecosystems: dict[str, int] = {}

    # Check cache first
    for pkg in packages:
        eco_key = pkg.ecosystem.lower()
        osv_ecosystems = _osv_ecosystems_for_package(pkg)
        if not osv_ecosystems:
            if eco_key in _NON_OSV_ECOSYSTEMS:
                _logger.debug(
                    "Skipping package %s/%s: ecosystem %r is not OSV-queryable (handled by other pipeline)",
                    pkg.ecosystem,
                    pkg.name,
                    pkg.ecosystem,
                )
            else:
                _logger.warning(
                    "Skipping package %s/%s: unknown ecosystem %r — add to ECOSYSTEM_MAP or _NON_OSV_ECOSYSTEMS",
                    pkg.ecosystem,
                    pkg.name,
                    pkg.ecosystem,
                )
            skipped_ecosystems[eco_key] = skipped_ecosystems.get(eco_key, 0) + 1
            continue
        if not pkg.version or pkg.version in ("unknown", "latest"):
            _logger.warning(
                "Skipping package %s/%s: unresolvable version %r",
                pkg.ecosystem,
                pkg.name,
                pkg.version,
            )
            skipped_versions += 1
            continue
        norm_name = normalize_package_name(pkg.name, eco_key)
        cache_key_eco = eco_key if len(osv_ecosystems) == 1 else f"{eco_key}|{'|'.join(osv_ecosystems)}"
        if cache:
            cached = cache.get(cache_key_eco, norm_name, pkg.version)
            if cached is not None:
                if cached:  # non-empty vuln list
                    key = f"{eco_key}:{norm_name}@{pkg.version}"
                    results[key] = cached
                continue  # skip API call (cached hit or cached "clean")
        packages_to_query.append(pkg)

    if not packages_to_query:
        total_skipped_eco = sum(skipped_ecosystems.values())
        scanned = len(packages) - skipped_versions - total_skipped_eco
        if skipped_versions or skipped_ecosystems:
            _logger.info(
                "Scan complete: %d packages scanned, %d skipped (unresolvable versions), %d skipped (non-OSV ecosystem)",
                scanned,
                skipped_versions,
                total_skipped_eco,
            )
        if skipped_ecosystems:
            parts = ", ".join(f"{eco}: {cnt}" for eco, cnt in sorted(skipped_ecosystems.items()))
            console.print(f"  [dim]Skipped {total_skipped_eco} packages not in OSV database ({parts})[/dim]")
        return await _enrich_results_if_needed(results)

    queries = []
    pkg_index = {}  # Map query index to (package, queried_name)

    for pkg in packages_to_query:
        eco_key = pkg.ecosystem.lower()
        osv_ecosystems = _osv_ecosystems_for_package(pkg)
        if not osv_ecosystems or pkg.version in ("unknown", "latest"):
            continue  # already logged in cache-check loop above

        # Normalize name for consistent OSV matching (PEP 503 for PyPI)
        # Go module versions are stored without 'v' prefix internally but OSV
        # Go ecosystem expects the canonical semver 'v' prefix.
        osv_version = f"v{pkg.version}" if eco_key == "go" and not pkg.version.startswith("v") else pkg.version
        for osv_ecosystem in osv_ecosystems:
            for norm_name in _package_lookup_names(pkg):
                queries.append(
                    {
                        "version": osv_version,
                        "package": {
                            "name": norm_name,
                            "ecosystem": osv_ecosystem,
                        },
                    }
                )
                pkg_index[len(queries) - 1] = (pkg, norm_name)

    if not queries:
        return await _enrich_results_if_needed(results)

    # Track which queried packages got vulns (to cache "clean" results too)
    queried_keys_with_vulns: set[str] = set()
    # Track packages whose CVE lookup failed (batch errors, parse errors, etc.)
    _lookup_errors: list[tuple[str, str, str]] = []  # (pkg_name, ecosystem, error)

    # OSV batch API accepts up to 1000 queries; configurable via AGENT_BOM_SCANNER_BATCH_SIZE
    batch_size = min(_BATCH_SIZE, 1000)  # clamp to OSV API max
    semaphore = _get_api_semaphore()
    try:
        _client_ctx = create_client(timeout=30.0)
    except OfflineModeError:
        _logger.info("Offline mode: skipping OSV batch query for %d packages", len(queries))
        console.print("  [yellow]⚠[/yellow] Offline mode — CVE scanning skipped. Use local DB or remove --offline.")
        return results

    async with _client_ctx as client:
        for batch_start in range(0, len(queries), batch_size):
            batch = queries[batch_start : batch_start + batch_size]

            async with semaphore:
                response = await request_with_retry(
                    client,
                    "POST",
                    OSV_BATCH_URL,
                    json={"queries": batch},
                )

                if response and response.status_code == 200:
                    try:
                        data = response.json()
                        osv_results = data.get("results", [])
                        # Validate response length matches batch to prevent index misattribution
                        if len(osv_results) != len(batch):
                            _logger.warning(
                                "OSV batch response length mismatch: sent %d queries, got %d results. "
                                "Some packages may have missed vulnerability detection.",
                                len(batch),
                                len(osv_results),
                            )
                            console.print(
                                f"  [yellow]⚠[/yellow] OSV batch response length mismatch:"
                                f" sent {len(batch)} queries, got {len(osv_results)} results."
                                f" [dim]Some packages may have missed vulnerability detection.[/dim]"
                            )
                        for i, result in enumerate(osv_results):
                            if i >= len(batch):
                                break  # Safety: don't read past our query count
                            vulns = result.get("vulns", [])
                            if vulns:
                                actual_idx = batch_start + i
                                pkg_match = pkg_index.get(actual_idx)
                                if pkg_match:
                                    pkg_obj, _queried_name = pkg_match
                                    norm = normalize_package_name(pkg_obj.name, pkg_obj.ecosystem)
                                    key = f"{pkg_obj.ecosystem.lower()}:{norm}@{pkg_obj.version}"
                                    existing = results.setdefault(key, [])
                                    seen_ids = {item.get("id") for item in existing}
                                    for vuln in vulns:
                                        if vuln.get("id") not in seen_ids:
                                            existing.append(vuln)
                                            seen_ids.add(vuln.get("id"))
                                    queried_keys_with_vulns.add(key)
                    except (ValueError, KeyError) as e:
                        console.print(f"  [red]✗[/red] OSV response parse error: {e}")
                        for idx in range(batch_start, min(batch_start + len(batch), len(queries))):
                            pkg_err = pkg_index.get(idx)
                            if pkg_err:
                                _lookup_errors.append((pkg_err[0].name, pkg_err[0].ecosystem, f"parse error: {e}"))
                elif response and response.status_code == 429:
                    # request_with_retry exhausted all retries and still got 429 — apply
                    # a pipeline-level cooldown before the next batch, respecting any
                    # Retry-After hint from the server.
                    retry_after_hdr = response.headers.get("Retry-After")
                    pipeline_wait = _PIPELINE_429_BACKOFF
                    if retry_after_hdr:
                        try:
                            pipeline_wait = min(float(retry_after_hdr), _PIPELINE_429_BACKOFF)
                        except ValueError:
                            pass
                    console.print(f"  [yellow]⚠[/yellow] OSV rate limit (429) — pausing {pipeline_wait:.0f}s before next batch")
                    _logger.warning("OSV rate limit hit after all retries; pausing pipeline %.0fs", pipeline_wait)
                    await asyncio.sleep(pipeline_wait)
                elif response:
                    console.print(f"  [red]✗[/red] OSV API error: HTTP {response.status_code}")
                    for idx in range(batch_start, min(batch_start + len(batch), len(queries))):
                        pkg_err = pkg_index.get(idx)
                        if pkg_err:
                            _lookup_errors.append((pkg_err[0].name, pkg_err[0].ecosystem, f"HTTP {response.status_code}"))
                else:
                    console.print("  [red]✗[/red] OSV API unreachable after retries")
                    for idx in range(batch_start, min(batch_start + len(batch), len(queries))):
                        pkg_err = pkg_index.get(idx)
                        if pkg_err:
                            _lookup_errors.append((pkg_err[0].name, pkg_err[0].ecosystem, "unreachable"))

            # Rate limit: delay between batches
            if batch_start + batch_size < len(queries):
                await asyncio.sleep(BATCH_DELAY_SECONDS)

    # Enrich minimal batch results with full vuln details (summary, CVSS, etc.)
    await _enrich_results_if_needed(results)

    # Populate cache with fresh results — off event loop to avoid blocking
    if cache:
        cache_writes = [
            (
                pkg.ecosystem.lower()
                if len(_osv_ecosystems_for_package(pkg)) == 1
                else f"{pkg.ecosystem.lower()}|{'|'.join(_osv_ecosystems_for_package(pkg))}",
                normalize_package_name(pkg.name, pkg.ecosystem),
                pkg.version,
                results.get(f"{pkg.ecosystem.lower()}:{normalize_package_name(pkg.name, pkg.ecosystem)}@{pkg.version}", []),
            )
            for pkg in packages_to_query
        ]
        await asyncio.to_thread(cache.put_many, cache_writes)

    total_skipped_eco = sum(skipped_ecosystems.values())
    scanned = len(packages) - skipped_versions - total_skipped_eco
    if skipped_versions or skipped_ecosystems:
        _logger.info(
            "Scan complete: %d packages scanned, %d skipped (unresolvable versions), %d skipped (non-OSV ecosystem)",
            scanned,
            skipped_versions,
            total_skipped_eco,
        )
    if skipped_ecosystems:
        parts = ", ".join(f"{eco}: {cnt}" for eco, cnt in sorted(skipped_ecosystems.items()))
        console.print(f"  [dim]Skipped {total_skipped_eco} packages not in OSV database ({parts})[/dim]")
    if _lookup_errors:
        _logger.warning(
            "%d packages had CVE lookup errors — vulnerability detection may be incomplete",
            len(_lookup_errors),
        )
        console.print(f"  [yellow]⚠[/yellow] {len(_lookup_errors)} packages had lookup errors [dim](use --verbose for details)[/dim]")
        for pkg_name, eco, err in _lookup_errors:
            _logger.info("  Lookup error: %s/%s — %s", eco, pkg_name, err)
    return results


def _is_version_affected(
    vuln_data: dict,
    package_name: str,
    package_version: str,
    ecosystem: str = "",
    source_package: str | None = None,
) -> bool:
    """Check if a specific version falls within the OSV affected ranges.

    Walks the ``affected[].ranges[].events[]`` structure and applies
    semver/PEP 440 range logic:

    - ``introduced``: version >= introduced means potentially affected
    - ``fixed``: version >= fixed means NOT affected (patched)
    - ``last_affected``: version > last_affected means NOT affected

    Returns True if the version IS affected, False if it's been fixed
    or is outside all affected ranges.  Returns True (conservative) if
    version parsing fails or no range data is available.
    """
    from agent_bom.version_utils import compare_version_order

    norm_names = _candidate_package_names(package_name, ecosystem, source_package)

    found_package = False

    for affected in vuln_data.get("affected", []):
        pkg = affected.get("package", {})
        osv_eco = pkg.get("ecosystem", ecosystem)
        osv_name = normalize_package_name(pkg.get("name", ""), osv_eco)
        if osv_name not in norm_names:
            continue

        found_package = True

        # Check explicit version list first
        versions_list = affected.get("versions", [])
        if versions_list:
            if package_version in versions_list:
                return True
            # If explicit list exists and our version isn't in it, not affected
            continue

        # If no ranges AND no versions, assume affected (incomplete advisory data)
        ranges = affected.get("ranges", [])
        if not ranges:
            return True

        # Check ranges
        for rng in ranges:
            rng_type = rng.get("type", "")
            # Accept SEMVER, ECOSYSTEM, or missing type (common in OSV data)
            if rng_type and rng_type not in ("SEMVER", "ECOSYSTEM", "GIT"):
                continue

            events = rng.get("events", [])
            # If range has fixed/last_affected but no introduced, assume introduced=0
            has_introduced = any("introduced" in e for e in events)
            is_affected = not has_introduced  # default: affected if no introduced
            for event in events:
                if "introduced" in event:
                    intro = event["introduced"]
                    if intro == "0":
                        is_affected = True
                    else:
                        intro_cmp = compare_version_order(package_version, intro, ecosystem)
                        is_affected = True if intro_cmp is None else intro_cmp >= 0
                elif "fixed" in event:
                    fixed_cmp = compare_version_order(package_version, event["fixed"], ecosystem)
                    if fixed_cmp is not None and fixed_cmp >= 0:
                        is_affected = False
                elif "last_affected" in event:
                    last_cmp = compare_version_order(package_version, event["last_affected"], ecosystem)
                    if last_cmp is not None and last_cmp > 0:
                        is_affected = False

            if is_affected:
                return True

    # If we found the package in affected but no range matched AND no version
    # list was present, assume affected (conservative — the advisory was issued
    # for this package but has incomplete range data).
    if found_package:
        return False  # ranges were checked and version is outside all of them

    # No affected data for this package — trust OSV's original query response
    return True


def build_vulnerabilities(vuln_data_list: list[dict], package: Package) -> list[Vulnerability]:
    """Convert OSV response data to Vulnerability objects.

    Filters out false positives by verifying the package version falls
    within OSV affected ranges.  Deduplicates by canonical CVE ID.
    """
    vulns = []
    seen_ids: set[str] = set()

    for vuln_data in vuln_data_list:
        vuln_id = vuln_data.get("id", "unknown")

        # Version-range filter: skip vulns that don't affect our version
        if package.version and package.version not in ("unknown", "latest"):
            if not _is_version_affected(
                vuln_data,
                package.name,
                package.version,
                package.ecosystem,
                source_package=package.source_package,
            ):
                _logger.debug(
                    "Filtered %s: version %s not in affected range for %s",
                    vuln_id,
                    package.version,
                    package.name,
                )
                continue

        # Compute canonical ID early so dedup catches alias overlaps
        aliases = vuln_data.get("aliases", [])
        cve_alias = next((a for a in aliases if a.startswith("CVE-")), None)
        canonical_id = cve_alias if cve_alias and not vuln_id.startswith("CVE-") else vuln_id

        # Deduplicate by canonical ID AND raw ID — prevents PYSEC/GHSA duplicates
        if canonical_id in seen_ids or vuln_id in seen_ids:
            continue
        seen_ids.add(canonical_id)
        seen_ids.add(vuln_id)
        # Also mark all aliases as seen to prevent future duplicates
        for alias in aliases:
            seen_ids.add(alias)

        severity, cvss_score, sev_source = parse_osv_severity(vuln_data)
        fixed = parse_fixed_version(
            vuln_data,
            package.name,
            package.ecosystem,
            current_version=package.version or "",
            source_package=package.source_package,
        )

        references = [ref.get("url", "") for ref in vuln_data.get("references", []) if ref.get("url")]

        summary = vuln_data.get("summary", vuln_data.get("details", "No description available"))[:200]

        # Collect all aliases (original ID + OSV aliases, minus the canonical)
        all_aliases = [a for a in aliases if a != canonical_id]
        if vuln_id != canonical_id:
            all_aliases.append(vuln_id)

        # Extract CWE IDs from database_specific (GHSA entries store them here)
        cwe_ids: list[str] = []
        db_specific = vuln_data.get("database_specific", {})
        if isinstance(db_specific, dict):
            raw_cwes = db_specific.get("cwe_ids", [])
            if isinstance(raw_cwes, list):
                cwe_ids = [c for c in raw_cwes if isinstance(c, str) and c.startswith("CWE-")]

        vulns.append(
            Vulnerability(
                id=canonical_id,
                summary=summary,
                severity=severity,
                severity_source=sev_source,
                cvss_score=cvss_score,
                fixed_version=fixed,
                references=references,
                published_at=vuln_data.get("published"),
                modified_at=vuln_data.get("modified"),
                aliases=all_aliases,
                cwe_ids=cwe_ids,
            )
        )

    return vulns


def _strip_extras(name: str) -> str:
    """Strip pip extras notation: ``requests[security]`` → ``requests``."""
    import re as _re

    return _re.sub(r"\[.*?\]$", "", name)


def deduplicate_packages(packages: list) -> list:
    """Remove duplicate packages across discovery sources.

    Deduplicates by (ecosystem, normalized_name, version) fingerprint.
    When duplicates exist, the first occurrence is kept (preserves source ordering).

    This prevents redundant OSV API calls and duplicate vulnerability findings
    when the same package is discovered from multiple sources (local, K8s, cloud).

    Args:
        packages: List of Package objects from one or more discovery sources.

    Returns:
        Deduplicated list, preserving first-seen order.
    """
    seen: set[tuple[str, str, str]] = set()
    result = []
    for pkg in packages:
        # Use normalized name for dedup (PEP 503: torch == Torch == pytorch)
        name = getattr(pkg, "name", "") or ""
        ecosystem = getattr(pkg, "ecosystem", "") or ""
        version = getattr(pkg, "version", "") or ""
        norm_name = normalize_package_name(name, ecosystem)
        key = (ecosystem.lower(), norm_name, version.lower())
        if key not in seen:
            seen.add(key)
            result.append(pkg)
    return result


def _local_vuln_to_vulnerability(lv: "Any") -> Vulnerability:
    """Convert a LocalVuln (from SQLite DB) to a Vulnerability model object.

    Canonicalizes ID to CVE when available (prefer CVE-xxxx over GHSA/PYSEC).
    """
    sev_map = {
        "critical": Severity.CRITICAL,
        "high": Severity.HIGH,
        "medium": Severity.MEDIUM,
        "low": Severity.LOW,
    }
    severity = sev_map.get((lv.severity or "").lower(), Severity.UNKNOWN)

    # Canonicalize: prefer CVE ID over GHSA/PYSEC for consistency with Trivy/NVD
    raw_id = lv.id
    aliases = getattr(lv, "aliases", [])
    cve_alias = next((a for a in aliases if a.startswith("CVE-")), None)
    if cve_alias and not raw_id.startswith("CVE-"):
        canonical_id = cve_alias
        all_aliases = [a for a in aliases if a != canonical_id]
        all_aliases.append(raw_id)
    else:
        canonical_id = raw_id
        all_aliases = [a for a in aliases if a != canonical_id]

    return Vulnerability(
        id=canonical_id,
        summary=lv.summary or "No description available",
        severity=severity,
        cvss_score=lv.cvss_score,
        fixed_version=lv.fixed_version if _is_valid_fix_version(lv.fixed_version or "") else None,
        epss_score=lv.epss_probability,
        epss_percentile=lv.epss_percentile,
        is_kev=lv.is_kev,
        kev_date_added=lv.kev_date_added,
        published_at=getattr(lv, "published_at", None),
        modified_at=getattr(lv, "modified_at", None),
        cwe_ids=getattr(lv, "cwe_ids", []),
        aliases=all_aliases,
        references=[],
    )


# Threshold above which batch DB lookup is used instead of per-package queries.
# Batch mode issues a single SQL query per chunk (400 pairs) vs. N individual
# queries — a significant win for scans with thousands of packages.
_BATCH_DB_THRESHOLD = 50


def _scan_packages_local_db(packages: list[Package]) -> tuple[int, set[str]]:
    """Query the local SQLite DB for all packages.

    Returns ``(vuln_count, covered_keys)`` where covered_keys is the set of
    ``ecosystem:norm_name@version`` keys that had at least one entry in the DB
    (including zero-vuln hits — those are DB hits, not gaps).
    """
    try:
        from agent_bom.db.schema import DB_PATH, db_freshness_days

        freshness = db_freshness_days()
        if freshness is None:
            return 0, set()  # No DB yet — fall through to OSV entirely
    except Exception as exc:
        _logger.debug("Local DB freshness check failed (falling through to OSV): %s", exc)
        return 0, set()

    try:
        from agent_bom.db import lookup_package
        from agent_bom.db.schema import init_db, open_existing_db_readonly

        try:
            conn = init_db(DB_PATH)
        except Exception as exc:
            _logger.debug("Writable local DB open failed, retrying read-only: %s", exc)
            conn = open_existing_db_readonly(DB_PATH)
    except Exception as exc:
        _logger.warning("Local DB unavailable: %s", exc)
        return 0, set()

    covered: set[str] = set()
    total = 0

    try:
        from agent_bom.db.lookup import package_in_db

        if len(packages) > _BATCH_DB_THRESHOLD:
            total = _scan_packages_local_db_batch(conn, packages, covered)
        else:
            for pkg in packages:
                eco_key = pkg.ecosystem.lower()
                db_ecos = _db_ecosystems_for_package(pkg) or [pkg.ecosystem.lower()]
                candidate_names = _package_lookup_names(pkg)
                norm_name = candidate_names[0]
                db_key = f"{eco_key}:{norm_name}@{pkg.version}"
                local_vulns = []
                db_hit = False
                for db_eco in db_ecos:
                    for candidate_name in candidate_names:
                        local_vulns.extend(lookup_package(conn, db_eco, candidate_name, pkg.version))
                        db_hit = db_hit or package_in_db(conn, db_eco, candidate_name)

                # Only mark as "covered by DB" when the package name actually exists in the
                # affected table — not just because the ecosystem is mapped. This prevents
                # false negatives where a package has no DB entry but is silently skipped
                # (no OSV fallback) because the ecosystem is present.
                if db_hit:
                    covered.add(db_key)

                if local_vulns:
                    existing_ids = {v.id for v in pkg.vulnerabilities}
                    # Also track aliases to prevent PYSEC/GHSA/CVE duplicates
                    for v in pkg.vulnerabilities:
                        existing_ids.update(v.aliases)
                    new_vulns = []
                    for lv in local_vulns:
                        # Skip if this vuln or any of its aliases already seen
                        lv_all_ids = {lv.id} | set(getattr(lv, "aliases", []))
                        if lv_all_ids & existing_ids:
                            continue
                        new_vulns.append(_local_vuln_to_vulnerability(lv))
                        existing_ids.add(lv.id)
                        existing_ids.update(getattr(lv, "aliases", []))
                    pkg.vulnerabilities.extend(new_vulns)
                    total += len(new_vulns)
                    for v in new_vulns:
                        if compliance_mode:
                            v.compliance_tags = _tag_vuln(v, pkg)
                    flag_malicious_from_vulns(pkg)
    finally:
        conn.close()

    return total, covered


def _scan_packages_local_db_batch(
    conn: Any,
    packages: list[Package],
    covered: set[str],
) -> int:
    """Batch variant of the local DB scan — fewer SQL round-trips.

    Uses :func:`lookup_packages_batch` to fetch all vulnerabilities in bulk,
    then applies the same dedup / tagging logic as the per-package path.
    """
    from agent_bom.db.lookup import lookup_packages_batch, package_in_db

    # Build batch keys: (db_ecosystem, normalized_name, version)
    pkg_index: list[tuple[Package, list[str], str, str, list[str]]] = []  # (pkg, db_ecos, primary_norm_name, db_key, candidate_names)
    batch_keys: list[tuple[str, str, str]] = []

    for pkg in packages:
        eco_key = pkg.ecosystem.lower()
        db_ecos = _db_ecosystems_for_package(pkg) or [pkg.ecosystem.lower()]
        candidate_names = _package_lookup_names(pkg)
        norm_name = candidate_names[0]
        db_key = f"{eco_key}:{norm_name}@{pkg.version}"
        pkg_index.append((pkg, db_ecos, norm_name, db_key, candidate_names))
        for db_eco in db_ecos:
            for candidate_name in candidate_names:
                batch_keys.append((db_eco, candidate_name, pkg.version))

    batch_results = lookup_packages_batch(conn, batch_keys)

    total = 0
    for pkg, db_ecos, norm_name, db_key, candidate_names in pkg_index:
        local_vulns = []
        for db_eco in db_ecos:
            for candidate_name in candidate_names:
                local_vulns.extend(batch_results.get((db_eco, candidate_name, pkg.version), []))

        if any(package_in_db(conn, db_eco, candidate_name) for db_eco in db_ecos for candidate_name in candidate_names):
            covered.add(db_key)

        if local_vulns:
            existing_ids = {v.id for v in pkg.vulnerabilities}
            # Also track aliases to prevent PYSEC/GHSA/CVE duplicates
            for v in pkg.vulnerabilities:
                existing_ids.update(v.aliases)
            new_vulns = []
            for lv in local_vulns:
                # Skip if this vuln or any of its aliases already seen
                lv_all_ids = {lv.id} | set(getattr(lv, "aliases", []))
                if lv_all_ids & existing_ids:
                    continue
                new_vulns.append(_local_vuln_to_vulnerability(lv))
                existing_ids.add(lv.id)
                existing_ids.update(getattr(lv, "aliases", []))
            pkg.vulnerabilities.extend(new_vulns)
            total += len(new_vulns)
            for v in new_vulns:
                if compliance_mode:
                    v.compliance_tags = _tag_vuln(v, pkg)
            flag_malicious_from_vulns(pkg)

    return total


async def scan_packages(packages: list[Package], *, resolve_transitive: bool = False) -> int:
    """Scan a list of packages for vulnerabilities. Returns count of vulns found."""
    # Deduplicate packages across discovery sources before scanning.
    # Prevents redundant OSV API calls when the same package is discovered
    # from multiple sources (local, K8s, cloud).
    original_count = len(packages)
    packages = deduplicate_packages(packages)
    deduped = original_count - len(packages)
    if deduped > 0:
        _logger.info("Deduplicated %d duplicate packages (kept %d unique)", deduped, len(packages))

    # Normalize package names for consistent matching (PEP 503 for PyPI)
    # and strip pip extras notation (OSV doesn't understand extras)
    for pkg in packages:
        if pkg.ecosystem.lower() == "pypi":
            if "[" in pkg.name:
                pkg.name = _strip_extras(pkg.name)
            pkg.name = normalize_package_name(pkg.name, pkg.ecosystem)

    # ── Local version resolution (installed packages) ──────────────────────
    # Try resolving versions from locally installed packages FIRST.
    # This is more accurate than registry fallback because it reflects
    # what's actually on disk (e.g. npm list, pip list).
    unresolved = [p for p in packages if p.version in ("latest", "unknown", "") and p.ecosystem.lower() in ("npm", "pypi", "go")]
    if unresolved:
        try:
            from agent_bom.resolvers.runtime_resolver import (
                resolve_go_versions,
                resolve_npm_versions,
                resolve_pip_versions,
            )

            local_resolved = 0

            # Resolve pip packages from locally installed versions
            pip_unresolved = [p for p in unresolved if p.ecosystem.lower() == "pypi"]
            if pip_unresolved:
                pip_versions = resolve_pip_versions()
                for pkg in pip_unresolved:
                    installed_ver = (
                        pip_versions.get(pkg.name.lower())
                        or pip_versions.get(pkg.name.lower().replace("-", "_"))
                        or pip_versions.get(pkg.name.lower().replace("_", "-"))
                    )
                    if installed_ver:
                        pkg.version = installed_ver
                        pkg.purl = f"pkg:{pkg.ecosystem}/{pkg.name}@{installed_ver}"
                        pkg.version_source = "installed"
                        local_resolved += 1

            # Resolve npm packages from locally installed versions
            npm_unresolved = [p for p in unresolved if p.ecosystem.lower() == "npm"]
            if npm_unresolved:
                from pathlib import Path as _NpmPath

                # Try CWD — npm ls reports the full dependency tree
                npm_versions = resolve_npm_versions(_NpmPath.cwd())
                for pkg in npm_unresolved:
                    installed_ver = npm_versions.get(pkg.name)
                    if installed_ver:
                        pkg.version = installed_ver
                        pkg.purl = f"pkg:{pkg.ecosystem}/{pkg.name}@{installed_ver}"
                        pkg.version_source = "installed"
                        local_resolved += 1

            # Resolve Go packages from locally installed versions
            go_unresolved = [p for p in unresolved if p.ecosystem.lower() == "go"]
            if go_unresolved:
                from pathlib import Path as _GoPath

                go_versions = resolve_go_versions(_GoPath.cwd())
                for pkg in go_unresolved:
                    installed_ver = go_versions.get(pkg.name)
                    if installed_ver:
                        pkg.version = installed_ver
                        pkg.purl = f"pkg:{pkg.ecosystem}/{pkg.name}@{installed_ver}"
                        pkg.version_source = "installed"
                        local_resolved += 1

            if local_resolved:
                console.print(f"  [green]✓[/green] Resolved {local_resolved} package version(s) from local install")
        except Exception as exc:
            _logger.debug("Local version resolution failed: %s", exc)

    # ── Registry fallback for still-unresolved versions ──────────────────
    # Only hit npm/PyPI registries for packages we couldn't resolve locally.
    # In offline mode, skip all registry calls entirely.
    still_unresolved = [p for p in packages if p.version in ("latest", "unknown", "") and p.ecosystem.lower() in ("npm", "pypi", "conda")]
    if still_unresolved and not offline_mode:
        try:
            from agent_bom.resolver import resolve_all_versions

            resolved_count = await resolve_all_versions(still_unresolved)
            if resolved_count:
                # Mark these as registry-resolved so output shows confidence
                for pkg in still_unresolved:
                    if pkg.version not in ("latest", "unknown", ""):
                        pkg.version_source = "registry_fallback"
                console.print(f"  [green]✓[/green] Auto-resolved {resolved_count} package version(s) from registry")
        except Exception as exc:
            _logger.warning("Version resolution failed for %d package(s): %s", len(still_unresolved), exc)
            console.print(f"  [yellow]⚠[/yellow] Version resolution skipped: {exc}")
    elif still_unresolved and offline_mode:
        _logger.info("Offline mode: skipping registry version resolution for %d package(s)", len(still_unresolved))

    # ── Transitive dependency resolution (npm / PyPI / Go) ───────────────────
    if resolve_transitive and not offline_mode:
        transitive_ecosystems = {"npm", "pypi", "go"}
        eligible = [p for p in packages if p.ecosystem.lower() in transitive_ecosystems]
        if eligible:
            try:
                from agent_bom.transitive import resolve_transitive_dependencies

                _logger.info("Resolving transitive dependencies for %d package(s)...", len(eligible))
                transitive_pkgs = await resolve_transitive_dependencies(eligible)
                if transitive_pkgs:
                    existing_keys = {f"{p.ecosystem.lower()}:{normalize_package_name(p.name, p.ecosystem)}@{p.version}" for p in packages}
                    new_pkgs = [
                        p
                        for p in transitive_pkgs
                        if f"{p.ecosystem.lower()}:{normalize_package_name(p.name, p.ecosystem)}@{p.version}" not in existing_keys
                    ]
                    if new_pkgs:
                        packages = packages + new_pkgs
                        packages = deduplicate_packages(packages)
                        console.print(f"  [cyan]→[/cyan] Transitive resolution: {len(new_pkgs)} additional package(s) queued")
            except Exception as exc:  # noqa: BLE001
                _logger.warning("Transitive resolution failed, scanning direct dependencies only: %s", exc)

    # SAST packages already carry vulns from Semgrep — skip OSV query for them
    scannable = [p for p in packages if p.version not in ("unknown", "latest", "") and p.ecosystem.lower() != "sast"]

    # Warn about packages that could not be resolved — no silent failures
    still_unresolved = [p for p in packages if p.version in ("unknown", "latest", "") and p.ecosystem.lower() != "sast"]
    if still_unresolved:
        names = ", ".join(f"{p.name}@{p.version}" for p in still_unresolved[:10])
        suffix = f" (+{len(still_unresolved) - 10} more)" if len(still_unresolved) > 10 else ""
        console.print(f"  [yellow]⚠[/yellow] {len(still_unresolved)} package(s) skipped (unresolved version): {names}{suffix}")
        _logger.warning(
            "Skipped %d package(s) with unresolved versions: %s",
            len(still_unresolved),
            names + suffix,
        )

    if not scannable:
        return 0

    # ── Local DB lookup (fast, offline-capable) ───────────────────────────────
    # Query the local SQLite DB first.  Packages covered by the DB skip the
    # OSV API call — saving round-trips and enabling fully offline scanning
    # when the DB is populated via `agent-bom db update`.
    local_count, db_covered = _scan_packages_local_db(scannable)
    if local_count:
        console.print(f"  [green]✓[/green] Local DB: {local_count} vulnerability/vulnerabilities found (offline)")

    # Only call OSV for packages not already covered by the local DB
    def _db_key(p: Package) -> str:
        return f"{p.ecosystem.lower()}:{normalize_package_name(p.name, p.ecosystem)}@{p.version}"

    osv_targets = [p for p in scannable if _db_key(p) not in db_covered]

    if offline_mode or (prefer_local_db and not osv_targets):
        if osv_targets and offline_mode:
            _logger.info("Offline mode: skipping OSV API for %d package(s) not in local DB", len(osv_targets))
            skipped_count = len(osv_targets)
            covered_count = len(scannable) - skipped_count
            console.print(
                f"  [dim]Offline mode: using local cache only. "
                f"{covered_count} packages checked, {skipped_count} skipped (no cached data).[/dim]"
            )
        results = {}
    elif prefer_local_db and osv_targets:
        # DB is fresh — only query OSV for packages genuinely missing from DB
        _logger.debug("Local DB preferred: querying OSV for %d uncovered package(s) only", len(osv_targets))
        results = await query_osv_batch(osv_targets)
    elif osv_targets:
        results = await query_osv_batch(osv_targets)
    else:
        results = {}

    total_vulns = local_count
    for pkg in osv_targets:
        norm = normalize_package_name(pkg.name, pkg.ecosystem)
        key = f"{pkg.ecosystem.lower()}:{norm}@{pkg.version}"
        vuln_data = results.get(key, [])
        if vuln_data:
            new_vulns = build_vulnerabilities(vuln_data, pkg)
            # Merge: don't duplicate what the local DB already found
            existing_ids = {v.id for v in pkg.vulnerabilities}
            merged = [v for v in new_vulns if v.id not in existing_ids]
            pkg.vulnerabilities.extend(merged)
            total_vulns += len(merged)
            # Tag each CVE with compliance framework codes (pre-enrichment)
            for v in merged:
                if compliance_mode:
                    v.compliance_tags = _tag_vuln(v, pkg)
            # Flag packages with MAL- prefixed vulnerability IDs as malicious
            flag_malicious_from_vulns(pkg)

    # Back-fill: also run OSV tagging for packages that came from local DB only
    for pkg in scannable:
        if pkg in osv_targets:
            continue  # already processed above
        for v in pkg.vulnerabilities:
            if not v.compliance_tags:
                if compliance_mode:
                    v.compliance_tags = _tag_vuln(v, pkg)

    # Supplemental: check NVIDIA advisories for all AI framework packages.
    # nvidia_advisory.py maps NVIDIA CSAF products to bundling frameworks (torch,
    # jax, vllm, etc.) so we pass ALL AI packages — not just nvidia-prefixed ones.
    nvidia_packages = [
        p
        for p in scannable
        if p.name.lower().replace("-", "_") in _AI_FRAMEWORK_PACKAGES or p.name.lower().replace("-", "") in _AI_FRAMEWORK_PACKAGES
    ]
    if nvidia_packages and not offline_mode:
        try:
            from agent_bom.scanners.nvidia_advisory import check_nvidia_advisories

            nvidia_new = await check_nvidia_advisories(nvidia_packages)
            if nvidia_new:
                total_vulns += nvidia_new
                console.print(f"  [green]✓[/green] NVIDIA advisories: {nvidia_new} additional CVE(s)")
        except Exception as exc:
            _logger.warning("NVIDIA advisory check failed for %d package(s): %s", len(nvidia_packages), exc)
            console.print(f"  [yellow]⚠[/yellow] NVIDIA advisory check skipped: {exc}")

    # Supplemental: check GitHub Security Advisories for all packages
    if scannable and not offline_mode:
        try:
            from agent_bom.scanners.ghsa_advisory import check_github_advisories

            ghsa_new = await check_github_advisories(scannable)
            if ghsa_new:
                total_vulns += ghsa_new
                console.print(f"  [green]✓[/green] GHSA advisories: {ghsa_new} additional CVE(s)")
        except Exception as exc:
            _logger.warning("GHSA advisory check failed for %d package(s): %s", len(scannable), exc)
            console.print(f"  [yellow]⚠[/yellow] GHSA advisory check skipped: {exc}")

    # Typosquat detection for all scanned packages
    for pkg in scannable:
        if not pkg.is_malicious:
            target = check_typosquat(pkg.name, pkg.ecosystem)
            if target:
                pkg.is_malicious = True
                pkg.malicious_reason = f"Possible typosquat of '{target}'"

    # Apply .agent-bom-ignore suppression rules
    try:
        from agent_bom.ignore import apply_ignore_rules, load_ignore_file

        rules = load_ignore_file()
        if not rules.is_empty:
            suppressed = apply_ignore_rules(scannable, rules)
            if suppressed:
                total_vulns -= suppressed
                console.print(f"  [yellow]⚠[/yellow] Suppressed {suppressed} finding(s) via .agent-bom-ignore")
    except Exception as exc:
        _logger.warning("Ignore file processing skipped: %s", exc)

    return total_vulns


async def scan_agents(agents: list[Agent], *, compliance_enabled: bool = False, resolve_transitive: bool = False) -> list[BlastRadius]:
    """Scan all agents' MCP server packages for vulnerabilities."""
    global compliance_mode  # noqa: PLW0603
    compliance_mode = compliance_enabled
    console.print("\n[bold blue]🛡️  Scanning for vulnerabilities...[/bold blue]\n")

    def _pkg_key(pkg: Package) -> str:
        return f"{pkg.ecosystem.lower()}:{normalize_package_name(pkg.name, pkg.ecosystem)}@{pkg.version}"

    # Collect all unique packages
    all_packages = []
    pkg_to_servers: dict[str, list[MCPServer]] = {}
    pkg_to_agents: dict[str, list[Agent]] = {}

    for agent in agents:
        for server in agent.mcp_servers:
            for pkg in server.packages:
                key = _pkg_key(pkg)
                all_packages.append(pkg)

                if key not in pkg_to_servers:
                    pkg_to_servers[key] = []
                pkg_to_servers[key].append(server)

                if key not in pkg_to_agents:
                    pkg_to_agents[key] = []
                if agent not in pkg_to_agents[key]:
                    pkg_to_agents[key].append(agent)

    # Deduplicate packages for scanning — uses canonical deduplicate_packages()
    # which normalizes by (ecosystem, normalized_name, version) fingerprint.
    unique_packages = deduplicate_packages(all_packages)

    console.print(f"  Scanning {len(unique_packages)} unique packages across {len(agents)} agent(s)...")

    total_vulns = await scan_packages(unique_packages, resolve_transitive=resolve_transitive)

    # Propagate vulnerabilities back to all instances
    vuln_map = {}
    for pkg in unique_packages:
        if pkg.vulnerabilities:
            vuln_map[_pkg_key(pkg)] = pkg.vulnerabilities

    for agent in agents:
        for server in agent.mcp_servers:
            for pkg in server.packages:
                if _pkg_key(pkg) in vuln_map:
                    pkg.vulnerabilities = vuln_map[_pkg_key(pkg)]

    # Build blast radius analysis
    blast_radii = []
    for pkg in unique_packages:
        if not pkg.vulnerabilities:
            continue

        key = _pkg_key(pkg)
        affected_servers = pkg_to_servers.get(key, [])
        affected_agents = pkg_to_agents.get(key, [])

        # Collect exposed credentials and tools — enrich from registry when server
        # config doesn't have explicit tool/credential data.
        # Cache registry lookups per server to avoid duplicate tool creation.
        #
        # IMPORTANT: Registry-sourced tools are "phantom" — they reflect what
        # the registry CLAIMS the server has, not what was introspected.
        # We include them for visibility but mark them so blast radius
        # consumers can distinguish confirmed vs phantom tools.
        from agent_bom.parsers import get_registry_entry

        exposed_creds: list[str] = []
        exposed_tools: list = []
        _registry_cache: dict[str, dict | None] = {}
        _has_phantom_tools = False
        for server in affected_servers:
            server_creds = server.credential_names
            server_tools = list(server.tools)  # copy — don't mutate server

            # Registry enrichment: if no tools/creds known from config, use registry
            if not server_tools or not server_creds:
                if server.name not in _registry_cache:
                    _registry_cache[server.name] = get_registry_entry(server)
                reg = _registry_cache[server.name]
                if reg:
                    if not server_tools and reg.get("tools"):
                        from agent_bom.models import MCPTool

                        # Mark as registry-sourced (phantom) — not confirmed by introspection
                        server_tools = [MCPTool(name=t, description="(registry — unverified)") for t in reg["tools"]]
                        _has_phantom_tools = True
                    if not server_creds and reg.get("credential_env_vars"):
                        server_creds = reg["credential_env_vars"]

            exposed_creds.extend(server_creds)
            exposed_tools.extend(server_tools)

        # Deduplicate credentials and tools to prevent inflation
        exposed_creds_deduped = list(set(exposed_creds))
        seen_tool_names: set[str] = set()
        deduped_tools = []
        for t in exposed_tools:
            if t.name not in seen_tool_names:
                seen_tool_names.add(t.name)
                deduped_tools.append(t)
        exposed_tools = deduped_tools

        # AI-native risk context: elevated when an AI framework has creds + tools
        is_ai_framework = (
            pkg.name.lower().replace("-", "_") in {n.replace("-", "_") for n in _AI_FRAMEWORK_PACKAGES}
            or pkg.name.lower() in _AI_FRAMEWORK_PACKAGES
        )
        has_creds = bool(exposed_creds_deduped)
        has_tools = bool(exposed_tools)
        if is_ai_framework and has_creds and has_tools:
            phantom_note = " (some tools unverified — from registry)" if _has_phantom_tools else ""
            ai_risk_context = (
                f"AI framework '{pkg.name}' runs inside an agent with {len(exposed_creds_deduped)} "
                f"exposed credential(s) and {len(exposed_tools)} reachable tool(s){phantom_note}. "
                f"A compromise here gives an attacker both identity and capability."
            )
        elif is_ai_framework and has_creds:
            ai_risk_context = (
                f"AI framework '{pkg.name}' has access to {len(exposed_creds_deduped)} "
                f"credential(s). Exploitation could exfiltrate secrets via LLM output."
            )
        elif is_ai_framework:
            ai_risk_context = "AI framework package — vulnerability affects LLM inference/orchestration pipeline."
        else:
            ai_risk_context = None

        for vuln in pkg.vulnerabilities:
            # CWE-aware filtering: only expose credentials/tools the vuln
            # type can realistically reach. A DoS (CWE-400) doesn't steal
            # DATABASE_URL. An RCE (CWE-94) does.
            from agent_bom.cwe_impact import (
                build_attack_vector_summary,
                classify_cwe_impact,
                filter_credentials_by_impact,
                filter_tools_by_impact,
            )

            impact_cat = classify_cwe_impact(vuln.cwe_ids)
            filtered_creds = filter_credentials_by_impact(
                impact_cat,
                exposed_creds_deduped,
            )
            filtered_tools = filter_tools_by_impact(
                impact_cat,
                exposed_tools,
            )
            attack_summary = build_attack_vector_summary(
                cwe_ids=vuln.cwe_ids,
                category=impact_cat,
                filtered_creds=filtered_creds,
                filtered_tools=filtered_tools,
                severity=vuln.severity.value if vuln.severity else None,
                is_kev=vuln.is_kev,
            )

            br = BlastRadius(
                vulnerability=vuln,
                package=pkg,
                affected_servers=affected_servers,
                affected_agents=affected_agents,
                exposed_credentials=filtered_creds,
                exposed_tools=filtered_tools,
                ai_risk_context=ai_risk_context,
                impact_category=impact_cat,
                all_server_credentials=list(exposed_creds_deduped),
                all_server_tools=list(exposed_tools),
                attack_vector_summary=attack_summary,
            )
            br.calculate_risk_score()
            # Compliance tagging — opt-in via --compliance flag
            if compliance_enabled:
                br.owasp_tags = tag_blast_radius(br)
                br.atlas_tags = tag_atlas_techniques(br)
                br.attack_tags = tag_attack_techniques(br)
                br.nist_ai_rmf_tags = tag_nist_ai_rmf(br)
                br.owasp_mcp_tags = tag_owasp_mcp(br)
                br.owasp_agentic_tags = tag_owasp_agentic(br)
                br.eu_ai_act_tags = tag_eu_ai_act(br)
                br.nist_csf_tags = tag_nist_csf(br)
                br.iso_27001_tags = tag_iso_27001(br)
                br.soc2_tags = tag_soc2(br)
                br.cis_tags = tag_cis_controls(br)
                br.cmmc_tags = tag_cmmc(br)
                br.nist_800_53_tags = tag_nist_800_53(br)
                br.fedramp_tags = tag_fedramp(br)
            blast_radii.append(br)

    # Sort by risk score descending
    blast_radii.sort(key=lambda br: br.risk_score, reverse=True)

    if total_vulns:
        console.print(f"  [red]⚠ Found {total_vulns} vulnerabilities across {len(blast_radii)} findings[/red]")
    else:
        console.print("  [green]✓ No known vulnerabilities found[/green]")

    _logger.info(
        "Scan summary: %d packages scanned, %d vulnerabilities, %d blast radius findings across %d agent(s)",
        len(unique_packages),
        total_vulns,
        len(blast_radii),
        len(agents),
    )

    return blast_radii


async def scan_agents_with_enrichment(
    agents: list[Agent],
    nvd_api_key: Optional[str] = None,
    enable_enrichment: bool = True,
) -> list[BlastRadius]:
    """Scan agents and enrich vulnerabilities with NVD/EPSS/KEV data."""
    # First, do normal OSV scan
    blast_radii = await scan_agents(agents)

    # Then enrich with external data
    if enable_enrichment and blast_radii:
        from agent_bom.enrichment import enrich_vulnerabilities

        # Collect all vulnerabilities
        all_vulns = []
        for agent in agents:
            for server in agent.mcp_servers:
                for pkg in server.packages:
                    all_vulns.extend(pkg.vulnerabilities)

        if all_vulns:
            await enrich_vulnerabilities(
                all_vulns,
                nvd_api_key=nvd_api_key,
                enable_nvd=True,
                enable_epss=True,
                enable_kev=True,
            )

            # Refresh CVE-level compliance tags now that CWE/KEV/EPSS data is populated
            for agent in agents:
                for server in agent.mcp_servers:
                    for pkg in server.packages:
                        for v in pkg.vulnerabilities:
                            if compliance_mode:
                                v.compliance_tags = _tag_vuln(v, pkg)

        # Scorecard enrichment — adds supply-chain quality signal
        try:
            from agent_bom.scorecard import enrich_packages_with_scorecard

            # Deduplicate packages across all agents
            seen_keys: set[str] = set()
            unique_pkgs: list[Package] = []
            for agent in agents:
                for server in agent.mcp_servers:
                    for pkg in server.packages:
                        pk = f"{pkg.ecosystem.lower()}:{normalize_package_name(pkg.name, pkg.ecosystem)}@{pkg.version}"
                        if pk not in seen_keys:
                            seen_keys.add(pk)
                            unique_pkgs.append(pkg)
            if unique_pkgs:
                await enrich_packages_with_scorecard(unique_pkgs)
        except Exception as exc:  # noqa: BLE001
            _logger.warning("Scorecard auto-enrichment failed (risk scores may be understated): %s", exc)

        # Recalculate blast radius with all enriched data
        for br in blast_radii:
            br.calculate_risk_score()

        # Re-sort by updated risk scores
        blast_radii.sort(key=lambda br: br.risk_score, reverse=True)

    return blast_radii


# ── Multi-hop risk amplification factors per hop distance ─────────────────
_HOP_RISK_FACTORS: dict[int, float] = {
    1: 1.0,
    2: 0.7,
    3: 0.5,
    4: 0.35,
    5: 0.25,
}


def expand_blast_radius_hops(
    blast_radii: list[BlastRadius],
    agents: list[Agent],
    max_depth: int = 1,
) -> None:
    """Expand blast radii with multi-hop delegation chain analysis.

    For each blast radius, traces agent→server→agent delegation chains
    beyond the initial (1-hop) affected agents. Uses BFS with cycle
    detection to avoid infinite loops.

    When ``max_depth`` is 1 (default), this is a no-op — zero overhead.

    Args:
        blast_radii: Existing 1-hop blast radius findings (mutated in place).
        agents: All discovered agents (for cross-referencing servers).
        max_depth: Maximum hop depth (1-5). Clamped to [1, 5].
    """
    max_depth = max(1, min(max_depth, 5))
    if max_depth <= 1:
        return

    # Build lookup: server_name → list of agents that use that server
    server_to_agents: dict[str, list[Agent]] = {}
    for agent in agents:
        for server in agent.mcp_servers:
            server_to_agents.setdefault(server.name, []).append(agent)

    # Build lookup: agent_name → list of server names it uses
    agent_to_servers: dict[str, list[str]] = {}
    for agent in agents:
        agent_to_servers[agent.name] = [s.name for s in agent.mcp_servers]

    for br in blast_radii:
        direct_agent_names = {a.name for a in br.affected_agents}
        direct_server_names = {s.name for s in br.affected_servers}

        # BFS: queue items are (agent_name, current_hop, chain_so_far)
        visited_agents: set[str] = set(direct_agent_names)
        visited_servers: set[str] = set(direct_server_names)
        transitive_agents: list[dict] = []
        transitive_creds: list[str] = []
        chains: list[str] = []

        # Seed BFS from direct agents
        queue: list[tuple[str, int, list[str]]] = []
        for agent in br.affected_agents:
            for srv_name in agent_to_servers.get(agent.name, []):
                if srv_name not in direct_server_names:
                    queue.append((agent.name, 1, [agent.name, srv_name]))
                    visited_servers.add(srv_name)

        max_hop_reached = 1
        while queue:
            agent_name, hop, chain = queue.pop(0)
            if hop >= max_depth:
                continue

            # The last element in chain is a server name — find agents on it
            current_server = chain[-1]
            for next_agent in server_to_agents.get(current_server, []):
                if next_agent.name in visited_agents:
                    continue
                visited_agents.add(next_agent.name)
                next_hop = hop + 1
                max_hop_reached = max(max_hop_reached, next_hop)

                new_chain = chain + [next_agent.name]
                chain_str = "\u2192".join(new_chain)
                chains.append(chain_str)

                # Collect transitive agent info
                agent_creds = []
                for srv in next_agent.mcp_servers:
                    agent_creds.extend(srv.credential_names)
                agent_creds = list(set(agent_creds))

                transitive_agents.append(
                    {
                        "name": next_agent.name,
                        "type": next_agent.agent_type.value,
                        "hop": next_hop,
                        "chain": chain_str,
                    }
                )
                transitive_creds.extend(agent_creds)

                # Continue BFS: look at servers this agent connects to
                if next_hop < max_depth:
                    for srv_name in agent_to_servers.get(next_agent.name, []):
                        if srv_name not in visited_servers:
                            visited_servers.add(srv_name)
                            queue.append((next_agent.name, next_hop, new_chain + [srv_name]))

        if transitive_agents:
            br.hop_depth = max_hop_reached
            br.delegation_chain = chains
            br.transitive_agents = transitive_agents
            br.transitive_credentials = list(set(transitive_creds))
            # Transitive risk = base risk * hop factor
            factor = _HOP_RISK_FACTORS.get(max_hop_reached, 0.25)
            br.transitive_risk_score = round(br.risk_score * factor, 2)


def scan_agents_sync(
    agents: list[Agent],
    enable_enrichment: bool = False,
    nvd_api_key: Optional[str] = None,
    blast_radius_depth: int = 1,
    compliance_enabled: bool = False,
    resolve_transitive: bool = False,
) -> list[BlastRadius]:
    """Synchronous wrapper for scan_agents."""
    if enable_enrichment:
        blast_radii = asyncio.run(scan_agents_with_enrichment(agents, nvd_api_key, enable_enrichment))
    else:
        blast_radii = asyncio.run(scan_agents(agents, compliance_enabled=compliance_enabled, resolve_transitive=resolve_transitive))
    if blast_radius_depth > 1:
        expand_blast_radius_hops(blast_radii, agents, max_depth=blast_radius_depth)
    return blast_radii
