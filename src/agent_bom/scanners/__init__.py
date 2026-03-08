"""Vulnerability scanning using OSV.dev API."""

from __future__ import annotations

import asyncio
import logging
import math
import time
from typing import Optional

import httpx
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn

from agent_bom.atlas import tag_blast_radius as tag_atlas_techniques
from agent_bom.cis_controls import tag_blast_radius as tag_cis_controls
from agent_bom.config import (
    SCANNER_BATCH_DELAY as BATCH_DELAY_SECONDS,
)
from agent_bom.config import (
    SCANNER_MAX_CONCURRENT as MAX_CONCURRENT_REQUESTS,
)

# Single source of truth for AI/ML package catalog — imported from constants.
# Vulnerabilities in these carry elevated risk because they run inside AI
# agents that have credentials and tool access.
from agent_bom.constants import AI_PACKAGES as _AI_FRAMEWORK_PACKAGES
from agent_bom.eu_ai_act import tag_blast_radius as tag_eu_ai_act
from agent_bom.http_client import create_client, request_with_retry
from agent_bom.iso_27001 import tag_blast_radius as tag_iso_27001
from agent_bom.malicious import check_typosquat, flag_malicious_from_vulns
from agent_bom.models import Agent, BlastRadius, MCPServer, Package, Severity, Vulnerability
from agent_bom.nist_ai_rmf import tag_blast_radius as tag_nist_ai_rmf
from agent_bom.nist_csf import tag_blast_radius as tag_nist_csf
from agent_bom.owasp import tag_blast_radius
from agent_bom.owasp_agentic import tag_blast_radius as tag_owasp_agentic
from agent_bom.owasp_mcp import tag_blast_radius as tag_owasp_mcp
from agent_bom.soc2 import tag_blast_radius as tag_soc2
from agent_bom.vuln_compliance import tag_vulnerability as _tag_vuln

console = Console(stderr=True)
_logger = logging.getLogger(__name__)

OSV_API_URL = "https://api.osv.dev/v1"
OSV_BATCH_URL = f"{OSV_API_URL}/querybatch"
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
}


def _get_api_semaphore() -> asyncio.Semaphore:
    """Create a semaphore bound to the current event loop.

    Module-level semaphores can bind to the wrong event loop when called from
    different threads (e.g. concurrent scans via ThreadPoolExecutor + asyncio.run()).
    """
    return asyncio.Semaphore(MAX_CONCURRENT_REQUESTS)


# ── Scan cache (optional, lazy-initialised) ────────────────────────────────

_scan_cache_instance = None  # type: ignore[var-annotated]


def _get_scan_cache():  # noqa: ANN202
    """Return the shared ScanCache singleton, or *None* if unavailable."""
    global _scan_cache_instance  # noqa: PLW0603
    if _scan_cache_instance is None:
        try:
            from agent_bom.scan_cache import ScanCache

            _scan_cache_instance = ScanCache()
        except Exception:  # noqa: BLE001
            _scan_cache_instance = False  # mark as attempted, don't retry
    return _scan_cache_instance if _scan_cache_instance is not False else None


# Map CVSS scores to severity
def cvss_to_severity(score: Optional[float]) -> Severity:
    if score is None:
        return Severity.MEDIUM
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
    except Exception:
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

    except Exception:
        return None


def parse_osv_severity(vuln_data: dict) -> tuple[Severity, Optional[float]]:
    """Extract severity and CVSS score from OSV vulnerability data."""
    cvss_score = None
    severity = Severity.MEDIUM  # Default

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
        severity = severity_map.get(sev_str, Severity.MEDIUM)

    # CVSS score overrides label-based severity
    if cvss_score is not None:
        severity = cvss_to_severity(cvss_score)

    return severity, cvss_score


def parse_fixed_version(vuln_data: dict, package_name: str) -> Optional[str]:
    """Extract fixed version from OSV affected data.

    Prefers stable releases over pre-release versions.
    """
    prerelease_candidate: Optional[str] = None

    for affected in vuln_data.get("affected", []):
        pkg = affected.get("package", {})
        if pkg.get("name", "").lower() == package_name.lower():
            for rng in affected.get("ranges", []):
                for event in rng.get("events", []):
                    if "fixed" in event:
                        fixed = event["fixed"]
                        try:
                            from packaging.version import Version

                            pv = Version(fixed)
                            if not pv.is_prerelease:
                                return fixed
                            # Remember pre-release as fallback
                            if prerelease_candidate is None:
                                prerelease_candidate = fixed
                        except Exception:  # noqa: BLE001
                            # Can't parse (e.g. non-PEP440 npm version) — return as-is
                            return fixed
    return prerelease_candidate


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
        _logger.debug("OSV detail enrichment skipped: %s", exc)
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

    # Check cache first
    for pkg in packages:
        # Normalize ecosystem case — ECOSYSTEM_MAP keys are all lowercase.
        # Accepts "PyPI", "NPM", "PYPI", etc. from external callers.
        eco_key = pkg.ecosystem.lower()
        osv_ecosystem = ECOSYSTEM_MAP.get(eco_key)
        if not osv_ecosystem or pkg.version in ("unknown", "latest"):
            continue
        if cache:
            cached = cache.get(eco_key, pkg.name, pkg.version)
            if cached is not None:
                if cached:  # non-empty vuln list
                    key = f"{eco_key}:{pkg.name}@{pkg.version}"
                    results[key] = cached
                continue  # skip API call (cached hit or cached "clean")
        packages_to_query.append(pkg)

    if not packages_to_query:
        return await _enrich_results_if_needed(results)

    queries = []
    pkg_index = {}  # Map query index to package

    for pkg in packages_to_query:
        eco_key = pkg.ecosystem.lower()
        osv_ecosystem = ECOSYSTEM_MAP.get(eco_key)
        if not osv_ecosystem or pkg.version in ("unknown", "latest"):
            continue

        queries.append(
            {
                "version": pkg.version,
                "package": {
                    "name": pkg.name,
                    "ecosystem": osv_ecosystem,
                },
            }
        )
        pkg_index[len(queries) - 1] = pkg

    if not queries:
        return await _enrich_results_if_needed(results)

    # Track which queried packages got vulns (to cache "clean" results too)
    queried_keys_with_vulns: set[str] = set()

    # OSV batch API accepts up to 1000 queries; rate-limited with retries
    batch_size = 1000
    semaphore = _get_api_semaphore()
    async with create_client(timeout=30.0) as client:
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
                        for i, result in enumerate(data.get("results", [])):
                            vulns = result.get("vulns", [])
                            if vulns:
                                actual_idx = batch_start + i
                                pkg = pkg_index.get(actual_idx)
                                if pkg:
                                    key = f"{pkg.ecosystem.lower()}:{pkg.name}@{pkg.version}"
                                    results[key] = vulns
                                    queried_keys_with_vulns.add(key)
                    except (ValueError, KeyError) as e:
                        console.print(f"  [red]✗[/red] OSV response parse error: {e}")
                elif response:
                    console.print(f"  [red]✗[/red] OSV API error: HTTP {response.status_code}")
                else:
                    console.print("  [red]✗[/red] OSV API unreachable after retries")

            # Rate limit: delay between batches
            if batch_start + batch_size < len(queries):
                await asyncio.sleep(BATCH_DELAY_SECONDS)

    # Enrich minimal batch results with full vuln details (summary, CVSS, etc.)
    await _enrich_results_if_needed(results)

    # Populate cache with fresh results (including "clean" packages)
    if cache:
        for pkg in packages_to_query:
            eco_key = pkg.ecosystem.lower()
            key = f"{eco_key}:{pkg.name}@{pkg.version}"
            if key in queried_keys_with_vulns:
                cache.put(eco_key, pkg.name, pkg.version, results[key])
            else:
                cache.put(eco_key, pkg.name, pkg.version, [])

    return results


def build_vulnerabilities(vuln_data_list: list[dict], package: Package) -> list[Vulnerability]:
    """Convert OSV response data to Vulnerability objects."""
    vulns = []
    seen_ids = set()

    for vuln_data in vuln_data_list:
        vuln_id = vuln_data.get("id", "unknown")
        if vuln_id in seen_ids:
            continue
        seen_ids.add(vuln_id)

        severity, cvss_score = parse_osv_severity(vuln_data)
        fixed = parse_fixed_version(vuln_data, package.name)

        references = [ref.get("url", "") for ref in vuln_data.get("references", []) if ref.get("url")][:5]  # Limit to 5 references

        # Use aliases to surface CVE ID when primary ID is GHSA/OSV/RUSTSEC
        aliases = vuln_data.get("aliases", [])
        cve_alias = next((a for a in aliases if a.startswith("CVE-")), None)
        # Use CVE alias as the canonical ID so EPSS/NVD enrichment picks it up
        canonical_id = cve_alias if cve_alias and not vuln_id.startswith("CVE-") else vuln_id

        summary = vuln_data.get("summary", vuln_data.get("details", "No description available"))[:200]

        # Collect all aliases (original ID + OSV aliases, minus the canonical)
        all_aliases = [a for a in aliases if a != canonical_id]
        if vuln_id != canonical_id:
            all_aliases.append(vuln_id)

        vulns.append(
            Vulnerability(
                id=canonical_id,
                summary=summary,
                severity=severity,
                cvss_score=cvss_score,
                fixed_version=fixed,
                references=references,
                aliases=all_aliases,
            )
        )

    return vulns


def _strip_extras(name: str) -> str:
    """Strip pip extras notation: ``requests[security]`` → ``requests``."""
    import re as _re

    return _re.sub(r"\[.*?\]$", "", name)


async def scan_packages(packages: list[Package]) -> int:
    """Scan a list of packages for vulnerabilities. Returns count of vulns found."""
    # Strip pip extras notation before OSV queries (OSV doesn't understand extras)
    for pkg in packages:
        if pkg.ecosystem.lower() == "pypi" and "[" in pkg.name:
            pkg.name = _strip_extras(pkg.name)

    # Auto-resolve "latest"/"unknown" versions before OSV query
    unresolved = [p for p in packages if p.version in ("latest", "unknown", "") and p.ecosystem.lower() in ("npm", "pypi")]
    if unresolved:
        try:
            from agent_bom.resolver import resolve_all_versions

            resolved_count = await resolve_all_versions(unresolved)
            if resolved_count:
                console.print(f"  [green]✓[/green] Auto-resolved {resolved_count} package version(s)")
        except Exception as exc:
            console.print(f"  [yellow]⚠[/yellow] Version resolution skipped: {exc}")

    # SAST packages already carry vulns from Semgrep — skip OSV query for them
    scannable = [p for p in packages if p.version not in ("unknown", "latest") and p.ecosystem.lower() != "sast"]

    if not scannable:
        return 0

    results = await query_osv_batch(scannable)

    total_vulns = 0
    for pkg in scannable:
        key = f"{pkg.ecosystem.lower()}:{pkg.name}@{pkg.version}"
        vuln_data = results.get(key, [])
        if vuln_data:
            pkg.vulnerabilities = build_vulnerabilities(vuln_data, pkg)
            total_vulns += len(pkg.vulnerabilities)
            # Tag each CVE with compliance framework codes (pre-enrichment)
            for v in pkg.vulnerabilities:
                v.compliance_tags = _tag_vuln(v, pkg)
            # Flag packages with MAL- prefixed vulnerability IDs as malicious
            flag_malicious_from_vulns(pkg)

    # Supplemental: check NVIDIA advisories for AI framework packages
    nvidia_packages = [
        p
        for p in scannable
        if p.name.lower().replace("-", "_") in _AI_FRAMEWORK_PACKAGES and p.name.lower().startswith(("nvidia", "cuda", "tensorrt", "nccl"))
    ]
    if nvidia_packages:
        try:
            from agent_bom.scanners.nvidia_advisory import check_nvidia_advisories

            nvidia_new = await check_nvidia_advisories(nvidia_packages)
            if nvidia_new:
                total_vulns += nvidia_new
                console.print(f"  [green]✓[/green] NVIDIA advisories: {nvidia_new} additional CVE(s)")
        except Exception as exc:
            console.print(f"  [yellow]⚠[/yellow] NVIDIA advisory check skipped: {exc}")

    # Supplemental: check GitHub Security Advisories for all packages
    if scannable:
        try:
            from agent_bom.scanners.ghsa_advisory import check_github_advisories

            ghsa_new = await check_github_advisories(scannable)
            if ghsa_new:
                total_vulns += ghsa_new
                console.print(f"  [green]✓[/green] GHSA advisories: {ghsa_new} additional CVE(s)")
        except Exception as exc:
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
        _logger.debug("Ignore file processing skipped: %s", exc)

    return total_vulns


async def scan_agents(agents: list[Agent]) -> list[BlastRadius]:
    """Scan all agents' MCP server packages for vulnerabilities."""
    console.print("\n[bold blue]🛡️  Scanning for vulnerabilities...[/bold blue]\n")

    # Collect all unique packages
    all_packages = []
    pkg_to_servers: dict[str, list[MCPServer]] = {}
    pkg_to_agents: dict[str, list[Agent]] = {}

    for agent in agents:
        for server in agent.mcp_servers:
            for pkg in server.packages:
                key = f"{pkg.ecosystem}:{pkg.name}@{pkg.version}"
                all_packages.append(pkg)

                if key not in pkg_to_servers:
                    pkg_to_servers[key] = []
                pkg_to_servers[key].append(server)

                if key not in pkg_to_agents:
                    pkg_to_agents[key] = []
                if agent not in pkg_to_agents[key]:
                    pkg_to_agents[key].append(agent)

    # Deduplicate packages for scanning
    seen = set()
    unique_packages = []
    for pkg in all_packages:
        key = f"{pkg.ecosystem}:{pkg.name}@{pkg.version}"
        if key not in seen:
            seen.add(key)
            unique_packages.append(pkg)

    console.print(f"  Scanning {len(unique_packages)} unique packages across {len(agents)} agent(s)...")

    total_vulns = await scan_packages(unique_packages)

    # Propagate vulnerabilities back to all instances
    vuln_map = {}
    for pkg in unique_packages:
        if pkg.vulnerabilities:
            key = f"{pkg.ecosystem}:{pkg.name}@{pkg.version}"
            vuln_map[key] = pkg.vulnerabilities

    for agent in agents:
        for server in agent.mcp_servers:
            for pkg in server.packages:
                key = f"{pkg.ecosystem}:{pkg.name}@{pkg.version}"
                if key in vuln_map:
                    pkg.vulnerabilities = vuln_map[key]

    # Build blast radius analysis
    blast_radii = []
    for pkg in unique_packages:
        if not pkg.vulnerabilities:
            continue

        key = f"{pkg.ecosystem}:{pkg.name}@{pkg.version}"
        affected_servers = pkg_to_servers.get(key, [])
        affected_agents = pkg_to_agents.get(key, [])

        # Collect exposed credentials and tools — enrich from registry when server
        # config doesn't have explicit tool/credential data.
        # Cache registry lookups per server to avoid duplicate tool creation.
        from agent_bom.parsers import get_registry_entry

        exposed_creds: list[str] = []
        exposed_tools: list = []
        _registry_cache: dict[str, dict | None] = {}
        for server in affected_servers:
            server_creds = server.credential_names
            server_tools = server.tools

            # Registry enrichment: if no tools/creds known from config, use registry
            if not server_tools or not server_creds:
                if server.name not in _registry_cache:
                    _registry_cache[server.name] = get_registry_entry(server)
                reg = _registry_cache[server.name]
                if reg:
                    if not server_tools and reg.get("tools"):
                        from agent_bom.models import MCPTool

                        server_tools = [MCPTool(name=t, description="") for t in reg["tools"]]
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
            ai_risk_context = (
                f"AI framework '{pkg.name}' runs inside an agent with {len(exposed_creds_deduped)} "
                f"exposed credential(s) and {len(exposed_tools)} reachable tool(s). "
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
            br = BlastRadius(
                vulnerability=vuln,
                package=pkg,
                affected_servers=affected_servers,
                affected_agents=affected_agents,
                exposed_credentials=exposed_creds_deduped,
                exposed_tools=exposed_tools,
                ai_risk_context=ai_risk_context,
            )
            br.calculate_risk_score()
            br.owasp_tags = tag_blast_radius(br)
            br.atlas_tags = tag_atlas_techniques(br)
            br.nist_ai_rmf_tags = tag_nist_ai_rmf(br)
            br.owasp_mcp_tags = tag_owasp_mcp(br)
            br.owasp_agentic_tags = tag_owasp_agentic(br)
            br.eu_ai_act_tags = tag_eu_ai_act(br)
            br.nist_csf_tags = tag_nist_csf(br)
            br.iso_27001_tags = tag_iso_27001(br)
            br.soc2_tags = tag_soc2(br)
            br.cis_tags = tag_cis_controls(br)
            blast_radii.append(br)

    # Sort by risk score descending
    blast_radii.sort(key=lambda br: br.risk_score, reverse=True)

    if total_vulns:
        console.print(f"  [red]⚠ Found {total_vulns} vulnerabilities across {len(blast_radii)} findings[/red]")
    else:
        console.print("  [green]✓ No known vulnerabilities found[/green]")

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
                        pk = f"{pkg.ecosystem}:{pkg.name}@{pkg.version}"
                        if pk not in seen_keys:
                            seen_keys.add(pk)
                            unique_pkgs.append(pkg)
            if unique_pkgs:
                await enrich_packages_with_scorecard(unique_pkgs)
        except Exception as exc:  # noqa: BLE001
            _logger.debug("Scorecard auto-enrichment skipped: %s", exc)

        # Recalculate blast radius with all enriched data
        for br in blast_radii:
            br.calculate_risk_score()

        # Re-sort by updated risk scores
        blast_radii.sort(key=lambda br: br.risk_score, reverse=True)

    return blast_radii


def scan_agents_sync(agents: list[Agent], enable_enrichment: bool = False, nvd_api_key: Optional[str] = None) -> list[BlastRadius]:
    """Synchronous wrapper for scan_agents."""
    if enable_enrichment:
        return asyncio.run(scan_agents_with_enrichment(agents, nvd_api_key, enable_enrichment))
    return asyncio.run(scan_agents(agents))
