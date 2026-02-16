"""Vulnerability scanning using OSV.dev API."""

from __future__ import annotations

import asyncio
from typing import Optional

import httpx
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn

from agent_bom.models import Agent, BlastRadius, MCPServer, Package, Severity, Vulnerability

console = Console()

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


def parse_osv_severity(vuln_data: dict) -> tuple[Severity, Optional[float]]:
    """Extract severity and CVSS score from OSV vulnerability data."""
    cvss_score = None
    severity = Severity.MEDIUM  # Default

    # Check severity array
    for sev in vuln_data.get("severity", []):
        if sev.get("type") == "CVSS_V3":
            score_str = sev.get("score", "")
            # Try to extract numeric score from CVSS vector
            try:
                # Sometimes it's just a number
                cvss_score = float(score_str)
            except ValueError:
                # It's a CVSS vector string, estimate from it
                pass

    # Check database_specific for severity
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

    if cvss_score:
        severity = cvss_to_severity(cvss_score)

    return severity, cvss_score


def parse_fixed_version(vuln_data: dict, package_name: str) -> Optional[str]:
    """Extract fixed version from OSV affected data."""
    for affected in vuln_data.get("affected", []):
        pkg = affected.get("package", {})
        if pkg.get("name", "").lower() == package_name.lower():
            for rng in affected.get("ranges", []):
                for event in rng.get("events", []):
                    if "fixed" in event:
                        return event["fixed"]
    return None


async def query_osv_batch(packages: list[Package]) -> dict[str, list[dict]]:
    """Query OSV API for vulnerabilities in batch."""
    if not packages:
        return {}

    queries = []
    pkg_index = {}  # Map query index to package

    for i, pkg in enumerate(packages):
        osv_ecosystem = ECOSYSTEM_MAP.get(pkg.ecosystem)
        if not osv_ecosystem or pkg.version in ("unknown", "latest"):
            continue

        queries.append({
            "version": pkg.version,
            "package": {
                "name": pkg.name,
                "ecosystem": osv_ecosystem,
            }
        })
        pkg_index[len(queries) - 1] = pkg

    if not queries:
        return {}

    results = {}

    # OSV batch API accepts up to 1000 queries
    batch_size = 1000
    async with httpx.AsyncClient(timeout=30.0) as client:
        for batch_start in range(0, len(queries), batch_size):
            batch = queries[batch_start:batch_start + batch_size]

            try:
                response = await client.post(
                    OSV_BATCH_URL,
                    json={"queries": batch},
                )
                response.raise_for_status()
                data = response.json()

                for i, result in enumerate(data.get("results", [])):
                    vulns = result.get("vulns", [])
                    if vulns:
                        actual_idx = batch_start + i
                        pkg = pkg_index.get(actual_idx)
                        if pkg:
                            key = f"{pkg.ecosystem}:{pkg.name}@{pkg.version}"
                            results[key] = vulns

            except httpx.HTTPError as e:
                console.print(f"  [red]✗[/red] OSV API error: {e}")

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

        references = [
            ref.get("url", "")
            for ref in vuln_data.get("references", [])
            if ref.get("url")
        ][:5]  # Limit to 5 references

        # Also check for aliases (CVE IDs)
        aliases = vuln_data.get("aliases", [])
        summary = vuln_data.get("summary", vuln_data.get("details", "No description available"))[:200]

        vulns.append(Vulnerability(
            id=vuln_id,
            summary=summary,
            severity=severity,
            cvss_score=cvss_score,
            fixed_version=fixed,
            references=references,
        ))

    return vulns


async def scan_packages(packages: list[Package]) -> int:
    """Scan a list of packages for vulnerabilities. Returns count of vulns found."""
    scannable = [p for p in packages if p.version not in ("unknown", "latest")]

    if not scannable:
        return 0

    results = await query_osv_batch(scannable)

    total_vulns = 0
    for pkg in scannable:
        key = f"{pkg.ecosystem}:{pkg.name}@{pkg.version}"
        vuln_data = results.get(key, [])
        if vuln_data:
            pkg.vulnerabilities = build_vulnerabilities(vuln_data, pkg)
            total_vulns += len(pkg.vulnerabilities)

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

        # Collect exposed credentials and tools
        exposed_creds = []
        exposed_tools = []
        for server in affected_servers:
            exposed_creds.extend(server.credential_names)
            exposed_tools.extend(server.tools)

        for vuln in pkg.vulnerabilities:
            br = BlastRadius(
                vulnerability=vuln,
                package=pkg,
                affected_servers=affected_servers,
                affected_agents=affected_agents,
                exposed_credentials=list(set(exposed_creds)),
                exposed_tools=exposed_tools,
            )
            br.calculate_risk_score()
            blast_radii.append(br)

    # Sort by risk score descending
    blast_radii.sort(key=lambda br: br.risk_score, reverse=True)

    if total_vulns:
        console.print(f"  [red]⚠ Found {total_vulns} vulnerabilities across {len(blast_radii)} findings[/red]")
    else:
        console.print(f"  [green]✓ No known vulnerabilities found[/green]")

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

            # Recalculate blast radius with enriched data
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
