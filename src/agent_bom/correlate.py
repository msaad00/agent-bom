"""Multi-source correlation engine — deduplication, provenance, SBOM enrichment.

When agent-bom collects data from multiple sources (local discovery, cloud
providers, Docker images, SBOMs, Snyk, etc.), the same package can appear
from different sources with different version strings or ecosystem labels.

This module:
1. Deduplicates packages by (name, ecosystem) across all agents/servers
2. Merges version info (prefers specific over "unknown"/"latest")
3. Unions vulnerability lists (deduplicated by vuln ID)
4. Reverse-looks up SBOM packages to find which agents use them
5. Tracks source provenance for the "full picture" view
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field

from agent_bom.models import Agent, Package

logger = logging.getLogger(__name__)


@dataclass
class CorrelationResult:
    """Result of multi-source correlation."""

    deduplicated_packages: int = 0
    cross_source_matches: int = 0
    enriched_from_sbom: int = 0
    source_summary: dict[str, int] = field(default_factory=dict)


def _best_version(v1: str, v2: str) -> str:
    """Pick the more specific version string."""
    unknowns = {"unknown", "latest", ""}
    if v1 in unknowns and v2 not in unknowns:
        return v2
    if v2 in unknowns and v1 not in unknowns:
        return v1
    # If both are specific, prefer the one that looks like a semver
    if "." in v1 and "." not in v2:
        return v1
    if "." in v2 and "." not in v1:
        return v2
    return v1  # default to first


def _merge_vulns(pkg: Package, other: Package) -> int:
    """Merge vulnerabilities from other into pkg, avoiding duplicates. Returns count added."""
    existing_ids = {v.id.upper() for v in pkg.vulnerabilities}
    added = 0
    for v in other.vulnerabilities:
        if v.id.upper() not in existing_ids:
            pkg.vulnerabilities.append(v)
            existing_ids.add(v.id.upper())
            added += 1
    return added


def correlate_agents(agents: list[Agent]) -> tuple[list[Agent], CorrelationResult]:
    """Deduplicate and cross-reference packages across agents from multiple sources.

    For each (name, ecosystem) tuple found in multiple agents/servers:
    - Merge version info (prefer specific over "unknown")
    - Union vulnerability lists
    - Track which sources reported each package

    Args:
        agents: List of Agent objects from all discovery sources.

    Returns:
        (agents, result) — agents with merged package data + statistics.
    """
    result = CorrelationResult()

    # Build source summary
    for agent in agents:
        source = agent.source or "local"
        result.source_summary[source] = result.source_summary.get(source, 0) + 1

    # If only one source, skip correlation
    if len(result.source_summary) <= 1:
        return agents, result

    # Build global package index: (name, ecosystem) → list of (agent, server, package)
    pkg_index: dict[tuple[str, str], list[tuple[Agent, object, Package]]] = {}
    for agent in agents:
        for server in agent.mcp_servers:
            for pkg in server.packages:
                key = (pkg.name.lower(), pkg.ecosystem.lower())
                if key not in pkg_index:
                    pkg_index[key] = []
                pkg_index[key].append((agent, server, pkg))

    # Find cross-source packages and merge
    for key, occurrences in pkg_index.items():
        if len(occurrences) <= 1:
            continue

        sources = {(a.source or "local") for a, _s, _p in occurrences}
        if len(sources) <= 1:
            continue

        result.cross_source_matches += 1

        # Pick the "primary" occurrence (first one with a real version)
        primary_agent, primary_server, primary_pkg = occurrences[0]
        for a, s, p in occurrences[1:]:
            # Merge version
            primary_pkg.version = _best_version(primary_pkg.version, p.version)
            # Merge vulnerabilities
            merged = _merge_vulns(primary_pkg, p)
            if merged:
                result.deduplicated_packages += 1
            # Merge purl if better
            if not primary_pkg.purl and p.purl:
                primary_pkg.purl = p.purl

        # Remove duplicates from other agents/servers
        for a, s, p in occurrences[1:]:
            if p is not primary_pkg and p in s.packages:
                s.packages.remove(p)
                result.deduplicated_packages += 1

    return agents, result


def reverse_lookup_sbom_packages(
    sbom_packages: list[Package],
    agents: list[Agent],
) -> dict[str, list[str]]:
    """Given SBOM packages, find which agents/servers they map to.

    This addresses the "SBOM enrichment" requirement: when a user provides
    --sbom, we can tell them which of their agents actually use those packages.

    Args:
        sbom_packages: Packages from SBOM ingestion.
        agents: Agents discovered from local/cloud sources.

    Returns:
        dict mapping package name → list of "agent:server" strings.
    """
    # Build index of known packages from agents
    agent_pkg_index: dict[str, list[str]] = {}
    for agent in agents:
        for server in agent.mcp_servers:
            for pkg in server.packages:
                name_lower = pkg.name.lower()
                location = f"{agent.name}:{server.name}"
                if name_lower not in agent_pkg_index:
                    agent_pkg_index[name_lower] = []
                agent_pkg_index[name_lower].append(location)

    # Match SBOM packages to agents
    matches: dict[str, list[str]] = {}
    for sbom_pkg in sbom_packages:
        name_lower = sbom_pkg.name.lower()
        if name_lower in agent_pkg_index:
            matches[sbom_pkg.name] = agent_pkg_index[name_lower]

    return matches


def build_source_provenance(agents: list[Agent]) -> dict[str, list[str]]:
    """Build a map of package → list of discovery sources.

    Useful for the "full picture" view: showing that 'langchain==0.1.0'
    was found in AWS Bedrock, the SBOM, AND the Snyk scan.

    Args:
        agents: All agents from all discovery sources.

    Returns:
        dict mapping "name@version" → list of source strings.
    """
    provenance: dict[str, list[str]] = {}
    for agent in agents:
        source = agent.source or "local"
        for server in agent.mcp_servers:
            for pkg in server.packages:
                key = f"{pkg.name}@{pkg.version}"
                if key not in provenance:
                    provenance[key] = []
                if source not in provenance[key]:
                    provenance[key].append(source)

    return provenance
