"""Tests for multi-source correlation engine."""

from agent_bom.correlate import (
    build_source_provenance,
    correlate_agents,
    reverse_lookup_sbom_packages,
)
from agent_bom.models import (
    Agent,
    AgentType,
    MCPServer,
    Package,
    Severity,
    TransportType,
    Vulnerability,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_agent(name, source, servers=None):
    return Agent(
        name=name,
        agent_type=AgentType.CUSTOM,
        config_path=f"/tmp/{name}",
        mcp_servers=servers or [],
        source=source,
    )


def _make_server(name, packages=None):
    return MCPServer(
        name=name,
        command="npx",
        args=[],
        env={},
        transport=TransportType.STDIO,
        packages=packages or [],
    )


def _make_pkg(name, version="1.0.0", ecosystem="npm", vulns=None):
    return Package(
        name=name,
        version=version,
        ecosystem=ecosystem,
        vulnerabilities=vulns or [],
    )


# ---------------------------------------------------------------------------
# correlate_agents
# ---------------------------------------------------------------------------


def test_single_source_passthrough():
    """Single source agents pass through unchanged."""
    pkg = _make_pkg("express", "4.17.1")
    srv = _make_server("server-1", [pkg])
    agent = _make_agent("agent-1", "local", [srv])

    agents, result = correlate_agents([agent])
    assert result.cross_source_matches == 0
    assert result.deduplicated_packages == 0
    assert len(agents) == 1
    assert len(agents[0].mcp_servers[0].packages) == 1


def test_dedup_same_package_different_sources():
    """Same package from two sources gets merged."""
    pkg1 = _make_pkg("express", "4.17.1", "npm")
    pkg2 = _make_pkg("express", "4.17.1", "npm")
    srv1 = _make_server("server-1", [pkg1])
    srv2 = _make_server("server-2", [pkg2])
    agent1 = _make_agent("agent-aws", "aws-bedrock", [srv1])
    agent2 = _make_agent("agent-local", "local", [srv2])

    agents, result = correlate_agents([agent1, agent2])
    assert result.cross_source_matches == 1
    assert len(result.source_summary) == 2


def test_version_preference():
    """Specific version preferred over 'unknown'."""
    pkg1 = _make_pkg("requests", "unknown", "pypi")
    pkg2 = _make_pkg("requests", "2.31.0", "pypi")
    srv1 = _make_server("srv-1", [pkg1])
    srv2 = _make_server("srv-2", [pkg2])
    agent1 = _make_agent("a1", "aws-bedrock", [srv1])
    agent2 = _make_agent("a2", "local", [srv2])

    agents, result = correlate_agents([agent1, agent2])
    # The primary occurrence should now have the specific version
    primary_pkg = agents[0].mcp_servers[0].packages[0]
    assert primary_pkg.version == "2.31.0"


def test_vuln_merge_no_duplicates():
    """Vulnerabilities from two sources are unioned without duplicates."""
    vuln1 = Vulnerability(id="CVE-2025-0001", summary="Vuln 1", severity=Severity.HIGH)
    vuln2 = Vulnerability(id="CVE-2025-0002", summary="Vuln 2", severity=Severity.MEDIUM)
    vuln3 = Vulnerability(id="CVE-2025-0001", summary="Vuln 1 dup", severity=Severity.HIGH)

    pkg1 = _make_pkg("express", "4.17.1", vulns=[vuln1])
    pkg2 = _make_pkg("express", "4.17.1", vulns=[vuln2, vuln3])
    srv1 = _make_server("srv-1", [pkg1])
    srv2 = _make_server("srv-2", [pkg2])
    agent1 = _make_agent("a1", "aws-bedrock", [srv1])
    agent2 = _make_agent("a2", "local", [srv2])

    agents, result = correlate_agents([agent1, agent2])
    # Primary package should have both vulns but no duplicate
    primary_pkg = agents[0].mcp_servers[0].packages[0]
    vuln_ids = [v.id for v in primary_pkg.vulnerabilities]
    assert len(vuln_ids) == 2
    assert "CVE-2025-0001" in vuln_ids
    assert "CVE-2025-0002" in vuln_ids


def test_source_summary():
    """Source summary counts agents per source."""
    agent1 = _make_agent("a1", "aws-bedrock", [_make_server("s1")])
    agent2 = _make_agent("a2", "aws-bedrock", [_make_server("s2")])
    agent3 = _make_agent("a3", "local", [_make_server("s3")])

    _, result = correlate_agents([agent1, agent2, agent3])
    assert result.source_summary["aws-bedrock"] == 2
    assert result.source_summary["local"] == 1


# ---------------------------------------------------------------------------
# reverse_lookup_sbom_packages
# ---------------------------------------------------------------------------


def test_reverse_lookup_finds_matches():
    """SBOM packages matched to agents."""
    pkg = _make_pkg("express", "4.17.1")
    srv = _make_server("filesystem", [pkg])
    agent = _make_agent("claude-desktop", "local", [srv])

    sbom_pkgs = [_make_pkg("express", "4.17.1")]
    matches = reverse_lookup_sbom_packages(sbom_pkgs, [agent])
    assert "express" in matches
    assert "claude-desktop:filesystem" in matches["express"]


def test_reverse_lookup_no_matches():
    """SBOM packages not found in any agent returns empty."""
    srv = _make_server("server", [_make_pkg("lodash")])
    agent = _make_agent("agent", "local", [srv])

    sbom_pkgs = [_make_pkg("unknown-pkg")]
    matches = reverse_lookup_sbom_packages(sbom_pkgs, [agent])
    assert len(matches) == 0


# ---------------------------------------------------------------------------
# build_source_provenance
# ---------------------------------------------------------------------------


def test_provenance_tracking():
    """Packages from multiple sources are tracked."""
    pkg1 = _make_pkg("langchain", "0.1.0")
    pkg2 = _make_pkg("langchain", "0.1.0")
    srv1 = _make_server("s1", [pkg1])
    srv2 = _make_server("s2", [pkg2])
    agent1 = _make_agent("a1", "aws-bedrock", [srv1])
    agent2 = _make_agent("a2", "local", [srv2])

    provenance = build_source_provenance([agent1, agent2])
    assert "langchain@0.1.0" in provenance
    assert "aws-bedrock" in provenance["langchain@0.1.0"]
    assert "local" in provenance["langchain@0.1.0"]


def test_provenance_single_source():
    """Single-source package has one entry."""
    pkg = _make_pkg("express", "4.17.1")
    srv = _make_server("s1", [pkg])
    agent = _make_agent("a1", "local", [srv])

    provenance = build_source_provenance([agent])
    assert provenance["express@4.17.1"] == ["local"]
