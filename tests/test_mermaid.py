"""Tests for Mermaid diagram output."""

from __future__ import annotations

from agent_bom.models import (
    Agent,
    AgentType,
    AIBOMReport,
    BlastRadius,
    MCPServer,
    Package,
    Severity,
    TransportType,
    Vulnerability,
)
from agent_bom.output.mermaid import to_mermaid


def _make_report_and_blast_radii():
    """Create a minimal report with one blast radius for testing."""
    server = MCPServer(
        name="test-server",
        command="npx",
        args=["-y", "@test/server"],
        env={"API_KEY": "***"},
        transport=TransportType.STDIO,
        packages=[Package(name="express", version="4.17.1", ecosystem="npm")],
    )
    agent = Agent(
        name="claude-desktop",
        agent_type=AgentType.CLAUDE_DESKTOP,
        config_path="/tmp/config.json",
        mcp_servers=[server],
    )
    vuln = Vulnerability(
        id="CVE-2024-1234",
        severity=Severity.HIGH,
        summary="Test vulnerability in express",
        cvss_score=7.5,
        fixed_version="4.18.0",
    )
    br = BlastRadius(
        vulnerability=vuln,
        package=Package(name="express", version="4.17.1", ecosystem="npm"),
        affected_servers=[server],
        affected_agents=[agent],
        exposed_credentials=["API_KEY"],
        exposed_tools=[],
    )
    report = AIBOMReport(agents=[agent], blast_radii=[br])
    return report, [br]


def test_mermaid_basic_output():
    """Mermaid output contains graph LR header and CVE node."""
    report, brs = _make_report_and_blast_radii()
    result = to_mermaid(report, brs)
    assert result.startswith("graph LR\n")
    assert "CVE-2024-1234" in result
    assert "express@4.17.1" in result
    assert "test-server" in result
    assert "claude-desktop" in result


def test_mermaid_edges():
    """Mermaid output contains expected edge labels."""
    report, brs = _make_report_and_blast_radii()
    result = to_mermaid(report, brs)
    assert "-->|affects|" in result
    assert "-->|in|" in result
    assert "-->|used by|" in result
    assert "-->|exposes|" in result


def test_mermaid_credential_exposure():
    """Mermaid output shows exposed credentials."""
    report, brs = _make_report_and_blast_radii()
    result = to_mermaid(report, brs)
    assert "API_KEY" in result


def test_mermaid_severity_styling():
    """Mermaid output contains severity-based styling."""
    report, brs = _make_report_and_blast_radii()
    result = to_mermaid(report, brs)
    # HIGH severity should have orange styling
    assert "fill:#f57c00" in result


def test_mermaid_critical_styling():
    """Critical severity gets red styling."""
    report, brs = _make_report_and_blast_radii()
    brs[0].vulnerability.severity = Severity.CRITICAL
    result = to_mermaid(report, brs)
    assert "fill:#d32f2f" in result


def test_mermaid_empty_blast_radii():
    """Empty blast radii returns minimal graph."""
    report = AIBOMReport(agents=[], blast_radii=[])
    result = to_mermaid(report, [])
    assert "graph LR" in result
    assert "No vulnerabilities found" in result


def test_mermaid_multiple_vulns():
    """Multiple blast radii produce multiple CVE nodes."""
    server = MCPServer(
        name="srv",
        command="npx",
        args=[],
        env={},
        transport=TransportType.STDIO,
    )
    agent = Agent(
        name="agt",
        agent_type=AgentType.CLAUDE_DESKTOP,
        config_path="/tmp/c.json",
        mcp_servers=[server],
    )
    br1 = BlastRadius(
        vulnerability=Vulnerability(id="CVE-2024-0001", severity=Severity.HIGH, summary="V1"),
        package=Package(name="pkg-a", version="1.0", ecosystem="npm"),
        affected_servers=[server],
        affected_agents=[agent],
        exposed_credentials=[],
        exposed_tools=[],
    )
    br2 = BlastRadius(
        vulnerability=Vulnerability(id="CVE-2024-0002", severity=Severity.MEDIUM, summary="V2"),
        package=Package(name="pkg-b", version="2.0", ecosystem="pypi"),
        affected_servers=[server],
        affected_agents=[agent],
        exposed_credentials=[],
        exposed_tools=[],
    )
    report = AIBOMReport(agents=[agent], blast_radii=[br1, br2])
    result = to_mermaid(report, [br1, br2])
    assert "CVE-2024-0001" in result
    assert "CVE-2024-0002" in result
    assert "pkg-a@1.0" in result
    assert "pkg-b@2.0" in result


def test_mermaid_no_duplicate_edges():
    """Same edge from two blast radii should not appear twice."""
    server = MCPServer(
        name="srv",
        command="npx",
        args=[],
        env={},
        transport=TransportType.STDIO,
    )
    agent = Agent(
        name="agt",
        agent_type=AgentType.CLAUDE_DESKTOP,
        config_path="/tmp/c.json",
        mcp_servers=[server],
    )
    vuln = Vulnerability(id="CVE-2024-DUP", severity=Severity.LOW, summary="Dup")
    pkg = Package(name="same-pkg", version="1.0", ecosystem="npm")
    br = BlastRadius(
        vulnerability=vuln,
        package=pkg,
        affected_servers=[server],
        affected_agents=[agent],
        exposed_credentials=[],
        exposed_tools=[],
    )
    report = AIBOMReport(agents=[agent], blast_radii=[br, br])
    result = to_mermaid(report, [br, br])
    # Count occurrences of the CVE → package edge
    edge_count = result.count("-->|affects|")
    assert edge_count == 1
