"""Tests for print_posture_summary output."""

from io import StringIO

from rich.console import Console

from agent_bom.models import (
    Agent,
    AgentStatus,
    AgentType,
    AIBOMReport,
    BlastRadius,
    MCPServer,
    Package,
    Severity,
    TransportType,
    Vulnerability,
)
from agent_bom.output import print_posture_summary


def _capture_posture(report: AIBOMReport) -> str:
    """Capture print_posture_summary output as plain text."""
    buf = StringIO()
    con = Console(file=buf, width=120, force_terminal=True, no_color=True)
    # Temporarily swap the module-level console
    import agent_bom.output as out_mod

    orig = out_mod.console
    out_mod.console = con
    try:
        print_posture_summary(report)
    finally:
        out_mod.console = orig
    return buf.getvalue()


def _make_server(name="test-server", packages=None, env=None, tools=None):
    return MCPServer(
        name=name,
        command="npx",
        args=[f"@test/{name}"],
        transport=TransportType.STDIO,
        env=env or {},
        packages=packages or [],
        tools=tools or [],
    )


def _make_agent(name="test-agent", agent_type=AgentType.CLAUDE_DESKTOP,
                status=AgentStatus.CONFIGURED, servers=None):
    return Agent(
        name=name,
        agent_type=agent_type,
        config_path=f"/home/user/.{name}/config.json",
        mcp_servers=servers or [],
        status=status,
    )


def test_posture_summary_clean():
    """0 vulns → 'CLEAN' posture."""
    agent = _make_agent(servers=[
        _make_server(packages=[
            Package(name="express", version="4.19.0", ecosystem="npm"),
        ])
    ])
    report = AIBOMReport(agents=[agent])
    output = _capture_posture(report)
    assert "CLEAN" in output
    assert "1" in output  # 1 agent
    assert "npm" in output


def test_posture_summary_with_vulns():
    """Shows severity breakdown when vulns exist."""
    vuln_crit = Vulnerability(id="CVE-2024-0001", summary="RCE", severity=Severity.CRITICAL)
    vuln_high = Vulnerability(id="CVE-2024-0002", summary="XSS", severity=Severity.HIGH)
    pkg = Package(name="lodash", version="4.17.20", ecosystem="npm",
                  vulnerabilities=[vuln_crit, vuln_high])
    server = _make_server(packages=[pkg])
    agent = _make_agent(servers=[server])

    br_crit = BlastRadius(
        vulnerability=vuln_crit, package=pkg,
        affected_servers=[server], affected_agents=[agent],
        exposed_credentials=[], exposed_tools=[],
    )
    br_high = BlastRadius(
        vulnerability=vuln_high, package=pkg,
        affected_servers=[server], affected_agents=[agent],
        exposed_credentials=[], exposed_tools=[],
    )
    report = AIBOMReport(agents=[agent], blast_radii=[br_crit, br_high])
    output = _capture_posture(report)
    assert "CRITICAL" in output
    assert "HIGH" in output
    assert "lodash@4.17.20" in output


def test_posture_summary_credential_aggregation():
    """Groups credentials by server across agents."""
    server1 = _make_server(name="github", env={"GITHUB_TOKEN": "xxx"})
    server2 = _make_server(name="slack", env={"SLACK_BOT_TOKEN": "yyy"})
    agent = _make_agent(servers=[server1, server2])
    report = AIBOMReport(agents=[agent])
    output = _capture_posture(report)
    assert "GITHUB_TOKEN" in output
    assert "SLACK_BOT_TOKEN" in output
    assert "2 server(s) with credentials exposed" in output


def test_posture_summary_ecosystem_breakdown():
    """Counts npm/pypi packages correctly."""
    pkgs_npm = [
        Package(name="express", version="4.19.0", ecosystem="npm"),
        Package(name="axios", version="1.6.0", ecosystem="npm"),
    ]
    pkgs_pypi = [
        Package(name="flask", version="3.0.0", ecosystem="pypi"),
    ]
    agent = _make_agent(servers=[
        _make_server(name="web", packages=pkgs_npm),
        _make_server(name="api", packages=pkgs_pypi),
    ])
    report = AIBOMReport(agents=[agent])
    output = _capture_posture(report)
    assert "npm" in output
    assert "pypi" in output
    assert "3 unique" in output


def test_posture_summary_agent_status_counts():
    """Shows X configured, Y not-configured."""
    a1 = _make_agent(name="claude-desktop", status=AgentStatus.CONFIGURED)
    a2 = _make_agent(name="cursor", status=AgentStatus.CONFIGURED)
    a3 = _make_agent(name="openclaw", status=AgentStatus.INSTALLED_NOT_CONFIGURED)
    report = AIBOMReport(agents=[a1, a2, a3])
    output = _capture_posture(report)
    assert "2 configured" in output
    assert "1 installed-not-configured" in output
