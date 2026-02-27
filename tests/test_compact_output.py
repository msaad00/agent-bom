"""Tests for compact CLI output functions."""

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
from agent_bom.output import (
    print_compact_agents,
    print_compact_blast_radius,
    print_compact_export_hint,
    print_compact_remediation,
    print_compact_summary,
)


def _capture(fn, *args, **kwargs) -> str:
    """Capture compact output as plain text."""
    buf = StringIO()
    con = Console(file=buf, width=120, force_terminal=True, no_color=True)
    import agent_bom.output as out_mod

    orig = out_mod.console
    out_mod.console = con
    try:
        fn(*args, **kwargs)
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


def _vuln(vid="CVE-2024-0001", severity=Severity.CRITICAL, fixed=None, kev=False):
    return Vulnerability(
        id=vid, summary="test vuln", severity=severity,
        fixed_version=fixed, is_kev=kev,
    )


def _blast(vuln, pkg, agents, servers, creds=None):
    return BlastRadius(
        vulnerability=vuln, package=pkg,
        affected_servers=servers, affected_agents=agents,
        exposed_credentials=creds or [], exposed_tools=[],
    )


# ── print_compact_summary ────────────────────────────────────────────────────


def test_compact_summary_clean():
    """0 vulns → CLEAN posture."""
    agent = _make_agent(servers=[
        _make_server(packages=[
            Package(name="express", version="4.19.0", ecosystem="npm"),
        ])
    ])
    report = AIBOMReport(agents=[agent])
    output = _capture(print_compact_summary, report)
    assert "CLEAN" in output
    assert "Agents" in output
    assert "1" in output


def test_compact_summary_with_vulns():
    """Shows severity breakdown when vulns exist."""
    vuln = _vuln()
    pkg = Package(name="lodash", version="4.17.20", ecosystem="npm",
                  vulnerabilities=[vuln])
    server = _make_server(packages=[pkg])
    agent = _make_agent(servers=[server])
    br = _blast(vuln, pkg, [agent], [server])
    report = AIBOMReport(agents=[agent], blast_radii=[br])
    output = _capture(print_compact_summary, report)
    assert "CRITICAL" in output
    assert "Vulns" in output


def test_compact_summary_credentials():
    """Shows credential names."""
    server = _make_server(name="github", env={"GITHUB_TOKEN": "xxx"})
    agent = _make_agent(servers=[server])
    report = AIBOMReport(agents=[agent])
    output = _capture(print_compact_summary, report)
    assert "GITHUB_TOKEN" in output


# ── print_compact_agents ─────────────────────────────────────────────────────


def test_compact_agents_table():
    """One row per configured agent."""
    a1 = _make_agent(name="claude-desktop", servers=[
        _make_server(packages=[
            Package(name="express", version="4.19.0", ecosystem="npm"),
        ])
    ])
    a2 = _make_agent(name="cursor", agent_type=AgentType.CURSOR, servers=[
        _make_server(name="s2", packages=[
            Package(name="flask", version="3.0.0", ecosystem="pypi"),
            Package(name="requests", version="2.31.0", ecosystem="pypi"),
        ])
    ])
    report = AIBOMReport(agents=[a1, a2])
    output = _capture(print_compact_agents, report)
    assert "claude-desktop" in output
    assert "cursor" in output


def test_compact_agents_skips_unconfigured():
    """Only configured agents shown."""
    a1 = _make_agent(name="configured", status=AgentStatus.CONFIGURED)
    a2 = _make_agent(name="notconfigured", status=AgentStatus.INSTALLED_NOT_CONFIGURED)
    report = AIBOMReport(agents=[a1, a2])
    output = _capture(print_compact_agents, report)
    assert "configured" in output
    assert "notconfigured" not in output


# ── print_compact_blast_radius ───────────────────────────────────────────────


def test_compact_blast_radius_limit():
    """Respects limit and shows 'more' hint."""
    pkg = Package(name="lodash", version="4.17.20", ecosystem="npm")
    server = _make_server(packages=[pkg])
    agent = _make_agent(servers=[server])
    radii = []
    for i in range(8):
        v = _vuln(vid=f"CVE-2024-{i:04d}", severity=Severity.HIGH)
        radii.append(_blast(v, pkg, [agent], [server]))
    report = AIBOMReport(agents=[agent], blast_radii=radii)
    output = _capture(print_compact_blast_radius, report, limit=3)
    assert "3 of 8" in output
    assert "more" in output
    assert "--verbose" in output


def test_compact_blast_radius_empty():
    """No output when no blast radii."""
    report = AIBOMReport(agents=[])
    output = _capture(print_compact_blast_radius, report)
    assert output.strip() == ""


def test_compact_blast_radius_kev():
    """KEV badge shown for known-exploited vulns."""
    v = _vuln(vid="CVE-2024-0001", severity=Severity.CRITICAL, kev=True)
    pkg = Package(name="log4j", version="2.14.0", ecosystem="maven",
                  vulnerabilities=[v])
    server = _make_server(packages=[pkg])
    agent = _make_agent(servers=[server])
    br = _blast(v, pkg, [agent], [server])
    report = AIBOMReport(agents=[agent], blast_radii=[br])
    output = _capture(print_compact_blast_radius, report)
    assert "KEV" in output


# ── print_compact_remediation ────────────────────────────────────────────────


def test_compact_remediation_limit():
    """Respects limit and shows 'more' hint."""
    server = _make_server()
    agent = _make_agent(servers=[server])
    radii = []
    for i in range(5):
        v = _vuln(vid=f"CVE-2024-{i:04d}", severity=Severity.HIGH, fixed="9.9.9")
        p = Package(name=f"pkg-{i}", version="1.0.0", ecosystem="npm",
                    vulnerabilities=[v])
        radii.append(_blast(v, p, [agent], [server]))
    report = AIBOMReport(agents=[agent], blast_radii=radii)
    output = _capture(print_compact_remediation, report, limit=2)
    assert "more" in output
    assert "--verbose" in output


def test_compact_remediation_empty():
    """No output when no blast radii."""
    report = AIBOMReport(agents=[])
    output = _capture(print_compact_remediation, report)
    assert output.strip() == ""


# ── print_compact_export_hint ────────────────────────────────────────────────


def test_compact_export_hint():
    """Shows export formats and serve hint."""
    agent = _make_agent(servers=[_make_server()])
    report = AIBOMReport(agents=[agent])
    output = _capture(print_compact_export_hint, report)
    assert "json" in output
    assert "cyclonedx" in output
    assert "sarif" in output
    assert "serve" in output
    assert "--verbose" in output
