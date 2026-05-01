"""Tests for compact CLI output functions."""

import re
from io import StringIO

from rich.console import Console

from agent_bom.finding import Asset, Finding, FindingSource, FindingType
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


def _plain(text: str) -> str:
    """Remove ANSI styling so assertions stay stable across CI terminals."""
    return re.sub(r"\x1b\[[0-9;]*m", "", text)


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


def _make_agent(name="test-agent", agent_type=AgentType.CLAUDE_DESKTOP, status=AgentStatus.CONFIGURED, servers=None):
    return Agent(
        name=name,
        agent_type=agent_type,
        config_path=f"/home/user/.{name}/config.json",
        mcp_servers=servers or [],
        status=status,
    )


def _vuln(vid="CVE-2024-0001", severity=Severity.CRITICAL, fixed=None, kev=False):
    return Vulnerability(
        id=vid,
        summary="test vuln",
        severity=severity,
        fixed_version=fixed,
        is_kev=kev,
    )


def _blast(vuln, pkg, agents, servers, creds=None):
    return BlastRadius(
        vulnerability=vuln,
        package=pkg,
        affected_servers=servers,
        affected_agents=agents,
        exposed_credentials=creds or [],
        exposed_tools=[],
    )


# ── print_compact_summary ────────────────────────────────────────────────────


def test_compact_summary_clean():
    """0 vulns → CLEAN posture."""
    agent = _make_agent(
        servers=[
            _make_server(
                packages=[
                    Package(name="express", version="4.19.0", ecosystem="npm"),
                ]
            )
        ]
    )
    report = AIBOMReport(agents=[agent])
    output = _capture(print_compact_summary, report)
    assert "CLEAN" in output
    assert "CONFIG POSTURE GRADE" in output
    assert "Agents" in output
    assert "1" in output


def test_compact_summary_with_vulns():
    """Shows severity breakdown when vulns exist."""
    vuln = _vuln()
    pkg = Package(name="lodash", version="4.17.20", ecosystem="npm", vulnerabilities=[vuln])
    server = _make_server(packages=[pkg])
    agent = _make_agent(servers=[server])
    br = _blast(vuln, pkg, [agent], [server])
    report = AIBOMReport(agents=[agent], blast_radii=[br])
    output = _capture(print_compact_summary, report)
    assert "CONFIG POSTURE GRADE" in output
    assert "CRIT" in output  # Badge shows " CRIT " not "CRITICAL"
    assert "Vulns" in output


def test_compact_summary_distinguishes_clean_vulns_from_config_posture():
    agent = _make_agent(
        servers=[
            _make_server(
                packages=[
                    Package(name="express", version="4.19.0", ecosystem="npm"),
                ]
            )
        ]
    )
    report = AIBOMReport(agents=[agent])
    output = _plain(_capture(print_compact_summary, report))
    assert "CONFIG POSTURE GRADE" in output
    assert "best-practice/config posture" in output
    assert "SECURITY POSTURE:" in output
    assert "CLEAN" in output


def test_compact_summary_includes_non_cve_findings():
    """Policy and blocklist findings should not render as CLEAN."""
    finding = Finding(
        finding_type=FindingType.MCP_BLOCKLIST,
        source=FindingSource.MCP_SCAN,
        asset=Asset(name="bad-server", asset_type="mcp_server"),
        severity="high",
        title="Blocked MCP server",
    )
    report = AIBOMReport(findings=[finding])

    output = _capture(print_compact_summary, report)

    assert "CLEAN" not in output
    assert "HIGH" in output
    assert "Findings" in output
    assert "high-risk policy/security" in output
    assert "finding(s) present" in output
    assert "Strong security posture" not in output


def test_compact_summary_credentials():
    """Shows credential names."""
    server = _make_server(name="github", env={"GITHUB_TOKEN": "xxx"})
    agent = _make_agent(servers=[server])
    report = AIBOMReport(agents=[agent])
    output = _capture(print_compact_summary, report)
    assert "GITHUB_TOKEN" in output


def test_compact_summary_unknown_severity_is_labeled_advisory():
    """UNKNOWN severity should read as advisory, not vague unscored noise."""
    vuln = Vulnerability(id="GHSA-test", summary="Advisory without CVSS", severity=Severity.UNKNOWN)
    pkg = Package(name="mystery", version="1.0.0", ecosystem="npm", vulnerabilities=[vuln])
    server = _make_server(packages=[pkg])
    agent = _make_agent(servers=[server])
    br = _blast(vuln, pkg, [agent], [server])
    report = AIBOMReport(agents=[agent], blast_radii=[br])
    output = _capture(print_compact_summary, report)
    assert "advisory" in output.lower()
    assert "unscored" not in output.lower()


def test_compact_summary_shows_top_drivers_for_weak_posture():
    """Weak posture should surface the key drivers inline."""
    vuln = _vuln(severity=Severity.HIGH, fixed="9.9.9")
    pkg = Package(name="pkg", version="1.0.0", ecosystem="npm", vulnerabilities=[vuln])
    server = _make_server(packages=[pkg], env={"AWS_SECRET_ACCESS_KEY": "x"})
    agent = _make_agent(servers=[server])
    br = _blast(vuln, pkg, [agent], [server], creds=["AWS_SECRET_ACCESS_KEY"])
    report = AIBOMReport(agents=[agent], blast_radii=[br])
    output = _capture(print_compact_summary, report)
    assert "Top Drivers" in output
    assert "Credential Hygiene" in output


# ── print_compact_agents ─────────────────────────────────────────────────────


def test_compact_agents_table():
    """One row per configured agent."""
    a1 = _make_agent(
        name="claude-desktop",
        servers=[
            _make_server(
                packages=[
                    Package(name="express", version="4.19.0", ecosystem="npm"),
                ]
            )
        ],
    )
    a2 = _make_agent(
        name="cursor",
        agent_type=AgentType.CURSOR,
        servers=[
            _make_server(
                name="s2",
                packages=[
                    Package(name="flask", version="3.0.0", ecosystem="pypi"),
                    Package(name="requests", version="2.31.0", ecosystem="pypi"),
                ],
            )
        ],
    )
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
    # Title rendered via Rule may have ANSI codes between characters — strip them
    import re

    plain = re.sub(r"\x1b\[[0-9;]*m", "", output)
    assert "3 of 8" in plain
    assert "more" in plain
    assert "--verbose" in plain


def test_compact_blast_radius_empty():
    """No output when no blast radii."""
    report = AIBOMReport(agents=[])
    output = _capture(print_compact_blast_radius, report)
    assert output.strip() == ""


def test_compact_blast_radius_kev():
    """KEV badge shown for known-exploited vulns."""
    v = _vuln(vid="CVE-2024-0001", severity=Severity.CRITICAL, kev=True)
    pkg = Package(name="log4j", version="2.14.0", ecosystem="maven", vulnerabilities=[v])
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
        p = Package(name=f"pkg-{i}", version="1.0.0", ecosystem="npm", vulnerabilities=[v])
        radii.append(_blast(v, p, [agent], [server]))
    report = AIBOMReport(agents=[agent], blast_radii=radii)
    output = _capture(print_compact_remediation, report, limit=2)
    assert "more" in output
    assert "--verbose" in output


def test_compact_remediation_shows_priority_and_action():
    """Default remediation output should explain why an item is first."""
    server = _make_server(env={"GITHUB_TOKEN": "x"}, tools=[{"name": "read_file"}])
    agent = _make_agent(servers=[server])
    vuln = _vuln(vid="CVE-2024-0001", severity=Severity.CRITICAL, fixed="2.0.0", kev=True)
    pkg = Package(name="openssl", version="1.0.0", ecosystem="pypi", vulnerabilities=[vuln])
    br = _blast(vuln, pkg, [agent], [server], creds=["GITHUB_TOKEN"])
    report = AIBOMReport(agents=[agent], blast_radii=[br])
    output = _capture(print_compact_remediation, report)
    plain = _plain(output)
    assert "Fix First" in plain
    assert "P1" in plain
    assert "rotate exposed credentials" in plain
    assert "pip install 'openssl>=2.0.0'" in plain
    assert "agent-bom check openssl@2.0.0 --ecosystem pypi" in plain


def test_compact_remediation_empty():
    """No output when no blast radii."""
    report = AIBOMReport(agents=[])
    output = _capture(print_compact_remediation, report)
    assert output.strip() == ""


def test_compact_remediation_command_prefix_and_spacing():
    """Install + verify commands render with a `$` prefix (copy-this affordance),
    and numbered items are separated by a blank line for scan-ability."""
    server = _make_server(env={"GITHUB_TOKEN": "x"}, tools=[{"name": "read_file"}])
    agent = _make_agent(servers=[server])
    radii = []
    for i in range(3):
        v = _vuln(vid=f"CVE-2024-{i:04d}", severity=Severity.HIGH, fixed="9.9.9", kev=True)
        p = Package(name=f"pkg-{i}", version="1.0.0", ecosystem="pypi", vulnerabilities=[v])
        radii.append(_blast(v, p, [agent], [server], creds=["GITHUB_TOKEN"]))
    report = AIBOMReport(agents=[agent], blast_radii=radii)
    plain = _plain(_capture(print_compact_remediation, report, limit=3))

    # Install command is prefixed with "$ " to signal a copy-this line.
    assert "$ pip install 'pkg-0>=9.9.9'" in plain
    # Verify command is also "$ "-prefixed and annotated as verify.
    assert "$ agent-bom check pkg-0@9.9.9 --ecosystem pypi" in plain
    assert "(verify)" in plain

    # Numbered items are separated by a blank line (breathing room).
    # Strip leading/trailing blank lines, then look for the pattern of a
    # dedented numbered item preceded by an empty line.
    lines = plain.splitlines()
    item_indices = [idx for idx, line in enumerate(lines) if line.lstrip().startswith(("1.", "2.", "3."))]
    assert len(item_indices) == 3
    # Items 2 and 3 must each be preceded by a blank line.
    for idx in item_indices[1:]:
        assert lines[idx - 1].strip() == "", f"Expected blank line before {lines[idx]!r}"


# ── print_compact_export_hint ────────────────────────────────────────────────


def test_compact_export_hint():
    """Shows key metrics summary."""
    agent = _make_agent(servers=[_make_server()])
    report = AIBOMReport(agents=[agent])
    output = _capture(print_compact_export_hint, report)
    assert "agents" in output
    assert "servers" in output
    assert "packages" in output
    assert "vulns" in output
