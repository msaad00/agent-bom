"""Regression tests for compact/console formatters on unified Finding (#2918 PR1)."""

from __future__ import annotations

import re
from io import StringIO

from rich.console import Console

from agent_bom.finding import Asset, Finding, FindingSource, FindingType, blast_radius_to_finding
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
    build_remediation_plan,
    print_blast_radius,
    print_compact_blast_radius,
    print_compact_remediation,
    print_compact_summary,
    print_severity_chart,
)
from agent_bom.output.finding_views import active_cve_findings, cve_findings


def _capture(fn, *args, **kwargs) -> str:
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
    return re.sub(r"\x1b\[[0-9;]*m", "", text)


def _cve_finding(**overrides) -> Finding:
    base = Finding(
        finding_type=FindingType.CVE,
        source=FindingSource.MCP_SCAN,
        asset=Asset(name="lodash", asset_type="package", identifier="pkg:npm/lodash@4.17.20"),
        severity="critical",
        title="CVE-2024-0001: lodash@4.17.20",
        description="Prototype pollution in lodash",
        cve_id="CVE-2024-0001",
        fixed_version="4.17.21",
        is_kev=True,
        epss_score=0.82,
        risk_score=9.1,
        is_actionable=True,
        affected_agents=["prod-agent"],
        affected_servers=["prod-mcp"],
        exposed_credentials=["GITHUB_TOKEN"],
        evidence={
            "package_name": "lodash",
            "package_version": "4.17.20",
            "ecosystem": "npm",
            "package_is_direct": True,
        },
    )
    for key, value in overrides.items():
        setattr(base, key, value)
    return base


def test_cve_findings_from_unified_stream_without_blast_radii():
    finding = _cve_finding()
    report = AIBOMReport(agents=[], findings=[finding])

    rows = cve_findings(report)

    assert len(rows) == 1
    assert rows[0].cve_id == "CVE-2024-0001"
    assert rows[0].affected_agents == ["prod-agent"]


def test_active_cve_findings_matches_blast_radius_projection():
    vuln = Vulnerability(id="CVE-2024-0002", summary="x", severity=Severity.HIGH, fixed_version="2.0.0")
    pkg = Package(name="axios", version="0.21.0", ecosystem="npm", vulnerabilities=[vuln])
    server = MCPServer(name="srv", command="npx", transport=TransportType.STDIO, packages=[pkg])
    agent = Agent(
        name="agent",
        agent_type=AgentType.CURSOR,
        config_path="/tmp/cursor.json",
        mcp_servers=[server],
        status=AgentStatus.CONFIGURED,
    )
    br = BlastRadius(
        vulnerability=vuln,
        package=pkg,
        affected_agents=[agent],
        affected_servers=[server],
        exposed_credentials=[],
        exposed_tools=[],
    )
    report = AIBOMReport(agents=[agent], blast_radii=[br])

    projected = active_cve_findings(report)
    legacy = [blast_radius_to_finding(item) for item in report.blast_radii]

    assert len(projected) == 1
    assert projected[0].cve_id == legacy[0].cve_id
    assert projected[0].affected_agents == legacy[0].affected_agents


def test_compact_summary_renders_from_unified_findings():
    report = AIBOMReport(agents=[], findings=[_cve_finding()])
    output = _plain(_capture(print_compact_summary, report))

    assert "CRIT" in output
    assert "CLEAN" not in output


def test_compact_blast_radius_renders_from_unified_findings():
    report = AIBOMReport(agents=[], findings=[_cve_finding()])
    output = _plain(_capture(print_compact_blast_radius, report, limit=5))

    assert "CVE-2024-0001" in output
    assert "lodash" in output
    assert "4.17" in output
    assert "KEV" in output
    assert "prod-agent" in output


def test_compact_remediation_renders_from_unified_findings():
    report = AIBOMReport(agents=[], findings=[_cve_finding()])
    output = _plain(_capture(print_compact_remediation, report))

    assert "Fix First" in output
    assert "lodash" in output
    assert "4.17.21" in output


def test_console_blast_radius_renders_from_unified_findings():
    report = AIBOMReport(agents=[], findings=[_cve_finding()])
    output = _plain(_capture(print_blast_radius, report))

    assert "CVE-2024-0001" in output
    assert "lodash" in output
    assert "4.17" in output


def test_build_remediation_plan_accepts_findings():
    finding = _cve_finding()
    plan = build_remediation_plan([finding])

    assert len(plan) == 1
    assert plan[0]["package"] == "lodash"
    assert plan[0]["fix"] == "4.17.21"


def test_severity_chart_from_unified_findings():
    report = AIBOMReport(agents=[], findings=[_cve_finding()])
    output = _plain(_capture(print_severity_chart, report))

    assert "CRITICAL" in output
    assert "1 (" in output
