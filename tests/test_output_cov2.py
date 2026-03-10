"""Tests for agent_bom.output to improve coverage."""

from __future__ import annotations

from datetime import datetime, timezone

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
    _coverage_bar,
    _pct,
    _risk_narrative,
    build_remediation_plan,
    print_agent_tree,
    print_blast_radius,
    print_export_hint,
    print_posture_summary,
    print_summary,
    print_threat_frameworks,
    to_json,
)

# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def _make_pkg(name="lodash", version="4.17.20", ecosystem="npm", vulns=None):
    return Package(name=name, version=version, ecosystem=ecosystem, vulnerabilities=vulns or [])


def _make_vuln(vid="CVE-2025-0001", sev=Severity.HIGH, fixed="4.17.22"):
    return Vulnerability(id=vid, severity=sev, summary="test vuln", fixed_version=fixed)


def _make_server(name="srv", pkgs=None, creds=None, tools=None):
    # credential_names is a property derived from env keys matching sensitive patterns
    env = {}
    if creds:
        for c in creds:
            env[c] = "secret-value"
    return MCPServer(
        name=name,
        command="node",
        transport=TransportType.STDIO,
        packages=pkgs or [],
        env=env,
        tools=tools or [],
    )


def _make_agent(name="agent1", servers=None, status=AgentStatus.CONFIGURED):
    return Agent(
        name=name,
        agent_type=AgentType.CUSTOM,
        config_path="/test",
        mcp_servers=servers or [],
        status=status,
    )


def _make_report(agents=None, blast_radii=None):
    return AIBOMReport(
        agents=agents or [],
        blast_radii=blast_radii or [],
        generated_at=datetime(2025, 1, 1, tzinfo=timezone.utc),
    )


def _make_blast_radius(vuln=None, pkg=None, agents=None, servers=None, creds=None, tools=None):
    v = vuln or _make_vuln()
    p = pkg or _make_pkg(vulns=[v])
    return BlastRadius(
        vulnerability=v,
        package=p,
        affected_agents=agents or [],
        affected_servers=servers or [],
        exposed_credentials=creds or [],
        exposed_tools=tools or [],
    )


# ---------------------------------------------------------------------------
# _pct / _coverage_bar
# ---------------------------------------------------------------------------


def test_pct_normal():
    assert _pct(3, 10) == "30%"


def test_pct_zero_total():
    assert _pct(5, 0) == "\u2014"


def test_coverage_bar():
    result = _coverage_bar(5, 10, "red", width=10)
    assert "\u2588" in result


def test_coverage_bar_zero():
    result = _coverage_bar(0, 10, "blue")
    assert "\u2591" in result


# ---------------------------------------------------------------------------
# _risk_narrative
# ---------------------------------------------------------------------------


def test_risk_narrative_with_creds_and_tools():
    item = {
        "vulns": ["CVE-2025-0001"],
        "agents": ["agent1"],
        "creds": ["API_KEY"],
        "tools": ["read_file"],
    }
    result = _risk_narrative(item)
    assert "CVE-2025-0001" in result
    assert "API_KEY" in result
    assert "read_file" in result


def test_risk_narrative_no_creds():
    item = {"vulns": ["CVE-1"], "agents": ["a"], "creds": [], "tools": []}
    result = _risk_narrative(item)
    assert "CVE-1" in result
    assert "via a" in result


# ---------------------------------------------------------------------------
# print_summary
# ---------------------------------------------------------------------------


def test_print_summary():
    report = _make_report(agents=[_make_agent()])
    # Just verify it doesn't crash
    print_summary(report)


# ---------------------------------------------------------------------------
# print_posture_summary
# ---------------------------------------------------------------------------


def test_print_posture_clean():
    """No vulns = CLEAN posture."""
    report = _make_report(agents=[_make_agent()])
    print_posture_summary(report)


def test_print_posture_critical():
    """Critical vulns in posture."""
    vuln = _make_vuln(sev=Severity.CRITICAL)
    pkg = _make_pkg(vulns=[vuln])
    srv = _make_server(pkgs=[pkg])
    agent = _make_agent(servers=[srv])
    br = _make_blast_radius(vuln=vuln, pkg=pkg, agents=[agent], servers=[srv])
    report = _make_report(agents=[agent], blast_radii=[br])
    print_posture_summary(report)


def test_print_posture_medium_only():
    """Medium vulns only = yellow posture."""
    vuln = _make_vuln(sev=Severity.MEDIUM)
    pkg = _make_pkg(vulns=[vuln])
    srv = _make_server(pkgs=[pkg])
    agent = _make_agent(servers=[srv])
    br = _make_blast_radius(vuln=vuln, pkg=pkg, agents=[agent], servers=[srv])
    report = _make_report(agents=[agent], blast_radii=[br])
    print_posture_summary(report)


def test_print_posture_with_credentials():
    """Servers with credentials show credential exposure."""
    srv = _make_server(creds=["API_KEY", "SECRET", "TOKEN", "PASS", "AUTH"])
    agent = _make_agent(servers=[srv])
    report = _make_report(agents=[agent])
    print_posture_summary(report)


def test_print_posture_not_configured():
    """Agents with INSTALLED_NOT_CONFIGURED status."""
    agent = _make_agent(status=AgentStatus.INSTALLED_NOT_CONFIGURED)
    report = _make_report(agents=[agent])
    print_posture_summary(report)


# ---------------------------------------------------------------------------
# print_agent_tree
# ---------------------------------------------------------------------------


def test_print_agent_tree_basic():
    pkg = _make_pkg()
    srv = _make_server(pkgs=[pkg], creds=["KEY"])
    agent = _make_agent(servers=[srv])
    report = _make_report(agents=[agent])
    print_agent_tree(report)


def test_print_agent_tree_not_configured():
    agent = _make_agent(status=AgentStatus.INSTALLED_NOT_CONFIGURED)
    report = _make_report(agents=[agent])
    print_agent_tree(report)


def test_print_agent_tree_with_vulns():
    vuln = _make_vuln()
    pkg = _make_pkg(vulns=[vuln])
    srv = _make_server(pkgs=[pkg])
    agent = _make_agent(servers=[srv])
    report = _make_report(agents=[agent])
    print_agent_tree(report)


def test_print_agent_tree_transitive_pkgs():
    direct = _make_pkg()
    direct.is_direct = True
    trans = _make_pkg(name="dep", version="1.0")
    trans.is_direct = False
    trans.dependency_depth = 2
    trans.parent_package = "lodash"
    srv = _make_server(pkgs=[direct, trans])
    agent = _make_agent(servers=[srv])
    report = _make_report(agents=[agent])
    print_agent_tree(report)


# ---------------------------------------------------------------------------
# print_blast_radius
# ---------------------------------------------------------------------------


def test_print_blast_radius_empty():
    report = _make_report()
    print_blast_radius(report)  # no-op, no crash


def test_print_blast_radius_with_findings():
    vuln = _make_vuln()
    vuln.epss_score = 0.85
    vuln.is_kev = True
    vuln.references = ["https://example.com"]
    pkg = _make_pkg(vulns=[vuln])
    srv = _make_server(pkgs=[pkg])
    agent = _make_agent(servers=[srv])
    br = _make_blast_radius(vuln=vuln, pkg=pkg, agents=[agent], servers=[srv], creds=["KEY"])
    br.owasp_tags = ["LLM01"]
    br.atlas_tags = ["AML.T0001"]
    br.nist_ai_rmf_tags = ["MAP-1.1"]
    report = _make_report(agents=[agent], blast_radii=[br])
    print_blast_radius(report)


def test_print_blast_radius_no_fix():
    vuln = _make_vuln(fixed=None)
    pkg = _make_pkg(vulns=[vuln])
    br = _make_blast_radius(vuln=vuln, pkg=pkg)
    report = _make_report(blast_radii=[br])
    print_blast_radius(report)


def test_print_blast_radius_ghsa():
    vuln = _make_vuln(vid="GHSA-xxxx-yyyy-zzzz")
    pkg = _make_pkg(vulns=[vuln])
    br = _make_blast_radius(vuln=vuln, pkg=pkg)
    report = _make_report(blast_radii=[br])
    print_blast_radius(report)


# ---------------------------------------------------------------------------
# build_remediation_plan
# ---------------------------------------------------------------------------


def test_build_remediation_plan_empty():
    assert build_remediation_plan([]) == []


def test_build_remediation_plan_with_items():
    vuln = _make_vuln()
    pkg = _make_pkg(vulns=[vuln])
    agent = _make_agent()
    srv = _make_server(pkgs=[pkg])
    br = _make_blast_radius(vuln=vuln, pkg=pkg, agents=[agent], servers=[srv], creds=["KEY"])
    plan = build_remediation_plan([br])
    assert len(plan) >= 1
    assert plan[0]["package"] == "lodash"


# ---------------------------------------------------------------------------
# to_json
# ---------------------------------------------------------------------------


def test_to_json_empty_report():
    report = _make_report()
    result = to_json(report)
    assert result["document_type"] == "AI-BOM"
    assert result["summary"]["total_agents"] == 0
    assert isinstance(result["agents"], list)


def test_to_json_with_agents():
    pkg = _make_pkg()
    srv = _make_server(pkgs=[pkg])
    agent = _make_agent(servers=[srv])
    report = _make_report(agents=[agent])
    result = to_json(report)
    assert len(result["agents"]) == 1
    assert result["agents"][0]["name"] == "agent1"


def test_to_json_with_blast_radius():
    vuln = _make_vuln()
    pkg = _make_pkg(vulns=[vuln])
    agent = _make_agent()
    br = _make_blast_radius(vuln=vuln, pkg=pkg, agents=[agent])
    report = _make_report(agents=[agent], blast_radii=[br])
    result = to_json(report)
    assert len(result["blast_radius"]) >= 1
    assert "threat_framework_summary" in result


# ---------------------------------------------------------------------------
# print_threat_frameworks
# ---------------------------------------------------------------------------


def test_print_threat_frameworks_no_blast():
    report = _make_report()
    print_threat_frameworks(report)  # no-op


def test_print_threat_frameworks_with_tags():
    vuln = _make_vuln()
    pkg = _make_pkg(vulns=[vuln])
    br = _make_blast_radius(vuln=vuln, pkg=pkg)
    br.owasp_tags = ["LLM01"]
    br.atlas_tags = ["AML.T0001"]
    br.nist_ai_rmf_tags = ["MAP-1.1"]
    br.owasp_mcp_tags = ["MCP01"]
    br.owasp_agentic_tags = ["AGT01"]
    br.eu_ai_act_tags = ["ART-9"]
    br.nist_csf_tags = ["ID.AM"]
    br.iso_27001_tags = ["A.5.1"]
    br.soc2_tags = ["CC1.1"]
    br.cis_tags = ["CIS-1.1"]
    report = _make_report(blast_radii=[br])
    print_threat_frameworks(report)


# ---------------------------------------------------------------------------
# print_export_hint
# ---------------------------------------------------------------------------


def test_print_export_hint_no_vulns():
    report = _make_report()
    print_export_hint(report)


def test_print_export_hint_with_vulns():
    vuln = _make_vuln()
    pkg = _make_pkg(vulns=[vuln])
    br = _make_blast_radius(vuln=vuln, pkg=pkg)
    br.owasp_tags = ["LLM01"]
    report = _make_report(blast_radii=[br])
    print_export_hint(report)


# ---------------------------------------------------------------------------
# to_cyclonedx
# ---------------------------------------------------------------------------


def test_to_cyclonedx_empty():
    from agent_bom.output import to_cyclonedx

    report = _make_report()
    result = to_cyclonedx(report)
    assert result["bomFormat"] == "CycloneDX"
    assert result["specVersion"] == "1.6"


def test_to_cyclonedx_with_agent():
    from agent_bom.output import to_cyclonedx

    vuln = _make_vuln()
    pkg = _make_pkg(vulns=[vuln])
    srv = _make_server(pkgs=[pkg])
    agent = _make_agent(servers=[srv])
    report = _make_report(agents=[agent])
    result = to_cyclonedx(report)
    assert len(result["components"]) >= 2  # agent + server + pkg
    assert "vulnerabilities" in result


def test_to_cyclonedx_no_fix():
    from agent_bom.output import to_cyclonedx

    vuln = _make_vuln(fixed=None)
    pkg = _make_pkg(vulns=[vuln])
    srv = _make_server(pkgs=[pkg])
    agent = _make_agent(servers=[srv])
    report = _make_report(agents=[agent])
    result = to_cyclonedx(report)
    assert "vulnerabilities" in result


# ---------------------------------------------------------------------------
# to_spdx
# ---------------------------------------------------------------------------


def test_to_spdx_empty():
    from agent_bom.output import to_spdx

    report = _make_report()
    result = to_spdx(report)
    assert result["spdxVersion"] == "SPDX-3.0"


def test_to_spdx_with_agent():
    from agent_bom.output import to_spdx

    vuln = _make_vuln()
    pkg = _make_pkg(vulns=[vuln])
    srv = _make_server(pkgs=[pkg])
    agent = _make_agent(servers=[srv])
    report = _make_report(agents=[agent])
    result = to_spdx(report)
    assert len(result.get("packages", result.get("elements", []))) >= 1


# ---------------------------------------------------------------------------
# to_sarif
# ---------------------------------------------------------------------------


def test_to_sarif_empty():
    from agent_bom.output import to_sarif

    report = _make_report()
    result = to_sarif(report)
    assert result["$schema"] is not None or "runs" in result


def test_to_sarif_with_findings():
    from agent_bom.output import to_sarif

    vuln = _make_vuln()
    pkg = _make_pkg(vulns=[vuln])
    agent = _make_agent()
    br = _make_blast_radius(vuln=vuln, pkg=pkg, agents=[agent])
    report = _make_report(agents=[agent], blast_radii=[br])
    result = to_sarif(report)
    assert "runs" in result
    run = result["runs"][0]
    assert len(run.get("results", [])) >= 1


# ---------------------------------------------------------------------------
# print_attack_flow_tree
# ---------------------------------------------------------------------------


def test_print_attack_flow_tree():
    from agent_bom.output import print_attack_flow_tree

    vuln = _make_vuln()
    vuln.cvss_score = 9.8
    vuln.epss_score = 0.5
    vuln.is_kev = True
    pkg = _make_pkg(vulns=[vuln])
    from agent_bom.models import MCPTool

    tool = MCPTool(name="read_file", description="Read a file")
    srv = _make_server(pkgs=[pkg], tools=[tool])
    agent = _make_agent(servers=[srv])
    br = _make_blast_radius(vuln=vuln, pkg=pkg, agents=[agent], servers=[srv], creds=["API_KEY"], tools=[tool])
    report = _make_report(agents=[agent], blast_radii=[br])
    print_attack_flow_tree(report)


def test_print_attack_flow_tree_no_servers():
    from agent_bom.output import print_attack_flow_tree

    vuln = _make_vuln()
    pkg = _make_pkg(vulns=[vuln])
    from agent_bom.models import MCPTool

    tool = MCPTool(name="exec", description="Execute")
    agent = _make_agent()
    br = _make_blast_radius(vuln=vuln, pkg=pkg, agents=[agent], servers=[], creds=["SECRET"], tools=[tool])
    report = _make_report(blast_radii=[br])
    print_attack_flow_tree(report)


# ---------------------------------------------------------------------------
# _build_remediation_json
# ---------------------------------------------------------------------------


def test_build_remediation_json():
    from agent_bom.output import _build_remediation_json

    vuln = _make_vuln()
    pkg = _make_pkg(vulns=[vuln])
    agent = _make_agent()
    from agent_bom.models import MCPTool

    tool = MCPTool(name="read_file", description="Read")
    srv = _make_server(pkgs=[pkg], tools=[tool])
    br = _make_blast_radius(vuln=vuln, pkg=pkg, agents=[agent], servers=[srv], creds=["KEY"], tools=[tool])
    report = _make_report(agents=[agent], blast_radii=[br])
    result = _build_remediation_json(report)
    assert isinstance(result, list)


# ---------------------------------------------------------------------------
# export_json
# ---------------------------------------------------------------------------


def test_export_json(tmp_path):
    from agent_bom.output import export_json

    report = _make_report()
    out = tmp_path / "report.json"
    export_json(report, str(out))
    assert out.exists()
    import json

    data = json.loads(out.read_text())
    assert data["document_type"] == "AI-BOM"


# ---------------------------------------------------------------------------
# to_json with optional fields
# ---------------------------------------------------------------------------


def test_to_json_with_optional_fields():
    report = _make_report()
    report.executive_summary = "Test summary"
    report.ai_threat_chains = [{"chain": "test"}]
    report.skill_audit_data = {"findings": []}
    report.trust_assessment_data = {"score": 0.8}
    report.cis_benchmark_data = {"checks": []}
    result = to_json(report)
    assert result.get("executive_summary") == "Test summary"
    assert "skill_audit" in result
    assert "trust_assessment" in result
