"""Tests for the compliance narrative generator."""

from __future__ import annotations

import pytest

from agent_bom.models import (
    Agent,
    AgentType,
    AIBOMReport,
    BlastRadius,
    MCPServer,
    Package,
    Severity,
    Vulnerability,
)
from agent_bom.output.compliance_narrative import (
    ALL_FRAMEWORK_SLUGS,
    ComplianceNarrative,
    ControlNarrative,
    RemediationImpact,
    generate_compliance_narrative,
)

# ─── Fixtures ─────────────────────────────────────────────────────────────────


def _make_vuln(
    vuln_id: str = "CVE-2025-1234",
    severity: Severity = Severity.HIGH,
    fixed_version: str | None = "2.0.0",
    is_kev: bool = False,
) -> Vulnerability:
    return Vulnerability(
        id=vuln_id,
        summary="Test vulnerability",
        severity=severity,
        fixed_version=fixed_version,
        is_kev=is_kev,
    )


def _make_blast_radius(
    vuln: Vulnerability | None = None,
    pkg_name: str = "requests",
    pkg_version: str = "1.0.0",
    agents: list[str] | None = None,
    owasp_tags: list[str] | None = None,
    owasp_mcp_tags: list[str] | None = None,
    nist_tags: list[str] | None = None,
    cmmc_tags: list[str] | None = None,
    exposed_credentials: list[str] | None = None,
    risk_score: float = 6.0,
) -> BlastRadius:
    if vuln is None:
        vuln = _make_vuln()
    pkg = Package(name=pkg_name, version=pkg_version, ecosystem="pypi")
    agent_objs = [Agent(name=n, agent_type=AgentType.CLAUDE_CODE, config_path="/tmp") for n in (agents or ["claude"])]
    server = MCPServer(name="test-server")
    return BlastRadius(
        vulnerability=vuln,
        package=pkg,
        affected_servers=[server],
        affected_agents=agent_objs,
        exposed_credentials=exposed_credentials or [],
        exposed_tools=[],
        risk_score=risk_score,
        owasp_tags=owasp_tags or ["LLM05"],
        owasp_mcp_tags=owasp_mcp_tags or [],
        nist_ai_rmf_tags=nist_tags or [],
        cmmc_tags=cmmc_tags or [],
    )


def _make_report(blast_radii: list[BlastRadius] | None = None) -> AIBOMReport:
    agents = [Agent(name="claude", agent_type=AgentType.CLAUDE_CODE, config_path="/tmp")]
    return AIBOMReport(agents=agents, blast_radii=blast_radii or [])


# ─── Dataclass structure tests ────────────────────────────────────────────────


def test_generate_returns_compliance_narrative_type():
    report = _make_report()
    result = generate_compliance_narrative(report)
    assert isinstance(result, ComplianceNarrative)


def test_compliance_narrative_fields_present():
    report = _make_report()
    result = generate_compliance_narrative(report)
    assert isinstance(result.executive_summary, str)
    assert isinstance(result.framework_narratives, list)
    assert isinstance(result.remediation_impact, list)
    assert isinstance(result.risk_narrative, str)
    assert isinstance(result.generated_at, str)
    # ISO 8601 — should contain 'T'
    assert "T" in result.generated_at


# ─── Framework coverage ───────────────────────────────────────────────────────


def test_all_frameworks_returned_when_no_filter():
    report = _make_report()
    result = generate_compliance_narrative(report)
    returned_slugs = {fn.slug for fn in result.framework_narratives}
    assert returned_slugs == set(ALL_FRAMEWORK_SLUGS)


def test_single_framework_filter():
    report = _make_report()
    result = generate_compliance_narrative(report, framework="owasp-llm")
    assert len(result.framework_narratives) == 1
    assert result.framework_narratives[0].slug == "owasp-llm"
    assert result.framework_narratives[0].framework == "OWASP Top 10 for LLM"


def test_single_framework_cmmc():
    report = _make_report()
    result = generate_compliance_narrative(report, framework="cmmc")
    assert result.framework_narratives[0].slug == "cmmc"
    assert result.framework_narratives[0].framework == "CMMC 2.0"


def test_unknown_framework_raises_value_error():
    report = _make_report()
    with pytest.raises(ValueError, match="Unknown framework"):
        generate_compliance_narrative(report, framework="not-a-real-framework")


# ─── Framework narrative content ──────────────────────────────────────────────


def test_passing_framework_status_when_no_vulns():
    report = _make_report(blast_radii=[])
    result = generate_compliance_narrative(report, framework="owasp-llm")
    fw = result.framework_narratives[0]
    assert fw.status == "passing"
    assert fw.score == 100
    assert fw.failing_controls == []


def test_failing_framework_status_for_critical_vuln():
    br = _make_blast_radius(
        vuln=_make_vuln(severity=Severity.CRITICAL),
        owasp_tags=["LLM05"],
    )
    report = _make_report(blast_radii=[br])
    result = generate_compliance_narrative(report, framework="owasp-llm")
    fw = result.framework_narratives[0]
    assert fw.status == "failing"
    assert fw.score < 100
    assert len(fw.failing_controls) >= 1


def test_at_risk_framework_status_for_medium_vuln():
    br = _make_blast_radius(
        vuln=_make_vuln(severity=Severity.MEDIUM),
        owasp_tags=["LLM05"],
    )
    report = _make_report(blast_radii=[br])
    result = generate_compliance_narrative(report, framework="owasp-llm")
    fw = result.framework_narratives[0]
    assert fw.status == "at_risk"


def test_framework_score_is_integer_0_to_100():
    br = _make_blast_radius(owasp_tags=["LLM01", "LLM05"])
    report = _make_report(blast_radii=[br])
    result = generate_compliance_narrative(report, framework="owasp-llm")
    fw = result.framework_narratives[0]
    assert isinstance(fw.score, int)
    assert 0 <= fw.score <= 100


def test_framework_narrative_is_non_empty_string():
    report = _make_report()
    result = generate_compliance_narrative(report, framework="nist")
    fw = result.framework_narratives[0]
    assert len(fw.narrative) > 20


def test_framework_has_recommendations():
    br = _make_blast_radius(
        vuln=_make_vuln(severity=Severity.HIGH),
        owasp_tags=["LLM05"],
    )
    report = _make_report(blast_radii=[br])
    result = generate_compliance_narrative(report, framework="owasp-llm")
    fw = result.framework_narratives[0]
    assert len(fw.recommendations) >= 1


# ─── ControlNarrative tests ───────────────────────────────────────────────────


def test_failing_control_has_correct_fields():
    br = _make_blast_radius(
        vuln=_make_vuln(severity=Severity.HIGH),
        owasp_tags=["LLM05"],
        pkg_name="requests",
        pkg_version="1.0.0",
        agents=["claude-agent"],
    )
    report = _make_report(blast_radii=[br])
    result = generate_compliance_narrative(report, framework="owasp-llm")
    fw = result.framework_narratives[0]

    llm05 = next((c for c in fw.failing_controls if c.control_id == "LLM05"), None)
    assert llm05 is not None
    assert isinstance(llm05, ControlNarrative)
    assert llm05.status in ("warning", "fail")
    assert "requests@1.0.0" in llm05.affected_packages
    assert "claude-agent" in llm05.affected_agents
    assert len(llm05.narrative) > 0
    assert len(llm05.remediation_steps) >= 1


def test_passing_control_not_in_failing_list():
    br = _make_blast_radius(owasp_tags=["LLM05"])
    report = _make_report(blast_radii=[br])
    result = generate_compliance_narrative(report, framework="owasp-llm")
    fw = result.framework_narratives[0]
    failing_ids = {c.control_id for c in fw.failing_controls}
    # LLM01 was not tagged so it should not appear in failing_controls
    assert "LLM01" not in failing_ids


# ─── Remediation impact tests ─────────────────────────────────────────────────


def test_remediation_impact_generated_for_tagged_vulns():
    br = _make_blast_radius(
        vuln=_make_vuln(fixed_version="2.0.0"),
        owasp_tags=["LLM05"],
        owasp_mcp_tags=["MCP04"],
    )
    report = _make_report(blast_radii=[br])
    result = generate_compliance_narrative(report)
    assert len(result.remediation_impact) >= 1


def test_remediation_impact_fields():
    br = _make_blast_radius(
        vuln=_make_vuln(fixed_version="2.0.0"),
        pkg_name="requests",
        pkg_version="1.0.0",
        owasp_tags=["LLM05"],
    )
    report = _make_report(blast_radii=[br])
    result = generate_compliance_narrative(report)

    ri = result.remediation_impact[0]
    assert isinstance(ri, RemediationImpact)
    assert ri.package == "requests"
    assert ri.current_version == "1.0.0"
    assert ri.fix_version == "2.0.0"
    assert "LLM05" in ri.controls_fixed
    assert "OWASP Top 10 for LLM" in ri.frameworks_impacted
    assert "requests" in ri.narrative
    assert "2.0.0" in ri.narrative


def test_remediation_impact_no_fix_version():
    br = _make_blast_radius(
        vuln=_make_vuln(fixed_version=None),
        owasp_tags=["LLM05"],
    )
    report = _make_report(blast_radii=[br])
    result = generate_compliance_narrative(report)
    ri = result.remediation_impact[0]
    assert ri.fix_version == ""
    assert "no fix available" in ri.narrative.lower()


def test_remediation_impact_sorted_by_control_count():
    br1 = _make_blast_radius(
        pkg_name="pkg-a",
        pkg_version="1.0",
        vuln=_make_vuln("CVE-2025-001", fixed_version="2.0"),
        owasp_tags=["LLM05"],
    )
    br2 = _make_blast_radius(
        pkg_name="pkg-b",
        pkg_version="1.0",
        vuln=_make_vuln("CVE-2025-002", fixed_version="2.0"),
        owasp_tags=["LLM01", "LLM05"],
        owasp_mcp_tags=["MCP04"],
    )
    report = _make_report(blast_radii=[br1, br2])
    result = generate_compliance_narrative(report)
    # pkg-b has more controls — should appear first
    assert result.remediation_impact[0].package == "pkg-b"


def test_remediation_impact_empty_for_no_tags():
    br = _make_blast_radius(owasp_tags=[], owasp_mcp_tags=[], nist_tags=[], cmmc_tags=[])
    # manually clear all tags on the blast radius object
    br.owasp_tags = []
    br.owasp_mcp_tags = []
    br.atlas_tags = []
    br.nist_ai_rmf_tags = []
    br.owasp_agentic_tags = []
    br.eu_ai_act_tags = []
    br.nist_csf_tags = []
    br.iso_27001_tags = []
    br.soc2_tags = []
    br.cis_tags = []
    br.cmmc_tags = []
    report = _make_report(blast_radii=[br])
    result = generate_compliance_narrative(report)
    assert result.remediation_impact == []


# ─── Risk narrative tests ─────────────────────────────────────────────────────


def test_risk_narrative_empty_scan():
    report = _make_report(blast_radii=[])
    result = generate_compliance_narrative(report)
    assert "no vulnerabilities" in result.risk_narrative.lower()


def test_risk_narrative_mentions_vuln_count():
    brs = [_make_blast_radius(vuln=_make_vuln(f"CVE-2025-{i}"), owasp_tags=["LLM05"]) for i in range(3)]
    report = _make_report(blast_radii=brs)
    result = generate_compliance_narrative(report)
    assert "3" in result.risk_narrative


def test_risk_narrative_mentions_kev():
    br = _make_blast_radius(
        vuln=_make_vuln(is_kev=True),
        owasp_tags=["LLM05"],
    )
    report = _make_report(blast_radii=[br])
    result = generate_compliance_narrative(report)
    assert "kev" in result.risk_narrative.lower() or "known exploited" in result.risk_narrative.lower()


# ─── Executive summary tests ──────────────────────────────────────────────────


def test_executive_summary_non_empty():
    report = _make_report()
    result = generate_compliance_narrative(report)
    assert len(result.executive_summary) > 50


def test_executive_summary_mentions_scan_date():
    report = _make_report()
    result = generate_compliance_narrative(report)
    # generated_at starts with YYYY-MM-DD; the first 10 chars should appear in summary
    date_prefix = result.generated_at[:10]
    assert date_prefix in result.executive_summary


def test_executive_summary_mentions_agent_count():
    agents = [Agent(name=f"agent-{i}", agent_type=AgentType.CLAUDE_CODE, config_path="/tmp") for i in range(3)]
    report = AIBOMReport(agents=agents, blast_radii=[])
    result = generate_compliance_narrative(report)
    assert "3" in result.executive_summary


def test_executive_summary_all_passing_when_no_vulns():
    report = _make_report(blast_radii=[])
    result = generate_compliance_narrative(report)
    # Should mention all frameworks passing or no findings
    lower = result.executive_summary.lower()
    assert "passing" in lower or "no vulnerabilities" in lower or "clean" in lower


def test_executive_summary_mentions_failing_framework():
    br = _make_blast_radius(
        vuln=_make_vuln(severity=Severity.CRITICAL),
        owasp_tags=["LLM05"],
    )
    report = _make_report(blast_radii=[br])
    result = generate_compliance_narrative(report)
    # At least one framework should be failing; summary should mention it
    lower = result.executive_summary.lower()
    assert "failing" in lower or "critical" in lower


# ─── Multi-framework blast radius coverage ────────────────────────────────────


def test_multi_framework_tags_affect_multiple_frameworks():
    br = _make_blast_radius(
        vuln=_make_vuln(severity=Severity.HIGH),
        owasp_tags=["LLM05"],
        owasp_mcp_tags=["MCP04"],
        nist_tags=["MAP-3.5"],
        cmmc_tags=["RA.L2-3.11.2"],
    )
    report = _make_report(blast_radii=[br])
    result = generate_compliance_narrative(report)

    status_by_slug = {fn.slug: fn.status for fn in result.framework_narratives}
    # Frameworks that were tagged should not be "passing"
    assert status_by_slug["owasp-llm"] != "passing"
    assert status_by_slug["owasp-mcp"] != "passing"
    assert status_by_slug["nist"] != "passing"
    assert status_by_slug["cmmc"] != "passing"
    # Untagged framework should be passing
    assert status_by_slug["soc2"] == "passing"


def test_all_framework_slugs_covered():
    """Ensure ALL_FRAMEWORK_SLUGS matches the expected set of 14 frameworks."""
    expected = {
        "owasp-llm",
        "owasp-mcp",
        "atlas",
        "nist",
        "owasp-agentic",
        "eu-ai-act",
        "nist-csf",
        "iso-27001",
        "soc2",
        "cis",
        "cmmc",
    }
    assert set(ALL_FRAMEWORK_SLUGS) == expected
