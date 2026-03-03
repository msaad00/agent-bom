"""Tests for NIST Cybersecurity Framework (CSF) 2.0 tagging."""

from agent_bom.models import (
    Agent,
    AgentType,
    BlastRadius,
    MCPServer,
    MCPTool,
    Package,
    Severity,
    Vulnerability,
)
from agent_bom.nist_csf import (
    NIST_CSF,
    nist_csf_label,
    nist_csf_labels,
    tag_blast_radius,
)


def _br(
    *,
    severity=Severity.HIGH,
    pkg_name="flask",
    tools=None,
    creds=None,
    fixed_version=None,
    is_kev=False,
    epss_score=None,
    num_agents=1,
) -> BlastRadius:
    vuln = Vulnerability(
        id="CVE-2025-9999",
        summary="test",
        severity=severity,
        fixed_version=fixed_version,
        is_kev=is_kev,
        epss_score=epss_score,
    )
    pkg = Package(name=pkg_name, version="1.0.0", ecosystem="pypi")
    agents = [Agent(name=f"a{i}", agent_type=AgentType.CLAUDE_DESKTOP, config_path="/tmp") for i in range(num_agents)]
    return BlastRadius(
        vulnerability=vuln,
        package=pkg,
        affected_servers=[MCPServer(name="srv")],
        affected_agents=agents,
        exposed_credentials=creds or [],
        exposed_tools=tools or [],
    )


def test_catalog_has_14_controls():
    assert len(NIST_CSF) == 14


def test_always_applied_tags():
    tags = tag_blast_radius(_br())
    assert "GV.SC-05" in tags
    assert "GV.SC-07" in tags
    assert "ID.RA-01" in tags
    assert "DE.CM-09" in tags


def test_kev_triggers_threat_intel_and_containment():
    tags = tag_blast_radius(_br(is_kev=True))
    assert "ID.RA-02" in tags
    assert "RS.MI-02" in tags


def test_epss_triggers_threat_intel():
    tags = tag_blast_radius(_br(epss_score=0.5))
    assert "ID.RA-02" in tags


def test_high_severity_triggers_risk_assessment():
    tags = tag_blast_radius(_br(severity=Severity.CRITICAL))
    assert "ID.RA-05" in tags
    tags_low = tag_blast_radius(_br(severity=Severity.LOW))
    assert "ID.RA-05" not in tags_low


def test_ai_package_triggers_asset_classification():
    tags = tag_blast_radius(_br(pkg_name="langchain"))
    assert "ID.AM-05" in tags
    tags_normal = tag_blast_radius(_br(pkg_name="flask"))
    assert "ID.AM-05" not in tags_normal


def test_credentials_trigger_identity_management():
    tags = tag_blast_radius(_br(creds=["API_KEY"]))
    assert "PR.AA-01" in tags
    tags_no = tag_blast_radius(_br())
    assert "PR.AA-01" not in tags_no


def test_exec_and_creds_trigger_auth():
    tags = tag_blast_radius(_br(creds=["SECRET"], tools=[MCPTool(name="exec", description="execute shell")]))
    assert "PR.AA-03" in tags


def test_read_and_creds_trigger_data_at_rest():
    tags = tag_blast_radius(_br(creds=["DB_TOKEN"], tools=[MCPTool(name="read_file", description="read a file")]))
    assert "PR.DS-01" in tags


def test_many_agents_trigger_data_in_transit():
    tags = tag_blast_radius(_br(num_agents=5))
    assert "PR.DS-02" in tags
    tags_few = tag_blast_radius(_br(num_agents=2))
    assert "PR.DS-02" not in tags_few


def test_multi_agent_triggers_network_monitoring():
    tags = tag_blast_radius(_br(num_agents=3))
    assert "DE.CM-01" in tags
    tags_single = tag_blast_radius(_br(num_agents=1))
    assert "DE.CM-01" not in tags_single


def test_fixable_triggers_remediation_analysis():
    tags = tag_blast_radius(_br(fixed_version="2.0.0"))
    assert "RS.AN-03" in tags
    tags_no = tag_blast_radius(_br())
    assert "RS.AN-03" not in tags_no


def test_label_functions():
    assert nist_csf_label("ID.RA-01") == "ID.RA-01 Vulnerabilities in assets are identified"
    labels = nist_csf_labels(["GV.SC-05", "ID.RA-01"])
    assert len(labels) == 2


def test_minimal_finding_gets_base_tags_only():
    tags = tag_blast_radius(_br(severity=Severity.LOW, pkg_name="requests"))
    assert "GV.SC-05" in tags
    assert "ID.RA-01" in tags
    assert "PR.AA-01" not in tags
    assert "RS.MI-02" not in tags
