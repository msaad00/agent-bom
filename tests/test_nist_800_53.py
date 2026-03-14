"""Tests for NIST 800-53 Rev 5 control tagging."""

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
from agent_bom.nist_800_53 import (
    NIST_800_53,
    nist_800_53_label,
    nist_800_53_labels,
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
    cwe_ids=None,
) -> BlastRadius:
    vuln = Vulnerability(
        id="CVE-2025-9999",
        summary="test",
        severity=severity,
        fixed_version=fixed_version,
        is_kev=is_kev,
        epss_score=epss_score,
        cwe_ids=cwe_ids,
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


def test_catalog_has_expected_controls():
    assert len(NIST_800_53) == 29


def test_always_applied_tags():
    tags = tag_blast_radius(_br(severity=Severity.LOW, pkg_name="requests"))
    assert "RA-5" in tags
    assert "SI-2" in tags
    assert "SR-3" in tags
    assert "CM-8" in tags


def test_high_severity_triggers_risk_response_and_monitoring():
    tags = tag_blast_radius(_br(severity=Severity.CRITICAL))
    assert "RA-7" in tags
    assert "SI-4" in tags
    assert "IR-5" in tags


def test_low_severity_no_risk_response():
    tags = tag_blast_radius(_br(severity=Severity.LOW))
    assert "RA-7" not in tags
    assert "IR-5" not in tags


def test_kev_triggers_alert_and_reporting():
    tags = tag_blast_radius(_br(is_kev=True))
    assert "SI-5" in tags
    assert "IR-6" in tags


def test_credentials_trigger_access_controls():
    tags = tag_blast_radius(_br(creds=["API_KEY"]))
    assert "AC-3" in tags
    assert "AC-6" in tags
    assert "IA-5" in tags
    tags_no = tag_blast_radius(_br())
    assert "AC-3" not in tags_no
    assert "IA-5" not in tags_no


def test_exec_and_creds_trigger_least_privilege():
    tags = tag_blast_radius(_br(creds=["SECRET"], tools=[MCPTool(name="exec", description="execute shell")]))
    assert "AC-6" in tags


def test_read_and_creds_trigger_data_at_rest():
    tags = tag_blast_radius(
        _br(
            creds=["DB_TOKEN"],
            tools=[MCPTool(name="read_file", description="read a file")],
        )
    )
    assert "SC-28" in tags


def test_ai_package_triggers_provenance_and_authenticity():
    tags = tag_blast_radius(_br(pkg_name="langchain"))
    assert "SR-4" in tags
    assert "SR-11" in tags
    tags_normal = tag_blast_radius(_br(pkg_name="flask"))
    assert "SR-4" not in tags_normal
    assert "SR-11" not in tags_normal


def test_fixable_triggers_config_settings():
    tags = tag_blast_radius(_br(fixed_version="2.0.0"))
    assert "CM-6" in tags
    tags_no = tag_blast_radius(_br())
    assert "CM-6" not in tags_no


def test_multi_agent_triggers_system_monitoring():
    tags = tag_blast_radius(_br(num_agents=3, severity=Severity.LOW))
    assert "SI-4" in tags
    tags_single = tag_blast_radius(_br(num_agents=1, severity=Severity.LOW))
    assert "SI-4" not in tags_single


def test_cwe_based_tagging():
    tags = tag_blast_radius(_br(severity=Severity.LOW, cwe_ids=["CWE-798"]))
    assert "IA-5" in tags
    assert "SC-28" in tags


def test_label_functions():
    assert nist_800_53_label("RA-5") == "RA-5 Vulnerability Monitoring and Scanning"
    labels = nist_800_53_labels(["RA-5", "SI-2"])
    assert len(labels) == 2


def test_minimal_finding_gets_base_tags_only():
    tags = tag_blast_radius(_br(severity=Severity.LOW, pkg_name="requests"))
    assert "RA-5" in tags
    assert "SI-2" in tags
    assert "SR-3" in tags
    assert "CM-8" in tags
    assert "AC-3" not in tags
    assert "IR-6" not in tags
    assert "SR-4" not in tags
