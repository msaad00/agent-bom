"""Tests for SOC 2 Trust Services Criteria tagging."""

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
from agent_bom.soc2 import (
    SOC2_TSC,
    soc2_label,
    soc2_labels,
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
) -> BlastRadius:
    vuln = Vulnerability(
        id="CVE-2025-9999",
        summary="test",
        severity=severity,
        fixed_version=fixed_version,
        is_kev=is_kev,
    )
    pkg = Package(name=pkg_name, version="1.0.0", ecosystem="pypi")
    return BlastRadius(
        vulnerability=vuln,
        package=pkg,
        affected_servers=[MCPServer(name="srv")],
        affected_agents=[Agent(name="a1", agent_type=AgentType.CLAUDE_DESKTOP, config_path="/tmp")],
        exposed_credentials=creds or [],
        exposed_tools=tools or [],
    )


def test_catalog_has_nine_criteria():
    assert len(SOC2_TSC) == 9


def test_always_applied_tags():
    tags = tag_blast_radius(_br())
    # CC7.1 is detective: a fresh scan evidences it, so findings never fail it.
    assert "CC7.1" not in tags
    assert "CC9.1" in tags
    assert "CC9.2" in tags


def test_creds_trigger_access_controls():
    tags = tag_blast_radius(_br(creds=["API_KEY"]))
    assert "CC6.1" in tags
    tags_no = tag_blast_radius(_br())
    assert "CC6.1" not in tags_no


def test_exec_tools_trigger_boundary_enforcement():
    tags = tag_blast_radius(_br(tools=[MCPTool(name="exec", description="execute shell command")]))
    assert "CC6.6" in tags


def test_severity_alone_is_not_malicious_software():
    assert "CC6.8" not in tag_blast_radius(_br(severity=Severity.CRITICAL))
    br = _br(severity=Severity.LOW)
    br.package.is_malicious = True
    assert "CC6.8" in tag_blast_radius(br)


def test_ai_package_does_not_claim_anomaly_monitoring():
    assert "CC7.2" not in tag_blast_radius(_br(pkg_name="transformers"))


def test_kev_triggers_incident_response():
    tags = tag_blast_radius(_br(is_kev=True))
    assert "CC7.4" in tags
    tags_no = tag_blast_radius(_br())
    assert "CC7.4" not in tags_no


def test_fixable_triggers_change_management():
    tags = tag_blast_radius(_br(fixed_version="2.0.0"))
    assert "CC8.1" in tags
    tags_no = tag_blast_radius(_br())
    assert "CC8.1" not in tags_no


def test_label_functions():
    # agent-bom's own descriptor, not the copyrighted AICPA TSC criterion text.
    assert soc2_label("CC7.1") == "CC7.1 Vulnerability and configuration-change detection"
    labels = soc2_labels(["CC7.1", "CC9.1"])
    assert len(labels) == 2


def test_minimal_finding_gets_base_tags_only():
    tags = tag_blast_radius(_br(severity=Severity.LOW, pkg_name="requests"))
    assert tags == ["CC9.1", "CC9.2"]
