"""Tests for ISO/IEC 27001:2022 Annex A tagging."""

from agent_bom.iso_27001 import (
    ISO_27001,
    iso_27001_label,
    iso_27001_labels,
    tag_blast_radius,
)
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


def _br(
    *,
    severity=Severity.HIGH,
    pkg_name="flask",
    tools=None,
    creds=None,
    fixed_version=None,
    is_kev=False,
    num_agents=1,
) -> BlastRadius:
    vuln = Vulnerability(
        id="CVE-2025-9999",
        summary="test",
        severity=severity,
        fixed_version=fixed_version,
        is_kev=is_kev,
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


def test_catalog_has_nine_controls():
    assert len(ISO_27001) == 9


def test_always_applied_tags():
    tags = tag_blast_radius(_br())
    assert "A.5.19" in tags
    assert "A.5.21" in tags
    assert "A.8.8" in tags


def test_high_severity_triggers_supplier_agreements():
    tags = tag_blast_radius(_br(severity=Severity.CRITICAL))
    assert "A.5.20" in tags
    tags_low = tag_blast_radius(_br(severity=Severity.LOW))
    assert "A.5.20" not in tags_low


def test_multi_agent_triggers_cloud_services():
    tags = tag_blast_radius(_br(num_agents=3))
    assert "A.5.23" in tags


def test_ai_package_triggers_cloud_services():
    tags = tag_blast_radius(_br(pkg_name="torch"))
    assert "A.5.23" in tags


def test_kev_triggers_evidence_collection():
    tags = tag_blast_radius(_br(is_kev=True))
    assert "A.5.28" in tags
    tags_no = tag_blast_radius(_br())
    assert "A.5.28" not in tags_no


def test_creds_trigger_config_management():
    tags = tag_blast_radius(_br(creds=["DB_PASSWORD"]))
    assert "A.8.9" in tags
    tags_no = tag_blast_radius(_br())
    assert "A.8.9" not in tags_no


def test_creds_and_exec_trigger_cryptography():
    tags = tag_blast_radius(_br(creds=["SECRET"], tools=[MCPTool(name="exec", description="execute shell")]))
    assert "A.8.24" in tags


def test_fixable_triggers_secure_coding():
    tags = tag_blast_radius(_br(fixed_version="2.0.0"))
    assert "A.8.28" in tags
    tags_no = tag_blast_radius(_br())
    assert "A.8.28" not in tags_no


def test_label_functions():
    assert iso_27001_label("A.8.8") == "A.8.8 Management of technical vulnerabilities"
    labels = iso_27001_labels(["A.5.19", "A.8.8"])
    assert len(labels) == 2


def test_minimal_finding_gets_base_tags_only():
    tags = tag_blast_radius(_br(severity=Severity.LOW, pkg_name="requests"))
    assert tags == ["A.5.19", "A.5.21", "A.8.8"]
