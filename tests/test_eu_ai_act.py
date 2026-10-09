"""Tests for EU AI Act risk classification tagging."""

from agent_bom.eu_ai_act import (
    EU_AI_ACT,
    eu_ai_act_label,
    eu_ai_act_labels,
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
) -> BlastRadius:
    vuln = Vulnerability(id="CVE-2025-5678", summary="test", severity=severity, fixed_version=fixed_version)
    pkg = Package(name=pkg_name, version="1.0.0", ecosystem="pypi")
    return BlastRadius(
        vulnerability=vuln,
        package=pkg,
        affected_servers=[MCPServer(name="srv")],
        affected_agents=[Agent(name="a1", agent_type=AgentType.CLAUDE_DESKTOP, config_path="/tmp")],
        exposed_credentials=creds or [],
        exposed_tools=tools or [],
    )


def test_always_applied_tags():
    tags = tag_blast_radius(_br())
    assert "ART-9" in tags  # risk management
    assert "ART-15" in tags  # cybersecurity


def test_catalog_has_six_articles():
    assert len(EU_AI_ACT) == 6


def test_never_tags_prohibited_or_high_risk_classification():
    tags = tag_blast_radius(
        _br(
            severity=Severity.CRITICAL,
            pkg_name="langchain",
            creds=["SECRET"],
            tools=[MCPTool(name="exec", description="execute shell command")],
        )
    )
    assert "ART-5" not in tags
    assert "ART-6" not in tags


def test_exec_tools_are_human_oversight():
    tags = tag_blast_radius(_br(tools=[MCPTool(name="exec", description="execute shell command")]))
    assert "ART-14" in tags
    assert "ART-14" not in tag_blast_radius(_br())


def test_read_tools_and_creds_are_not_data_governance():
    tags = tag_blast_radius(_br(creds=["DB_TOKEN"], tools=[MCPTool(name="read_file", description="read a file from disk")]))
    assert "ART-10" not in tags


def test_art17_quality_management_needs_fix():
    tags = tag_blast_radius(_br(fixed_version="2.0.0"))
    assert "ART-17" in tags
    tags_no_fix = tag_blast_radius(_br())
    assert "ART-17" not in tags_no_fix


def test_label_functions():
    assert eu_ai_act_label("ART-15") == "ART-15 Accuracy, Robustness and Cybersecurity"
    labels = eu_ai_act_labels(["ART-9", "ART-15"])
    assert len(labels) == 2


def test_minimal_finding_gets_base_tags_only():
    tags = tag_blast_radius(_br(severity=Severity.LOW, pkg_name="requests"))
    assert tags == ["ART-15", "ART-9"]
