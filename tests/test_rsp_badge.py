"""Tests for Anthropic RSP alignment badge."""

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
from agent_bom.output import to_rsp_badge


def test_rsp_aligned_no_vulns():
    report = AIBOMReport(
        agents=[Agent(name="claude", agent_type=AgentType.CLAUDE_CODE, config_path="/tmp")],
    )
    badge = to_rsp_badge(report)
    assert badge["message"] == "RSP v3.0 aligned"
    assert badge["color"] == "brightgreen"


def test_rsp_review_needed_with_vulns():
    vuln = Vulnerability(id="CVE-2025-1", summary="x", severity=Severity.HIGH)
    pkg = Package(name="openai", version="1.0", ecosystem="pypi")
    br = BlastRadius(
        vulnerability=vuln,
        package=pkg,
        affected_servers=[MCPServer(name="s")],
        affected_agents=[Agent(name="claude", agent_type=AgentType.CLAUDE_CODE, config_path="/tmp")],
        exposed_credentials=[],
        exposed_tools=[],
    )
    report = AIBOMReport(
        agents=[Agent(name="claude", agent_type=AgentType.CLAUDE_CODE, config_path="/tmp")],
        blast_radii=[br],
    )
    badge = to_rsp_badge(report)
    assert badge["message"] == "RSP review needed"
    assert badge["color"] == "orange"


def test_rsp_not_applicable():
    report = AIBOMReport(
        agents=[Agent(name="cursor", agent_type=AgentType.CURSOR, config_path="/tmp")],
    )
    badge = to_rsp_badge(report)
    assert badge["message"] == "RSP n/a"
    assert badge["color"] == "lightgrey"
