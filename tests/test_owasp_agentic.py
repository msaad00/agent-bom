"""Tests for OWASP Agentic Top 10 tagging."""

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
from agent_bom.owasp_agentic import (
    OWASP_AGENTIC_TOP10,
    owasp_agentic_label,
    owasp_agentic_labels,
    tag_blast_radius,
)


def _br(
    *,
    severity=Severity.HIGH,
    pkg_name="flask",
    tools=None,
    creds=None,
    agents=None,
    servers=None,
) -> BlastRadius:
    vuln = Vulnerability(id="CVE-2025-1234", summary="test", severity=severity)
    pkg = Package(name=pkg_name, version="1.0.0", ecosystem="pypi")
    return BlastRadius(
        vulnerability=vuln,
        package=pkg,
        affected_servers=servers or [MCPServer(name="srv")],
        affected_agents=agents or [Agent(name="a1", agent_type=AgentType.CLAUDE_DESKTOP, config_path="/tmp")],
        exposed_credentials=creds or [],
        exposed_tools=tools or [],
    )


def test_always_applied_tags():
    tags = tag_blast_radius(_br())
    assert "ASI01" in tags  # autonomy
    assert "ASI04" in tags  # supply chain
    assert "ASI09" in tags  # trust exploitation


def test_catalog_has_ten_entries():
    assert len(OWASP_AGENTIC_TOP10) == 10


def test_asi02_tool_misuse_needs_tools_and_high():
    tags = tag_blast_radius(_br(tools=[MCPTool(name="run_cmd", description="execute shell")]))
    assert "ASI02" in tags
    # low severity should not trigger ASI02
    tags_low = tag_blast_radius(_br(tools=[MCPTool(name="run_cmd", description="execute shell")], severity=Severity.LOW))
    assert "ASI02" not in tags_low


def test_asi03_identity_abuse_needs_creds():
    tags = tag_blast_radius(_br(creds=["API_KEY"]))
    assert "ASI03" in tags
    tags_no_creds = tag_blast_radius(_br())
    assert "ASI03" not in tags_no_creds


def test_asi05_execute_tools():
    tags = tag_blast_radius(_br(tools=[MCPTool(name="run_code", description="execute python code")]))
    assert "ASI05" in tags


def test_asi06_memory_poisoning_needs_read_and_ai():
    tags = tag_blast_radius(_br(pkg_name="langchain", tools=[MCPTool(name="read_file", description="read a file from disk")]))
    assert "ASI06" in tags
    # non-AI package should not trigger
    tags_normal = tag_blast_radius(_br(pkg_name="flask", tools=[MCPTool(name="read_file", description="read a file")]))
    assert "ASI06" not in tags_normal


def test_asi07_multi_agent():
    agents = [
        Agent(name="a1", agent_type=AgentType.CLAUDE_DESKTOP, config_path="/tmp"),
        Agent(name="a2", agent_type=AgentType.CURSOR, config_path="/tmp"),
    ]
    tags = tag_blast_radius(_br(agents=agents))
    assert "ASI07" in tags
    # single agent should not trigger
    tags_single = tag_blast_radius(_br())
    assert "ASI07" not in tags_single


def test_asi08_cascading_failures():
    tools = [MCPTool(name=f"tool_{i}", description="do something") for i in range(5)]
    tags = tag_blast_radius(_br(pkg_name="openai", tools=tools))
    assert "ASI08" in tags


def test_asi10_rogue_agent():
    tags = tag_blast_radius(_br(creds=["SECRET"], tools=[MCPTool(name="exec", description="execute shell command")]))
    assert "ASI10" in tags


def test_label_functions():
    assert owasp_agentic_label("ASI04") == "ASI04 Agentic Supply Chain Vulnerabilities"
    labels = owasp_agentic_labels(["ASI01", "ASI04"])
    assert len(labels) == 2
    assert "ASI01" in labels[0]
