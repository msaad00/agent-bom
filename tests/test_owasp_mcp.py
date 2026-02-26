"""Tests for OWASP MCP Top 10 tagging module."""

from agent_bom.models import (
    Agent,
    AgentType,
    BlastRadius,
    MCPServer,
    MCPTool,
    Package,
    PermissionProfile,
    Severity,
    TransportType,
    Vulnerability,
)
from agent_bom.owasp_mcp import (
    OWASP_MCP_TOP10,
    owasp_mcp_label,
    owasp_mcp_labels,
    tag_blast_radius,
)


def _make_br(
    severity=Severity.HIGH,
    creds=None,
    tools=None,
    registry_verified=True,
    transport=TransportType.STDIO,
    permission_profile=None,
):
    """Helper to build a BlastRadius with configurable fields."""
    vuln = Vulnerability(id="GHSA-test-1234", summary="Test vulnerability", severity=severity)
    pkg = Package(name="test-pkg", version="1.0.0", ecosystem="npm")
    server = MCPServer(
        name="test-server",
        command="npx test-server",
        registry_verified=registry_verified,
        transport=transport,
        permission_profile=permission_profile,
    )
    agent = Agent(name="test-agent", agent_type=AgentType.CLAUDE_DESKTOP, config_path="/tmp/test", mcp_servers=[server])
    return BlastRadius(
        vulnerability=vuln,
        package=pkg,
        affected_servers=[server],
        affected_agents=[agent],
        exposed_credentials=creds or [],
        exposed_tools=tools or [],
    )


# ─── Catalog ─────────────────────────────────────────────────────────────────


def test_catalog_has_10_entries():
    assert len(OWASP_MCP_TOP10) == 10


def test_catalog_codes_are_mcp01_through_mcp10():
    expected = {f"MCP{i:02d}" for i in range(1, 11)}
    assert set(OWASP_MCP_TOP10.keys()) == expected


# ─── MCP04 always tagged ─────────────────────────────────────────────────────


def test_mcp04_always_present():
    """Any CVE in an MCP server dependency is MCP04 (supply chain)."""
    br = _make_br(severity=Severity.LOW)
    tags = tag_blast_radius(br)
    assert "MCP04" in tags


# ─── MCP01: Token Mismanagement ──────────────────────────────────────────────


def test_mcp01_triggered_by_credentials():
    br = _make_br(creds=["AWS_SECRET_KEY", "GITHUB_TOKEN"])
    tags = tag_blast_radius(br)
    assert "MCP01" in tags


def test_mcp01_not_triggered_without_credentials():
    br = _make_br(creds=[])
    tags = tag_blast_radius(br)
    assert "MCP01" not in tags


# ─── MCP02: Privilege Escalation ─────────────────────────────────────────────


def test_mcp02_triggered_by_elevated_permissions():
    pp = PermissionProfile(runs_as_root=True)
    br = _make_br(severity=Severity.CRITICAL, permission_profile=pp)
    tags = tag_blast_radius(br)
    assert "MCP02" in tags


def test_mcp02_triggered_by_many_tools():
    tools = [MCPTool(name=f"tool_{i}", description=f"Tool {i}") for i in range(6)]
    br = _make_br(severity=Severity.HIGH, tools=tools)
    tags = tag_blast_radius(br)
    assert "MCP02" in tags


def test_mcp02_not_triggered_low_severity():
    pp = PermissionProfile(runs_as_root=True)
    br = _make_br(severity=Severity.LOW, permission_profile=pp)
    tags = tag_blast_radius(br)
    assert "MCP02" not in tags


# ─── MCP03: Tool Poisoning ──────────────────────────────────────────────────


def test_mcp03_triggered_unverified_high_severity():
    br = _make_br(severity=Severity.HIGH, registry_verified=False)
    tags = tag_blast_radius(br)
    assert "MCP03" in tags


def test_mcp03_not_triggered_verified_server():
    br = _make_br(severity=Severity.CRITICAL, registry_verified=True)
    tags = tag_blast_radius(br)
    assert "MCP03" not in tags


# ─── MCP05: Command Injection ────────────────────────────────────────────────


def test_mcp05_triggered_by_execute_tool():
    tools = [MCPTool(name="run_shell", description="Execute a shell command")]
    br = _make_br(tools=tools)
    tags = tag_blast_radius(br)
    assert "MCP05" in tags


def test_mcp05_not_triggered_by_read_only_tool():
    tools = [MCPTool(name="list_files", description="List files in a directory")]
    br = _make_br(tools=tools)
    tags = tag_blast_radius(br)
    assert "MCP05" not in tags


# ─── MCP07: Insufficient Auth ────────────────────────────────────────────────


def test_mcp07_triggered_unverified_stdio():
    br = _make_br(registry_verified=False, transport=TransportType.STDIO)
    tags = tag_blast_radius(br)
    assert "MCP07" in tags


def test_mcp07_not_triggered_verified_server():
    br = _make_br(registry_verified=True, transport=TransportType.STDIO)
    tags = tag_blast_radius(br)
    assert "MCP07" not in tags


# ─── MCP09: Shadow MCP Servers ───────────────────────────────────────────────


def test_mcp09_triggered_unverified():
    br = _make_br(registry_verified=False)
    tags = tag_blast_radius(br)
    assert "MCP09" in tags


def test_mcp09_not_triggered_verified():
    br = _make_br(registry_verified=True)
    tags = tag_blast_radius(br)
    assert "MCP09" not in tags


# ─── MCP10: Context Injection ────────────────────────────────────────────────


def test_mcp10_triggered_read_tool_with_creds():
    tools = [MCPTool(name="read_file", description="Read contents of a file")]
    br = _make_br(creds=["DB_PASSWORD"], tools=tools)
    tags = tag_blast_radius(br)
    assert "MCP10" in tags


def test_mcp10_not_triggered_read_tool_without_creds():
    tools = [MCPTool(name="read_file", description="Read contents of a file")]
    br = _make_br(creds=[], tools=tools)
    tags = tag_blast_radius(br)
    assert "MCP10" not in tags


# ─── Sorting ─────────────────────────────────────────────────────────────────


def test_tags_are_sorted():
    tools = [MCPTool(name="run_shell", description="Execute command")]
    br = _make_br(
        severity=Severity.CRITICAL,
        creds=["TOKEN"],
        tools=tools,
        registry_verified=False,
    )
    tags = tag_blast_radius(br)
    assert tags == sorted(tags)


# ─── Label helpers ───────────────────────────────────────────────────────────


def test_owasp_mcp_label():
    assert owasp_mcp_label("MCP04") == "MCP04 Software Supply Chain Attacks"


def test_owasp_mcp_label_unknown():
    assert owasp_mcp_label("MCP99") == "MCP99 Unknown"


def test_owasp_mcp_labels():
    labels = owasp_mcp_labels(["MCP01", "MCP04"])
    assert len(labels) == 2
    assert "MCP01 Token Mismanagement & Secret Exposure" in labels
    assert "MCP04 Software Supply Chain Attacks" in labels


# ─── Combined scenario ──────────────────────────────────────────────────────


def test_full_attack_surface():
    """Unverified server with root, execute tools, creds, and CRITICAL CVE triggers many tags."""
    pp = PermissionProfile(runs_as_root=True, shell_access=True)
    tools = [
        MCPTool(name="run_command", description="Execute a bash command"),
        MCPTool(name="read_file", description="Read a file from disk"),
    ] + [MCPTool(name=f"tool_{i}", description=f"Tool {i}") for i in range(5)]
    br = _make_br(
        severity=Severity.CRITICAL,
        creds=["AWS_SECRET_KEY", "DB_PASSWORD"],
        tools=tools,
        registry_verified=False,
        permission_profile=pp,
    )
    tags = tag_blast_radius(br)
    # Should trigger: MCP01, MCP02, MCP03, MCP04, MCP05, MCP07, MCP09, MCP10
    assert "MCP01" in tags  # credentials exposed
    assert "MCP02" in tags  # elevated + CRITICAL
    assert "MCP03" in tags  # unverified + CRITICAL
    assert "MCP04" in tags  # always
    assert "MCP05" in tags  # execute tool
    assert "MCP07" in tags  # unverified + stdio
    assert "MCP09" in tags  # unverified
    assert "MCP10" in tags  # read tool + creds
