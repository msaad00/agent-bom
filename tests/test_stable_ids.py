"""Tests for deterministic UUID v5 stable IDs on assets and findings (issue: stable IDs)."""

from agent_bom.finding import Asset, Finding, FindingSource, FindingType, stable_id
from agent_bom.models import Agent, AgentType, MCPPrompt, MCPResource, MCPServer, MCPTool, Package, TransportType

# ---------------------------------------------------------------------------
# Finding determinism
# ---------------------------------------------------------------------------


def test_finding_id_is_deterministic():
    """Same asset + same CVE → same Finding.id on two different instantiations."""
    asset = Asset(
        name="requests",
        asset_type="package",
        identifier="pkg:pypi/requests@2.0.0",
    )
    f1 = Finding(
        finding_type=FindingType.CVE,
        source=FindingSource.MCP_SCAN,
        asset=asset,
        severity="HIGH",
        cve_id="CVE-2024-1234",
    )
    f2 = Finding(
        finding_type=FindingType.CVE,
        source=FindingSource.MCP_SCAN,
        asset=Asset(
            name="requests",
            asset_type="package",
            identifier="pkg:pypi/requests@2.0.0",
        ),
        severity="HIGH",
        cve_id="CVE-2024-1234",
    )
    assert f1.id == f2.id
    assert len(f1.id) == 36  # valid UUID format


def test_finding_id_differs_for_different_cve():
    """Same asset, different CVE → different Finding.id."""
    asset = Asset(
        name="torch",
        asset_type="package",
        identifier="pkg:pypi/torch@2.3.0",
    )
    f1 = Finding(
        finding_type=FindingType.CVE,
        source=FindingSource.MCP_SCAN,
        asset=asset,
        severity="HIGH",
        cve_id="CVE-2024-0001",
    )
    f2 = Finding(
        finding_type=FindingType.CVE,
        source=FindingSource.MCP_SCAN,
        asset=Asset(
            name="torch",
            asset_type="package",
            identifier="pkg:pypi/torch@2.3.0",
        ),
        severity="HIGH",
        cve_id="CVE-2024-0002",
    )
    assert f1.id != f2.id


def test_finding_id_differs_for_different_asset():
    """Same CVE, different asset → different Finding.id."""
    f1 = Finding(
        finding_type=FindingType.CVE,
        source=FindingSource.MCP_SCAN,
        asset=Asset(name="requests", asset_type="package", identifier="pkg:pypi/requests@2.0.0"),
        severity="HIGH",
        cve_id="CVE-2024-9999",
    )
    f2 = Finding(
        finding_type=FindingType.CVE,
        source=FindingSource.MCP_SCAN,
        asset=Asset(name="flask", asset_type="package", identifier="pkg:pypi/flask@3.0.0"),
        severity="HIGH",
        cve_id="CVE-2024-9999",
    )
    assert f1.id != f2.id


# ---------------------------------------------------------------------------
# Asset stable_id
# ---------------------------------------------------------------------------


def test_asset_stable_id_is_deterministic():
    """Same asset_type + identifier → same stable_id."""
    a1 = Asset(name="requests", asset_type="package", identifier="pkg:pypi/requests@2.0.0")
    a2 = Asset(name="requests", asset_type="package", identifier="pkg:pypi/requests@2.0.0")
    assert a1.stable_id == a2.stable_id
    assert a1.canonical_id == a1.stable_id
    assert len(a1.stable_id) == 36


def test_asset_stable_id_differs_by_type():
    """'package' vs 'mcp_server' with same name → different stable_ids."""
    a1 = Asset(name="my-tool", asset_type="package", identifier="pkg:pypi/my-tool@1.0.0")
    a2 = Asset(name="my-tool", asset_type="mcp_server", identifier="pkg:pypi/my-tool@1.0.0")
    assert a1.stable_id != a2.stable_id


# ---------------------------------------------------------------------------
# Package stable_id
# ---------------------------------------------------------------------------


def test_package_stable_id_deterministic():
    """Same ecosystem/name/version → same stable_id."""
    p1 = Package(name="numpy", version="1.26.0", ecosystem="pypi")
    p2 = Package(name="numpy", version="1.26.0", ecosystem="pypi")
    assert p1.stable_id == p2.stable_id
    assert len(p1.stable_id) == 36


def test_package_stable_id_uses_purl_when_available():
    """purl takes precedence over ecosystem/name/version for the stable_id."""
    explicit_purl = "pkg:pypi/numpy@1.26.0"
    p_with_purl = Package(name="numpy", version="1.26.0", ecosystem="pypi", purl=explicit_purl)
    p_without_purl = Package(name="numpy", version="1.26.0", ecosystem="pypi")
    # Both should resolve to the same ID since purl == synthesized purl
    assert p_with_purl.stable_id == p_without_purl.stable_id

    # But an explicitly different purl should produce a different ID
    p_different_purl = Package(name="numpy", version="1.26.0", ecosystem="pypi", purl="pkg:conda/numpy@1.26.0")
    assert p_different_purl.stable_id != p_without_purl.stable_id


def test_package_stable_id_uses_canonical_package_identity():
    """PyPI separator/case variants must not split scan history identity."""
    p_hyphen = Package(name="torch-audio", version="1.0.0", ecosystem="pypi")
    p_under = Package(name="torch_audio", version="1.0.0", ecosystem="pypi")
    p_dot = Package(name="Torch.Audio", version="1.0.0", ecosystem="PyPI", purl="pkg:pypi/Torch.Audio@1.0.0")

    assert p_hyphen.stable_id == p_under.stable_id == p_dot.stable_id
    assert p_hyphen.canonical_id == p_hyphen.stable_id


def test_tool_canonical_id_ignores_schema_key_order():
    """Non-semantic JSON schema key order must not split tool identity."""
    t1 = MCPTool(name="search", description="Search", input_schema={"b": 2, "a": {"z": True, "m": False}})
    t2 = MCPTool(name="search", description="Search docs", input_schema={"a": {"m": False, "z": True}, "b": 2})

    assert t1.stable_id == t2.stable_id
    assert t1.canonical_id == t1.stable_id


# ---------------------------------------------------------------------------
# MCPServer stable_id
# ---------------------------------------------------------------------------


def test_mcpserver_stable_id_deterministic():
    """Same name+command → same stable_id for MCPServer."""
    s1 = MCPServer(name="filesystem", command="npx @modelcontextprotocol/server-filesystem", transport=TransportType.STDIO)
    s2 = MCPServer(name="filesystem", command="npx @modelcontextprotocol/server-filesystem", transport=TransportType.STDIO)
    assert s1.stable_id == s2.stable_id
    assert len(s1.stable_id) == 36


def test_mcpserver_stable_id_uses_registry_id_when_available():
    """registry_id takes precedence over name+command."""
    s_with_registry = MCPServer(
        name="filesystem",
        command="npx @modelcontextprotocol/server-filesystem",
        transport=TransportType.STDIO,
        registry_id="modelcontextprotocol/filesystem",
    )
    s_without_registry = MCPServer(
        name="filesystem",
        command="npx @modelcontextprotocol/server-filesystem",
        transport=TransportType.STDIO,
    )
    # registry_id is different from name:command fallback → different IDs
    assert s_with_registry.stable_id != s_without_registry.stable_id


def test_mcpserver_canonical_id_survives_registry_rename():
    """Registry IDs are authoritative so display-name changes do not split history."""
    s1 = MCPServer(name="filesystem", command="npx @modelcontextprotocol/server-filesystem", registry_id="modelcontextprotocol/filesystem")
    s2 = MCPServer(name="File System", command="uvx filesystem-server", registry_id="modelcontextprotocol/filesystem")

    assert s1.stable_id == s2.stable_id
    assert s1.canonical_id == s1.stable_id


def test_mcpserver_remote_servers_distinct_by_url():
    """Two remote SSE servers with empty command must stay distinct via their urls.

    The dedup identity keys remote servers by url; the served canonical id must be
    at least as fine-grained or distinct remote servers collapse onto one id.
    """
    s1 = MCPServer(name="docs", transport=TransportType.SSE, url="https://a.example.com/sse")
    s2 = MCPServer(name="docs", transport=TransportType.SSE, url="https://b.example.com/sse")
    assert s1.command == "" and s2.command == ""
    assert s1.stable_id != s2.stable_id


def test_mcpserver_stdio_distinct_by_args():
    """Same command but different args (e.g. different mounted path) → distinct id."""
    s1 = MCPServer(name="fs", command="npx", args=["@modelcontextprotocol/server-filesystem", "/workspace/a"])
    s2 = MCPServer(name="fs", command="npx", args=["@modelcontextprotocol/server-filesystem", "/workspace/b"])
    assert s1.stable_id != s2.stable_id


# ---------------------------------------------------------------------------
# Child id scoping (tool / resource / prompt) under the owning server
# ---------------------------------------------------------------------------


def test_tool_id_scoped_to_owning_server():
    """The same tool name on two different servers yields distinct ids."""
    s1 = MCPServer(name="alpha", command="npx alpha", tools=[MCPTool(name="search", description="x")])
    s2 = MCPServer(name="beta", command="npx beta", tools=[MCPTool(name="search", description="x")])
    assert s1.tools[0].stable_id != s2.tools[0].stable_id
    # Same server identity + tool → stable across instances.
    s1b = MCPServer(name="alpha", command="npx alpha", tools=[MCPTool(name="search", description="x")])
    assert s1.tools[0].stable_id == s1b.tools[0].stable_id


def test_resource_and_prompt_ids_scoped_to_owning_server():
    """Same resource uri / prompt name on two servers stays distinct."""
    s1 = MCPServer(
        name="alpha",
        command="npx alpha",
        resources=[MCPResource(uri="mem://notes", name="notes")],
        prompts=[MCPPrompt(name="summarize")],
    )
    s2 = MCPServer(
        name="beta",
        command="npx beta",
        resources=[MCPResource(uri="mem://notes", name="notes")],
        prompts=[MCPPrompt(name="summarize")],
    )
    assert s1.resources[0].stable_id != s2.resources[0].stable_id
    assert s1.prompts[0].stable_id != s2.prompts[0].stable_id


# ---------------------------------------------------------------------------
# Agent stable_id
# ---------------------------------------------------------------------------


def test_agent_stable_id_deterministic():
    """Same agent_type+name+install location → same stable_id."""
    a1 = Agent(name="Claude Desktop", agent_type=AgentType.CLAUDE_DESKTOP, config_path="/path/a")
    a2 = Agent(name="Claude Desktop", agent_type=AgentType.CLAUDE_DESKTOP, config_path="/path/a")
    assert a1.stable_id == a2.stable_id
    assert a1.canonical_id == a1.stable_id
    assert len(a1.stable_id) == 36


def test_agent_stable_id_distinct_by_install_location():
    """Same agent_type+name but different install (config_path) → distinct stable_id.

    Two distinct installs (e.g. global vs per-project Claude config) must not mint
    the same UUID, or the manifest emits duplicate rows and the graph collapses one.
    """
    a1 = Agent(name="Claude Desktop", agent_type=AgentType.CLAUDE_DESKTOP, config_path="/path/a")
    a2 = Agent(name="Claude Desktop", agent_type=AgentType.CLAUDE_DESKTOP, config_path="/path/b")
    assert a1.stable_id != a2.stable_id


def test_agent_stable_id_prefers_explicit_source():
    """An explicit inventory source wins over config_path as the discriminator."""
    a1 = Agent(name="Bot", agent_type=AgentType.CUSTOM, config_path="/path/a", source="snowflake")
    a2 = Agent(name="Bot", agent_type=AgentType.CUSTOM, config_path="/path/b", source="snowflake")
    assert a1.stable_id == a2.stable_id


# ---------------------------------------------------------------------------
# Public stable_id function
# ---------------------------------------------------------------------------


def test_stable_id_function_exported():
    """from agent_bom.finding import stable_id must be callable."""
    assert callable(stable_id)
    result = stable_id("asset_type", "my-identifier")
    assert len(result) == 36
    # Deterministic
    assert result == stable_id("asset_type", "my-identifier")
