"""Tests for deterministic UUID v5 stable IDs on assets and findings (issue: stable IDs)."""

from agent_bom.finding import Asset, Finding, FindingSource, FindingType, stable_id
from agent_bom.models import Agent, AgentType, MCPServer, Package, TransportType

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


# ---------------------------------------------------------------------------
# Agent stable_id
# ---------------------------------------------------------------------------


def test_agent_stable_id_deterministic():
    """Same agent_type+name → same stable_id."""
    a1 = Agent(name="Claude Desktop", agent_type=AgentType.CLAUDE_DESKTOP, config_path="/path/a")
    a2 = Agent(name="Claude Desktop", agent_type=AgentType.CLAUDE_DESKTOP, config_path="/path/b")
    assert a1.stable_id == a2.stable_id
    assert len(a1.stable_id) == 36


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
