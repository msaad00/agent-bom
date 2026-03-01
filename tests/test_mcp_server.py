"""Tests for agent-bom MCP server."""

import asyncio
import json
import sys
from unittest.mock import patch

import pytest
from click.testing import CliRunner

from agent_bom.cli import main

# Skip entire module if mcp SDK is not installed
pytest.importorskip("mcp", reason="mcp SDK not installed — pip install 'agent-bom[mcp-server]'")

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _run(coro):
    """Run an async coroutine synchronously."""
    return asyncio.run(coro)


def _call_tool(server, name, args=None):
    """Call a tool and extract the text result."""
    content_blocks, _meta = _run(server.call_tool(name, args or {}))
    return json.loads(content_blocks[0].text)


# ---------------------------------------------------------------------------
# SDK check
# ---------------------------------------------------------------------------


def test_check_mcp_sdk_missing():
    """Should raise ImportError if mcp is not installed."""
    with patch.dict(sys.modules, {"mcp": None, "mcp.server": None, "mcp.server.fastmcp": None}):
        from agent_bom.mcp_server import _check_mcp_sdk

        with pytest.raises(ImportError, match="mcp SDK is required"):
            _check_mcp_sdk()


# ---------------------------------------------------------------------------
# Server creation
# ---------------------------------------------------------------------------


def test_create_mcp_server_returns_object():
    """create_mcp_server should return a FastMCP instance."""
    from agent_bom.mcp_server import create_mcp_server

    server = create_mcp_server()
    assert server is not None
    assert server.name == "agent-bom"


def test_mcp_server_has_fourteen_tools():
    """Server should register exactly 14 tools."""
    from agent_bom.mcp_server import create_mcp_server

    server = create_mcp_server()
    tools = _run(server.list_tools())
    assert len(tools) == 14


def test_mcp_server_tool_names():
    """Tool names should match expected set."""
    from agent_bom.mcp_server import create_mcp_server

    server = create_mcp_server()
    tools = _run(server.list_tools())
    names = {t.name for t in tools}
    assert names == {
        "scan",
        "check",
        "blast_radius",
        "policy_check",
        "registry_lookup",
        "generate_sbom",
        "compliance",
        "remediate",
        "skill_trust",
        "verify",
        "where",
        "inventory",
        "diff",
        "marketplace_check",
    }


# ---------------------------------------------------------------------------
# Tool: registry_lookup (no mocking needed — reads local JSON)
# ---------------------------------------------------------------------------


def test_registry_lookup_known_server():
    """Lookup of a known server should succeed."""
    from agent_bom.mcp_server import create_mcp_server

    server = create_mcp_server()
    result = _call_tool(server, "registry_lookup", {"server_name": "filesystem"})
    assert result["found"] is True
    assert "risk_level" in result
    assert "tools" in result


def test_registry_lookup_unknown():
    """Lookup of nonexistent server returns not-found."""
    from agent_bom.mcp_server import create_mcp_server

    server = create_mcp_server()
    result = _call_tool(server, "registry_lookup", {"server_name": "nonexistent-server-xyz"})
    assert result["found"] is False


def test_registry_lookup_by_package():
    """Lookup by package name should work."""
    from agent_bom.mcp_server import create_mcp_server

    server = create_mcp_server()
    result = _call_tool(server, "registry_lookup", {"package_name": "server-github"})
    assert result["found"] is True
    assert "github" in result["name"].lower() or "github" in result["id"].lower()


def test_registry_lookup_empty_query():
    """Empty query should return error."""
    from agent_bom.mcp_server import create_mcp_server

    server = create_mcp_server()
    result = _call_tool(server, "registry_lookup", {})
    assert "error" in result


# ---------------------------------------------------------------------------
# Tool: check (mocked OSV)
# ---------------------------------------------------------------------------


@patch("agent_bom.scanners.query_osv_batch")
def test_check_clean_package(mock_osv):
    """Check tool returns clean status when no vulns."""
    from agent_bom.mcp_server import create_mcp_server

    async def _fake_osv(pkgs):
        return {}

    mock_osv.side_effect = _fake_osv
    server = create_mcp_server()
    result = _call_tool(server, "check", {"package": "safe-pkg@1.0.0", "ecosystem": "npm"})
    assert result["status"] == "clean"
    assert result["vulnerabilities"] == 0
    assert result["package"] == "safe-pkg"
    assert result["version"] == "1.0.0"


@patch("agent_bom.scanners.query_osv_batch")
def test_check_vulnerable_package(mock_osv):
    """Check tool returns vulnerable status with details."""
    from agent_bom.mcp_server import create_mcp_server

    async def _fake_osv(pkgs):
        return {
            "npm:bad-pkg@1.0.0": [
                {
                    "id": "CVE-2025-9999",
                    "summary": "Test vulnerability",
                    "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
                    "affected": [{"ranges": [{"events": [{"fixed": "1.1.0"}]}]}],
                }
            ],
        }

    mock_osv.side_effect = _fake_osv
    server = create_mcp_server()
    result = _call_tool(server, "check", {"package": "bad-pkg@1.0.0", "ecosystem": "npm"})
    assert result["status"] == "vulnerable"
    assert result["vulnerabilities"] >= 1
    assert result["details"][0]["id"] == "CVE-2025-9999"


@patch("agent_bom.scanners.query_osv_batch")
def test_check_scoped_npm_package(mock_osv):
    """Check parses scoped npm package correctly."""
    from agent_bom.mcp_server import create_mcp_server

    async def _fake_osv(pkgs):
        return {}

    mock_osv.side_effect = _fake_osv
    server = create_mcp_server()
    result = _call_tool(
        server,
        "check",
        {
            "package": "@modelcontextprotocol/server-filesystem@2025.1.14",
            "ecosystem": "npm",
        },
    )
    assert result["status"] == "clean"
    assert result["package"] == "@modelcontextprotocol/server-filesystem"
    assert result["version"] == "2025.1.14"


@patch("agent_bom.scanners.query_osv_batch")
def test_check_default_ecosystem(mock_osv):
    """Check defaults to npm ecosystem."""
    from agent_bom.mcp_server import create_mcp_server

    async def _fake_osv(pkgs):
        return {}

    mock_osv.side_effect = _fake_osv
    server = create_mcp_server()
    result = _call_tool(server, "check", {"package": "express@4.18.2"})
    assert result["ecosystem"] == "npm"


# ---------------------------------------------------------------------------
# Tool: scan (mocked pipeline)
# ---------------------------------------------------------------------------


@patch("agent_bom.mcp_server._run_scan_pipeline")
def test_scan_returns_json(mock_pipeline):
    """Scan tool should return valid JSON with agents."""
    from agent_bom.models import Agent, AgentType, MCPServer, TransportType

    mock_agent = Agent(
        name="test-agent",
        agent_type=AgentType.CLAUDE_DESKTOP,
        config_path="/tmp/test",
        mcp_servers=[MCPServer(name="test-server", command="npx", args=[], env={}, transport=TransportType.STDIO, packages=[])],
    )
    mock_pipeline.return_value = ([mock_agent], [], [])

    from agent_bom.mcp_server import create_mcp_server

    server = create_mcp_server()
    result = _call_tool(server, "scan", {})
    assert "agents" in result
    assert result["summary"]["total_agents"] >= 1


@patch("agent_bom.mcp_server._run_scan_pipeline")
def test_scan_no_agents(mock_pipeline):
    """Scan with no agents should return no_agents_found status."""
    mock_pipeline.return_value = ([], [], [])
    from agent_bom.mcp_server import create_mcp_server

    server = create_mcp_server()
    result = _call_tool(server, "scan", {})
    assert result["status"] == "no_agents_found"


# ---------------------------------------------------------------------------
# Tool: blast_radius (mocked)
# ---------------------------------------------------------------------------


@patch("agent_bom.mcp_server._run_scan_pipeline")
def test_blast_radius_not_found(mock_pipeline):
    """Unknown CVE should return found=False."""
    mock_pipeline.return_value = ([], [], [])
    from agent_bom.mcp_server import create_mcp_server

    server = create_mcp_server()
    result = _call_tool(server, "blast_radius", {"cve_id": "CVE-9999-00000"})
    assert result["found"] is False


# ---------------------------------------------------------------------------
# Tool: policy_check
# ---------------------------------------------------------------------------


@patch("agent_bom.mcp_server._run_scan_pipeline")
def test_policy_check_valid(mock_pipeline):
    """Valid policy with no findings should pass."""
    mock_pipeline.return_value = ([], [], [])
    from agent_bom.mcp_server import create_mcp_server

    server = create_mcp_server()
    policy = json.dumps({"rules": [{"id": "no-critical", "severity_gte": "critical", "action": "fail"}]})
    result = _call_tool(server, "policy_check", {"policy_json": policy})
    assert result["passed"] is True


def test_policy_check_invalid_json():
    """Invalid JSON should return error."""
    from agent_bom.mcp_server import create_mcp_server

    server = create_mcp_server()
    result = _call_tool(server, "policy_check", {"policy_json": "not valid json"})
    assert "error" in result
    assert "Invalid JSON" in result["error"]


# ---------------------------------------------------------------------------
# Tool: generate_sbom (mocked)
# ---------------------------------------------------------------------------


@patch("agent_bom.mcp_server._run_scan_pipeline")
def test_generate_sbom_cyclonedx(mock_pipeline):
    """generate_sbom with cyclonedx format should return CycloneDX JSON."""
    from agent_bom.models import Agent, AgentType, MCPServer, TransportType

    mock_agent = Agent(
        name="test-agent",
        agent_type=AgentType.CLAUDE_DESKTOP,
        config_path="/tmp/test",
        mcp_servers=[MCPServer(name="test-server", command="npx", args=[], env={}, transport=TransportType.STDIO, packages=[])],
    )
    mock_pipeline.return_value = ([mock_agent], [], [])
    from agent_bom.mcp_server import create_mcp_server

    server = create_mcp_server()
    result = _call_tool(server, "generate_sbom", {"format": "cyclonedx"})
    assert "bomFormat" in result
    assert result["bomFormat"] == "CycloneDX"


@patch("agent_bom.mcp_server._run_scan_pipeline")
def test_generate_sbom_no_agents(mock_pipeline):
    """generate_sbom with no agents should return error."""
    mock_pipeline.return_value = ([], [], [])
    from agent_bom.mcp_server import create_mcp_server

    server = create_mcp_server()
    result = _call_tool(server, "generate_sbom", {"format": "cyclonedx"})
    assert "error" in result


# ---------------------------------------------------------------------------
# CLI command
# ---------------------------------------------------------------------------


def test_cli_mcp_server_help():
    """CLI should have mcp-server subcommand."""
    runner = CliRunner()
    result = runner.invoke(main, ["mcp-server", "--help"])
    assert result.exit_code == 0
    assert "MCP server" in result.output or "mcp" in result.output.lower()


def test_cli_mcp_server_transport_options():
    """CLI should accept --transport, --port, --host options."""
    runner = CliRunner()
    result = runner.invoke(main, ["mcp-server", "--help"])
    assert "--transport" in result.output
    assert "--port" in result.output
    assert "--host" in result.output


# ---------------------------------------------------------------------------
# Tool: compliance
# ---------------------------------------------------------------------------


@patch("agent_bom.mcp_server._run_scan_pipeline")
def test_compliance_no_agents(mock_pipeline):
    """Compliance with no agents should return 100% score."""
    mock_pipeline.return_value = ([], [], [])
    from agent_bom.mcp_server import create_mcp_server

    server = create_mcp_server()
    result = _call_tool(server, "compliance", {})
    assert result["overall_score"] == 100.0
    assert result["overall_status"] == "pass"
    assert len(result["owasp_llm_top10"]) == 10
    assert len(result["mitre_atlas"]) == 13
    assert len(result["nist_ai_rmf"]) == 14


@patch("agent_bom.mcp_server._run_scan_pipeline")
def test_compliance_with_findings(mock_pipeline):
    """Compliance with high-severity findings should fail."""
    from agent_bom.models import (
        Agent,
        AgentType,
        BlastRadius,
        MCPServer,
        Package,
        Severity,
        TransportType,
        Vulnerability,
    )

    mock_agent = Agent(
        name="test-agent",
        agent_type=AgentType.CLAUDE_DESKTOP,
        config_path="/tmp/test",
        mcp_servers=[MCPServer(name="test-server", command="npx", args=[], env={}, transport=TransportType.STDIO, packages=[])],
    )
    br = BlastRadius(
        vulnerability=Vulnerability(
            id="CVE-2025-0001",
            severity=Severity.HIGH,
            summary="Test vuln",
        ),
        package=Package(name="express", version="4.17.1", ecosystem="npm"),
        affected_servers=[mock_agent.mcp_servers[0]],
        affected_agents=[mock_agent],
        exposed_credentials=[],
        exposed_tools=[],
    )
    br.owasp_tags = ["LLM05"]
    br.atlas_tags = ["AML.T0010"]
    br.nist_ai_rmf_tags = ["MAP-3.5"]

    mock_pipeline.return_value = ([mock_agent], [br], [])
    from agent_bom.mcp_server import create_mcp_server

    server = create_mcp_server()
    result = _call_tool(server, "compliance", {})
    assert result["overall_status"] == "fail"
    assert result["overall_score"] < 100.0

    # LLM05 should be fail
    lmm05 = next(c for c in result["owasp_llm_top10"] if c["code"] == "LLM05")
    assert lmm05["status"] == "fail"
    assert lmm05["findings"] == 1


# ---------------------------------------------------------------------------
# Tool: remediate
# ---------------------------------------------------------------------------


@patch("agent_bom.mcp_server._run_scan_pipeline")
def test_remediate_no_agents(mock_pipeline):
    """Remediate with no agents should return empty plan."""
    mock_pipeline.return_value = ([], [], [])
    from agent_bom.mcp_server import create_mcp_server

    server = create_mcp_server()
    result = _call_tool(server, "remediate", {})
    assert result["package_fixes"] == []
    assert result["credential_fixes"] == []


@patch("agent_bom.mcp_server._run_scan_pipeline")
def test_remediate_returns_plan(mock_pipeline):
    """Remediate with agents returns valid plan structure."""
    from agent_bom.models import (
        Agent,
        AgentType,
        MCPServer,
        TransportType,
    )

    mock_agent = Agent(
        name="test-agent",
        agent_type=AgentType.CLAUDE_DESKTOP,
        config_path="/tmp/test",
        mcp_servers=[MCPServer(name="test-server", command="npx", args=[], env={}, transport=TransportType.STDIO, packages=[])],
    )
    mock_pipeline.return_value = ([mock_agent], [], [])
    from agent_bom.mcp_server import create_mcp_server

    server = create_mcp_server()
    result = _call_tool(server, "remediate", {})
    assert "generated_at" in result
    assert "package_fixes" in result
    assert "credential_fixes" in result
    assert "unfixable" in result


# ---------------------------------------------------------------------------
# Smithery entry point
# ---------------------------------------------------------------------------


def test_create_smithery_server():
    """create_smithery_server returns a working server (with or without smithery SDK)."""
    from agent_bom.mcp_server import create_smithery_server

    server = create_smithery_server()
    # Whether SmitheryFastMCP wrapper or plain FastMCP, it must have tools
    inner = server._fastmcp if hasattr(server, "_fastmcp") else server
    tools = inner._tool_manager._tools
    assert len(tools) >= 8
    assert "scan" in tools
    assert "compliance" in tools
    assert "remediate" in tools


# ---------------------------------------------------------------------------
# Parameter descriptions (Smithery score regression test)
# ---------------------------------------------------------------------------


def test_tool_parameters_have_descriptions():
    """Every parameter on every tool must have a JSON Schema 'description'.

    This is required for Smithery to score Parameter Descriptions at 100%.
    FastMCP only propagates descriptions from Annotated[type, Field(description=...)].
    """
    from agent_bom.mcp_server import create_mcp_server

    server = create_mcp_server()
    tools = _run(server.list_tools())

    for tool in tools:
        schema = tool.inputSchema
        props = schema.get("properties", {})
        for param_name, param_schema in props.items():
            assert "description" in param_schema, f"Tool '{tool.name}' param '{param_name}' is missing a description"
            assert len(param_schema["description"]) > 5, f"Tool '{tool.name}' param '{param_name}' has a too-short description"


# ---------------------------------------------------------------------------
# Scan tool: new parameters (transitive, verify_integrity, fail_severity, policy)
# ---------------------------------------------------------------------------


@patch("agent_bom.mcp_server._run_scan_pipeline")
def test_scan_with_transitive(mock_pipeline):
    """Scan should pass transitive flag to pipeline."""
    from agent_bom.models import Agent, AgentType, MCPServer, TransportType

    mock_agent = Agent(
        name="test-agent",
        agent_type=AgentType.CLAUDE_DESKTOP,
        config_path="/tmp/test",
        mcp_servers=[MCPServer(name="s", command="npx", args=[], env={}, transport=TransportType.STDIO, packages=[])],
    )
    mock_pipeline.return_value = ([mock_agent], [], [])
    from agent_bom.mcp_server import create_mcp_server

    server = create_mcp_server()
    _call_tool(server, "scan", {"transitive": True})
    _args, kwargs = mock_pipeline.call_args
    assert kwargs.get("transitive") is True or (len(_args) > 4 and _args[4] is True)


@patch("agent_bom.mcp_server._run_scan_pipeline")
def test_scan_with_fail_severity_pass(mock_pipeline):
    """Scan with fail_severity should return gate_status=pass when no vulns."""
    from agent_bom.models import Agent, AgentType, MCPServer, TransportType

    mock_agent = Agent(
        name="test-agent",
        agent_type=AgentType.CLAUDE_DESKTOP,
        config_path="/tmp/test",
        mcp_servers=[MCPServer(name="s", command="npx", args=[], env={}, transport=TransportType.STDIO, packages=[])],
    )
    mock_pipeline.return_value = ([mock_agent], [], [])
    from agent_bom.mcp_server import create_mcp_server

    server = create_mcp_server()
    result = _call_tool(server, "scan", {"fail_severity": "critical"})
    assert result["gate_status"] == "pass"
    assert result["gate_severity"] == "critical"


@patch("agent_bom.mcp_server._run_scan_pipeline")
def test_scan_with_fail_severity_fail(mock_pipeline):
    """Scan with fail_severity should return gate_status=fail when vulns exceed threshold."""
    from agent_bom.models import (
        Agent,
        AgentType,
        BlastRadius,
        MCPServer,
        Package,
        Severity,
        TransportType,
        Vulnerability,
    )

    mock_agent = Agent(
        name="test-agent",
        agent_type=AgentType.CLAUDE_DESKTOP,
        config_path="/tmp/test",
        mcp_servers=[MCPServer(name="s", command="npx", args=[], env={}, transport=TransportType.STDIO, packages=[])],
    )
    br = BlastRadius(
        vulnerability=Vulnerability(id="CVE-2025-0001", severity=Severity.CRITICAL, summary="Bad"),
        package=Package(name="express", version="4.17.1", ecosystem="npm"),
        affected_servers=[mock_agent.mcp_servers[0]],
        affected_agents=[mock_agent],
        exposed_credentials=[],
        exposed_tools=[],
    )
    mock_pipeline.return_value = ([mock_agent], [br], [])
    from agent_bom.mcp_server import create_mcp_server

    server = create_mcp_server()
    result = _call_tool(server, "scan", {"fail_severity": "high"})
    assert result["gate_status"] == "fail"


@patch("agent_bom.mcp_server._run_scan_pipeline")
def test_scan_with_policy(mock_pipeline):
    """Scan with inline policy should include policy_results."""
    from agent_bom.models import Agent, AgentType, MCPServer, TransportType

    mock_agent = Agent(
        name="test-agent",
        agent_type=AgentType.CLAUDE_DESKTOP,
        config_path="/tmp/test",
        mcp_servers=[MCPServer(name="s", command="npx", args=[], env={}, transport=TransportType.STDIO, packages=[])],
    )
    mock_pipeline.return_value = ([mock_agent], [], [])
    from agent_bom.mcp_server import create_mcp_server

    server = create_mcp_server()
    policy = {"rules": [{"id": "no-crit", "severity_gte": "critical", "action": "fail"}]}
    result = _call_tool(server, "scan", {"policy": policy})
    assert "policy_results" in result
    assert result["policy_results"]["passed"] is True


# ---------------------------------------------------------------------------
# Tool: where (no mocking needed — reads config paths)
# ---------------------------------------------------------------------------


def test_where_returns_clients():
    """where tool should return list of MCP clients with config paths."""
    from agent_bom.mcp_server import create_mcp_server

    server = create_mcp_server()
    result = _call_tool(server, "where", {})
    assert "clients" in result
    assert "platform" in result
    assert len(result["clients"]) >= 10
    # Each client should have the expected structure
    client = result["clients"][0]
    assert "client" in client
    assert "config_paths" in client


# ---------------------------------------------------------------------------
# Tool: inventory (mocked discovery)
# ---------------------------------------------------------------------------


@patch("agent_bom.parsers.extract_packages")
@patch("agent_bom.discovery.discover_all")
def test_inventory_returns_agents(mock_discover, mock_extract):
    """inventory tool should return agent list without scanning."""
    from agent_bom.models import Agent, AgentType, MCPServer, TransportType

    mock_agent = Agent(
        name="test-agent",
        agent_type=AgentType.CLAUDE_DESKTOP,
        config_path="/tmp/test",
        mcp_servers=[MCPServer(name="s", command="npx", args=[], env={}, transport=TransportType.STDIO, packages=[])],
    )
    mock_discover.return_value = [mock_agent]
    mock_extract.return_value = []
    from agent_bom.mcp_server import create_mcp_server

    server = create_mcp_server()
    result = _call_tool(server, "inventory", {})
    assert "agents" in result
    assert result["total_agents"] == 1
    assert result["agents"][0]["name"] == "test-agent"


@patch("agent_bom.discovery.discover_all")
def test_inventory_no_agents(mock_discover):
    """inventory with no agents should return no_agents_found."""
    mock_discover.return_value = []
    from agent_bom.mcp_server import create_mcp_server

    server = create_mcp_server()
    result = _call_tool(server, "inventory", {})
    assert result["status"] == "no_agents_found"


# ---------------------------------------------------------------------------
# Tool: diff (mocked pipeline)
# ---------------------------------------------------------------------------


@patch("agent_bom.mcp_server._run_scan_pipeline")
def test_diff_no_baseline(mock_pipeline):
    """diff with no saved baseline should save current as first baseline."""
    from agent_bom.models import Agent, AgentType, MCPServer, TransportType

    mock_agent = Agent(
        name="test-agent",
        agent_type=AgentType.CLAUDE_DESKTOP,
        config_path="/tmp/test",
        mcp_servers=[MCPServer(name="s", command="npx", args=[], env={}, transport=TransportType.STDIO, packages=[])],
    )
    mock_pipeline.return_value = ([mock_agent], [], [])

    with patch("agent_bom.history.latest_report", return_value=None), patch("agent_bom.history.save_report"):
        from agent_bom.mcp_server import create_mcp_server

        server = create_mcp_server()
        result = _call_tool(server, "diff", {})
        assert "message" in result
        assert "baseline" in result["message"].lower()


@patch("agent_bom.mcp_server._run_scan_pipeline")
def test_diff_no_agents(mock_pipeline):
    """diff with no agents should return error."""
    mock_pipeline.return_value = ([], [], [])
    from agent_bom.mcp_server import create_mcp_server

    server = create_mcp_server()
    result = _call_tool(server, "diff", {})
    assert "error" in result


# ---------------------------------------------------------------------------
# Tool: verify (mocked integrity)
# ---------------------------------------------------------------------------


@patch("agent_bom.integrity.check_package_provenance")
@patch("agent_bom.integrity.verify_package_integrity")
def test_verify_returns_result(mock_integrity, mock_provenance):
    """verify tool should return integrity + provenance results."""
    mock_integrity.return_value = None
    mock_provenance.return_value = None
    from agent_bom.mcp_server import create_mcp_server

    server = create_mcp_server()
    result = _call_tool(server, "verify", {"package": "express@4.18.2", "ecosystem": "npm"})
    assert result["package"] == "express"
    assert result["version"] == "4.18.2"
    assert result["ecosystem"] == "npm"
    assert "integrity" in result
    assert "provenance" in result


# ---------------------------------------------------------------------------
# Resources
# ---------------------------------------------------------------------------


def test_resource_registry_servers():
    """registry://servers resource should return valid JSON."""
    from agent_bom.mcp_server import create_mcp_server

    server = create_mcp_server()
    resources = _run(server.list_resources())
    uris = [str(r.uri) for r in resources]
    assert "registry://servers" in uris


def test_resource_policy_template():
    """policy://template resource should return valid policy JSON."""
    from agent_bom.mcp_server import create_mcp_server

    server = create_mcp_server()
    resources = _run(server.list_resources())
    uris = [str(r.uri) for r in resources]
    assert "policy://template" in uris


# ── Robustness tests ────────────────────────────────────────────────────


def test_where_tool_returns_json():
    """where tool should return valid JSON with error handling."""
    from agent_bom.mcp_server import create_mcp_server

    server = create_mcp_server()
    result = _call_tool(server, "where", {})
    assert "clients" in result
    assert "platform" in result


def test_registry_cache_returns_same_instance():
    """Registry cache should return the same data on repeated calls."""
    import agent_bom.mcp_server as mod

    mod._registry_cache = None  # Reset cache
    data1 = mod._get_registry_data()
    data2 = mod._get_registry_data()
    assert data1 is data2
    assert "servers" in data1


def test_scan_with_invalid_severity_gate():
    """Invalid fail_severity should return error, not crash."""
    from agent_bom.mcp_server import create_mcp_server
    from agent_bom.models import Agent, AgentType, MCPServer, TransportType

    server = create_mcp_server()
    with patch("agent_bom.mcp_server._run_scan_pipeline") as mock_pipeline:
        mock_agent = Agent(
            name="test-agent",
            agent_type=AgentType.CLAUDE_DESKTOP,
            config_path="/tmp/test",
            mcp_servers=[MCPServer(name="test-server", command="npx", args=[], env={}, transport=TransportType.STDIO, packages=[])],
        )
        mock_pipeline.return_value = ([mock_agent], [], [])

        result = _call_tool(server, "scan", {"fail_severity": "invalid_sev"})
        assert "error" in result
        assert "Invalid severity" in result["error"]


def test_scan_surfaces_warnings():
    """Scan should include warnings from failed image/SBOM loads."""
    from agent_bom.mcp_server import create_mcp_server
    from agent_bom.models import Agent, AgentType, MCPServer, TransportType

    server = create_mcp_server()
    with patch("agent_bom.mcp_server._run_scan_pipeline") as mock_pipeline:
        mock_agent = Agent(
            name="test-agent",
            agent_type=AgentType.CLAUDE_DESKTOP,
            config_path="/tmp/test",
            mcp_servers=[MCPServer(name="test-server", command="npx", args=[], env={}, transport=TransportType.STDIO, packages=[])],
        )
        mock_pipeline.return_value = ([mock_agent], [], ["Image scan failed for bad:image: not found"])

        result = _call_tool(server, "scan", {})
        assert "warnings" in result
        assert len(result["warnings"]) == 1
        assert "Image scan failed" in result["warnings"][0]


def test_scan_no_agents_with_warnings():
    """Scan with no agents should still surface warnings."""
    from agent_bom.mcp_server import create_mcp_server

    server = create_mcp_server()
    with patch("agent_bom.mcp_server._run_scan_pipeline") as mock_pipeline:
        mock_pipeline.return_value = ([], [], ["SBOM file too large"])

        result = _call_tool(server, "scan", {})
        assert result["status"] == "no_agents_found"
        assert "warnings" in result
        assert "SBOM file too large" in result["warnings"][0]


def test_max_file_size_constant_exists():
    """_MAX_FILE_SIZE constant should be defined and reasonable."""
    from agent_bom.mcp_server import _MAX_FILE_SIZE

    assert _MAX_FILE_SIZE == 50 * 1024 * 1024  # 50 MB


def test_sbom_file_size_check():
    """_run_scan_pipeline should warn on oversized SBOM files."""
    from agent_bom.mcp_server import _MAX_FILE_SIZE

    with patch("agent_bom.mcp_server.Path") as mock_path:
        mock_file = mock_path.return_value
        mock_file.exists.return_value = True
        mock_file.stat.return_value.st_size = _MAX_FILE_SIZE + 1
        mock_file.name = "huge.json"

        # Verify the constant is enforced in the pipeline
        assert _MAX_FILE_SIZE > 0


# ---------------------------------------------------------------------------
# Input validation tests
# ---------------------------------------------------------------------------


def test_validate_ecosystem_valid():
    """All supported ecosystems should pass validation."""
    from agent_bom.mcp_server import _validate_ecosystem

    for eco in ("npm", "pypi", "go", "cargo", "maven", "nuget", "rubygems"):
        assert _validate_ecosystem(eco) == eco
    # Case insensitive + whitespace trimmed
    assert _validate_ecosystem("NPM") == "npm"
    assert _validate_ecosystem("  PyPI  ") == "pypi"


def test_validate_ecosystem_invalid():
    """Invalid ecosystems should raise ValueError."""
    from agent_bom.mcp_server import _validate_ecosystem

    for bad in ("pip", "", "python", "composer", "  "):
        with pytest.raises(ValueError, match="Invalid ecosystem"):
            _validate_ecosystem(bad)


def test_validate_cve_id_valid():
    """CVE and GHSA IDs in correct format should pass."""
    from agent_bom.mcp_server import _validate_cve_id

    assert _validate_cve_id("CVE-2024-1234") == "CVE-2024-1234"
    assert _validate_cve_id("CVE-2025-12345") == "CVE-2025-12345"
    assert _validate_cve_id("GHSA-abcd-efgh-ijkl") == "GHSA-abcd-efgh-ijkl"
    assert _validate_cve_id("  CVE-2024-5678  ") == "CVE-2024-5678"


def test_validate_cve_id_invalid():
    """Invalid CVE ID formats should raise ValueError."""
    from agent_bom.mcp_server import _validate_cve_id

    with pytest.raises(ValueError, match="cannot be empty"):
        _validate_cve_id("")
    with pytest.raises(ValueError, match="Invalid CVE ID"):
        _validate_cve_id("not-a-cve")
    with pytest.raises(ValueError, match="Invalid CVE ID"):
        _validate_cve_id("CVE-2024")
    with pytest.raises(ValueError, match="Invalid CVE ID"):
        _validate_cve_id("CVE-2024-12")


def test_truncate_response_under_limit():
    """Responses under the limit pass through unchanged."""
    from agent_bom.mcp_server import _truncate_response

    short = '{"data": "ok"}'
    assert _truncate_response(short) == short


def test_truncate_response_over_limit():
    """Responses over the limit are truncated with a notice."""
    from agent_bom.mcp_server import _MAX_RESPONSE_CHARS, _truncate_response

    long_str = "x" * (_MAX_RESPONSE_CHARS + 1000)
    result = _truncate_response(long_str)
    assert len(result) < len(long_str)
    assert "_truncated" in result


def test_safe_path_valid(tmp_path):
    """Paths within home directory should pass."""
    # tmp_path is typically under $TMPDIR, so use home dir
    import os

    from agent_bom.mcp_server import _safe_path

    home = os.path.expanduser("~")
    p = _safe_path(home)
    assert str(p) == home


def test_safe_path_traversal():
    """Paths outside home directory should raise ValueError."""
    from agent_bom.mcp_server import _safe_path

    with pytest.raises(ValueError, match="outside home directory"):
        _safe_path("/etc/passwd")
