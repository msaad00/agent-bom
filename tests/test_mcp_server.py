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


def test_mcp_server_has_five_tools():
    """Server should register exactly 5 tools."""
    from agent_bom.mcp_server import create_mcp_server
    server = create_mcp_server()
    tools = _run(server.list_tools())
    assert len(tools) == 5


def test_mcp_server_tool_names():
    """Tool names should match expected set."""
    from agent_bom.mcp_server import create_mcp_server
    server = create_mcp_server()
    tools = _run(server.list_tools())
    names = {t.name for t in tools}
    assert names == {"scan", "blast_radius", "policy_check", "registry_lookup", "generate_sbom"}


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
# Tool: scan (mocked pipeline)
# ---------------------------------------------------------------------------


@patch("agent_bom.mcp_server._run_scan_pipeline")
def test_scan_returns_json(mock_pipeline):
    """Scan tool should return valid JSON with agents."""
    from agent_bom.models import Agent, AgentType, MCPServer, TransportType
    mock_agent = Agent(
        name="test-agent", agent_type=AgentType.CLAUDE_DESKTOP,
        config_path="/tmp/test", mcp_servers=[
            MCPServer(name="test-server", command="npx", args=[], env={},
                      transport=TransportType.STDIO, packages=[])
        ],
    )
    mock_pipeline.return_value = ([mock_agent], [])

    from agent_bom.mcp_server import create_mcp_server
    server = create_mcp_server()
    result = _call_tool(server, "scan", {})
    assert "agents" in result
    assert result["summary"]["total_agents"] >= 1


@patch("agent_bom.mcp_server._run_scan_pipeline")
def test_scan_no_agents(mock_pipeline):
    """Scan with no agents should return no_agents_found status."""
    mock_pipeline.return_value = ([], [])
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
    mock_pipeline.return_value = ([], [])
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
    mock_pipeline.return_value = ([], [])
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
        name="test-agent", agent_type=AgentType.CLAUDE_DESKTOP,
        config_path="/tmp/test", mcp_servers=[
            MCPServer(name="test-server", command="npx", args=[], env={},
                      transport=TransportType.STDIO, packages=[])
        ],
    )
    mock_pipeline.return_value = ([mock_agent], [])
    from agent_bom.mcp_server import create_mcp_server
    server = create_mcp_server()
    result = _call_tool(server, "generate_sbom", {"format": "cyclonedx"})
    assert "bomFormat" in result
    assert result["bomFormat"] == "CycloneDX"


@patch("agent_bom.mcp_server._run_scan_pipeline")
def test_generate_sbom_no_agents(mock_pipeline):
    """generate_sbom with no agents should return error."""
    mock_pipeline.return_value = ([], [])
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
