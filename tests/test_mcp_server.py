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


def test_mcp_server_has_nine_tools():
    """Server should register exactly 9 tools."""
    from agent_bom.mcp_server import create_mcp_server
    server = create_mcp_server()
    tools = _run(server.list_tools())
    assert len(tools) == 9


def test_mcp_server_tool_names():
    """Tool names should match expected set."""
    from agent_bom.mcp_server import create_mcp_server
    server = create_mcp_server()
    tools = _run(server.list_tools())
    names = {t.name for t in tools}
    assert names == {
        "scan", "check", "blast_radius", "policy_check", "registry_lookup",
        "generate_sbom", "compliance", "remediate", "skill_trust",
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
    result = _call_tool(server, "check", {
        "package": "@modelcontextprotocol/server-filesystem@2025.1.14",
        "ecosystem": "npm",
    })
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


# ---------------------------------------------------------------------------
# Tool: compliance
# ---------------------------------------------------------------------------


@patch("agent_bom.mcp_server._run_scan_pipeline")
def test_compliance_no_agents(mock_pipeline):
    """Compliance with no agents should return 100% score."""
    mock_pipeline.return_value = ([], [])
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
        name="test-agent", agent_type=AgentType.CLAUDE_DESKTOP,
        config_path="/tmp/test", mcp_servers=[
            MCPServer(name="test-server", command="npx", args=[], env={},
                      transport=TransportType.STDIO, packages=[])
        ],
    )
    br = BlastRadius(
        vulnerability=Vulnerability(
            id="CVE-2025-0001", severity=Severity.HIGH, summary="Test vuln",
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

    mock_pipeline.return_value = ([mock_agent], [br])
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
    mock_pipeline.return_value = ([], [])
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
        name="test-agent", agent_type=AgentType.CLAUDE_DESKTOP,
        config_path="/tmp/test", mcp_servers=[
            MCPServer(name="test-server", command="npx", args=[], env={},
                      transport=TransportType.STDIO, packages=[])
        ],
    )
    mock_pipeline.return_value = ([mock_agent], [])
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
