"""Tests for MCP Runtime Introspection."""

import sys
from unittest.mock import MagicMock, patch

import pytest

from agent_bom.models import MCPResource, MCPServer, MCPTool, TransportType

# ─── IntrospectionError when SDK missing ─────────────────────────────────────


def test_introspection_error_when_no_mcp_sdk():
    """Should raise IntrospectionError if mcp is not installed."""
    with patch.dict(sys.modules, {"mcp": None}):
        # Need to reimport to trigger the check
        from agent_bom.mcp_introspect import IntrospectionError, _check_mcp_sdk
        with pytest.raises(IntrospectionError, match="mcp SDK is required"):
            _check_mcp_sdk()


# ─── ServerIntrospection model ───────────────────────────────────────────────


def test_server_introspection_no_drift():
    from agent_bom.mcp_introspect import ServerIntrospection
    result = ServerIntrospection(server_name="test", success=True)
    assert not result.has_drift
    assert result.tool_count == 0
    assert result.resource_count == 0


def test_server_introspection_with_drift():
    from agent_bom.mcp_introspect import ServerIntrospection
    result = ServerIntrospection(
        server_name="test",
        success=True,
        tools_added=["new_tool"],
        tools_removed=["old_tool"],
    )
    assert result.has_drift


def test_server_introspection_with_tools():
    from agent_bom.mcp_introspect import ServerIntrospection
    result = ServerIntrospection(
        server_name="test",
        success=True,
        runtime_tools=[
            MCPTool(name="read_file", description="Read a file"),
            MCPTool(name="write_file", description="Write a file"),
        ],
        runtime_resources=[
            MCPResource(uri="file:///tmp", name="tmp", description="Temp dir"),
        ],
    )
    assert result.tool_count == 2
    assert result.resource_count == 1


# ─── IntrospectionReport model ──────────────────────────────────────────────


def test_introspection_report_stats():
    from agent_bom.mcp_introspect import IntrospectionReport, ServerIntrospection
    report = IntrospectionReport(
        results=[
            ServerIntrospection(server_name="a", success=True, runtime_tools=[
                MCPTool(name="t1", description=""),
            ]),
            ServerIntrospection(server_name="b", success=False, error="timeout"),
            ServerIntrospection(server_name="c", success=True, tools_added=["new"], runtime_resources=[
                MCPResource(uri="r1", name="r1"),
            ]),
        ]
    )
    assert report.total_servers == 3
    assert report.successful == 2
    assert report.failed == 1
    assert report.total_tools == 1
    assert report.total_resources == 1
    assert report.drift_count == 1


# ─── enrich_servers ──────────────────────────────────────────────────────────


def test_enrich_servers_adds_new_tools():
    from agent_bom.mcp_introspect import IntrospectionReport, ServerIntrospection, enrich_servers

    server = MCPServer(
        name="my-server",
        command="node",
        transport=TransportType.STDIO,
        tools=[MCPTool(name="existing_tool", description="Already known")],
    )

    report = IntrospectionReport(
        results=[
            ServerIntrospection(
                server_name="my-server",
                success=True,
                protocol_version="2024-11-05",
                runtime_tools=[
                    MCPTool(name="existing_tool", description="Already known"),
                    MCPTool(name="new_tool", description="Discovered at runtime"),
                ],
                runtime_resources=[
                    MCPResource(uri="file:///data", name="data", description="Data dir"),
                ],
            ),
        ]
    )

    enriched = enrich_servers([server], report)
    assert enriched == 1
    assert len(server.tools) == 2
    assert any(t.name == "new_tool" for t in server.tools)
    assert len(server.resources) == 1
    assert server.mcp_version == "2024-11-05"


def test_enrich_servers_no_duplicate_tools():
    from agent_bom.mcp_introspect import IntrospectionReport, ServerIntrospection, enrich_servers

    server = MCPServer(
        name="my-server",
        command="node",
        transport=TransportType.STDIO,
        tools=[MCPTool(name="read_file", description="Read a file")],
    )

    report = IntrospectionReport(
        results=[
            ServerIntrospection(
                server_name="my-server",
                success=True,
                runtime_tools=[
                    MCPTool(name="read_file", description="Read a file"),
                ],
            ),
        ]
    )

    enriched = enrich_servers([server], report)
    assert enriched == 0  # nothing new to add
    assert len(server.tools) == 1


def test_enrich_servers_skips_failed():
    from agent_bom.mcp_introspect import IntrospectionReport, ServerIntrospection, enrich_servers

    server = MCPServer(name="my-server", command="node", transport=TransportType.STDIO)

    report = IntrospectionReport(
        results=[
            ServerIntrospection(
                server_name="my-server",
                success=False,
                error="Connection refused",
            ),
        ]
    )

    enriched = enrich_servers([server], report)
    assert enriched == 0


# ─── introspect_server with unsupported transport ────────────────────────────


@pytest.mark.asyncio
async def test_introspect_server_unknown_transport():
    from agent_bom.mcp_introspect import introspect_server

    server = MCPServer(
        name="unknown-server",
        transport=TransportType.UNKNOWN,
    )

    # Mock the SDK check
    with patch("agent_bom.mcp_introspect._check_mcp_sdk"):
        result = await introspect_server(server, timeout=1.0)
    assert not result.success
    assert "Unsupported transport" in result.error


@pytest.mark.asyncio
async def test_introspect_server_no_command():
    from agent_bom.mcp_introspect import introspect_server

    server = MCPServer(
        name="no-cmd",
        transport=TransportType.STDIO,
        command="",
    )

    with patch("agent_bom.mcp_introspect._check_mcp_sdk"):
        result = await introspect_server(server, timeout=1.0)
    assert not result.success
    assert "No command" in result.error


@pytest.mark.asyncio
async def test_introspect_server_no_url():
    from agent_bom.mcp_introspect import introspect_server

    server = MCPServer(
        name="no-url",
        transport=TransportType.SSE,
        url=None,
    )

    with patch("agent_bom.mcp_introspect._check_mcp_sdk"):
        result = await introspect_server(server, timeout=1.0)
    assert not result.success
    assert "No URL" in result.error


# ─── Drift detection logic ──────────────────────────────────────────────────


def test_drift_detection_tools():
    """Tools added and removed should be detected."""
    from agent_bom.mcp_introspect import ServerIntrospection

    result = ServerIntrospection(
        server_name="test",
        success=True,
        tools_added=["tool_c"],
        tools_removed=["tool_a"],
        resources_added=[],
        resources_removed=[],
    )
    assert result.has_drift
    assert "tool_c" in result.tools_added
    assert "tool_a" in result.tools_removed


def test_drift_detection_resources():
    """Resources added and removed should be detected."""
    from agent_bom.mcp_introspect import ServerIntrospection

    result = ServerIntrospection(
        server_name="test",
        success=True,
        tools_added=[],
        tools_removed=[],
        resources_added=["file:///new"],
        resources_removed=["file:///old"],
    )
    assert result.has_drift


# ─── NIST AI RMF integration in blast radius ────────────────────────────────


def test_blast_radius_has_nist_tags_field():
    """BlastRadius model should have nist_ai_rmf_tags field."""
    from agent_bom.models import BlastRadius
    br = BlastRadius(
        vulnerability=MagicMock(),
        package=MagicMock(),
        affected_servers=[],
        affected_agents=[],
        exposed_credentials=[],
        exposed_tools=[],
    )
    assert hasattr(br, "nist_ai_rmf_tags")
    assert br.nist_ai_rmf_tags == []


# ─── Output integration ─────────────────────────────────────────────────────


def test_json_output_includes_nist_tags():
    """JSON output should include nist_ai_rmf_tags in blast_radius entries."""
    from agent_bom.models import AIBOMReport, BlastRadius, Package, Severity, Vulnerability
    from agent_bom.output import to_json

    vuln = Vulnerability(id="CVE-2024-0001", summary="Test", severity=Severity.MEDIUM)
    pkg = Package(name="express", version="4.18.2", ecosystem="npm")
    br = BlastRadius(
        vulnerability=vuln,
        package=pkg,
        affected_servers=[],
        affected_agents=[],
        exposed_credentials=[],
        exposed_tools=[],
        nist_ai_rmf_tags=["MAP-3.5", "GOVERN-1.7"],
    )
    report = AIBOMReport(agents=[], blast_radii=[br])
    data = to_json(report)

    assert "nist_ai_rmf_tags" in data["blast_radius"][0]
    assert "MAP-3.5" in data["blast_radius"][0]["nist_ai_rmf_tags"]


def test_framework_summary_includes_nist():
    """Threat framework summary should include nist_ai_rmf section."""
    from agent_bom.models import BlastRadius, Package, Severity, Vulnerability
    from agent_bom.output import _build_framework_summary

    vuln = Vulnerability(id="CVE-2024-0001", summary="Test", severity=Severity.MEDIUM)
    pkg = Package(name="express", version="4.18.2", ecosystem="npm")
    br = BlastRadius(
        vulnerability=vuln,
        package=pkg,
        affected_servers=[],
        affected_agents=[],
        exposed_credentials=[],
        exposed_tools=[],
        nist_ai_rmf_tags=["MAP-3.5", "GOVERN-1.7"],
    )
    summary = _build_framework_summary([br])

    assert "nist_ai_rmf" in summary
    assert "total_nist_triggered" in summary
    assert summary["total_nist_triggered"] == 2

    # Check specific entries
    nist_entries = {e["subcategory_id"]: e for e in summary["nist_ai_rmf"]}
    assert nist_entries["MAP-3.5"]["findings"] == 1
    assert nist_entries["MAP-3.5"]["triggered"] is True
    assert nist_entries["MEASURE-2.5"]["findings"] == 0
    assert nist_entries["MEASURE-2.5"]["triggered"] is False


# ─── CLI --introspect flag exists ────────────────────────────────────────────


def test_cli_introspect_flag():
    """CLI should accept --introspect flag."""
    from click.testing import CliRunner

    from agent_bom.cli import main

    runner = CliRunner()
    result = runner.invoke(main, ["scan", "--help"])
    assert "--introspect" in result.output
    assert "--introspect-timeout" in result.output
