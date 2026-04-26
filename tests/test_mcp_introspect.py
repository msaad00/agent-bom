"""Tests for MCP Runtime Introspection."""

import sys
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from agent_bom.models import MCPPrompt, MCPResource, MCPServer, MCPTool, TransportType

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
    assert result.prompt_count == 0


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
    from agent_bom.mcp_introspect import ServerIntrospection, _apply_runtime_risk

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
    server = MCPServer(
        name="test",
        command="npx",
        transport=TransportType.STDIO,
        env={"API_KEY": "secret"},
    )
    _apply_runtime_risk(server, result)
    assert result.tool_count == 2
    assert result.resource_count == 1
    assert result.capability_risk_score > 0
    assert result.tool_risk_profiles
    assert "read" in result.capability_counts


# ─── IntrospectionReport model ──────────────────────────────────────────────


def test_introspection_report_stats():
    from agent_bom.mcp_introspect import IntrospectionReport, ServerIntrospection

    report = IntrospectionReport(
        results=[
            ServerIntrospection(
                server_name="a",
                success=True,
                runtime_tools=[
                    MCPTool(name="t1", description=""),
                ],
            ),
            ServerIntrospection(server_name="b", success=False, error="timeout"),
            ServerIntrospection(
                server_name="c",
                success=True,
                tools_added=["new"],
                runtime_resources=[
                    MCPResource(uri="r1", name="r1"),
                ],
                runtime_prompts=[
                    MCPPrompt(name="summarize", description="Summarize the supplied text"),
                ],
            ),
        ]
    )
    assert report.total_servers == 3
    assert report.successful == 2
    assert report.failed == 1
    assert report.total_tools == 1
    assert report.total_resources == 1
    assert report.total_prompts == 1
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
                runtime_prompts=[
                    MCPPrompt(name="summarize", description="Summarize user-provided text"),
                ],
            ),
        ]
    )

    enriched = enrich_servers([server], report)
    assert enriched == 1
    assert len(server.tools) == 2
    assert any(t.name == "new_tool" for t in server.tools)
    assert len(server.resources) == 1
    assert len(server.prompts) == 1
    assert server.mcp_version == "2024-11-05"


def test_tool_schema_resource_and_prompt_lint_findings():
    from agent_bom.mcp_introspect import _lint_prompt, _lint_resource, _lint_tool_schema

    tool = MCPTool(
        name="run_shell",
        description="Run shell command",
        input_schema={
            "type": "object",
            "properties": {
                "command": {"type": "string"},
                "path": {"type": "string", "description": "Workspace path"},
                "url": {"type": "string", "description": "Webhook URL"},
            },
        },
    )
    tool_findings = _lint_tool_schema(tool)
    assert any("shell-execution-capability" in finding for finding in tool_findings)
    assert any("filesystem-capability" in finding for finding in tool_findings)
    assert any("network-egress-capability" in finding for finding in tool_findings)

    resource = MCPResource(
        uri="resource://prompt-template",
        name="system prompt",
        description="Mutable markdown instructions",
        mime_type="text/markdown",
    )
    resource_findings = _lint_resource(resource)
    assert any("prompt-bearing-resource" in finding for finding in resource_findings)
    assert any("rich-content-resource" in finding for finding in resource_findings)

    prompt = MCPPrompt(
        name="system_prompt",
        description="Hidden instruction template for developer messages",
        arguments=[{"name": "user_prompt", "required": True}],
    )
    prompt_findings = _lint_prompt(prompt)
    assert any("system-prompt-surface" in finding for finding in prompt_findings)
    assert any("hidden-instruction-surface" in finding for finding in prompt_findings)
    assert any("required-freeform-argument" in finding for finding in prompt_findings)


def test_server_introspection_captures_fingerprint_and_auth_mode():
    from agent_bom.mcp_introspect import ServerIntrospection

    server = MCPServer(
        name="filesystem",
        command="npx",
        args=["@modelcontextprotocol/server-filesystem"],
        transport=TransportType.STDIO,
        env={"API_KEY": "${API_KEY}"},
        tools=[MCPTool(name="read_file", description="Read file", input_schema={"type": "object"})],
    )
    result = ServerIntrospection(
        server_name=server.name,
        success=True,
        auth_mode=server.auth_mode,
        configured_fingerprint=server.fingerprint,
        runtime_fingerprint=server.fingerprint,
        configured_tool_count=len(server.tools),
        configured_resource_count=len(server.resources),
    )
    assert result.auth_mode == "env-credentials"
    assert result.configured_fingerprint == server.fingerprint
    assert result.configured_tool_count == 1


def test_server_introspection_to_dict_includes_capability_risk():
    from agent_bom.mcp_introspect import ServerIntrospection

    result = ServerIntrospection(
        server_name="filesystem",
        success=True,
        capability_risk_score=7.5,
        capability_risk_level="high",
        capability_counts={"execute": 1},
        capability_tools={"execute": ["run_command"]},
        dangerous_combinations=["Can execute arbitrary code/commands"],
        risk_justification="Server has EXECUTE capabilities.",
        tool_risk_profiles=[{"tool_name": "run_command", "risk_score": 8.0, "risk_level": "high"}],
    )
    payload = result.to_dict()
    assert payload["capability_risk_score"] == 7.5
    assert payload["capability_risk_level"] == "high"
    assert payload["tool_risk_profiles"][0]["tool_name"] == "run_command"


def test_server_introspection_to_dict_includes_structured_schema_rule_findings():
    from agent_bom.mcp_introspect import ServerIntrospection

    tool = MCPTool(
        name="read_file",
        description="Read a file from the workspace",
        schema_findings=["read_file.path: filesystem-capability"],
        schema_rule_findings=[
            {
                "rule_id": "mcp.tool.path-input",
                "severity": "medium",
                "category": "filesystem",
                "message": "Tool accepts filesystem paths.",
            }
        ],
    )
    result = ServerIntrospection(
        server_name="filesystem",
        success=True,
        runtime_tools=[tool],
        tool_schema_findings=["read_file.path: filesystem-capability"],
        tool_schema_rule_findings=tool.schema_rule_findings,
    )

    payload = result.to_dict(include_runtime_objects=True)
    assert payload["tool_schema_rule_findings"][0]["rule_id"] == "mcp.tool.path-input"
    assert payload["runtime_tools"][0]["schema_rule_findings"][0]["category"] == "filesystem"


def test_server_introspection_to_dict_includes_runtime_prompts():
    from agent_bom.mcp_introspect import ServerIntrospection

    prompt = MCPPrompt(
        name="summarize",
        description="Summarize user-provided text",
        arguments=[{"name": "text", "required": True}],
        content_findings=["summarize.text: required-freeform-argument"],
    )
    result = ServerIntrospection(
        server_name="prompt-server",
        success=True,
        runtime_prompts=[prompt],
        prompt_findings=prompt.content_findings,
    )

    payload = result.to_dict(include_runtime_objects=True)
    assert payload["prompt_count"] == 1
    assert payload["prompt_findings"] == ["summarize.text: required-freeform-argument"]
    assert payload["runtime_prompts"][0]["name"] == "summarize"


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


def test_enrich_servers_adds_new_prompts_without_duplicates():
    from agent_bom.mcp_introspect import IntrospectionReport, ServerIntrospection, enrich_servers

    server = MCPServer(
        name="my-server",
        command="node",
        transport=TransportType.STDIO,
        prompts=[MCPPrompt(name="existing", description="Known prompt")],
    )

    report = IntrospectionReport(
        results=[
            ServerIntrospection(
                server_name="my-server",
                success=True,
                runtime_prompts=[
                    MCPPrompt(name="existing", description="Known prompt", content_findings=["existing: system-prompt-surface"]),
                    MCPPrompt(name="new", description="New prompt"),
                ],
            ),
        ]
    )

    enriched = enrich_servers([server], report)
    assert enriched == 1
    assert [p.name for p in server.prompts] == ["existing", "new"]
    assert server.prompts[0].content_findings == ["existing: system-prompt-surface"]


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


@pytest.mark.asyncio
async def test_query_capabilities_collects_prompts_list():
    from agent_bom.mcp_introspect import ServerIntrospection, _query_capabilities

    class FakeSession:
        async def list_tools(self):
            return SimpleNamespace(tools=[])

        async def list_resources(self):
            return SimpleNamespace(resources=[])

        async def list_prompts(self):
            prompt = SimpleNamespace(
                name="system_prompt",
                description="Hidden instruction template",
                arguments=[SimpleNamespace(name="text", description="", required=True)],
            )
            return SimpleNamespace(prompts=[prompt])

    server = MCPServer(
        name="prompt-server",
        command="node",
        transport=TransportType.STDIO,
        prompts=[MCPPrompt(name="old_prompt", description="Old prompt")],
    )
    result = await _query_capabilities(FakeSession(), server, ServerIntrospection(server_name=server.name, success=False))

    assert result.success is True
    assert result.prompt_count == 1
    assert result.prompts_added == ["system_prompt"]
    assert result.prompts_removed == ["old_prompt"]
    assert any("system-prompt-surface" in finding for finding in result.prompt_findings)


@pytest.mark.asyncio
async def test_query_capabilities_tolerates_missing_prompts_list():
    from agent_bom.mcp_introspect import ServerIntrospection, _query_capabilities

    class FakeSession:
        async def list_tools(self):
            return SimpleNamespace(tools=[])

        async def list_resources(self):
            return SimpleNamespace(resources=[])

    server = MCPServer(name="no-prompts", command="node", transport=TransportType.STDIO)
    result = await _query_capabilities(FakeSession(), server, ServerIntrospection(server_name=server.name, success=False))

    assert result.success is True
    assert result.prompt_count == 0
    assert result.prompts_added == []


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
