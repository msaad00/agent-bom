"""Focused MCP surfaces must be small, truthful and enforced at invocation."""

import asyncio
import json

import pytest

pytest.importorskip("mcp")

SCAN_TOOLS = {"scan", "check", "intel_lookup", "exposure_paths", "compliance", "remediate", "generate_sbom", "policy_check"}


def test_default_profile_is_small_and_preserves_scan_to_remediation():
    from agent_bom.mcp_server import create_mcp_server

    server = create_mcp_server()
    tools = asyncio.run(server.list_tools())
    assert {tool.name for tool in tools} == SCAN_TOOLS
    full = asyncio.run(create_mcp_server(profile="full").list_tools())

    def encode(tools):
        return json.dumps([tool.model_dump(by_alias=True) for tool in tools], separators=(",", ":")).encode()

    assert len(encode(tools)) < len(encode(full)) / 5


def test_default_does_not_advertise_unavailable_workflows():
    from agent_bom.mcp_server import create_mcp_server

    prompts = asyncio.run(create_mcp_server().list_prompts())
    assert {prompt.name for prompt in prompts} == {"quick-audit", "pre-install-check", "remediation-plan"}


def test_excluded_tool_cannot_be_called_directly():
    from agent_bom.mcp_server import create_mcp_server

    with pytest.raises(Exception, match="Unknown tool"):
        asyncio.run(create_mcp_server().call_tool("graph_correlate", {}))


def test_cli_uses_focused_default():
    from click.testing import CliRunner

    from agent_bom.cli import main

    result = CliRunner().invoke(main, ["mcp", "server", "--help"])
    assert result.exit_code == 0
    assert "[default: scan]" in result.output
    assert "default is the full" not in result.output


@pytest.mark.parametrize(
    "profile, count", [("scan", 8), ("graph", 8), ("cloud", 5), ("runtime", 7), ("audit", 4), ("guided", 25), ("full", 86)]
)
def test_live_card_and_health_match_active_surface(profile, count):
    from starlette.testclient import TestClient

    from agent_bom.mcp_server import create_mcp_server
    from agent_bom.mcp_server_metadata import build_server_card

    server = create_mcp_server(profile=profile)
    tools = asyncio.run(server.list_tools())
    expected = build_server_card(profile=profile)
    assert len(tools) == count
    assert {t.name for t in tools} == {t["name"] for t in expected["tools"]}
    assert all(t.inputSchema["additionalProperties"] is False for t in tools)
    with TestClient(server.streamable_http_app()) as client:
        card = client.get("/.well-known/mcp/server-card.json").json()
        assert card["profile"] == profile
        assert card["profile_version"] == 1
        assert {t["name"] for t in card["tools"]} == {t.name for t in tools}
        assert {p["name"] for p in card["prompts"]} == {p["name"] for p in expected["prompts"]}
        assert {r["uri"] for r in card["resources"]} == {r["uri"] for r in expected["resources"]}
        assert client.get("/health").json()["tool_count"] == count
        assert client.get("/").json()["profile"] == profile
    if profile == "graph":
        assert card["capabilities"]["read_only"] is False
    if profile == "scan":
        assert card["capabilities"]["read_only"] is True


def test_schema_construction_skips_excluded_tools(monkeypatch):
    from mcp.server.fastmcp import FastMCP

    from agent_bom.mcp_server import create_mcp_server

    registered = []
    original = FastMCP.add_tool

    def capture(self, fn, *args, **kwargs):
        registered.append(kwargs.get("name") or fn.__name__)
        return original(self, fn, *args, **kwargs)

    monkeypatch.setattr(FastMCP, "add_tool", capture)
    create_mcp_server()
    assert set(registered) == SCAN_TOOLS
    assert len(registered) == 8


def test_profile_instances_do_not_expand_each_other_or_allow_late_registration():
    from agent_bom.mcp_server import create_mcp_server

    scan = create_mcp_server()
    graph = create_mcp_server(profile="graph")

    @scan.tool(name="unselected_plugin")
    def plugin() -> str:
        return "must not be callable"

    assert {t.name for t in asyncio.run(scan.list_tools())} == SCAN_TOOLS
    assert "graph_correlate" in {t.name for t in asyncio.run(graph.list_tools())}
    with pytest.raises(Exception, match="Unknown tool"):
        asyncio.run(scan.call_tool("unselected_plugin", {}))


@pytest.mark.parametrize("profile", ["scan", "graph", "cloud", "runtime", "audit", "full"])
def test_stdio_wire_profile_discovery_and_strict_calls(profile, tmp_path):
    import os
    import sys
    from pathlib import Path

    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client

    from agent_bom.mcp_server_metadata import build_server_card

    expected = build_server_card(profile=profile)

    async def probe():
        env = {**os.environ, "PYTHONPATH": str(Path(__file__).resolve().parents[1] / "src"), "AGENT_BOM_STATE_DIR": str(tmp_path)}
        env.pop("AGENT_BOM_ENABLE_EXTENSION_ENTRYPOINTS", None)
        env.pop("AGENT_BOM_ACTIVATE_MCP_TOOL_PLUGINS", None)
        params = StdioServerParameters(
            command=sys.executable,
            args=["-c", "from agent_bom.cli import cli_main; cli_main()", "mcp", "server", "--profile", profile],
            env=env,
        )
        async with stdio_client(params) as (read, write):
            async with ClientSession(read, write) as session:
                initialized = await session.initialize()
                assert f"Active profile: {profile}" in initialized.instructions
                tools = (await session.list_tools()).tools
                assert {t.name for t in tools} == {t["name"] for t in expected["tools"]}
                prompts = (await session.list_prompts()).prompts
                assert {p.name for p in prompts} == {p["name"] for p in expected["prompts"]}
                resource = await session.read_resource("profiles://catalog")
                catalog = json.loads(resource.contents[0].text)
                assert catalog["active_profile"] == profile
                assert "inputSchema" not in json.dumps(catalog)
                assert {p["name"] for p in catalog["profiles"]} >= {"scan", "graph", "full"}
                rejected = await session.call_tool(tools[0].name, {"unexpected_profile_argument": True})
                assert rejected.isError
                if profile != "full":
                    hidden = await session.call_tool("identity_issue", {})
                    assert hidden.isError

    asyncio.run(asyncio.wait_for(probe(), timeout=30))


def test_focused_profiles_do_not_activate_optional_plugins(monkeypatch):
    from agent_bom.mcp_server import create_mcp_server

    def unexpected_activation(server):
        pytest.fail("focused profiles must not load third-party tool plugins")

    monkeypatch.setattr("agent_bom.plugin_activation.activate_mcp_tool_plugins", unexpected_activation)
    create_mcp_server()
    create_mcp_server(profile="graph")


def test_docker_catalog_matches_real_default_argument_names():
    from pathlib import Path

    from agent_bom.mcp_server import create_mcp_server

    catalog = json.loads((Path(__file__).resolve().parents[1] / "integrations/docker-mcp-registry/tools.json").read_text())
    live = {tool.name: tool for tool in asyncio.run(create_mcp_server().list_tools())}
    assert {tool["name"] for tool in catalog} == set(live)
    for tool in catalog:
        assert {arg["name"] for arg in tool["arguments"]} == set(live[tool["name"]].inputSchema["properties"])
