"""MCP assessment uses the server-bound tenant and strict advertised arguments."""

import asyncio
import json

import pytest

from tests.test_graph_tenant_scope_and_bounds import api  # noqa: F401


def test_mcp_compromise_uses_server_tenant_and_returns_revision(api, monkeypatch):  # noqa: F811
    from agent_bom.mcp_tools.compromise import compromise_assessment_impl

    _, store, _ = api
    monkeypatch.setenv("AGENT_BOM_MCP_TENANT_ID", "tenant-a")
    result = json.loads(
        asyncio.run(
            compromise_assessment_impl(
                root_node_id="principal:reader",
                scan_id="shared-scan",
                assume_control=True,
                tenant_id="tenant-b",
                _get_graph_store=lambda: store,
            )
        )
    )
    assert result["tenant_id"] == "tenant-a"
    assert result["snapshot_generation"]
    assert result["actions"][0]["permission"] == "unknown"


def test_mcp_compromise_validates_before_reading_storage():
    from agent_bom.mcp_tools.compromise import compromise_assessment_impl

    def no_storage():
        pytest.fail("invalid assumptions must not access storage")

    result = json.loads(
        asyncio.run(compromise_assessment_impl(root_node_id="node", scan_id="s", assume_control=False, _get_graph_store=no_storage))
    )
    assert result["error"]["code"] == "AGENTBOM_MCP_VALIDATION_INVALID_ARGUMENT"


def test_mcp_compromise_errors_never_disclose_storage_secrets():
    from agent_bom.mcp_tools.compromise import compromise_assessment_impl

    def unavailable():
        raise RuntimeError("postgres://user:secret@private-host/db")

    result = asyncio.run(compromise_assessment_impl(root_node_id="node", scan_id="s", assume_control=True, _get_graph_store=unavailable))
    assert "secret" not in result and "private-host" not in result
    assert json.loads(result)["error"]["code"] == "AGENTBOM_MCP_UPSTREAM_UNAVAILABLE"


def test_mcp_compromise_advertises_strict_readonly_graph_profile_tool():
    from agent_bom.mcp_server import create_mcp_server

    server = create_mcp_server(profile="graph")
    tools = {tool.name: tool for tool in asyncio.run(server.list_tools())}
    tool = tools["compromise_assessment"]
    assert tool.annotations.readOnlyHint is True
    assert tool.inputSchema["additionalProperties"] is False
    assert {"root_node_id", "scan_id", "assume_control"} <= set(tool.inputSchema["required"])
    with pytest.raises(Exception, match="Unknown argument"):
        asyncio.run(
            server.call_tool(
                "compromise_assessment", {"root_node_id": "node", "scan_id": "s", "assume_control": True, "invent_access": True}
            )
        )


@pytest.mark.parametrize("assumption", [1, "true"])
def test_mcp_compromise_never_coerces_control_assumptions(assumption):
    from agent_bom.mcp_server import create_mcp_server

    server = create_mcp_server(profile="graph")
    with pytest.raises(Exception, match="valid boolean"):
        asyncio.run(server.call_tool("compromise_assessment", {"root_node_id": "node", "scan_id": "s", "assume_control": assumption}))


def test_scan_profile_starts_without_the_optional_api_dependency():
    import subprocess
    import sys

    script = """
import asyncio
import importlib.abc
import sys
class NoAPI(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname == "fastapi" or fullname.startswith("fastapi."):
            raise ModuleNotFoundError("optional API dependency unavailable")
sys.meta_path.insert(0, NoAPI())
from agent_bom.mcp_server import create_mcp_server
assert len(asyncio.run(create_mcp_server(profile="scan").list_tools())) == 8
"""
    result = subprocess.run([sys.executable, "-c", script], capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stderr
