"""CLI/MCP expose the same scoped endpoint service without vendor credentials in tools."""

from __future__ import annotations

import json

import pytest
from click.testing import CliRunner

from agent_bom.cli import main


def test_cli_sync_preserves_partial_status(monkeypatch):
    from agent_bom.cli import _endpoint_connectors as cli

    class Fake:
        _client = type("Transport", (), {"timeout": 30})()

        def sync_endpoint_connection(self, connection_id, **kwargs):
            assert connection_id == "c" and kwargs == {"restart": False, "max_pages": 5}
            return {"status": "partial", "gap": "more_pages_required", "device_count": 3}

        def close(self):
            pass

    monkeypatch.setattr(cli, "_make_client", lambda *args: Fake())
    result = CliRunner().invoke(main, ["connect", "endpoints", "sync", "c"])
    assert result.exit_code == 2
    assert json.loads(result.output)["device_count"] == 3


def test_cli_configuration_error_does_not_echo_secret(monkeypatch, tmp_path):
    config = tmp_path / "bad.json"
    config.write_text('{"provider":"bad"}')
    monkeypatch.setenv("CONNECTOR_FIXTURE_SECRET", "secret-do-not-echo")
    result = CliRunner().invoke(
        main, ["connect", "endpoints", "create", "--config", str(config), "--secret-env", "CONNECTOR_FIXTURE_SECRET"]
    )
    assert result.exit_code == 1
    assert "secret-do-not-echo" not in result.output


@pytest.mark.asyncio
async def test_mcp_inventory_and_sync_registration_contract():
    from agent_bom.mcp_server import create_mcp_server

    server = create_mcp_server(profile="full")
    tools = {tool.name: tool for tool in await server.list_tools()}
    assert {"endpoint_inventory", "endpoint_sync"} <= set(tools)
    for name in ("endpoint_inventory", "endpoint_sync"):
        properties = tools[name].inputSchema["properties"]
        assert not {"client_secret", "client_id", "url", "jamf_url"}.intersection(properties)
    assert tools["endpoint_sync"].annotations.destructiveHint is True
    cloud = create_mcp_server(profile="cloud")
    assert "endpoint_inventory" in {tool.name for tool in await cloud.list_tools()}


def test_cli_rotation_uses_write_only_environment_secret(monkeypatch):
    from agent_bom.cli import _endpoint_connectors as cli

    class Fake:
        def update_endpoint_connection(self, connection_id, body):
            assert connection_id == "c"
            assert body == {"enabled": False, "client_secret": "fixture-rotation-secret"}
            return {"enabled": False}

        def close(self):
            pass

    monkeypatch.setattr(cli, "_make_client", lambda *args: Fake())
    monkeypatch.setenv("ENDPOINT_ROTATION_SECRET", "fixture-rotation-secret")
    result = CliRunner().invoke(main, ["connect", "endpoints", "update", "c", "--disabled", "--secret-env", "ENDPOINT_ROTATION_SECRET"])
    assert result.exit_code == 0
    assert "fixture-rotation-secret" not in result.output
    assert json.loads(result.output) == {"enabled": False}
