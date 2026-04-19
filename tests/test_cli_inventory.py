"""Tests for agent_bom.cli._inventory to improve coverage."""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

from click.testing import CliRunner

from agent_bom.cli._inventory import _inventory_schema_path, completions_cmd, inventory, validate, where

# ---------------------------------------------------------------------------
# inventory
# ---------------------------------------------------------------------------


def test_inventory_no_agents():
    runner = CliRunner()
    with patch("agent_bom.cli._inventory.discover_all", return_value=[]):
        result = runner.invoke(inventory, [])
        assert result.exit_code == 0
        assert "No MCP configurations" in result.output


def test_inventory_with_agents():
    runner = CliRunner()
    from agent_bom.models import Agent, AgentType, MCPServer, TransportType

    mock_server = MCPServer(name="test-srv", command="npx", args=["test"], transport=TransportType.STDIO)
    mock_agent = Agent(name="test-agent", agent_type=AgentType.CUSTOM, config_path="/test", mcp_servers=[mock_server])

    with (
        patch("agent_bom.cli._inventory.discover_all", return_value=[mock_agent]),
        patch("agent_bom.cli._inventory.extract_packages", return_value=[]),
    ):
        result = runner.invoke(inventory, [])
        assert result.exit_code == 0


def test_inventory_with_config_file(tmp_path):
    runner = CliRunner()
    config = {"mcpServers": {"test": {"command": "echo", "args": ["hello"]}}}
    config_file = tmp_path / "config.json"
    config_file.write_text(json.dumps(config))

    with patch("agent_bom.cli._inventory.extract_packages", return_value=[]):
        result = runner.invoke(inventory, ["--config", str(config_file)])
        assert result.exit_code == 0


def test_inventory_with_bad_config(tmp_path):
    runner = CliRunner()
    config_file = tmp_path / "bad.json"
    config_file.write_text("not json")

    result = runner.invoke(inventory, ["--config", str(config_file)])
    assert result.exit_code == 1
    assert "Error parsing" in result.output


def test_inventory_transitive():
    runner = CliRunner()
    with patch("agent_bom.cli._inventory.discover_all", return_value=[]):
        result = runner.invoke(inventory, ["--transitive"])
        assert result.exit_code == 0


def test_inventory_security_blocked():
    """Servers with security_blocked should skip package extraction."""
    runner = CliRunner()
    from agent_bom.models import Agent, AgentType, MCPServer, TransportType

    mock_server = MCPServer(name="blocked-srv", command="evil", transport=TransportType.STDIO, security_blocked=True)
    mock_agent = Agent(name="a", agent_type=AgentType.CUSTOM, config_path="/t", mcp_servers=[mock_server])

    with (
        patch("agent_bom.cli._inventory.discover_all", return_value=[mock_agent]),
        patch("agent_bom.cli._inventory.extract_packages") as mock_extract,
    ):
        runner.invoke(inventory, [])
        mock_extract.assert_not_called()


# ---------------------------------------------------------------------------
# validate
# ---------------------------------------------------------------------------


def test_validate_valid_file(tmp_path):
    runner = CliRunner()
    data = {
        "schema_version": "1",
        "generated_at": "2025-01-01T00:00:00Z",
        "agents": [{"name": "demo-agent", "agent_type": "custom", "mcp_servers": []}],
    }
    inv_file = tmp_path / "inv.json"
    inv_file.write_text(json.dumps(data))

    schema_path = _inventory_schema_path()
    assert schema_path is not None
    assert schema_path.exists()

    result = runner.invoke(validate, [str(inv_file)])
    assert result.exit_code == 0
    assert "Valid" in result.output


def test_validate_invalid_json(tmp_path):
    runner = CliRunner()
    inv_file = tmp_path / "bad.json"
    inv_file.write_text("not json {{{")

    schema_path = _inventory_schema_path()
    assert schema_path is not None
    assert schema_path.exists()

    result = runner.invoke(validate, [str(inv_file)])
    assert result.exit_code == 1


def test_inventory_schema_path_points_to_repo_schema():
    schema_path = _inventory_schema_path()
    assert schema_path is not None
    assert schema_path.name == "inventory.schema.json"
    assert "config/schemas" in schema_path.as_posix()


# ---------------------------------------------------------------------------
# where
# ---------------------------------------------------------------------------


def test_where_console():
    runner = CliRunner()
    result = runner.invoke(where, [])
    assert result.exit_code == 0
    assert "MCP Client" in result.output or "Total" in result.output


def test_where_json():
    runner = CliRunner()
    result = runner.invoke(where, ["--json"])
    assert result.exit_code == 0
    data = json.loads(result.output)
    assert "platform" in data
    assert "paths" in data


# ---------------------------------------------------------------------------
# completions
# ---------------------------------------------------------------------------


def test_completions_bash():
    runner = CliRunner()
    with patch("subprocess.run") as mock_run:
        mock_result = MagicMock()
        mock_result.stdout = "# bash completion"
        mock_run.return_value = mock_result
        result = runner.invoke(completions_cmd, ["bash"])
        assert result.exit_code == 0


def test_completions_zsh_fallback():
    runner = CliRunner()
    with patch("subprocess.run", side_effect=Exception("fail")):
        result = runner.invoke(completions_cmd, ["zsh"])
        assert result.exit_code == 0
        assert "zsh_source" in result.output


def test_completions_fish_fallback():
    runner = CliRunner()
    with patch("subprocess.run", side_effect=Exception("fail")):
        result = runner.invoke(completions_cmd, ["fish"])
        assert result.exit_code == 0
        assert "fish_source" in result.output
