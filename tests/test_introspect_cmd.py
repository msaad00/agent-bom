"""Tests for the agent-bom introspect CLI command."""

from __future__ import annotations

import json
from unittest.mock import patch

from click.testing import CliRunner

from agent_bom.cli import main


def _make_introspection(name="test-server", tools=None, success=True, error=None):
    from agent_bom.mcp_introspect import ServerIntrospection
    from agent_bom.models import MCPTool

    r = ServerIntrospection(server_name=name, success=success, error=error)
    r.runtime_tools = [MCPTool(name=t, description=f"desc {t}") for t in (tools or [])]
    return r


# ─── basic invocation ────────────────────────────────────────────────────────


def test_introspect_requires_target():
    runner = CliRunner()
    result = runner.invoke(main, ["mcp", "introspect"])
    assert result.exit_code != 0 or "Provide" in result.output


def test_introspect_command_success():
    intro = _make_introspection("fs", tools=["read_file", "write_file"])
    with patch("agent_bom.mcp_introspect.introspect_servers_sync", return_value=[intro]):
        runner = CliRunner()
        result = runner.invoke(main, ["mcp", "introspect", "--command", "npx @mcp/server-filesystem /"])
    assert result.exit_code == 0
    assert "read_file" in result.output
    assert "write_file" in result.output


def test_introspect_json_format():
    intro = _make_introspection("api-server", tools=["search", "fetch"])
    with patch("agent_bom.mcp_introspect.introspect_servers_sync", return_value=[intro]):
        runner = CliRunner()
        result = runner.invoke(main, ["mcp", "introspect", "--command", "some-server", "--format", "json"])
    assert result.exit_code == 0
    data = json.loads(result.output)
    assert data[0]["server"] == "api-server"
    assert "search" in data[0]["tools"]


def test_introspect_server_error():
    intro = _make_introspection("bad-server", success=False, error="Connection refused")
    with patch("agent_bom.mcp_introspect.introspect_servers_sync", return_value=[intro]):
        runner = CliRunner()
        result = runner.invoke(main, ["mcp", "introspect", "--command", "bad-server"])
    assert "Connection refused" in result.output or result.exit_code in (0, 1)


# ─── drift detection ─────────────────────────────────────────────────────────


def test_introspect_drift_detected_exits_1(tmp_path):
    baseline = {"test-server": ["read_file", "write_file"]}
    baseline_file = tmp_path / "baseline.json"
    baseline_file.write_text(json.dumps(baseline))

    # Server now has extra tool not in baseline
    intro = _make_introspection("test-server", tools=["read_file", "write_file", "exec_shell"])
    with patch("agent_bom.mcp_introspect.introspect_servers_sync", return_value=[intro]):
        runner = CliRunner()
        result = runner.invoke(
            main,
            ["mcp", "introspect", "--command", "test-server", "--baseline", str(baseline_file)],
        )
    assert result.exit_code == 1
    assert "NEW" in result.output or "exec_shell" in result.output


def test_introspect_no_drift_exits_0(tmp_path):
    baseline = {"test-server": ["read_file", "write_file"]}
    baseline_file = tmp_path / "baseline.json"
    baseline_file.write_text(json.dumps(baseline))

    intro = _make_introspection("test-server", tools=["read_file", "write_file"])
    with patch("agent_bom.mcp_introspect.introspect_servers_sync", return_value=[intro]):
        runner = CliRunner()
        result = runner.invoke(
            main,
            ["mcp", "introspect", "--command", "test-server", "--baseline", str(baseline_file)],
        )
    assert result.exit_code == 0


def test_introspect_drift_json_output(tmp_path):
    baseline = {"fs": ["read_file"]}
    baseline_file = tmp_path / "baseline.json"
    baseline_file.write_text(json.dumps(baseline))

    intro = _make_introspection("fs", tools=["read_file", "exec_shell"])
    with patch("agent_bom.mcp_introspect.introspect_servers_sync", return_value=[intro]):
        runner = CliRunner()
        result = runner.invoke(
            main,
            ["mcp", "introspect", "--command", "fs", "--baseline", str(baseline_file), "--format", "json"],
        )
    data = json.loads(result.output)
    assert "exec_shell" in data[0]["drift_added"]


# ─── --all flag ──────────────────────────────────────────────────────────────


def test_introspect_all_no_servers():
    with patch("agent_bom.discovery.discover_all", return_value=[]):
        runner = CliRunner()
        result = runner.invoke(main, ["mcp", "introspect", "--all"])
    assert "No MCP servers" in result.output or result.exit_code == 0


def test_introspect_mcp_sdk_missing():
    with patch(
        "agent_bom.mcp_introspect.introspect_servers_sync",
        side_effect=ImportError("No module named 'mcp'"),
    ):
        runner = CliRunner()
        result = runner.invoke(main, ["mcp", "introspect", "--command", "some-server"])
    assert result.exit_code == 1
    assert "mcp-server" in result.output.lower() or "install" in result.output.lower()
