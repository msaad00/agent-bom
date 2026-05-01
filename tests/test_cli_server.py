"""Tests for agent_bom.cli._server to improve coverage."""

from __future__ import annotations

import os
from unittest.mock import MagicMock, patch

from click.testing import CliRunner

from agent_bom.cli._gateway import serve_cmd as gateway_serve_cmd
from agent_bom.cli._server import api_cmd, mcp_server_cmd, serve_cmd

# ---------------------------------------------------------------------------
# serve_cmd
# ---------------------------------------------------------------------------


def test_serve_cmd_no_uvicorn():
    CliRunner()
    with patch.dict("sys.modules", {"uvicorn": None}), patch("builtins.__import__", side_effect=ImportError("no uvicorn")):
        # Can't easily test import error path with click, skip if complex
        pass


def test_serve_cmd_missing_uvicorn():
    """Test serve command when uvicorn is not installed."""
    runner = CliRunner()

    import builtins

    original_import = builtins.__import__

    def mock_import(name, *args, **kwargs):
        if name == "uvicorn":
            raise ImportError("mocked")
        return original_import(name, *args, **kwargs)

    with patch("builtins.__import__", side_effect=mock_import):
        result = runner.invoke(serve_cmd, [])
        assert result.exit_code == 1


def test_serve_cmd_help_mentions_auth_for_non_loopback_bind():
    runner = CliRunner()
    result = runner.invoke(serve_cmd, ["--help"])
    assert result.exit_code == 0
    assert "non-loopback requires" in result.output
    assert "--allow-insecure-no-auth" in result.output
    assert "Local only:" in result.output
    assert "Remote with auth:" in result.output
    assert "serve --host 0.0.0.0 --api-key <key>" in result.output


def test_serve_cmd_invalid_port_is_usage_error():
    runner = CliRunner()
    result = runner.invoke(serve_cmd, ["--port", "99999"])

    assert result.exit_code == 2
    assert "Invalid value for '--port'" in result.output
    assert "1<=x<=65535" in result.output


# ---------------------------------------------------------------------------
# api_cmd
# ---------------------------------------------------------------------------


def test_api_cmd_missing_uvicorn():
    """Test api command when uvicorn is not installed."""
    runner = CliRunner()

    import builtins

    original_import = builtins.__import__

    def mock_import(name, *args, **kwargs):
        if name == "uvicorn":
            raise ImportError("mocked")
        return original_import(name, *args, **kwargs)

    with patch("builtins.__import__", side_effect=mock_import):
        result = runner.invoke(api_cmd, [])
        assert result.exit_code == 1
        assert "uvicorn" in result.output.lower()
        assert "uv pip install 'agent-bom[api]'" in result.output


def test_api_cmd_invalid_port_is_usage_error():
    runner = CliRunner()
    result = runner.invoke(api_cmd, ["--port", "0"])

    assert result.exit_code == 2
    assert "Invalid value for '--port'" in result.output
    assert "1<=x<=65535" in result.output


def test_api_cmd_rejects_unauthenticated_non_loopback_bind():
    """API should fail closed when exposed beyond loopback without auth."""
    runner = CliRunner()

    with patch("uvicorn.run") as mock_run:
        result = runner.invoke(api_cmd, ["--host", "0.0.0.0"])

    assert result.exit_code == 1
    assert "without authentication" in result.output
    mock_run.assert_not_called()


def test_api_cmd_allows_non_loopback_bind_with_api_key():
    """API should allow non-loopback exposure when API key auth is configured."""
    runner = CliRunner()

    with patch("agent_bom.api.server.configure_api") as mock_configure, patch("uvicorn.run") as mock_run:
        result = runner.invoke(api_cmd, ["--host", "0.0.0.0", "--api-key", "test-key"])

    assert result.exit_code == 0
    mock_configure.assert_called_once()
    mock_run.assert_called_once()
    assert "API key required" in result.output
    assert "Bind" in result.output


def test_api_cmd_loopback_no_auth_warns_local_mode():
    runner = CliRunner()

    with patch("agent_bom.api.server.configure_api") as mock_configure, patch("uvicorn.run") as mock_run:
        result = runner.invoke(api_cmd, [])

    assert result.exit_code == 0
    mock_configure.assert_called_once()
    mock_run.assert_called_once()
    assert "local unauthenticated mode" in result.output
    assert "In-memory (ephemeral)" in result.output


def test_api_cmd_enables_clickhouse_analytics():
    runner = CliRunner()

    with (
        patch.dict(os.environ, {}, clear=False),
        patch("agent_bom.api.server.configure_api") as mock_configure,
        patch("uvicorn.run") as mock_run,
    ):
        result = runner.invoke(
            api_cmd,
            [
                "--host",
                "0.0.0.0",
                "--api-key",
                "test-key",
                "--analytics-backend",
                "clickhouse",
                "--clickhouse-url",
                "http://clickhouse:8123",
            ],
        )

    assert result.exit_code == 0
    mock_configure.assert_called_once()
    mock_run.assert_called_once()
    assert "ClickHouse" in result.output
    assert "Analytics URL" in result.output


def test_api_cmd_requires_clickhouse_url_for_backend():
    runner = CliRunner()

    with patch.dict(os.environ, {"AGENT_BOM_CLICKHOUSE_URL": ""}, clear=False), patch("uvicorn.run") as mock_run:
        result = runner.invoke(api_cmd, ["--api-key", "test-key", "--analytics-backend", "clickhouse"])

    assert result.exit_code == 1
    assert "ClickHouse analytics requires" in result.output
    mock_run.assert_not_called()


def test_gateway_serve_invalid_bind_port_is_usage_error(tmp_path):
    runner = CliRunner()
    upstreams = tmp_path / "upstreams.yml"
    upstreams.write_text("upstreams:\n  - name: jira\n    url: https://jira.example.com/mcp\n", encoding="utf-8")

    result = runner.invoke(
        gateway_serve_cmd,
        ["--bind", "127.0.0.1:99999", "--upstreams", str(upstreams)],
    )

    assert result.exit_code == 2
    assert "--bind port must be in range 1..65535" in result.output


def test_gateway_serve_policy_json_error_is_wrapped(tmp_path):
    runner = CliRunner()
    upstreams = tmp_path / "upstreams.yml"
    upstreams.write_text("upstreams:\n  - name: jira\n    url: https://jira.example.com/mcp\n", encoding="utf-8")
    policy = tmp_path / "policy.json"
    policy.write_text("{bad", encoding="utf-8")

    result = runner.invoke(
        gateway_serve_cmd,
        ["--bind", "127.0.0.1:8090", "--upstreams", str(upstreams), "--policy", str(policy)],
    )

    assert result.exit_code == 1
    assert "policy file JSON error" in result.output
    assert "JSONDecodeError" not in result.output


def test_serve_cmd_rejects_unauthenticated_non_loopback_bind():
    """Serve should use the same auth-default guard as the raw API command."""
    runner = CliRunner()

    with patch("uvicorn.run") as mock_run:
        result = runner.invoke(serve_cmd, ["--host", "0.0.0.0"])

    assert result.exit_code == 1
    assert "without authentication" in result.output
    mock_run.assert_not_called()


def test_serve_cmd_configures_api_auth():
    """Serve should route through configure_api so dashboard and API stay aligned."""
    runner = CliRunner()

    with patch("agent_bom.api.server.configure_api") as mock_configure, patch("uvicorn.run") as mock_run:
        result = runner.invoke(serve_cmd, ["--api-key", "test-key"])

    assert result.exit_code == 0
    mock_configure.assert_called_once()
    mock_run.assert_called_once()
    assert "API key required" in result.output
    assert "Storage" in result.output


def test_serve_cmd_loopback_no_auth_warns_local_mode():
    runner = CliRunner()

    with patch("agent_bom.api.server.configure_api") as mock_configure, patch("uvicorn.run") as mock_run:
        result = runner.invoke(serve_cmd, [])

    assert result.exit_code == 0
    mock_configure.assert_called_once()
    mock_run.assert_called_once()
    assert "local unauthenticated mode" in result.output
    assert "In-memory (ephemeral)" in result.output


def test_serve_cmd_enables_clickhouse_analytics():
    runner = CliRunner()

    with (
        patch.dict(os.environ, {}, clear=False),
        patch("agent_bom.api.server.configure_api") as mock_configure,
        patch("uvicorn.run") as mock_run,
    ):
        result = runner.invoke(
            serve_cmd,
            ["--api-key", "test-key", "--analytics-backend", "clickhouse", "--clickhouse-url", "http://clickhouse:8123"],
        )

    assert result.exit_code == 0
    mock_configure.assert_called_once()
    mock_run.assert_called_once()
    assert "ClickHouse" in result.output
    assert "Analytics URL" in result.output


def test_serve_cmd_requires_clickhouse_url_for_backend():
    runner = CliRunner()

    with patch.dict(os.environ, {"AGENT_BOM_CLICKHOUSE_URL": ""}, clear=False), patch("uvicorn.run") as mock_run:
        result = runner.invoke(serve_cmd, ["--api-key", "test-key", "--analytics-backend", "clickhouse"])

    assert result.exit_code == 1
    assert "ClickHouse analytics requires" in result.output
    mock_run.assert_not_called()


# ---------------------------------------------------------------------------
# mcp_server_cmd
# ---------------------------------------------------------------------------


def test_mcp_server_cmd_stdio():
    """Test mcp-server command in stdio mode — just verify it starts."""
    runner = CliRunner()

    mock_server = MagicMock()
    with patch("agent_bom.mcp_server.create_mcp_server", return_value=mock_server):
        runner.invoke(mcp_server_cmd, [], catch_exceptions=False)
        mock_server.run.assert_called_once_with(transport="stdio")


def test_mcp_server_cmd_sse():
    """Test mcp-server command in SSE mode."""
    runner = CliRunner()

    mock_server = MagicMock()
    with patch("agent_bom.mcp_server.create_mcp_server", return_value=mock_server):
        runner.invoke(mcp_server_cmd, ["--transport", "sse"], catch_exceptions=False)
        mock_server.run.assert_called_once_with(transport="sse")


def test_mcp_server_cmd_rejects_unauthenticated_non_loopback_remote_bind():
    """Remote MCP transports should fail closed on non-loopback binds without auth."""
    runner = CliRunner()

    with patch("agent_bom.mcp_server.create_mcp_server") as mock_create:
        result = runner.invoke(mcp_server_cmd, ["--transport", "sse", "--host", "0.0.0.0"])

    assert result.exit_code == 1
    assert "without transport authentication" in result.output
    mock_create.assert_not_called()


def test_mcp_server_cmd_allows_remote_bind_with_bearer_token():
    """Remote MCP transports should allow non-loopback binds when bearer auth is configured."""
    runner = CliRunner()
    mock_server = MagicMock()

    with patch("agent_bom.mcp_server.create_mcp_server", return_value=mock_server) as mock_create:
        result = runner.invoke(
            mcp_server_cmd,
            ["--transport", "sse", "--host", "0.0.0.0", "--bearer-token", "test-token"],
            catch_exceptions=False,
        )

    assert result.exit_code == 0
    mock_create.assert_called_once_with(host="0.0.0.0", port=8423, bearer_token="test-token")
    mock_server.run.assert_called_once_with(transport="sse")
    assert "Bearer token required" in result.output
    assert "Transport" in result.output


def test_mcp_server_cmd_stdio_warns_when_bearer_token_is_unused():
    """Bearer auth config should warn when used with stdio transport."""
    runner = CliRunner()
    mock_server = MagicMock()

    with patch("agent_bom.mcp_server.create_mcp_server", return_value=mock_server):
        result = runner.invoke(mcp_server_cmd, ["--bearer-token", "test-token"], catch_exceptions=False)

    assert result.exit_code == 0
    assert "applies only to SSE / Streamable HTTP" in result.output


def test_gateway_serve_rejects_unauthenticated_non_loopback_bind(tmp_path):
    runner = CliRunner()
    upstreams = tmp_path / "upstreams.yaml"
    upstreams.write_text("upstreams:\n  - name: jira\n    url: https://jira.example.com/mcp\n")

    result = runner.invoke(gateway_serve_cmd, ["--bind", "0.0.0.0:8090", "--upstreams", str(upstreams)])
    assert result.exit_code == 1
    assert "without transport authentication" in result.output


def test_gateway_serve_allows_non_loopback_bind_with_bearer_token(tmp_path):
    runner = CliRunner()
    upstreams = tmp_path / "upstreams.yaml"
    upstreams.write_text("upstreams:\n  - name: jira\n    url: https://jira.example.com/mcp\n")

    with patch("uvicorn.run") as mock_run:
        result = runner.invoke(gateway_serve_cmd, ["--bind", "0.0.0.0:8090", "--upstreams", str(upstreams), "--bearer-token", "gw-token"])

    assert result.exit_code == 0
    assert "token required" in result.output
    assert "Upstreams" in result.output
    assert "Bind" in result.output
    assert "No runtime policy rules configured." in result.output
    mock_run.assert_called_once()


def test_gateway_serve_requires_visual_runtime_when_enabled(tmp_path):
    runner = CliRunner()
    upstreams = tmp_path / "upstreams.yaml"
    upstreams.write_text("upstreams:\n  - name: jira\n    url: https://jira.example.com/mcp\n")

    with patch("agent_bom.runtime.visual_leak_detector.visual_leak_runtime_ready", return_value=False):
        result = runner.invoke(
            gateway_serve_cmd,
            ["--bind", "127.0.0.1:8090", "--upstreams", str(upstreams), "--detect-visual-leaks"],
        )

    assert result.exit_code == 1
    assert "Visual leak detection requires" in result.output


def test_gateway_serve_passes_runtime_rate_limit_settings(tmp_path):
    runner = CliRunner()
    upstreams = tmp_path / "upstreams.yaml"
    upstreams.write_text("upstreams:\n  - name: jira\n    url: https://jira.example.com/mcp\n")

    with (
        patch("agent_bom.gateway_server.create_gateway_app") as mock_create_app,
        patch("uvicorn.run") as mock_run,
    ):
        mock_create_app.return_value = object()
        result = runner.invoke(
            gateway_serve_cmd,
            [
                "--bind",
                "127.0.0.1:8090",
                "--upstreams",
                str(upstreams),
                "--runtime-rate-limit-per-tenant-per-minute",
                "120",
                "--require-shared-rate-limit",
            ],
        )

    assert result.exit_code == 0
    settings = mock_create_app.call_args.args[0]
    assert settings.runtime_rate_limit_per_tenant_per_minute == 120
    assert settings.require_shared_rate_limit is True
    mock_run.assert_called_once()


def test_gateway_serve_rejects_policy_reload_without_policy_file():
    runner = CliRunner()
    with runner.isolated_filesystem():
        upstreams = "upstreams.yaml"
        with open(upstreams, "w", encoding="utf-8") as handle:
            handle.write("upstreams:\n  - name: jira\n    url: https://jira.example.com/mcp\n")
        result = runner.invoke(
            gateway_serve_cmd,
            ["--bind", "127.0.0.1:8090", "--upstreams", upstreams, "--policy-reload-seconds", "5"],
        )
    assert result.exit_code == 1
    assert "--policy-reload-seconds requires --policy" in result.output


def test_gateway_serve_passes_policy_reload_settings(tmp_path):
    runner = CliRunner()
    upstreams = tmp_path / "upstreams.yaml"
    policy = tmp_path / "policy.json"
    upstreams.write_text("upstreams:\n  - name: jira\n    url: https://jira.example.com/mcp\n")
    policy.write_text('{"rules":[]}')

    with (
        patch("agent_bom.gateway_server.create_gateway_app") as mock_create_app,
        patch("uvicorn.run") as mock_run,
    ):
        mock_create_app.return_value = object()
        result = runner.invoke(
            gateway_serve_cmd,
            [
                "--bind",
                "127.0.0.1:8090",
                "--upstreams",
                str(upstreams),
                "--policy",
                str(policy),
                "--policy-reload-seconds",
                "5",
            ],
        )

    assert result.exit_code == 0
    settings = mock_create_app.call_args.args[0]
    assert settings.policy_path == policy
    assert settings.policy_reload_interval_seconds == 5
    assert "Policy hot reload: enabled every 5s" in result.output
    mock_run.assert_called_once()


def test_gateway_serve_reports_advisory_only_policy_summary(tmp_path):
    runner = CliRunner()
    upstreams = tmp_path / "upstreams.yaml"
    policy = tmp_path / "policy.json"
    upstreams.write_text("upstreams:\n  - name: jira\n    url: https://jira.example.com/mcp\n")
    policy.write_text('{"rules":[{"id":"warn-secret","block_secret_paths":true}]}')

    with (
        patch("agent_bom.gateway_server.create_gateway_app") as mock_create_app,
        patch("uvicorn.run") as mock_run,
    ):
        mock_create_app.return_value = object()
        result = runner.invoke(
            gateway_serve_cmd,
            [
                "--bind",
                "127.0.0.1:8090",
                "--upstreams",
                str(upstreams),
                "--policy",
                str(policy),
            ],
        )

    assert result.exit_code == 0
    assert "Policy matches are advisory only; runtime will not block." in result.output
    assert "Rules=1 (block=0, warn=1)" in result.output
    mock_run.assert_called_once()


def test_mcp_server_cmd_missing_sdk():
    """Test mcp-server command when MCP SDK is not installed."""
    runner = CliRunner()

    import builtins

    original_import = builtins.__import__

    def mock_import(name, *args, **kwargs):
        if "mcp_server" in name and "create_mcp_server" not in str(args):
            raise ImportError("mocked")
        return original_import(name, *args, **kwargs)

    with patch("agent_bom.mcp_server.create_mcp_server", side_effect=ImportError("no mcp")):
        result = runner.invoke(mcp_server_cmd, [])
        assert result.exit_code == 1
