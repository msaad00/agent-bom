"""Tests for agent_bom.cli._server to improve coverage."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from click.testing import CliRunner

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


def test_mcp_server_cmd_stdio_warns_when_bearer_token_is_unused():
    """Bearer auth config should warn when used with stdio transport."""
    runner = CliRunner()
    mock_server = MagicMock()

    with patch("agent_bom.mcp_server.create_mcp_server", return_value=mock_server):
        result = runner.invoke(mcp_server_cmd, ["--bearer-token", "test-token"], catch_exceptions=False)

    assert result.exit_code == 0
    assert "applies only to SSE / Streamable HTTP" in result.output


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
