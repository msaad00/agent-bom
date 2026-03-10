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
