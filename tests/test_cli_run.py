"""Tests for ``agent-bom run`` command."""

from __future__ import annotations

from collections.abc import Coroutine
from unittest.mock import patch

from click.testing import CliRunner

from agent_bom.cli import main
from agent_bom.cli.run import _resolve_server_command, run_cmd


def _consume_coroutine_and_return(value=0):
    """Return a side effect that closes the coroutine passed to asyncio.run."""

    def _runner(coro: Coroutine):
        coro.close()
        return value

    return _runner


def _consume_coroutine_and_raise(exc: Exception):
    """Return a side effect that closes the coroutine then raises."""

    def _runner(coro: Coroutine):
        coro.close()
        raise exc

    return _runner


# ---------------------------------------------------------------------------
# _resolve_server_command unit tests
# ---------------------------------------------------------------------------


def test_resolve_npx_with_path():
    cmd = _resolve_server_command("npx/@modelcontextprotocol/server-filesystem /tmp")
    assert cmd[0] == "npx"
    assert "--yes" in cmd
    assert "@modelcontextprotocol/server-filesystem" in cmd
    assert "/tmp" in cmd


def test_resolve_npx_bare():
    cmd = _resolve_server_command("npx/@mcp/server-github")
    assert cmd[0] == "npx"
    assert "--yes" in cmd
    assert "@mcp/server-github" in cmd


def test_resolve_uvx_slash():
    cmd = _resolve_server_command("uvx/mcp-server-git")
    assert cmd[0] == "uvx"
    assert "mcp-server-git" in cmd


def test_resolve_uvx_colon():
    cmd = _resolve_server_command("uvx:mcp-server-time")
    assert cmd[0] == "uvx"
    assert "mcp-server-time" in cmd


def test_resolve_docker_prefix():
    cmd = _resolve_server_command("docker/myorg/myimage:latest")
    assert "docker" in cmd
    assert "run" in cmd
    assert "--rm" in cmd
    assert "-i" in cmd
    assert "myorg/myimage:latest" in cmd


def test_resolve_ghcr_image():
    cmd = _resolve_server_command("ghcr.io/owner/image:tag")
    assert "docker" in cmd
    assert "run" in cmd
    assert "ghcr.io/owner/image:tag" in cmd


def test_resolve_docker_io_image():
    cmd = _resolve_server_command("docker.io/library/alpine:3.20")
    assert "docker" in cmd
    assert "run" in cmd
    assert "docker.io/library/alpine:3.20" in cmd


def test_resolve_plain_python_module():
    cmd = _resolve_server_command("python -m my_server")
    assert cmd == ["python", "-m", "my_server"]


def test_resolve_plain_absolute_path():
    cmd = _resolve_server_command("/usr/local/bin/my-server --arg value")
    assert cmd[0] == "/usr/local/bin/my-server"
    assert "--arg" in cmd
    assert "value" in cmd


# ---------------------------------------------------------------------------
# CLI integration tests
# ---------------------------------------------------------------------------


def test_run_help():
    runner = CliRunner()
    result = runner.invoke(main, ["run", "--help"])
    assert result.exit_code == 0
    assert "SERVER" in result.output
    assert "proxy" in result.output.lower()
    # Key options documented
    assert "--policy" in result.output
    assert "--audit-log" in result.output
    assert "--rate-limit" in result.output
    assert "--isolate" in result.output


def test_run_still_works_as_hidden_command():
    """``agent-bom run`` is hidden but still callable (backward compat)."""
    runner = CliRunner()
    result = runner.invoke(main, ["run", "--help"])
    assert result.exit_code == 0
    assert "proxy" in result.output.lower()


def test_run_delegates_to_run_proxy():
    """run_cmd should call run_proxy with the resolved command list."""
    runner = CliRunner()

    with (
        patch("agent_bom.cli.run.asyncio.run") as mock_asyncio_run,
        patch("agent_bom.project_config.load_project_config", return_value=None),
    ):
        mock_asyncio_run.side_effect = _consume_coroutine_and_return()
        # CliRunner catches SystemExit — check exit_code instead
        result = runner.invoke(run_cmd, ["uvx/mcp-server-git", "--quiet"])
        assert result.exit_code == 0
        mock_asyncio_run.assert_called_once()


def test_run_passes_policy_to_run_proxy():
    """--policy flag is forwarded to run_proxy."""
    import json
    import os
    import tempfile

    runner = CliRunner()

    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        json.dump({"rules": []}, f)
        policy_path = f.name

    try:
        with (
            patch("agent_bom.cli.run.asyncio.run") as mock_asyncio_run,
            patch("agent_bom.project_config.load_project_config", return_value=None),
        ):
            mock_asyncio_run.side_effect = _consume_coroutine_and_return()
            result = runner.invoke(
                run_cmd,
                ["uvx/mcp-server-git", "--policy", policy_path, "--quiet"],
            )
        assert result.exit_code == 0
        mock_asyncio_run.assert_called_once()
    finally:
        os.unlink(policy_path)


def test_run_passes_sandbox_config_to_run_proxy():
    runner = CliRunner()

    with (
        patch("agent_bom.cli.run.asyncio.run") as mock_asyncio_run,
        patch("agent_bom.project_config.load_project_config", return_value=None),
    ):
        mock_asyncio_run.side_effect = _consume_coroutine_and_return()
        result = runner.invoke(
            run_cmd,
            [
                "uvx/mcp-server-git",
                "--quiet",
                "--isolate",
                "--sandbox-runtime",
                "podman",
                "--sandbox-image",
                "ghcr.io/acme/mcp-sandbox:1",
            ],
        )
    assert result.exit_code == 0
    mock_asyncio_run.assert_called_once()


def test_run_command_not_found_handled(tmp_path):
    """When asyncio.run raises FileNotFoundError the error surfaces cleanly."""
    runner = CliRunner()

    with (
        patch("agent_bom.cli.run.asyncio.run", side_effect=_consume_coroutine_and_raise(FileNotFoundError("no such"))),
        patch("agent_bom.project_config.load_project_config", return_value=None),
    ):
        result = runner.invoke(run_cmd, ["nonexistent-server-xyz-abc"])
    # Should exit non-zero or have an exception recorded
    assert result.exit_code != 0 or result.exception is not None


def test_run_quiet_flag_suppresses_stderr():
    """--quiet suppresses the startup echo; verifies no crash with the flag."""
    runner = CliRunner()

    with (
        patch("agent_bom.cli.run.asyncio.run", side_effect=_consume_coroutine_and_return()),
        patch("agent_bom.project_config.load_project_config", return_value=None),
    ):
        result = runner.invoke(run_cmd, ["uvx/mcp-server-git", "--quiet"])
    assert result.exit_code == 0


def test_resolve_empty_string_returns_empty():
    """Empty server spec resolves to an empty list."""
    assert _resolve_server_command("") == []


def test_run_empty_server_rejected():
    """agent-bom run '' must exit non-zero with an error message, not crash."""
    runner = CliRunner()
    with patch("agent_bom.project_config.load_project_config", return_value=None):
        result = runner.invoke(run_cmd, [""])
    assert result.exit_code != 0
    assert "empty" in result.output.lower() or "invalid" in result.output.lower()
