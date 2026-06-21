"""Lock-in for the MCP runtime sandbox posture (default-on, fail-closed).

Past audits flagged the runtime sandbox's default-opt-*out* as a sharp edge.
The current posture is the opposite — sandboxing is **on by default** and a
plain stdio command without an explicit ``--sandbox-image`` is **refused**
(fail-closed) rather than silently executed on the host. These tests assert
that posture explicitly so it cannot regress to a silent fail-open default.

Posture invariants pinned here:

1. ``SandboxConfig.enabled`` defaults to ``True``.
2. ``AGENT_BOM_MCP_SANDBOX`` unset (``None``) resolves to enabled.
3. A plain command under isolation with no image is required to carry an
   image (``sandbox_requires_image_for_command`` is ``True``).
4. ``build_sandboxed_command`` fail-closes (raises) on that path rather than
   running the command unsandboxed.
5. An existing ``docker run`` command is hardened in place without needing an
   operator image (it already names its own image).
6. The only bypass is the explicit ``--no-isolate`` opt-out / disable env
   value, which sets ``enabled=False`` and passes the command through.
7. The CLI surfaces (4) as a ``UsageError`` (fail-closed refusal), not a warn.
"""

from __future__ import annotations

from collections.abc import Coroutine
from unittest.mock import patch

import pytest
from click.testing import CliRunner

from agent_bom.cli.run import run_cmd
from agent_bom.proxy_sandbox import (
    SandboxConfig,
    build_sandboxed_command,
    sandbox_config_from_env,
    sandbox_requires_image_for_command,
)


def _consume_coroutine_and_return(value: int = 0):
    def _runner(coro: Coroutine) -> int:
        coro.close()
        return value

    return _runner


# ── Config-level posture ─────────────────────────────────────────────────────


def test_sandbox_enabled_by_default() -> None:
    """The dataclass default is sandbox-ON, not opt-in."""
    assert SandboxConfig().enabled is True


def test_sandbox_enabled_when_env_unset(monkeypatch: pytest.MonkeyPatch) -> None:
    """Unset AGENT_BOM_MCP_SANDBOX must resolve to enabled (default-on)."""
    monkeypatch.delenv("AGENT_BOM_MCP_SANDBOX", raising=False)
    config = sandbox_config_from_env(image="ghcr.io/acme/sandbox:1")
    assert config.enabled is True


@pytest.mark.parametrize("disable_value", ["0", "false", "no", "off", "disabled", "none"])
def test_sandbox_disable_env_is_explicit_opt_out(disable_value: str, monkeypatch: pytest.MonkeyPatch) -> None:
    """Only an explicit disable value flips the sandbox off."""
    monkeypatch.setenv("AGENT_BOM_MCP_SANDBOX", disable_value)
    config = sandbox_config_from_env()
    assert config.enabled is False


# ── Fail-closed: plain command without an image ──────────────────────────────


def test_plain_command_under_isolation_requires_image() -> None:
    """A plain stdio command + enabled sandbox + no image must demand an image."""
    config = SandboxConfig(enabled=True, image=None)
    assert sandbox_requires_image_for_command(["npx", "mcp-server-git"], config) is True


def test_build_sandboxed_command_fails_closed_without_image() -> None:
    """Fail-closed: no image for a plain command raises, never runs unsandboxed."""
    config = SandboxConfig(enabled=True, image=None)
    with pytest.raises(RuntimeError, match="requires --sandbox-image"):
        build_sandboxed_command(["npx", "mcp-server-git"], config, resolve_runtime=False)


def test_existing_container_run_does_not_need_operator_image() -> None:
    """A docker/podman run command already names its image and is hardened in place."""
    config = SandboxConfig(enabled=True, image=None)
    assert sandbox_requires_image_for_command(["docker", "run", "ghcr.io/acme/srv:1"], config) is False
    command, evidence = build_sandboxed_command(["docker", "run", "ghcr.io/acme/srv:1"], config, resolve_runtime=False)
    assert command[:2] == ["docker", "run"]
    assert evidence["mode"] == "harden_existing_container"
    # Hardening flags are injected even on the hardened-in-place path.
    assert "--read-only" in command
    assert "--cap-drop" in command


# ── Bypass gating: only --no-isolate / enabled=False passes through ───────────


def test_disabled_sandbox_passes_command_through_unwrapped() -> None:
    """The single bypass is an explicit opt-out; it returns the command verbatim."""
    config = SandboxConfig(enabled=False, image=None)
    assert sandbox_requires_image_for_command(["npx", "mcp-server-git"], config) is False
    command, evidence = build_sandboxed_command(["npx", "mcp-server-git"], config, resolve_runtime=False)
    assert command == ["npx", "mcp-server-git"]
    assert evidence["enabled"] is False


# ── CLI surface: refusal, not warn ───────────────────────────────────────────


def test_cli_refuses_plain_isolated_command_without_image() -> None:
    """The CLI fail-closes (UsageError exit 2), it does not warn-and-continue."""
    runner = CliRunner()
    with patch("agent_bom.project_config.load_project_config", return_value=None):
        result = runner.invoke(run_cmd, ["uvx/mcp-server-git", "--quiet"])
    assert result.exit_code == 2, result.output
    assert "requires --sandbox-image" in result.output
    assert "--no-isolate" in result.output


def test_cli_no_isolate_is_the_documented_bypass() -> None:
    """--no-isolate is the explicit, audited opt-out that lets a plain command run."""
    runner = CliRunner()
    with (
        patch("agent_bom.cli.run.asyncio.run") as mock_asyncio_run,
        patch("agent_bom.project_config.load_project_config", return_value=None),
    ):
        mock_asyncio_run.side_effect = _consume_coroutine_and_return()
        result = runner.invoke(run_cmd, ["uvx/mcp-server-git", "--quiet", "--no-isolate"])
    assert result.exit_code == 0, result.output
    mock_asyncio_run.assert_called_once()
