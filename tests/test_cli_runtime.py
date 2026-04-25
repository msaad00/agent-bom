"""Tests for agent_bom.cli._runtime to improve coverage."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

from click.testing import CliRunner

from agent_bom.cli._runtime import (
    _NoOpDetector,
    audit_replay_cmd,
    proxy_bootstrap_cmd,
    proxy_cmd,
    proxy_configure_cmd,
    watch_cmd,
)

# ---------------------------------------------------------------------------
# _NoOpDetector
# ---------------------------------------------------------------------------


def test_noop_detector_check():
    d = _NoOpDetector()
    assert d.check("anything") == []
    assert d.check(tool="x", args={}) == []


def test_noop_detector_record():
    d = _NoOpDetector()
    assert d.record("anything") == []


# ---------------------------------------------------------------------------
# proxy_cmd
# ---------------------------------------------------------------------------


def test_proxy_cmd_runs_proxy(tmp_path):
    runner = CliRunner()
    with (
        patch("agent_bom.proxy.run_proxy", new_callable=AsyncMock, return_value=0),
        patch("agent_bom.project_config.load_project_config", return_value=None),
    ):
        result = runner.invoke(proxy_cmd, ["--", "echo", "hello"])
        assert result.exit_code == 0


def test_proxy_cmd_with_project_config():
    runner = CliRunner()
    with (
        patch("agent_bom.proxy.run_proxy", new_callable=AsyncMock, return_value=0),
        patch("agent_bom.project_config.load_project_config", return_value={"policy": "test.json"}),
        patch("agent_bom.project_config.get_policy_path", return_value=None),
    ):
        result = runner.invoke(proxy_cmd, ["--", "echo"])
        assert result.exit_code == 0


def test_proxy_cmd_passes_control_plane_settings():
    runner = CliRunner()
    with (
        patch("agent_bom.proxy.run_proxy", new_callable=AsyncMock, return_value=0) as mock_run,
        patch("agent_bom.project_config.load_project_config", return_value=None),
    ):
        result = runner.invoke(
            proxy_cmd,
            [
                "--control-plane-url",
                "https://agent-bom.internal.example.com",
                "--control-plane-token",
                "token-123",
                "--policy-refresh-seconds",
                "45",
                "--audit-push-interval",
                "15",
                "--",
                "echo",
                "hello",
            ],
        )
        assert result.exit_code == 0
    assert mock_run.await_args.kwargs["control_plane_url"] == "https://agent-bom.internal.example.com"
    assert mock_run.await_args.kwargs["control_plane_token"] == "token-123"
    assert mock_run.await_args.kwargs["policy_refresh_seconds"] == 45
    assert mock_run.await_args.kwargs["audit_push_interval"] == 15


def test_proxy_cmd_passes_sandbox_config():
    runner = CliRunner()
    with (
        patch("agent_bom.proxy.run_proxy", new_callable=AsyncMock, return_value=0) as mock_run,
        patch("agent_bom.project_config.load_project_config", return_value=None),
    ):
        result = runner.invoke(
            proxy_cmd,
            [
                "--isolate",
                "--sandbox-runtime",
                "docker",
                "--sandbox-image",
                "ghcr.io/acme/mcp-sandbox:1",
                "--",
                "npx",
                "@mcp/server",
            ],
        )
        assert result.exit_code == 0
    config = mock_run.await_args.kwargs["sandbox_config"]
    assert config.enabled is True
    assert config.runtime == "docker"
    assert config.image == "ghcr.io/acme/mcp-sandbox:1"


# ---------------------------------------------------------------------------
# proxy_configure_cmd
# ---------------------------------------------------------------------------


def test_proxy_configure_no_servers():
    runner = CliRunner()
    with (
        patch("agent_bom.discovery.discover_all", return_value=[]),
        patch("agent_bom.proxy_configure.auto_configure_proxies", return_value=[]),
    ):
        result = runner.invoke(proxy_configure_cmd, [])
        assert result.exit_code == 0
        assert "No eligible" in result.output


def test_proxy_configure_with_servers():
    runner = CliRunner()
    mock_cfg = MagicMock()
    mock_cfg.server_name = "test-server"
    mock_cfg.config_path = "/test/config.json"
    mock_cfg.original_command = "npx"
    mock_cfg.original_args = ["@mcp/test"]
    mock_cfg.proxied_args = ["proxy", "--", "npx", "@mcp/test"]

    with (
        patch("agent_bom.discovery.discover_all", return_value=[]),
        patch("agent_bom.proxy_configure.auto_configure_proxies", return_value=[mock_cfg]),
    ):
        result = runner.invoke(proxy_configure_cmd, [])
        assert result.exit_code == 0
        assert "test-server" in result.output
        assert "Pass --apply" in result.output


def test_proxy_configure_apply():
    runner = CliRunner()
    mock_cfg = MagicMock()
    mock_cfg.server_name = "srv"
    mock_cfg.config_path = "/c.json"
    mock_cfg.original_command = "npx"
    mock_cfg.original_args = ["x"]
    mock_cfg.proxied_args = ["proxy", "--", "npx", "x"]

    with (
        patch("agent_bom.discovery.discover_all", return_value=[]),
        patch("agent_bom.proxy_configure.auto_configure_proxies", return_value=[mock_cfg]),
        patch("agent_bom.proxy_configure.apply_proxy_configs", return_value=1) as mock_apply,
    ):
        result = runner.invoke(proxy_configure_cmd, ["--apply"])
        assert result.exit_code == 0
        mock_apply.assert_called_once()
        assert "Patched" in result.output


def test_proxy_configure_apply_no_patch():
    runner = CliRunner()
    mock_cfg = MagicMock()
    mock_cfg.server_name = "srv"
    mock_cfg.config_path = "/c.json"
    mock_cfg.original_command = "npx"
    mock_cfg.original_args = []
    mock_cfg.proxied_args = ["proxy", "--", "npx"]

    with (
        patch("agent_bom.discovery.discover_all", return_value=[]),
        patch("agent_bom.proxy_configure.auto_configure_proxies", return_value=[mock_cfg]),
        patch("agent_bom.proxy_configure.apply_proxy_configs", return_value=0),
    ):
        result = runner.invoke(proxy_configure_cmd, ["--apply"])
        assert result.exit_code == 0


def test_proxy_configure_secure_defaults_enabled_by_default():
    runner = CliRunner()
    with (
        patch("agent_bom.discovery.discover_all", return_value=[]),
        patch("agent_bom.proxy_configure.auto_configure_proxies", return_value=[]) as mock_auto_configure,
    ):
        result = runner.invoke(proxy_configure_cmd, [])
        assert result.exit_code == 0
    mock_auto_configure.assert_called_once()
    assert mock_auto_configure.call_args.kwargs["secure_defaults"] is True


def test_proxy_configure_secure_defaults_can_be_disabled():
    runner = CliRunner()
    with (
        patch("agent_bom.discovery.discover_all", return_value=[]),
        patch("agent_bom.proxy_configure.auto_configure_proxies", return_value=[]) as mock_auto_configure,
    ):
        result = runner.invoke(proxy_configure_cmd, ["--no-secure-defaults"])
        assert result.exit_code == 0
    mock_auto_configure.assert_called_once()
    assert mock_auto_configure.call_args.kwargs["secure_defaults"] is False


def test_proxy_configure_passes_control_plane_settings():
    runner = CliRunner()
    with (
        patch("agent_bom.discovery.discover_all", return_value=[]),
        patch("agent_bom.proxy_configure.auto_configure_proxies", return_value=[]) as mock_auto_configure,
    ):
        result = runner.invoke(
            proxy_configure_cmd,
            [
                "--control-plane-url",
                "https://agent-bom.internal.example.com",
                "--control-plane-token",
                "token-123",
                "--policy-refresh-seconds",
                "45",
                "--audit-push-interval",
                "15",
            ],
        )
        assert result.exit_code == 0
    assert mock_auto_configure.call_args.kwargs["control_plane_url"] == "https://agent-bom.internal.example.com"
    assert mock_auto_configure.call_args.kwargs["control_plane_token"] == "token-123"
    assert mock_auto_configure.call_args.kwargs["policy_refresh_seconds"] == 45
    assert mock_auto_configure.call_args.kwargs["audit_push_interval"] == 15


def test_proxy_bootstrap_writes_bundle(tmp_path):
    runner = CliRunner()
    result = runner.invoke(
        proxy_bootstrap_cmd,
        [
            "--bundle-dir",
            str(tmp_path),
            "--control-plane-url",
            "https://agent-bom.internal.example.com",
            "--control-plane-token",
            "token-123",
            "--push-url",
            "https://agent-bom.internal.example.com/v1/fleet/sync",
            "--push-api-key",
            "fleet-key",
            "--source-id",
            "device-acme-001",
            "--enrollment-name",
            "corp-rollout",
            "--owner",
            "platform-security",
            "--environment",
            "production",
            "--tag",
            "developer-endpoint",
            "--tag",
            "mdm",
            "--mdm-provider",
            "jamf",
        ],
    )
    assert result.exit_code == 0
    assert "Wrote endpoint onboarding bundle" in result.output
    assert (tmp_path / "install-agent-bom-endpoint.sh").exists()
    assert (tmp_path / "install-agent-bom-endpoint.ps1").exists()
    assert (tmp_path / "jamf" / "install-agent-bom-endpoint.sh").exists()
    assert (tmp_path / "intune" / "install-agent-bom-endpoint.ps1").exists()
    assert (tmp_path / "intune" / "detect-agent-bom-endpoint.ps1").exists()
    assert (tmp_path / "kandji" / "install-agent-bom-endpoint.sh").exists()
    assert (tmp_path / "endpoint-onboarding-summary.json").exists()
    assert (tmp_path / "endpoint-enrollment.json").exists()


# ---------------------------------------------------------------------------
# watch_cmd
# ---------------------------------------------------------------------------


def test_watch_cmd_no_dirs():
    runner = CliRunner()
    with patch("agent_bom.watch.discover_config_dirs", return_value=[]):
        result = runner.invoke(watch_cmd, [])
        assert result.exit_code == 0
        assert "No MCP config directories" in result.output


# ---------------------------------------------------------------------------
# audit_replay_cmd
# ---------------------------------------------------------------------------


def test_audit_replay_cmd(tmp_path):
    import json

    log_file = tmp_path / "audit.jsonl"
    log_file.write_text(json.dumps({"type": "tools/call", "tool": "read", "policy": "allowed"}) + "\n")

    runner = CliRunner()
    result = runner.invoke(audit_replay_cmd, [str(log_file)])
    assert result.exit_code == 0


def test_audit_replay_cmd_blocked(tmp_path):
    import json

    log_file = tmp_path / "audit.jsonl"
    log_file.write_text(json.dumps({"type": "tools/call", "tool": "x", "policy": "blocked", "reason": "test"}) + "\n")

    runner = CliRunner()
    result = runner.invoke(audit_replay_cmd, [str(log_file), "--blocked-only"])
    assert result.exit_code == 0


def test_audit_replay_cmd_json(tmp_path):
    import json

    log_file = tmp_path / "audit.jsonl"
    log_file.write_text(json.dumps({"type": "tools/call", "tool": "x", "policy": "blocked"}) + "\n")

    runner = CliRunner()
    result = runner.invoke(audit_replay_cmd, [str(log_file), "--json"])
    assert result.exit_code == 1  # blocked calls


def test_audit_replay_cmd_alerts_only(tmp_path):
    import json

    log_file = tmp_path / "audit.jsonl"
    log_file.write_text(json.dumps({"severity": "high", "detector": "cred", "tool": "t", "message": "m"}) + "\n")

    runner = CliRunner()
    result = runner.invoke(audit_replay_cmd, [str(log_file), "--alerts-only"])
    assert result.exit_code == 0
