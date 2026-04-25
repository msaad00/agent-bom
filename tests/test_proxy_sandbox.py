from __future__ import annotations

from pathlib import Path

import pytest

from agent_bom.proxy_sandbox import (
    SandboxConfig,
    build_sandboxed_command,
    parse_sandbox_mount,
    sandbox_config_from_env,
)

PINNED_IMAGE = "ghcr.io/acme/mcp-sandbox:1@sha256:" + "a" * 64


def test_parse_sandbox_mount_defaults_to_readonly(tmp_path):
    mount = parse_sandbox_mount(f"{tmp_path}:/workspace")

    assert mount.source == str(tmp_path.resolve())
    assert mount.target == "/workspace"
    assert mount.readonly is True
    assert mount.as_docker_mount().endswith(",readonly")


def test_parse_sandbox_mount_accepts_rw(tmp_path):
    mount = parse_sandbox_mount(f"{tmp_path}:/workspace:rw")

    assert mount.readonly is False
    assert mount.as_docker_mount().endswith(",rw")


@pytest.mark.parametrize(
    "source",
    [
        "/",
        "/etc",
        "/proc",
        "/sys",
        "/dev",
        "/var/run",
        "/var/run/docker.sock",
    ],
)
def test_parse_sandbox_mount_rejects_sensitive_host_sources(source):
    with pytest.raises(ValueError, match="too sensitive"):
        parse_sandbox_mount(f"{source}:/workspace")


def test_parse_sandbox_mount_rejects_common_user_secret_dirs(monkeypatch, tmp_path):
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    ssh_dir = tmp_path / ".ssh"
    ssh_dir.mkdir()

    with pytest.raises(ValueError, match="too sensitive"):
        parse_sandbox_mount(f"{ssh_dir}:/workspace")


def test_parse_sandbox_mount_rejects_symlink_to_sensitive_path(tmp_path):
    link = tmp_path / "etc-link"
    link.symlink_to("/etc", target_is_directory=True)

    with pytest.raises(ValueError, match="too sensitive"):
        parse_sandbox_mount(f"{link}:/workspace")


def test_parse_sandbox_mount_requires_existing_source(tmp_path):
    missing = tmp_path / "missing"

    with pytest.raises(FileNotFoundError):
        parse_sandbox_mount(f"{missing}:/workspace")


def test_parse_sandbox_mount_requires_absolute_container_target(tmp_path):
    with pytest.raises(ValueError, match="container path must be absolute"):
        parse_sandbox_mount(f"{tmp_path}:workspace")


def test_sandbox_config_from_env_parses_operator_values(monkeypatch, tmp_path):
    monkeypatch.setenv("AGENT_BOM_MCP_SANDBOX", "true")
    monkeypatch.setenv("AGENT_BOM_MCP_SANDBOX_RUNTIME", "podman")
    monkeypatch.setenv("AGENT_BOM_MCP_SANDBOX_IMAGE", "ghcr.io/acme/mcp-sandbox:1")
    monkeypatch.setenv("AGENT_BOM_MCP_SANDBOX_IMAGE_PIN_POLICY", "enforce")
    monkeypatch.setenv("AGENT_BOM_MCP_SANDBOX_MOUNTS", f"{tmp_path}:/workspace")

    config = sandbox_config_from_env()

    assert config.enabled is True
    assert config.runtime == "podman"
    assert config.image == "ghcr.io/acme/mcp-sandbox:1"
    assert config.image_pin_policy == "enforce"
    assert config.mounts[0].target == "/workspace"


def test_sandbox_config_defaults_are_bounded_and_network_none(monkeypatch):
    monkeypatch.delenv("AGENT_BOM_MCP_SANDBOX_EGRESS", raising=False)
    monkeypatch.delenv("AGENT_BOM_MCP_SANDBOX_CPUS", raising=False)
    monkeypatch.delenv("AGENT_BOM_MCP_SANDBOX_MEMORY", raising=False)
    monkeypatch.delenv("AGENT_BOM_MCP_SANDBOX_PIDS_LIMIT", raising=False)
    monkeypatch.delenv("AGENT_BOM_MCP_SANDBOX_TMPFS_SIZE", raising=False)
    monkeypatch.delenv("AGENT_BOM_MCP_SANDBOX_TIMEOUT_SECONDS", raising=False)
    monkeypatch.setattr("agent_bom.proxy_sandbox.resolve_container_runtime", lambda runtime: "docker")

    config = sandbox_config_from_env(enabled=True, image="ghcr.io/acme/mcp-sandbox:1")
    command, evidence = build_sandboxed_command(["npx", "--yes", "@mcp/server"], config)

    assert config.egress_policy == "deny"
    assert command[command.index("--network") + 1] == "none"
    assert command[command.index("--cpus") + 1] == "1"
    assert command[command.index("--memory") + 1] == "512m"
    assert command[command.index("--pids-limit") + 1] == "256"
    assert command[command.index("--tmpfs") + 1] == "/tmp:size=64m,mode=1777"
    assert evidence["egress_policy"] == "deny"
    assert evidence["network"] == "none"
    assert evidence["cpus"] == "1"
    assert evidence["memory"] == "512m"
    assert evidence["pids_limit"] == 256
    assert evidence["tmpfs_size"] == "64m"
    assert evidence["timeout_seconds"] == 300
    assert evidence["image_pin_policy"] == "warn"
    assert evidence["image_pinned"] is False
    assert evidence["image_pin_warning"]


def test_build_sandboxed_command_wraps_non_container_command(monkeypatch):
    monkeypatch.setattr("agent_bom.proxy_sandbox.resolve_container_runtime", lambda runtime: "docker")
    config = SandboxConfig(
        enabled=True,
        runtime="auto",
        image="ghcr.io/acme/mcp-sandbox:1",
        cpus="0.5",
        memory="256m",
        pids_limit=64,
        tmpfs_size="32m",
        timeout_seconds=300,
    )

    command, evidence = build_sandboxed_command(["npx", "--yes", "@mcp/server"], config)

    assert command[:2] == ["docker", "run"]
    assert "--read-only" in command
    assert ["--cap-drop", "ALL"] == command[command.index("--cap-drop") : command.index("--cap-drop") + 2]
    assert ["--network", "none"] == command[command.index("--network") : command.index("--network") + 2]
    assert ["--cpus", "0.5"] == command[command.index("--cpus") : command.index("--cpus") + 2]
    assert ["--memory", "256m"] == command[command.index("--memory") : command.index("--memory") + 2]
    assert ["--pids-limit", "64"] == command[command.index("--pids-limit") : command.index("--pids-limit") + 2]
    assert ["/tmp:size=32m,mode=1777"] == command[command.index("--tmpfs") + 1 : command.index("--tmpfs") + 2]
    assert "ghcr.io/acme/mcp-sandbox:1" in command
    assert command[-3:] == ["npx", "--yes", "@mcp/server"]
    assert evidence["mode"] == "wrap_command_in_image"
    assert evidence["enabled"] is True
    assert evidence["timeout_seconds"] == 300
    assert evidence["image_pin_policy"] == "warn"
    assert evidence["image_pinned"] is False
    assert evidence["image_pin_warning"]


def test_build_sandboxed_command_records_digest_pinned_image(monkeypatch):
    monkeypatch.setattr("agent_bom.proxy_sandbox.resolve_container_runtime", lambda runtime: "docker")
    config = SandboxConfig(enabled=True, runtime="docker", image=PINNED_IMAGE, image_pin_policy="enforce")

    command, evidence = build_sandboxed_command(["npx", "--yes", "@mcp/server"], config)

    assert PINNED_IMAGE in command
    assert evidence["image"] == PINNED_IMAGE
    assert evidence["image_pinned"] is True
    assert evidence["image_pin_policy"] == "enforce"
    assert evidence["image_pin_warning"] is None


def test_build_sandboxed_command_rejects_tag_only_image_in_enforce_mode(monkeypatch):
    monkeypatch.setattr("agent_bom.proxy_sandbox.resolve_container_runtime", lambda runtime: "docker")
    config = SandboxConfig(enabled=True, runtime="docker", image="ghcr.io/acme/server:1", image_pin_policy="enforce")

    with pytest.raises(RuntimeError, match="requires a digest"):
        build_sandboxed_command(["npx", "@mcp/server"], config)


def test_build_sandboxed_command_hardens_existing_container_run(monkeypatch):
    monkeypatch.setattr("agent_bom.proxy_sandbox.resolve_container_runtime", lambda runtime: "podman")
    config = SandboxConfig(enabled=True, runtime="podman")

    command, evidence = build_sandboxed_command(["docker", "run", "--rm", "-i", "ghcr.io/acme/server:1"], config)

    assert command[:2] == ["podman", "run"]
    assert "--read-only" in command
    assert "--network" in command
    assert "ghcr.io/acme/server:1" in command
    assert evidence["mode"] == "harden_existing_container"
    assert evidence["runtime"] == "podman"
    assert evidence["image"] == "ghcr.io/acme/server:1"
    assert evidence["image_pinned"] is False
    assert evidence["image_pin_warning"]


def test_build_sandboxed_command_enforces_digest_for_existing_container_run(monkeypatch):
    monkeypatch.setattr("agent_bom.proxy_sandbox.resolve_container_runtime", lambda runtime: "docker")
    config = SandboxConfig(enabled=True, runtime="docker", image_pin_policy="enforce")

    with pytest.raises(RuntimeError, match="requires a digest"):
        build_sandboxed_command(["docker", "run", "ghcr.io/acme/server:1"], config)


def test_build_sandboxed_command_strips_weaker_existing_container_flags(monkeypatch):
    monkeypatch.setattr("agent_bom.proxy_sandbox.resolve_container_runtime", lambda runtime: "docker")
    config = SandboxConfig(enabled=True, runtime="docker")

    command, _ = build_sandboxed_command(
        [
            "docker",
            "run",
            "--network",
            "host",
            "--privileged",
            "--cap-add=SYS_ADMIN",
            "--memory=8g",
            "ghcr.io/acme/server:1",
        ],
        config,
    )

    assert "host" not in command
    assert "--privileged" not in command
    assert "--cap-add=SYS_ADMIN" not in command
    assert "--memory=8g" not in command
    assert command[command.index("--network") + 1] == "none"


def test_allow_all_egress_uses_bridge_network(monkeypatch):
    monkeypatch.setattr("agent_bom.proxy_sandbox.resolve_container_runtime", lambda runtime: "docker")
    config = SandboxConfig(enabled=True, runtime="docker", image="ghcr.io/acme/server:1", egress_policy="allow_all")

    command, evidence = build_sandboxed_command(["npx", "@mcp/server"], config)

    assert command[command.index("--network") + 1] == "bridge"
    assert evidence["egress_policy"] == "allow_all"
    assert evidence["network"] == "bridge"


def test_build_sandboxed_command_requires_image_for_plain_commands(monkeypatch):
    monkeypatch.setattr("agent_bom.proxy_sandbox.resolve_container_runtime", lambda runtime: "docker")

    with pytest.raises(RuntimeError, match="requires --sandbox-image"):
        build_sandboxed_command(["python", "-m", "server"], SandboxConfig(enabled=True))
