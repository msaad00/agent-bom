from __future__ import annotations

import pytest

from agent_bom.proxy_sandbox import (
    SandboxConfig,
    build_sandboxed_command,
    parse_sandbox_mount,
    sandbox_config_from_env,
)


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


def test_sandbox_config_from_env_parses_operator_values(monkeypatch, tmp_path):
    monkeypatch.setenv("AGENT_BOM_MCP_SANDBOX", "true")
    monkeypatch.setenv("AGENT_BOM_MCP_SANDBOX_RUNTIME", "podman")
    monkeypatch.setenv("AGENT_BOM_MCP_SANDBOX_IMAGE", "ghcr.io/acme/mcp-sandbox:1")
    monkeypatch.setenv("AGENT_BOM_MCP_SANDBOX_MOUNTS", f"{tmp_path}:/workspace")

    config = sandbox_config_from_env()

    assert config.enabled is True
    assert config.runtime == "podman"
    assert config.image == "ghcr.io/acme/mcp-sandbox:1"
    assert config.mounts[0].target == "/workspace"


def test_build_sandboxed_command_wraps_non_container_command(monkeypatch):
    monkeypatch.setattr("agent_bom.proxy_sandbox.resolve_container_runtime", lambda runtime: "docker")
    config = SandboxConfig(enabled=True, runtime="auto", image="ghcr.io/acme/mcp-sandbox:1")

    command, evidence = build_sandboxed_command(["npx", "--yes", "@mcp/server"], config)

    assert command[:2] == ["docker", "run"]
    assert "--read-only" in command
    assert ["--cap-drop", "ALL"] == command[command.index("--cap-drop") : command.index("--cap-drop") + 2]
    assert ["--network", "none"] == command[command.index("--network") : command.index("--network") + 2]
    assert "ghcr.io/acme/mcp-sandbox:1" in command
    assert command[-3:] == ["npx", "--yes", "@mcp/server"]
    assert evidence["mode"] == "wrap_command_in_image"
    assert evidence["enabled"] is True


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
            "ghcr.io/acme/server:1",
        ],
        config,
    )

    assert "host" not in command
    assert "--privileged" not in command
    assert "--cap-add=SYS_ADMIN" not in command
    assert command[command.index("--network") + 1] == "none"


def test_build_sandboxed_command_requires_image_for_plain_commands(monkeypatch):
    monkeypatch.setattr("agent_bom.proxy_sandbox.resolve_container_runtime", lambda runtime: "docker")

    with pytest.raises(RuntimeError, match="requires --sandbox-image"):
        build_sandboxed_command(["python", "-m", "server"], SandboxConfig(enabled=True))
