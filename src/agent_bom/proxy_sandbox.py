"""Container isolation helpers for MCP stdio proxy execution."""

from __future__ import annotations

import os
import shutil
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

SandboxRuntime = Literal["auto", "docker", "podman"]


@dataclass(frozen=True)
class SandboxMount:
    """Explicit host path mount for an isolated MCP server."""

    source: str
    target: str
    readonly: bool = True

    def as_docker_mount(self) -> str:
        mode = "readonly" if self.readonly else "rw"
        return f"type=bind,src={self.source},dst={self.target},{mode}"


@dataclass(frozen=True)
class SandboxConfig:
    """Process isolation posture for a proxied MCP server."""

    enabled: bool = False
    runtime: SandboxRuntime = "auto"
    image: str | None = None
    mounts: tuple[SandboxMount, ...] = field(default_factory=tuple)
    network: str = "none"
    read_only_rootfs: bool = True
    drop_capabilities: bool = True
    no_new_privileges: bool = True
    user: str | None = None

    def evidence(self) -> dict[str, object]:
        """Return non-secret runtime evidence for audit and posture output."""
        return {
            "enabled": self.enabled,
            "runtime": self.runtime,
            "image": self.image,
            "network": self.network,
            "read_only_rootfs": self.read_only_rootfs,
            "drop_capabilities": self.drop_capabilities,
            "no_new_privileges": self.no_new_privileges,
            "user": self.user,
            "mounts": [
                {
                    "source": mount.source,
                    "target": mount.target,
                    "readonly": mount.readonly,
                }
                for mount in self.mounts
            ],
        }


def parse_sandbox_mount(value: str) -> SandboxMount:
    """Parse ``host:container[:ro|rw]`` into a mount policy."""
    parts = value.split(":")
    if len(parts) not in (2, 3) or not parts[0] or not parts[1]:
        raise ValueError("sandbox mounts must use host_path:container_path[:ro|rw]")
    mode = parts[2].lower() if len(parts) == 3 else "ro"
    if mode not in {"ro", "rw", "readonly"}:
        raise ValueError("sandbox mount mode must be ro or rw")
    source = str(Path(parts[0]).expanduser().resolve())
    return SandboxMount(source=source, target=parts[1], readonly=mode != "rw")


def sandbox_config_from_env(
    *,
    enabled: bool | None = None,
    runtime: str | None = None,
    image: str | None = None,
    mounts: tuple[str, ...] = (),
    user: str | None = None,
) -> SandboxConfig:
    """Build sandbox config from CLI values and AGENT_BOM_MCP_SANDBOX_* env vars."""
    if enabled is None:
        env_enabled = os.environ.get("AGENT_BOM_MCP_SANDBOX")
        enabled = bool(env_enabled and env_enabled.strip().lower() in {"1", "true", "yes", "on", "container"})
    else:
        enabled = bool(enabled)
    requested_runtime = (runtime or os.environ.get("AGENT_BOM_MCP_SANDBOX_RUNTIME") or "auto").strip().lower()
    if requested_runtime not in {"auto", "docker", "podman"}:
        raise ValueError("sandbox runtime must be auto, docker, or podman")
    requested_image = image or os.environ.get("AGENT_BOM_MCP_SANDBOX_IMAGE")
    env_mounts = tuple(item.strip() for item in os.environ.get("AGENT_BOM_MCP_SANDBOX_MOUNTS", "").split(",") if item.strip())
    parsed_mounts = tuple(parse_sandbox_mount(item) for item in (*mounts, *env_mounts))
    requested_user = user or os.environ.get("AGENT_BOM_MCP_SANDBOX_USER")
    return SandboxConfig(
        enabled=enabled,
        runtime=requested_runtime,  # type: ignore[arg-type]
        image=requested_image,
        mounts=parsed_mounts,
        user=requested_user,
    )


def resolve_container_runtime(runtime: SandboxRuntime) -> str:
    """Resolve docker/podman, preferring Docker for operator familiarity."""
    if runtime != "auto":
        if not shutil.which(runtime):
            raise RuntimeError(f"MCP sandbox runtime '{runtime}' was requested but is not on PATH")
        return runtime
    for candidate in ("docker", "podman"):
        if shutil.which(candidate):
            return candidate
    raise RuntimeError("MCP sandbox isolation requires Docker or Podman on PATH")


def build_sandboxed_command(server_cmd: list[str], config: SandboxConfig) -> tuple[list[str], dict[str, object]]:
    """Return the command used to run the MCP server under container isolation."""
    if not config.enabled:
        return server_cmd, config.evidence()
    runtime = resolve_container_runtime(config.runtime)
    docker_args = _sandbox_docker_args(config)

    if _is_container_run(server_cmd):
        image_index = _container_image_index(server_cmd)
        before_image = _strip_conflicting_run_options(server_cmd[2:image_index])
        image_and_args = server_cmd[image_index:]
        command = [runtime, "run", *before_image, *docker_args, *image_and_args]
        evidence = dict(config.evidence())
        evidence.update({"runtime": runtime, "mode": "harden_existing_container"})
        if image_and_args:
            evidence["image"] = image_and_args[0]
        return command, evidence

    if not config.image:
        raise RuntimeError("MCP sandbox isolation for non-container commands requires --sandbox-image or AGENT_BOM_MCP_SANDBOX_IMAGE")
    command = [runtime, "run", *docker_args, config.image, *server_cmd]
    evidence = dict(config.evidence())
    evidence.update({"runtime": runtime, "mode": "wrap_command_in_image"})
    return command, evidence


def _sandbox_docker_args(config: SandboxConfig) -> list[str]:
    args = ["--rm", "-i"]
    if config.read_only_rootfs:
        args.append("--read-only")
    if config.no_new_privileges:
        args.extend(["--security-opt", "no-new-privileges"])
    if config.drop_capabilities:
        args.extend(["--cap-drop", "ALL"])
    if config.network:
        args.extend(["--network", config.network])
    if config.user:
        args.extend(["--user", config.user])
    for mount in config.mounts:
        args.extend(["--mount", mount.as_docker_mount()])
    return args


def _is_container_run(server_cmd: list[str]) -> bool:
    return len(server_cmd) >= 3 and Path(server_cmd[0]).name in {"docker", "podman"} and server_cmd[1] == "run"


def _container_image_index(server_cmd: list[str]) -> int:
    """Best-effort image index for docker/podman run commands."""
    index = 2
    while index < len(server_cmd):
        item = server_cmd[index]
        if item == "--":
            return min(index + 1, len(server_cmd))
        if not item.startswith("-"):
            return index
        # Options with a separate value.
        if item in {"--name", "--user", "--workdir", "--network", "--env", "-e", "--mount", "-v", "--volume"}:
            index += 2
            continue
        index += 1
    return len(server_cmd)


def _strip_conflicting_run_options(args: list[str]) -> list[str]:
    """Remove container flags that would weaken the sandbox contract."""
    stripped: list[str] = []
    skip_next = False
    options_with_values = {
        "--network",
        "--security-opt",
        "--cap-add",
        "--cap-drop",
        "--user",
        "--mount",
        "-v",
        "--volume",
    }
    forbidden_flags = {"--privileged", "--read-only=false"}
    for item in args:
        if skip_next:
            skip_next = False
            continue
        if item in forbidden_flags:
            continue
        if item in options_with_values:
            skip_next = True
            continue
        if any(item.startswith(f"{option}=") for option in options_with_values):
            continue
        stripped.append(item)
    return stripped
