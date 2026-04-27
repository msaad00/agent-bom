"""Container isolation helpers for MCP stdio proxy execution."""

from __future__ import annotations

import os
import shutil
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

SandboxRuntime = Literal["auto", "docker", "podman"]
SandboxEgressPolicy = Literal["deny", "allow_all"]
SandboxImagePinPolicy = Literal["off", "warn", "enforce"]

_DEFAULT_SANDBOX_CPUS = "1"
_DEFAULT_SANDBOX_MEMORY = "512m"
_DEFAULT_SANDBOX_PIDS_LIMIT = 256
_DEFAULT_SANDBOX_TMPFS_SIZE = "64m"
_DEFAULT_SANDBOX_TIMEOUT_SECONDS = 300

_SENSITIVE_EXACT_MOUNT_SOURCES = (Path("/"),)

_SENSITIVE_ABSOLUTE_MOUNT_SOURCES = (
    Path("/etc"),
    Path("/proc"),
    Path("/sys"),
    Path("/dev"),
    Path("/var/run"),
    Path("/run"),
    Path("/var/run/docker.sock"),
    Path("/run/docker.sock"),
)


def _sensitive_user_mount_sources() -> tuple[Path, ...]:
    home = Path.home()
    return (
        home / ".aws",
        home / ".azure",
        home / ".config" / "gcloud",
        home / ".docker",
        home / ".kube",
        home / ".ssh",
    )


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
    image_pin_policy: SandboxImagePinPolicy = "warn"
    mounts: tuple[SandboxMount, ...] = field(default_factory=tuple)
    network: str = "none"
    egress_policy: SandboxEgressPolicy = "deny"
    cpus: str | None = _DEFAULT_SANDBOX_CPUS
    memory: str | None = _DEFAULT_SANDBOX_MEMORY
    pids_limit: int | None = _DEFAULT_SANDBOX_PIDS_LIMIT
    tmpfs_size: str | None = _DEFAULT_SANDBOX_TMPFS_SIZE
    timeout_seconds: int | None = _DEFAULT_SANDBOX_TIMEOUT_SECONDS
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
            "image_pinned": _image_reference_has_digest(self.image),
            "image_pin_policy": self.image_pin_policy,
            "image_pin_warning": _image_pin_warning(self.image, self.image_pin_policy),
            "network": _effective_network(self),
            "egress_policy": self.egress_policy,
            "cpus": self.cpus,
            "memory": self.memory,
            "pids_limit": self.pids_limit,
            "tmpfs_size": self.tmpfs_size,
            "timeout_seconds": self.timeout_seconds,
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
    if not parts[1].startswith("/"):
        raise ValueError("sandbox mount container path must be absolute")
    mode = parts[2].lower() if len(parts) == 3 else "ro"
    if mode not in {"ro", "rw", "readonly"}:
        raise ValueError("sandbox mount mode must be ro or rw")
    raw_source = Path(parts[0]).expanduser()
    _validate_sandbox_mount_source(raw_source.resolve(strict=False))
    source_path = raw_source.resolve(strict=True)
    _validate_sandbox_mount_source(source_path)
    source = str(source_path)
    return SandboxMount(source=source, target=parts[1], readonly=mode != "rw")


def _validate_sandbox_mount_source(source: Path) -> None:
    denied_exact = tuple(path.resolve(strict=False) for path in _SENSITIVE_EXACT_MOUNT_SOURCES)
    if source in denied_exact:
        raise ValueError(f"sandbox mount source is too sensitive to expose to an MCP server: {source}")
    denied_candidates = (
        path
        for path in (*_SENSITIVE_ABSOLUTE_MOUNT_SOURCES, *_sensitive_user_mount_sources())
        if path not in _SENSITIVE_EXACT_MOUNT_SOURCES
    )
    denied_roots = tuple(path.resolve(strict=False) for path in denied_candidates)
    for denied in denied_roots:
        if _path_is_relative_to(source, denied):
            raise ValueError(f"sandbox mount source is too sensitive to expose to an MCP server: {source}")


def _path_is_relative_to(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


def sandbox_config_from_env(
    *,
    enabled: bool | None = None,
    runtime: str | None = None,
    image: str | None = None,
    mounts: tuple[str, ...] = (),
    user: str | None = None,
    egress_policy: str | None = None,
    cpus: str | None = None,
    memory: str | None = None,
    pids_limit: int | None = None,
    tmpfs_size: str | None = None,
    timeout_seconds: int | None = None,
    image_pin_policy: str | None = None,
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
    requested_egress = (egress_policy or os.environ.get("AGENT_BOM_MCP_SANDBOX_EGRESS") or "deny").strip().lower().replace("-", "_")
    if requested_egress not in {"deny", "allow_all"}:
        raise ValueError("sandbox egress policy must be deny or allow-all")
    requested_image = image or os.environ.get("AGENT_BOM_MCP_SANDBOX_IMAGE")
    requested_image_pin_policy = (image_pin_policy or os.environ.get("AGENT_BOM_MCP_SANDBOX_IMAGE_PIN_POLICY") or "warn").strip().lower()
    if requested_image_pin_policy not in {"off", "warn", "enforce"}:
        raise ValueError("sandbox image pin policy must be off, warn, or enforce")
    env_mounts = tuple(item.strip() for item in os.environ.get("AGENT_BOM_MCP_SANDBOX_MOUNTS", "").split(",") if item.strip())
    parsed_mounts = tuple(parse_sandbox_mount(item) for item in (*mounts, *env_mounts))
    requested_user = user or os.environ.get("AGENT_BOM_MCP_SANDBOX_USER")
    requested_cpus = cpus or os.environ.get("AGENT_BOM_MCP_SANDBOX_CPUS") or _DEFAULT_SANDBOX_CPUS
    requested_memory = memory or os.environ.get("AGENT_BOM_MCP_SANDBOX_MEMORY") or _DEFAULT_SANDBOX_MEMORY
    requested_tmpfs_size = tmpfs_size or os.environ.get("AGENT_BOM_MCP_SANDBOX_TMPFS_SIZE") or _DEFAULT_SANDBOX_TMPFS_SIZE
    requested_pids_limit = (
        _validate_positive_int("sandbox pids limit", pids_limit)
        if pids_limit is not None
        else _optional_positive_int("AGENT_BOM_MCP_SANDBOX_PIDS_LIMIT", default=_DEFAULT_SANDBOX_PIDS_LIMIT)
    )
    requested_timeout = (
        _validate_positive_int("sandbox timeout seconds", timeout_seconds)
        if timeout_seconds is not None
        else _optional_positive_int("AGENT_BOM_MCP_SANDBOX_TIMEOUT_SECONDS", default=_DEFAULT_SANDBOX_TIMEOUT_SECONDS)
    )
    return SandboxConfig(
        enabled=enabled,
        runtime=requested_runtime,  # type: ignore[arg-type]
        image=requested_image,
        image_pin_policy=requested_image_pin_policy,  # type: ignore[arg-type]
        mounts=parsed_mounts,
        user=requested_user,
        egress_policy=requested_egress,  # type: ignore[arg-type]
        cpus=requested_cpus,
        memory=requested_memory,
        pids_limit=requested_pids_limit,
        tmpfs_size=requested_tmpfs_size,
        timeout_seconds=requested_timeout,
    )


def resolve_container_runtime(runtime: SandboxRuntime) -> str:
    """Resolve docker/podman, preferring Docker for operator familiarity.

    Returns the absolute path returned by ``shutil.which`` rather than the
    bare name so subsequent ``subprocess.Popen`` calls do not re-resolve
    against PATH (audit-4 P2). A PATH change between resolve and exec
    would be a small TOCTOU window — operators control PATH but a
    container-runtime substitution under a long-running API process
    would be invisible without this.
    """
    if runtime != "auto":
        resolved = shutil.which(runtime)
        if not resolved:
            raise RuntimeError(f"MCP sandbox runtime '{runtime}' was requested but is not on PATH")
        return resolved
    for candidate in ("docker", "podman"):
        resolved = shutil.which(candidate)
        if resolved:
            return resolved
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
        if image_and_args:
            _validate_image_pin_policy(image_and_args[0], config.image_pin_policy)
        command = [runtime, "run", *before_image, *docker_args, *image_and_args]
        evidence = dict(config.evidence())
        evidence.update({"runtime": runtime, "mode": "harden_existing_container"})
        if image_and_args:
            evidence["image"] = image_and_args[0]
            evidence["image_pinned"] = _image_reference_has_digest(image_and_args[0])
            evidence["image_pin_warning"] = _image_pin_warning(image_and_args[0], config.image_pin_policy)
        return command, evidence

    if not config.image:
        raise RuntimeError("MCP sandbox isolation for non-container commands requires --sandbox-image or AGENT_BOM_MCP_SANDBOX_IMAGE")
    _validate_image_pin_policy(config.image, config.image_pin_policy)
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
    args.extend(["--network", _effective_network(config)])
    if config.cpus:
        args.extend(["--cpus", config.cpus])
    if config.memory:
        args.extend(["--memory", config.memory])
    if config.pids_limit is not None:
        args.extend(["--pids-limit", str(config.pids_limit)])
    if config.tmpfs_size:
        args.extend(["--tmpfs", f"/tmp:size={config.tmpfs_size},mode=1777"])  # nosec B108 - container-internal tmpfs mount
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
        "--tmpfs",
        "--cpus",
        "--memory",
        "--pids-limit",
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


def _effective_network(config: SandboxConfig) -> str:
    if config.network != "none":
        return config.network
    return "none" if config.egress_policy == "deny" else "bridge"


def _image_reference_has_digest(image: str | None) -> bool:
    if not image or "@sha256:" not in image:
        return False
    digest = image.rsplit("@sha256:", 1)[1]
    return len(digest) == 64 and all(ch in "0123456789abcdefABCDEF" for ch in digest)


def _image_pin_warning(image: str | None, policy: SandboxImagePinPolicy) -> str | None:
    if policy != "warn" or _image_reference_has_digest(image):
        return None
    return "sandbox image is mutable; use an image digest or enforce pinning for production isolation"


def _validate_image_pin_policy(image: str, policy: SandboxImagePinPolicy) -> None:
    if policy == "enforce" and not _image_reference_has_digest(image):
        raise RuntimeError("MCP sandbox image pin policy requires a digest reference such as image:tag@sha256:<digest>")


def _optional_positive_int(env_name: str, *, default: int | None = None) -> int | None:
    value = os.environ.get(env_name)
    if not value:
        return default
    try:
        parsed = int(value)
    except ValueError as exc:
        raise ValueError(f"{env_name} must be a positive integer") from exc
    return _validate_positive_int(env_name, parsed)


def _validate_positive_int(label: str, value: int) -> int:
    if value <= 0:
        raise ValueError(f"{label} must be a positive integer")
    return value


def describe_proxy_sandbox_posture() -> dict[str, object]:
    """Return non-secret operator posture for the MCP proxy sandbox defaults.

    Surfaces the process-wide default for ``image_pin_policy`` (resolved from
    ``AGENT_BOM_MCP_SANDBOX_IMAGE_PIN_POLICY``) so operators can verify in a
    dashboard whether mutable image references would be rejected before a
    proxied MCP server starts. Per-server configs may override the default.
    """
    raw = (os.environ.get("AGENT_BOM_MCP_SANDBOX_IMAGE_PIN_POLICY") or "warn").strip().lower()
    default_policy: SandboxImagePinPolicy = raw if raw in {"off", "warn", "enforce"} else "warn"  # type: ignore[assignment]
    return {
        "image_pin_policy_default": default_policy,
        "image_pin_policy_env": "AGENT_BOM_MCP_SANDBOX_IMAGE_PIN_POLICY",
        "production_recommendation": "enforce",
        "notes": (
            "Default 'warn' surfaces a non-blocking warning when a sandbox image is not pinned to a digest. "
            "Set the env to 'enforce' in production so unpinned image references are rejected at proxy start. "
            "Per-server SandboxConfig.image_pin_policy overrides this process-wide default."
        ),
    }
