"""Bounded, privacy-preserving workstation inventory collectors.

The endpoint preset inventories security-relevant software and runtime shape.
It deliberately does not collect process arguments, environment values,
remote network addresses, browser history, or arbitrary home-directory data.
"""

from __future__ import annotations

import ipaddress
import json
import platform
import plistlib
import shutil
import socket
import subprocess
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Literal

from agent_bom.security import sanitize_error

CollectorStatus = Literal["complete", "partial", "unsupported", "unavailable", "permission_denied"]
Runner = Callable[[list[str], float], "CommandResult"]

_AUTO_PSUTIL = object()
_DEFAULT_TIMEOUT_SECONDS = 5.0
_DEFAULT_MAX_ITEMS = 1_000


@dataclass(frozen=True)
class CommandResult:
    """Sanitized result from one fixed local inventory command."""

    status: CollectorStatus
    returncode: int
    stdout: str = ""
    message: str = ""


@dataclass
class CollectorResult:
    """One endpoint collector's items plus explicit execution status."""

    name: str
    status: CollectorStatus
    items: list[dict[str, Any]] = field(default_factory=list)
    message: str = ""

    @property
    def item_count(self) -> int | None:
        if self.status in {"unsupported", "unavailable", "permission_denied"}:
            return None
        return len(self.items)

    def summary(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "status": self.status,
            "item_count": self.item_count,
            "message": self.message,
        }


def _default_runner(command: list[str], timeout: float) -> CommandResult:
    executable = command[0]
    if not shutil.which(executable):
        return CommandResult(
            status="unavailable",
            returncode=127,
            message=f"{executable} is not installed; this inventory source was not collected.",
        )
    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return CommandResult(
            status="unavailable",
            returncode=124,
            message=f"{executable} inventory exceeded the {timeout:g}s time budget.",
        )
    except PermissionError:
        return CommandResult(
            status="permission_denied",
            returncode=126,
            message=f"Permission denied while collecting {executable} inventory.",
        )
    except OSError as exc:
        return CommandResult(
            status="unavailable",
            returncode=1,
            message=f"{executable} inventory failed: {sanitize_error(exc, generic=True)}",
        )
    if completed.returncode != 0:
        return CommandResult(
            status="unavailable",
            returncode=completed.returncode,
            message=f"{executable} inventory command was unavailable or returned a non-zero status.",
        )
    return CommandResult(status="complete", returncode=0, stdout=completed.stdout)


def _bounded_unique(items: list[dict[str, Any]], *, max_items: int) -> list[dict[str, Any]]:
    unique: dict[str, dict[str, Any]] = {}
    for item in items:
        key = json.dumps(item, sort_keys=True, separators=(",", ":"), default=str)
        unique.setdefault(key, item)
        if len(unique) >= max_items:
            break
    return sorted(unique.values(), key=lambda row: json.dumps(row, sort_keys=True, default=str).casefold())


def _parse_brew_versions(stdout: str, *, source: str, max_items: int) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    for line in stdout.splitlines():
        parts = line.strip().split()
        if len(parts) < 2:
            continue
        items.append({"name": parts[0], "version": parts[1], "source": source})
        if len(items) >= max_items:
            break
    return items


def _macos_applications(roots: tuple[Path, ...], *, max_items: int) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    for root in roots:
        if not root.is_dir():
            continue
        try:
            bundles = sorted(root.glob("*.app"), key=lambda path: path.name.casefold())
        except OSError:
            continue
        for bundle in bundles:
            info_path = bundle / "Contents" / "Info.plist"
            try:
                with info_path.open("rb") as handle:
                    info = plistlib.load(handle)
            except (OSError, plistlib.InvalidFileException):
                info = {}
            name = str(info.get("CFBundleDisplayName") or info.get("CFBundleName") or bundle.stem).strip()
            version = str(info.get("CFBundleShortVersionString") or info.get("CFBundleVersion") or "unknown").strip()
            item: dict[str, Any] = {"name": name or bundle.stem, "version": version or "unknown", "source": "macos_app"}
            identifier = str(info.get("CFBundleIdentifier") or "").strip()
            if identifier:
                item["identifier"] = identifier
            items.append(item)
            if len(items) >= max_items:
                return items
    return items


def _windows_applications(stdout: str, *, max_items: int) -> list[dict[str, Any]]:
    try:
        payload = json.loads(stdout or "[]")
    except json.JSONDecodeError:
        return []
    rows = payload if isinstance(payload, list) else [payload]
    items: list[dict[str, Any]] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        name = str(row.get("DisplayName") or "").strip()
        if not name:
            continue
        version = str(row.get("DisplayVersion") or "unknown").strip()
        item: dict[str, Any] = {"name": name, "version": version or "unknown", "source": "windows_uninstall"}
        publisher = str(row.get("Publisher") or "").strip()
        if publisher:
            item["publisher"] = publisher
        items.append(item)
        if len(items) >= max_items:
            break
    return items


_WINDOWS_APPLICATION_SCRIPT = (
    "$paths=@('HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*',"
    "'HKLM:\\Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*',"
    "'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*');"
    "@(Get-ItemProperty -Path $paths -ErrorAction SilentlyContinue | "
    "Where-Object {$_.DisplayName} | Select-Object DisplayName,DisplayVersion,Publisher) | "
    "ConvertTo-Json -Compress"
)


def collect_applications(
    *,
    system: str | None = None,
    runner: Runner = _default_runner,
    application_roots: tuple[Path, ...] | None = None,
    timeout_seconds: float = _DEFAULT_TIMEOUT_SECONDS,
    max_items: int = _DEFAULT_MAX_ITEMS,
) -> CollectorResult:
    """Collect installed applications from fixed, platform-owned sources."""

    host_system = system or platform.system()
    if host_system == "Darwin":
        roots = application_roots or (Path("/Applications"), Path("/System/Applications"))
        items = _macos_applications(roots, max_items=max_items)
        failures: list[str] = []
        for command, source in (
            (["brew", "list", "--formula", "--versions"], "homebrew_formula"),
            (["brew", "list", "--cask", "--versions"], "homebrew_cask"),
        ):
            result = runner(command, timeout_seconds)
            if result.status == "complete":
                items.extend(_parse_brew_versions(result.stdout, source=source, max_items=max_items))
            else:
                failures.append(result.message or f"{source} inventory unavailable")
        status: CollectorStatus = "complete" if not failures else "partial"
        return CollectorResult(
            name="applications",
            status=status,
            items=_bounded_unique(items, max_items=max_items),
            message=" ".join(failures),
        )

    if host_system == "Windows":
        result = runner(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", _WINDOWS_APPLICATION_SCRIPT],
            timeout_seconds,
        )
        if result.status != "complete":
            return CollectorResult(name="applications", status=result.status, message=result.message)
        items = _windows_applications(result.stdout, max_items=max_items)
        return CollectorResult(name="applications", status="complete", items=_bounded_unique(items, max_items=max_items))

    if host_system == "Linux":
        return CollectorResult(
            name="applications",
            status="complete",
            message="Linux installed software is represented by the os_packages scope.",
        )

    return CollectorResult(
        name="applications",
        status="unsupported",
        message=f"Installed application inventory is not implemented for {host_system or 'this platform'}.",
    )


def _load_psutil(psutil_module: Any) -> Any | None:
    if psutil_module is not _AUTO_PSUTIL:
        return psutil_module
    try:
        import psutil
    except ImportError:
        return None
    return psutil


def _is_access_denied(exc: Exception, psutil_module: Any) -> bool:
    access_denied = getattr(psutil_module, "AccessDenied", None)
    return isinstance(exc, PermissionError) or (isinstance(access_denied, type) and isinstance(exc, access_denied))


def _bind_scope(value: str) -> str:
    text = str(value or "").split("%", 1)[0]
    if text in {"0.0.0.0", "::", "", "*"}:  # nosec B104 - classifies an observed listener address; does not bind a socket
        return "all_interfaces"
    try:
        address = ipaddress.ip_address(text)
    except ValueError:
        return "unknown"
    if address.is_loopback:
        return "loopback"
    if address.is_link_local:
        return "link_local"
    if address.is_private:
        return "private"
    return "public"


def _split_local_endpoint(value: str) -> tuple[str, int] | None:
    endpoint = value.strip()
    if endpoint.startswith("[") and "]:" in endpoint:
        host, _, port_text = endpoint[1:].rpartition("]:")
    else:
        host, separator, port_text = endpoint.rpartition(":")
        if not separator:
            return None
    try:
        return host, int(port_text)
    except ValueError:
        return None


def _listener_fallback(
    *,
    system: str,
    runner: Runner,
    timeout_seconds: float,
    max_items: int,
) -> CollectorResult | None:
    if system == "Darwin":
        result = runner(["lsof", "-nP", "-iTCP", "-sTCP:LISTEN", "-Fpcn"], timeout_seconds)
        if result.status != "complete":
            return None
        items: list[dict[str, Any]] = []
        process_name = ""
        for line in result.stdout.splitlines():
            if line.startswith("c"):
                process_name = line[1:].strip()
                continue
            if not line.startswith("n"):
                continue
            parsed = _split_local_endpoint(line[1:])
            if parsed is None:
                continue
            host, port = parsed
            item: dict[str, Any] = {"transport": "tcp", "port": port, "bind_scope": _bind_scope(host)}
            if process_name:
                item["process_name"] = process_name
            items.append(item)
            if len(items) >= max_items:
                break
        return CollectorResult(name="listeners", status="complete", items=_bounded_unique(items, max_items=max_items))

    if system == "Linux":
        result = runner(["ss", "-H", "-ltn"], timeout_seconds)
        if result.status != "complete":
            return None
        items = []
        for line in result.stdout.splitlines():
            parts = line.split()
            if len(parts) < 4:
                continue
            parsed = _split_local_endpoint(parts[3])
            if parsed is None:
                continue
            host, port = parsed
            items.append({"transport": "tcp", "port": port, "bind_scope": _bind_scope(host)})
            if len(items) >= max_items:
                break
        return CollectorResult(name="listeners", status="complete", items=_bounded_unique(items, max_items=max_items))

    if system == "Windows":
        result = runner(
            [
                "powershell",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                "@(Get-NetTCPConnection -State Listen | Select-Object LocalAddress,LocalPort) | ConvertTo-Json -Compress",
            ],
            timeout_seconds,
        )
        if result.status != "complete":
            return None
        try:
            payload = json.loads(result.stdout or "[]")
        except json.JSONDecodeError:
            return None
        rows = payload if isinstance(payload, list) else [payload]
        items = []
        for row in rows[:max_items]:
            if not isinstance(row, dict):
                continue
            try:
                port = int(str(row.get("LocalPort") or ""))
            except (TypeError, ValueError):
                continue
            items.append(
                {
                    "transport": "tcp",
                    "port": port,
                    "bind_scope": _bind_scope(str(row.get("LocalAddress") or "")),
                }
            )
        return CollectorResult(name="listeners", status="complete", items=_bounded_unique(items, max_items=max_items))
    return None


def collect_processes_and_listeners(
    *,
    psutil_module: Any = _AUTO_PSUTIL,
    system: str | None = None,
    runner: Runner = _default_runner,
    timeout_seconds: float = _DEFAULT_TIMEOUT_SECONDS,
    max_items: int = _DEFAULT_MAX_ITEMS,
) -> tuple[CollectorResult, CollectorResult]:
    """Collect aggregate process names and local listeners without arguments."""

    psutil = _load_psutil(psutil_module)
    if psutil is None:
        message = "Process and listener inventory requires the optional psutil dependency."
        fallback = _listener_fallback(
            system=system or platform.system(),
            runner=runner,
            timeout_seconds=timeout_seconds,
            max_items=max_items,
        )
        return (
            CollectorResult(name="processes", status="unavailable", message=message),
            fallback or CollectorResult(name="listeners", status="unavailable", message=message),
        )

    counts: Counter[str] = Counter()
    pid_names: dict[int, str] = {}
    observation_count = 0
    process_status: CollectorStatus = "complete"
    process_message = ""
    try:
        for process in psutil.process_iter(["pid", "name"]):
            info = getattr(process, "info", {}) or {}
            name = str(info.get("name") or "unknown").strip() or "unknown"
            counts[name] += 1
            observation_count += 1
            pid = info.get("pid")
            if isinstance(pid, int):
                pid_names[pid] = name
            if observation_count >= max_items:
                process_status = "partial"
                process_message = f"Process inventory was limited to {max_items} observations."
                break
    except Exception as exc:  # psutil exposes platform-specific exception types
        if _is_access_denied(exc, psutil):
            process_status = "permission_denied"
            process_message = "Permission denied while collecting process inventory."
        else:
            process_status = "unavailable"
            process_message = f"Process inventory failed: {sanitize_error(exc, generic=True)}"

    process_items = [{"name": name, "instances": count} for name, count in sorted(counts.items(), key=lambda row: row[0].casefold())]
    process_result = CollectorResult(name="processes", status=process_status, items=process_items, message=process_message)

    listeners: list[dict[str, Any]] = []
    listener_status: CollectorStatus = "complete"
    listener_message = ""
    try:
        listen_state = getattr(psutil, "CONN_LISTEN", "LISTEN")
        for connection in psutil.net_connections(kind="inet"):
            status = str(getattr(connection, "status", "") or "")
            connection_type = getattr(connection, "type", socket.SOCK_STREAM)
            if connection_type == socket.SOCK_STREAM and status != listen_state:
                continue
            local = getattr(connection, "laddr", None)
            if not local:
                continue
            ip_value = getattr(local, "ip", local[0] if isinstance(local, tuple) and local else "")
            port_value = getattr(local, "port", local[1] if isinstance(local, tuple) and len(local) > 1 else 0)
            try:
                port = int(port_value)
            except (TypeError, ValueError):
                continue
            pid = getattr(connection, "pid", None)
            item: dict[str, Any] = {
                "transport": "tcp" if connection_type == socket.SOCK_STREAM else "udp",
                "port": port,
                "bind_scope": _bind_scope(str(ip_value)),
            }
            if isinstance(pid, int) and pid in pid_names:
                item["process_name"] = pid_names[pid]
            listeners.append(item)
            if len(listeners) >= max_items:
                listener_status = "partial"
                listener_message = f"Listener inventory was limited to {max_items} observations."
                break
    except Exception as exc:
        if _is_access_denied(exc, psutil):
            listener_status = "permission_denied"
            listener_message = "Permission denied while collecting listener inventory."
        else:
            listener_status = "unavailable"
            listener_message = f"Listener inventory failed: {sanitize_error(exc, generic=True)}"

    listener_result = CollectorResult(
        name="listeners",
        status=listener_status,
        items=_bounded_unique(listeners, max_items=max_items),
        message=listener_message,
    )
    if listener_status in {"unavailable", "permission_denied"}:
        fallback = _listener_fallback(
            system=system or platform.system(),
            runner=runner,
            timeout_seconds=timeout_seconds,
            max_items=max_items,
        )
        if fallback is not None:
            listener_result = fallback
    return process_result, listener_result


def _parse_services(system: str, stdout: str, *, max_items: int) -> list[dict[str, Any]]:
    if system == "Windows":
        try:
            payload = json.loads(stdout or "[]")
        except json.JSONDecodeError:
            return []
        rows = payload if isinstance(payload, list) else [payload]
        return [
            {"name": str(row.get("Name") or ""), "status": str(row.get("Status") or "unknown").lower()}
            for row in rows[:max_items]
            if isinstance(row, dict) and row.get("Name")
        ]
    items: list[dict[str, Any]] = []
    for line in stdout.splitlines():
        parts = line.strip().split()
        if not parts:
            continue
        if system == "Darwin":
            name = parts[-1]
            status = "running" if parts[0] != "-" else "stopped"
        else:
            name = parts[0]
            status = parts[2] if len(parts) > 2 else "unknown"
        items.append({"name": name, "status": status})
        if len(items) >= max_items:
            break
    return items


def collect_services(
    *,
    system: str | None = None,
    runner: Runner = _default_runner,
    timeout_seconds: float = _DEFAULT_TIMEOUT_SECONDS,
    max_items: int = _DEFAULT_MAX_ITEMS,
) -> CollectorResult:
    """Collect service names/states without definitions, arguments, or files."""

    host_system = system or platform.system()
    commands = {
        "Darwin": ["launchctl", "list"],
        "Linux": ["systemctl", "list-units", "--type=service", "--all", "--no-legend", "--no-pager", "--plain"],
        "Windows": [
            "powershell",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            "@(Get-Service | Select-Object Name,Status) | ConvertTo-Json -Compress",
        ],
    }
    command = commands.get(host_system)
    if command is None:
        return CollectorResult(
            name="services",
            status="unsupported",
            message=f"Service inventory is not implemented for {host_system or 'this platform'}.",
        )
    result = runner(command, timeout_seconds)
    if result.status != "complete":
        return CollectorResult(name="services", status=result.status, message=result.message)
    items = _bounded_unique(_parse_services(host_system, result.stdout, max_items=max_items), max_items=max_items)
    return CollectorResult(name="services", status="complete", items=items)


def _parse_json_lines(stdout: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for line in stdout.splitlines():
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(row, dict):
            rows.append(row)
    return rows


def _combined_runtime_status(statuses: list[CollectorStatus]) -> CollectorStatus:
    completed = sum(status == "complete" for status in statuses)
    if completed == len(statuses) and statuses:
        return "complete"
    if completed:
        return "partial"
    if "permission_denied" in statuses:
        return "permission_denied"
    return "unavailable"


def collect_container_assets(
    *,
    runner: Runner = _default_runner,
    runtimes: tuple[str, ...] = ("docker", "podman"),
    timeout_seconds: float = _DEFAULT_TIMEOUT_SECONDS,
    max_items: int = _DEFAULT_MAX_ITEMS,
) -> tuple[CollectorResult, CollectorResult]:
    """Collect bounded container/image metadata from local Docker and Podman."""

    containers: list[dict[str, Any]] = []
    images: list[dict[str, Any]] = []
    statuses: list[CollectorStatus] = []
    messages: list[str] = []
    for runtime in runtimes:
        info_format = "{{.Version.Version}}" if runtime == "podman" else "{{.ServerVersion}}"
        info = runner([runtime, "info", "--format", info_format], timeout_seconds)
        if info.status != "complete":
            statuses.append(info.status)
            messages.append(info.message or f"{runtime} runtime unavailable")
            continue
        ps_result = runner([runtime, "ps", "--format", "{{json .}}"], timeout_seconds)
        image_result = runner([runtime, "images", "--format", "{{json .}}"], timeout_seconds)
        runtime_status: CollectorStatus = "complete" if ps_result.status == image_result.status == "complete" else "partial"
        statuses.append(runtime_status)
        if ps_result.status == "complete":
            for row in _parse_json_lines(ps_result.stdout):
                containers.append(
                    {
                        "runtime": runtime,
                        "name": str(row.get("Names") or row.get("NamesString") or row.get("Name") or "unknown"),
                        "image": str(row.get("Image") or "unknown"),
                        "state": str(row.get("State") or row.get("Status") or "unknown").split()[0].lower(),
                    }
                )
        else:
            messages.append(ps_result.message or f"{runtime} container inventory unavailable")
        if image_result.status == "complete":
            for row in _parse_json_lines(image_result.stdout):
                image: dict[str, Any] = {
                    "runtime": runtime,
                    "repository": str(row.get("Repository") or "unknown"),
                    "tag": str(row.get("Tag") or "unknown"),
                    "digest": str(row.get("Digest") or row.get("ID") or "unknown"),
                }
                size = str(row.get("Size") or "").strip()
                if size:
                    image["size"] = size
                images.append(image)
        else:
            messages.append(image_result.message or f"{runtime} image inventory unavailable")

    status = _combined_runtime_status(statuses)
    message = " ".join(dict.fromkeys(message for message in messages if message))
    return (
        CollectorResult(
            name="containers",
            status=status,
            items=_bounded_unique(containers, max_items=max_items),
            message=message,
        ),
        CollectorResult(
            name="images",
            status=status,
            items=_bounded_unique(images, max_items=max_items),
            message=message,
        ),
    )


def collect_endpoint_inventory(
    *,
    system: str | None = None,
    runner: Runner = _default_runner,
    psutil_module: Any = _AUTO_PSUTIL,
    timeout_seconds: float = _DEFAULT_TIMEOUT_SECONDS,
    max_items: int = _DEFAULT_MAX_ITEMS,
) -> dict[str, Any]:
    """Return one deterministic endpoint inventory with per-collector truth."""

    host_system = system or platform.system()
    applications = collect_applications(
        system=host_system,
        runner=runner,
        timeout_seconds=timeout_seconds,
        max_items=max_items,
    )
    processes, listeners = collect_processes_and_listeners(
        psutil_module=psutil_module,
        system=host_system,
        runner=runner,
        timeout_seconds=timeout_seconds,
        max_items=max_items,
    )
    services = collect_services(
        system=host_system,
        runner=runner,
        timeout_seconds=timeout_seconds,
        max_items=max_items,
    )
    containers, images = collect_container_assets(
        runner=runner,
        timeout_seconds=timeout_seconds,
        max_items=max_items,
    )
    results = (applications, processes, services, listeners, containers, images)
    return {
        "schema_version": "1",
        "platform": {
            "system": host_system,
            "release": platform.release() if host_system == platform.system() else "",
            "machine": platform.machine(),
        },
        "privacy": {
            "process_arguments_collected": False,
            "environment_values_collected": False,
            "browser_history_collected": False,
            "arbitrary_home_directory_scan": False,
            "network_remote_addresses_collected": False,
        },
        "collectors": [result.summary() for result in results],
        **{result.name: result.items for result in results},
    }
