from __future__ import annotations

import json
import tomllib
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from click.testing import CliRunner

from agent_bom.cli import main
from agent_bom.endpoint.inventory import (
    CommandResult,
    collect_applications,
    collect_container_assets,
    collect_endpoint_inventory,
    collect_processes_and_listeners,
    collect_services,
)


def test_workstation_process_inventory_dependency_is_installed_by_default() -> None:
    pyproject = tomllib.loads(Path("pyproject.toml").read_text())

    assert any(str(requirement).startswith("psutil>=") for requirement in pyproject["project"]["dependencies"])


def _result(stdout: str = "", *, returncode: int = 0, status: str = "complete") -> CommandResult:
    return CommandResult(status=status, returncode=returncode, stdout=stdout, message="")


def test_macos_application_inventory_combines_brew_and_known_app_bundles(tmp_path: Path) -> None:
    applications = tmp_path / "Applications"
    info = applications / "Cursor.app" / "Contents" / "Info.plist"
    info.parent.mkdir(parents=True)
    info.write_bytes(
        b'<?xml version="1.0" encoding="UTF-8"?>\n'
        b'<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" '
        b'"http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n'
        b'<plist version="1.0"><dict>'
        b"<key>CFBundleDisplayName</key><string>Cursor</string>"
        b"<key>CFBundleShortVersionString</key><string>1.2.3</string>"
        b"<key>CFBundleIdentifier</key><string>com.todesktop.230313mzl4w4u92</string>"
        b"</dict></plist>"
    )

    def runner(command: list[str], _timeout: float) -> CommandResult:
        if command[-2:] == ["--formula", "--versions"]:
            return _result("openssl@3 3.5.2\npython@3.13 3.13.7\n")
        if command[-2:] == ["--cask", "--versions"]:
            return _result("docker-desktop 4.44.3\n")
        raise AssertionError(command)

    result = collect_applications(
        system="Darwin",
        runner=runner,
        application_roots=(applications,),
    )

    assert result.status == "complete"
    assert result.item_count == 4
    assert result.items == [
        {"name": "Cursor", "version": "1.2.3", "source": "macos_app", "identifier": "com.todesktop.230313mzl4w4u92"},
        {"name": "docker-desktop", "version": "4.44.3", "source": "homebrew_cask"},
        {"name": "openssl@3", "version": "3.5.2", "source": "homebrew_formula"},
        {"name": "python@3.13", "version": "3.13.7", "source": "homebrew_formula"},
    ]


def test_process_inventory_aggregates_names_and_redacts_paths_args_and_addresses() -> None:
    processes = [
        SimpleNamespace(
            info={"pid": 10, "name": "python", "exe": "/Users/alice/.venv/bin/python", "cmdline": ["python", "--token", "secret"]}
        ),
        SimpleNamespace(info={"pid": 11, "name": "python", "exe": "/opt/python", "cmdline": ["python", "server.py"]}),
        SimpleNamespace(info={"pid": 12, "name": "node", "exe": "/usr/bin/node", "cmdline": ["node", "app.js"]}),
    ]
    listeners = [
        SimpleNamespace(status="LISTEN", type=1, laddr=SimpleNamespace(ip="127.0.0.1", port=8422), pid=10),
        SimpleNamespace(status="LISTEN", type=1, laddr=SimpleNamespace(ip="0.0.0.0", port=3000), pid=12),
    ]
    fake_psutil = SimpleNamespace(
        CONN_LISTEN="LISTEN",
        process_iter=lambda _attrs: processes,
        net_connections=lambda kind: listeners,
    )

    process_result, listener_result = collect_processes_and_listeners(psutil_module=fake_psutil)

    assert process_result.items == [
        {"name": "node", "instances": 1},
        {"name": "python", "instances": 2},
    ]
    assert listener_result.items == [
        {"transport": "tcp", "port": 3000, "bind_scope": "all_interfaces", "process_name": "node"},
        {"transport": "tcp", "port": 8422, "bind_scope": "loopback", "process_name": "python"},
    ]
    serialized = json.dumps({"processes": process_result.items, "listeners": listener_result.items})
    assert "alice" not in serialized
    assert "secret" not in serialized
    assert "127.0.0.1" not in serialized
    assert "0.0.0.0" not in serialized
    assert "cmdline" not in serialized
    assert "exe" not in serialized


def test_process_access_denial_is_not_reported_as_generic_unavailability() -> None:
    class AccessDeniedError(Exception):
        pass

    fake_psutil = SimpleNamespace(
        AccessDenied=AccessDeniedError,
        CONN_LISTEN="LISTEN",
        process_iter=lambda _attrs: (_ for _ in ()).throw(AccessDeniedError("private process")),
        net_connections=lambda kind: (_ for _ in ()).throw(AccessDeniedError("private socket")),
    )

    processes, listeners = collect_processes_and_listeners(
        psutil_module=fake_psutil,
        system="Plan9",
        runner=lambda _command, _timeout: _result(status="unavailable", returncode=1),
    )

    assert processes.status == "permission_denied"
    assert listeners.status == "permission_denied"
    assert "private process" not in processes.message
    assert "private socket" not in listeners.message


def test_macos_listener_permission_denial_falls_back_to_bounded_lsof() -> None:
    class AccessDeniedError(Exception):
        pass

    fake_psutil = SimpleNamespace(
        AccessDenied=AccessDeniedError,
        CONN_LISTEN="LISTEN",
        process_iter=lambda _attrs: [SimpleNamespace(info={"pid": 10, "name": "python"})],
        net_connections=lambda kind: (_ for _ in ()).throw(AccessDeniedError("private socket")),
    )

    def runner(command: list[str], timeout: float) -> CommandResult:
        assert command == ["lsof", "-nP", "-iTCP", "-sTCP:LISTEN", "-Fpcn"]
        assert timeout == 5.0
        return _result("p10\ncpython\nn127.0.0.1:8422\np11\ncnode\nn*:3000\n")

    _, listeners = collect_processes_and_listeners(
        psutil_module=fake_psutil,
        system="Darwin",
        runner=runner,
    )

    assert listeners.status == "complete"
    assert listeners.items == [
        {"transport": "tcp", "port": 3000, "bind_scope": "all_interfaces", "process_name": "node"},
        {"transport": "tcp", "port": 8422, "bind_scope": "loopback", "process_name": "python"},
    ]


def test_windows_application_inventory_uses_fixed_registry_projection() -> None:
    observed: list[list[str]] = []

    def runner(command: list[str], timeout: float) -> CommandResult:
        observed.append(command)
        assert timeout == 5.0
        return _result(
            json.dumps(
                [
                    {"DisplayName": "Git", "DisplayVersion": "2.51.0", "Publisher": "Git Project"},
                    {"DisplayName": "Python", "DisplayVersion": "3.13.7", "Publisher": "Python Software Foundation"},
                ]
            )
        )

    result = collect_applications(system="Windows", runner=runner)

    assert result.status == "complete"
    assert result.items[0] == {
        "name": "Git",
        "version": "2.51.0",
        "source": "windows_uninstall",
        "publisher": "Git Project",
    }
    assert observed[0][:4] == ["powershell", "-NoProfile", "-NonInteractive", "-Command"]
    assert "ConvertTo-Json" in observed[0][-1]
    assert "Win32_Product" not in observed[0][-1]


def test_service_inventory_keeps_only_name_and_status() -> None:
    result = collect_services(
        system="Linux",
        runner=lambda _command, _timeout: _result(
            "agent-bom.service loaded active running Agent BOM API with /home/alice/secret.conf\n"
            "docker.service loaded inactive dead Docker service\n"
        ),
    )

    assert result.items == [
        {"name": "agent-bom.service", "status": "active"},
        {"name": "docker.service", "status": "inactive"},
    ]
    assert "alice" not in json.dumps(result.items)


def test_collector_timeout_is_explicit_and_does_not_leak_command_output() -> None:
    result = collect_services(
        system="Darwin",
        runner=lambda _command, _timeout: CommandResult(
            status="unavailable",
            returncode=124,
            stdout="TOKEN=secret-value",
            message="launchctl inventory exceeded the 2s time budget.",
        ),
        timeout_seconds=2.0,
    )

    assert result.status == "unavailable"
    assert result.items == []
    assert result.message == "launchctl inventory exceeded the 2s time budget."
    assert "secret-value" not in json.dumps(result.summary())


def test_container_inventory_combines_docker_and_podman_without_commands_or_labels() -> None:
    docker_ps = json.dumps({"Names": "api", "Image": "agentbom/agent-bom:0.101.0", "State": "running"})
    docker_images = json.dumps(
        {
            "Repository": "agentbom/agent-bom",
            "Tag": "0.101.0",
            "Digest": "sha256:abc",
            "Size": "1.2GB",
        }
    )

    def runner(command: list[str], _timeout: float) -> CommandResult:
        if command[0] == "docker" and command[1] == "info":
            return _result("27.0")
        if command[0] == "docker" and command[1] == "ps":
            return _result(docker_ps + "\n")
        if command[0] == "docker" and command[1] == "images":
            return _result(docker_images + "\n")
        if command[0] == "podman" and command[1] == "info":
            return _result(returncode=1, status="unavailable")
        raise AssertionError(command)

    containers, images = collect_container_assets(runner=runner, runtimes=("docker", "podman"))

    assert containers.status == "partial"
    assert containers.items == [{"runtime": "docker", "name": "api", "image": "agentbom/agent-bom:0.101.0", "state": "running"}]
    assert images.items == [
        {
            "runtime": "docker",
            "repository": "agentbom/agent-bom",
            "tag": "0.101.0",
            "digest": "sha256:abc",
            "size": "1.2GB",
        }
    ]
    serialized = json.dumps({"containers": containers.items, "images": images.items})
    assert "Command" not in serialized
    assert "Labels" not in serialized


def test_endpoint_inventory_has_bounded_privacy_contract_and_explicit_collectors() -> None:
    inventory = collect_endpoint_inventory(
        system="Plan9",
        runner=lambda _command, _timeout: _result(returncode=1, status="unavailable"),
        psutil_module=None,
    )

    assert inventory["schema_version"] == "1"
    assert inventory["platform"]["system"] == "Plan9"
    assert inventory["privacy"] == {
        "process_arguments_collected": False,
        "environment_values_collected": False,
        "browser_history_collected": False,
        "arbitrary_home_directory_scan": False,
        "network_remote_addresses_collected": False,
    }
    collectors = {entry["name"]: entry for entry in inventory["collectors"]}
    assert set(collectors) == {"applications", "processes", "services", "listeners", "containers", "images"}
    assert collectors["applications"]["status"] == "unsupported"
    assert collectors["processes"]["status"] == "unavailable"


def test_workstation_json_includes_endpoint_inventory_and_scope_truth(tmp_path: Path) -> None:
    output = tmp_path / "workstation.json"
    inventory = {
        "schema_version": "1",
        "platform": {"system": "Darwin", "release": "", "machine": "arm64"},
        "privacy": {},
        "collectors": [
            {"name": "applications", "status": "complete", "item_count": 4, "message": ""},
            {"name": "processes", "status": "complete", "item_count": 3, "message": ""},
            {"name": "services", "status": "complete", "item_count": 8, "message": ""},
            {"name": "listeners", "status": "complete", "item_count": 2, "message": ""},
            {"name": "containers", "status": "unavailable", "item_count": None, "message": "runtime unavailable"},
            {"name": "images", "status": "unavailable", "item_count": None, "message": "runtime unavailable"},
        ],
        "applications": [],
        "processes": [],
        "services": [],
        "listeners": [],
        "containers": [],
        "images": [],
    }

    with (
        patch("agent_bom.cli.agents.discover_all", return_value=[]),
        patch("agent_bom.endpoint.scope.platform.system", return_value="Darwin"),
        patch("agent_bom.endpoint.inventory.collect_endpoint_inventory", return_value=inventory),
        patch("agent_bom.parsers.browser_extensions.discover_browser_extensions", return_value=[]),
    ):
        result = CliRunner().invoke(
            main,
            [
                "scan",
                "--preset",
                "workstation",
                "--no-scan",
                "--offline",
                "--format",
                "json",
                "--output",
                str(output),
            ],
        )

    assert result.exit_code == 1, result.output
    payload = json.loads(output.read_text())
    assert payload["endpoint_inventory"] == inventory
    assert "endpoint_inventory" in payload["scan_sources"]
    scopes = {scope["name"]: scope for scope in payload["scan_run"]["scopes"]}
    assert scopes["installed_applications"]["status"] == "complete"
    assert scopes["running_processes"]["item_count"] == 3
    assert scopes["services"]["item_count"] == 8
    assert scopes["listeners"]["item_count"] == 2
    assert scopes["container_assets"]["status"] == "unavailable"
