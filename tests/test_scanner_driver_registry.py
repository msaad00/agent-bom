"""Tests for scanner driver registry contracts."""

from __future__ import annotations

import json
import sys
import types
from collections.abc import Callable
from typing import Any

import pytest
from click.testing import CliRunner
from starlette.testclient import TestClient

from agent_bom.api.server import app
from agent_bom.cli import main
from agent_bom.extensions import ENTRYPOINTS_ENABLED_ENV, ExtensionCapabilities
from agent_bom.scanners.base import ScannerExecutionState, ScannerFailureMode, ScannerPhase, ScannerRegistration


class FakeEntryPoint:
    def __init__(self, name: str, loader: Callable[[], Any]) -> None:
        self.name = name
        self._loader = loader

    def load(self) -> Any:
        return self._loader()


class FakeEntryPoints(list):
    def select(self, *, group: str) -> list[FakeEntryPoint]:
        return [entry_point for entry_point in self if getattr(entry_point, "group", group) == group]


def _patch_entry_points(monkeypatch, entries_by_group: dict[str, list[FakeEntryPoint]]) -> None:
    entries = FakeEntryPoints()
    for group, group_entries in entries_by_group.items():
        for entry_point in group_entries:
            entry_point.group = group
            entries.append(entry_point)
    monkeypatch.setattr("agent_bom.extensions.metadata.entry_points", lambda: entries)


@pytest.fixture(autouse=True)
def reset_scanner_registry(monkeypatch):
    import agent_bom.scanners.registry as scanner_registry

    monkeypatch.delenv(ENTRYPOINTS_ENABLED_ENV, raising=False)
    scanner_registry._reset_scanner_registry_for_tests()
    yield
    monkeypatch.delenv(ENTRYPOINTS_ENABLED_ENV, raising=False)
    scanner_registry._reset_scanner_registry_for_tests()
    scanner_registry.list_registered_scanners()


def test_builtin_scanner_registry_declares_core_scanner_families() -> None:
    from agent_bom.scanners.registry import list_registered_scanners, scanner_registry_summary

    scanners = {registration.name: registration for registration in list_registered_scanners()}

    expected = {
        "sca-vulnerability",
        "secret-patterns",
        "sast-semgrep",
        "container-image",
        "sbom-ingest",
        "iac-terraform",
        "cicd-github-actions",
        "dataset-pii",
        "prompt-injection",
        "firmware-advisory",
        "runtime-detectors",
        "yara-signature",
        "zero-day-heuristics",
    }
    assert expected <= set(scanners)
    assert scanners["sca-vulnerability"].failure_mode is ScannerFailureMode.FAIL_CLOSED
    assert scanners["sca-vulnerability"].capabilities.network_access is True
    assert scanners["secret-patterns"].capabilities.network_access is False
    assert scanners["sast-semgrep"].skip_when == ("semgrep_missing", "no_code_scope")
    assert scanners["runtime-detectors"].phase is ScannerPhase.SCANNING
    assert scanners["yara-signature"].execution_state is ScannerExecutionState.PLANNED
    assert scanners["zero-day-heuristics"].enabled_by_default is False

    summary = scanner_registry_summary()
    assert summary["total"] == len(scanners)
    assert summary["planned"] == 2
    assert summary["by_phase"]["scanning"] >= 6


def test_planned_scanners_can_be_excluded() -> None:
    from agent_bom.scanners.registry import list_registered_scanners

    active_names = {registration.name for registration in list_registered_scanners(include_planned=False)}

    assert "sca-vulnerability" in active_names
    assert "yara-signature" not in active_names
    assert "zero-day-heuristics" not in active_names


def test_duplicate_scanner_registration_is_rejected() -> None:
    from agent_bom.scanners.registry import register_scanner

    registration = ScannerRegistration(name="duplicate", module="agent_bom.tests.fake")
    register_scanner(registration)

    with pytest.raises(ValueError, match="duplicate scanner registration"):
        register_scanner(registration)


def test_entry_point_scanner_registration_loads_only_when_enabled(monkeypatch) -> None:
    import agent_bom.scanners.registry as scanner_registry

    module_name = "agent_bom.tests.fake_scanner_driver"
    fake_module = types.ModuleType(module_name)
    fake_module.run = lambda **_: {"ok": True}
    monkeypatch.setitem(sys.modules, module_name, fake_module)

    registration = ScannerRegistration(
        name="acme-secret-scanner",
        module=module_name,
        source="entry_point",
        phase=ScannerPhase.SCANNING,
        run_attr="run",
        input_types=("filesystem_path",),
        output_types=("secret_findings",),
        finding_types=("credential",),
        capabilities=ExtensionCapabilities(scan_modes=("local",), required_scopes=("local_project_read",)),
    )
    _patch_entry_points(
        monkeypatch,
        {"agent_bom.scanner_drivers": [FakeEntryPoint("acme-secret-scanner", lambda: registration)]},
    )

    scanner_registry._reset_scanner_registry_for_tests()
    assert "acme-secret-scanner" not in {item.name for item in scanner_registry.list_registered_scanners()}

    monkeypatch.setenv(ENTRYPOINTS_ENABLED_ENV, "true")
    scanner_registry._reset_scanner_registry_for_tests()
    scanners = {item.name: item for item in scanner_registry.list_registered_scanners()}

    assert scanners["acme-secret-scanner"].source == "entry_point"
    assert scanners["acme-secret-scanner"].input_types == ("filesystem_path",)


def test_scan_drivers_api_endpoint_returns_contracts() -> None:
    client = TestClient(app, raise_server_exceptions=False)

    response = client.get("/v1/scan/drivers")

    assert response.status_code == 200
    body = response.json()
    drivers = {driver["name"]: driver for driver in body["drivers"]}
    assert body["summary"]["total"] == len(drivers)
    assert drivers["sca-vulnerability"]["failure_mode"] == "fail_closed"
    assert drivers["secret-patterns"]["capabilities"]["network_access"] is False
    assert drivers["yara-signature"]["execution_state"] == "planned"


def test_scan_drivers_api_can_hide_planned_slots() -> None:
    client = TestClient(app, raise_server_exceptions=False)

    response = client.get("/v1/scan/drivers?include_planned=false")

    assert response.status_code == 200
    names = {driver["name"] for driver in response.json()["drivers"]}
    assert "secret-patterns" in names
    assert "yara-signature" not in names


def test_scanners_cli_lists_driver_contracts_as_json() -> None:
    result = CliRunner().invoke(main, ["scanners", "--active-only", "--format", "json"])

    assert result.exit_code == 0, result.output
    body = json.loads(result.output)
    names = {driver["name"] for driver in body["drivers"]}
    assert "sca-vulnerability" in names
    assert "secret-patterns" in names
    assert "yara-signature" not in names
