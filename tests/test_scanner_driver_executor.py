"""Tests for scanner driver runtime dispatch."""

from __future__ import annotations

import sys
import types

import pytest

from agent_bom.extensions import ExtensionCapabilities
from agent_bom.scanners.base import ScannerExecutionState, ScannerFailureMode, ScannerPhase, ScannerRegistration
from agent_bom.scanners.executor import ScannerDriverError, run_scanner_driver


@pytest.fixture(autouse=True)
def reset_scanner_registry(monkeypatch):
    import agent_bom.scanners.registry as scanner_registry
    from agent_bom.extensions import ENTRYPOINTS_ENABLED_ENV

    monkeypatch.delenv(ENTRYPOINTS_ENABLED_ENV, raising=False)
    scanner_registry._reset_scanner_registry_for_tests()
    yield
    scanner_registry._reset_scanner_registry_for_tests()
    scanner_registry.list_registered_scanners()


def _register_test_driver(
    *,
    name: str = "test-driver",
    module: str = "agent_bom.tests.fake_executor_driver",
    run_attr: str = "run",
    failure_mode: ScannerFailureMode = ScannerFailureMode.WARN_AND_CONTINUE,
    execution_state: ScannerExecutionState = ScannerExecutionState.ACTIVE,
) -> None:
    from agent_bom.scanners.registry import register_scanner

    register_scanner(
        ScannerRegistration(
            name=name,
            module=module,
            source="test",
            phase=ScannerPhase.SCANNING,
            execution_state=execution_state,
            failure_mode=failure_mode,
            run_attr=run_attr,
            input_types=("filesystem_path",),
            output_types=("findings",),
            finding_types=("test",),
            capabilities=ExtensionCapabilities(scan_modes=("local",)),
            summary="test driver",
        )
    )


def test_run_scanner_driver_invokes_declared_run_attr(monkeypatch):
    module_name = "agent_bom.tests.fake_executor_driver"
    calls: list[dict] = []

    fake_module = types.ModuleType(module_name)
    fake_module.run = lambda **kwargs: calls.append(kwargs) or {"findings": [{"id": "f-1"}]}
    monkeypatch.setitem(sys.modules, module_name, fake_module)
    _register_test_driver()

    result = run_scanner_driver("test-driver", path="/tmp/demo")

    assert calls == [{"path": "/tmp/demo"}]
    assert result.telemetry.status == "ok"
    assert result.telemetry.findings_emitted == 1
    assert result.payload == {"findings": [{"id": "f-1"}]}


def test_fail_closed_surfaces_as_scan_failure(monkeypatch):
    module_name = "agent_bom.tests.fake_executor_driver_fail"
    fake_module = types.ModuleType(module_name)

    def _boom(**_kwargs):
        raise RuntimeError("scanner exploded")

    fake_module.scan = _boom
    monkeypatch.setitem(sys.modules, module_name, fake_module)
    _register_test_driver(
        module=module_name,
        run_attr="scan",
        failure_mode=ScannerFailureMode.FAIL_CLOSED,
    )

    with pytest.raises(ScannerDriverError, match="test-driver failed"):
        run_scanner_driver("test-driver")


def test_warn_and_continue_returns_warning_instead_of_raising(monkeypatch):
    module_name = "agent_bom.tests.fake_executor_driver_warn"
    fake_module = types.ModuleType(module_name)
    fake_module.run = lambda **_kwargs: (_ for _ in ()).throw(ValueError("soft failure"))
    monkeypatch.setitem(sys.modules, module_name, fake_module)
    _register_test_driver(module=module_name, failure_mode=ScannerFailureMode.WARN_AND_CONTINUE)

    result = run_scanner_driver("test-driver")

    assert result.telemetry.status == "warning"
    assert result.telemetry.warnings
    assert result.payload is None


def test_skip_when_unavailable_skips_missing_runner(monkeypatch):
    module_name = "agent_bom.tests.fake_executor_driver_missing"
    fake_module = types.ModuleType(module_name)
    monkeypatch.setitem(sys.modules, module_name, fake_module)
    _register_test_driver(
        module=module_name,
        run_attr="missing_callable",
        failure_mode=ScannerFailureMode.SKIP_WHEN_UNAVAILABLE,
    )

    result = run_scanner_driver("test-driver")

    assert result.telemetry.status == "skipped"
    assert "missing_callable" in result.telemetry.warnings[0]


def test_planned_driver_is_not_executable_by_default(monkeypatch):
    module_name = "agent_bom.tests.fake_executor_driver_planned"
    fake_module = types.ModuleType(module_name)
    fake_module.run = lambda **_kwargs: {"findings": []}
    monkeypatch.setitem(sys.modules, module_name, fake_module)
    _register_test_driver(
        module=module_name,
        execution_state=ScannerExecutionState.PLANNED,
        failure_mode=ScannerFailureMode.SKIP_WHEN_UNAVAILABLE,
    )

    result = run_scanner_driver("test-driver")

    assert result.telemetry.status == "skipped"
    assert "planned" in result.telemetry.warnings[0].lower()
