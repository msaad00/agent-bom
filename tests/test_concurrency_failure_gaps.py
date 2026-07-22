"""Regression coverage for concurrency / failure-mode gap closures."""

from __future__ import annotations

import pytest

from agent_bom.api.models import JobStatus, ScanJob, ScanRequest
from agent_bom.api.pipeline import ScanCancelledError, _raise_if_cancelled, request_scan_cancellation
from agent_bom.extensions import ExtensionCapabilities
from agent_bom.guard import guard_install
from agent_bom.mcp_introspect import HealthStatus, health_check_servers
from agent_bom.models import MCPServer, TransportType
from agent_bom.parsers.skill_audit import _batch_verify_packages
from agent_bom.scanners.base import ScannerExecutionState, ScannerFailureMode, ScannerPhase, ScannerRegistration
from agent_bom.scanners.executor import ScannerDriverError, apply_registered_failure_mode


@pytest.mark.asyncio
async def test_batch_verify_packages_survives_sibling_raise(monkeypatch):
    async def _boom(name: str, eco: str):
        if name == "bad":
            raise RuntimeError("network down")
        return True

    monkeypatch.setattr("agent_bom.parsers.skill_audit._verify_package_exists", _boom)
    results = await _batch_verify_packages([("good", "npm"), ("bad", "npm")])
    assert results["good"] is True
    assert results["bad"] is True  # fail-open


@pytest.mark.asyncio
async def test_health_check_servers_survives_sibling_raise(monkeypatch):
    async def _probe_fail(server, timeout):  # noqa: ARG001
        raise RuntimeError("probe boom")

    monkeypatch.setattr("agent_bom.mcp_introspect.introspect_server", _probe_fail)
    servers = [
        MCPServer(name="a", command="npx", args=["x"], transport=TransportType.STDIO),
        MCPServer(name="b", command="npx", args=["y"], transport=TransportType.STDIO),
    ]
    statuses = await health_check_servers(servers, timeout=0.1, max_concurrent=2)
    assert len(statuses) == 2
    assert all(isinstance(item, HealthStatus) for item in statuses)
    assert all(item.reachable is False for item in statuses)


@pytest.mark.asyncio
async def test_guard_install_marks_raised_package_scan_failed(monkeypatch):
    async def _check(name, ecosystem, min_severity="high", block_kev=True):  # noqa: ARG001
        if name == "evil":
            raise RuntimeError("osv unavailable")
        return {"name": name, "blocked": False}

    monkeypatch.setattr("agent_bom.guard._check_package", _check)
    monkeypatch.setattr("agent_bom.guard._extract_pip_packages", lambda _args: ["safe", "evil"])
    result = await guard_install("pip", ["install", "safe", "evil"], allow_risky=True)
    assert result.install_allowed is False
    blocked = {item["name"]: item for item in result.blocked}
    assert blocked["evil"]["scan_failed"] is True


def test_apply_registered_failure_mode_fail_closed(monkeypatch):
    import agent_bom.scanners.registry as scanner_registry
    from agent_bom.scanners.registry import register_scanner

    scanner_registry._reset_scanner_registry_for_tests()
    register_scanner(
        ScannerRegistration(
            name="gap-test-closed",
            module="agent_bom.scanners",
            source="test",
            phase=ScannerPhase.SCANNING,
            execution_state=ScannerExecutionState.ACTIVE,
            failure_mode=ScannerFailureMode.FAIL_CLOSED,
            run_attr="scan_agents_sync",
            capabilities=ExtensionCapabilities(scan_modes=("local",)),
            summary="test",
        )
    )
    with pytest.raises(ScannerDriverError):
        apply_registered_failure_mode("gap-test-closed", RuntimeError("boom"))
    scanner_registry._reset_scanner_registry_for_tests()
    scanner_registry.list_registered_scanners()


def test_request_scan_cancellation_flips_status():
    job = ScanJob(
        job_id="cancel-test-1",
        request=ScanRequest(),
        status=JobStatus.RUNNING,
        created_at="2026-07-22T00:00:00Z",
    )
    status = request_scan_cancellation(job)
    assert status is JobStatus.CANCELLED
    assert job.status is JobStatus.CANCELLED


def test_raise_if_cancelled_raises():
    import threading

    job = ScanJob(
        job_id="cancel-test-2",
        request=ScanRequest(),
        status=JobStatus.CANCELLED,
        created_at="2026-07-22T00:00:00Z",
    )
    lock = threading.Lock()
    with pytest.raises(ScanCancelledError):
        _raise_if_cancelled(job, lock)
