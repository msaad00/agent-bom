"""Regression tests for per-scan scanner option isolation."""

from __future__ import annotations

import asyncio
from unittest.mock import patch

import pytest

import agent_bom.scanners as scanners
from agent_bom.models import Agent, AgentType, MCPServer, Package
from agent_bom.scanners import IncompleteScanError, ScanOptions, scan_agents, scan_agents_sync, scan_packages


def _agent(name: str = "agent", package: Package | None = None) -> Agent:
    pkg = package or Package(name="requests", version="2.28.0", ecosystem="pypi")
    return Agent(
        name=name,
        agent_type=AgentType.CUSTOM,
        config_path=f"/tmp/{name}.json",
        mcp_servers=[MCPServer(name=f"{name}-server", packages=[pkg])],
    )


def test_scan_packages_explicit_offline_option_ignores_global_online_state(monkeypatch):
    """Offline fail-closed behavior must be per scan, not read from a global."""
    monkeypatch.setattr(scanners, "offline_mode", False)
    pkg = Package(name="requests", version="2.28.0", ecosystem="pypi")

    with (
        patch("agent_bom.scanners._scan_packages_local_db", return_value=(0, set())),
        patch("agent_bom.scanners.query_osv_batch") as mock_osv,
    ):
        with pytest.raises(IncompleteScanError, match="populated local vulnerability DB"):
            asyncio.run(scan_packages([pkg], options=ScanOptions(offline=True)))

    mock_osv.assert_not_called()


def test_scan_agents_threads_independent_options_to_package_scan(monkeypatch):
    """Concurrent scans must carry their own options into package scanning."""
    seen: list[tuple[bool, bool]] = []

    async def _scan_packages(_packages, *, resolve_transitive=False, options=None):
        assert options is not None
        seen.append((options.offline, options.compliance_enabled))
        await asyncio.sleep(0)
        return 0

    monkeypatch.setattr(scanners, "scan_packages", _scan_packages)

    async def _run() -> None:
        await asyncio.gather(
            scan_agents(
                [_agent("offline")],
                options=ScanOptions(offline=True, compliance_enabled=True),
                show_scan_banner=False,
            ),
            scan_agents(
                [_agent("online")],
                options=ScanOptions(offline=False, compliance_enabled=False),
                show_scan_banner=False,
            ),
        )

    asyncio.run(_run())

    assert sorted(seen) == [(False, False), (True, True)]


def test_scan_agents_sync_does_not_mutate_legacy_compliance_global(monkeypatch):
    """The legacy compliance global must not become request-scoped state."""
    monkeypatch.setattr(scanners, "compliance_mode", False)

    async def _scan_packages(_packages, *, resolve_transitive=False, options=None):
        assert options is not None
        assert options.compliance_enabled is True
        return 0

    monkeypatch.setattr(scanners, "scan_packages", _scan_packages)

    scan_agents_sync([_agent("compliance")], compliance_enabled=True, show_scan_banner=False)

    assert scanners.compliance_mode is False
