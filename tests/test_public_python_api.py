"""Tests for the public ``agent_bom`` Python API."""

from __future__ import annotations

import importlib
import json
from types import SimpleNamespace

import pytest

import agent_bom
from agent_bom import sdk
from agent_bom.models import AIBOMReport, Package, Severity, Vulnerability


def test_public_api_exports_expected_functions():
    assert agent_bom.scan is sdk.scan
    assert agent_bom.check is sdk.check
    assert agent_bom.diff is sdk.diff
    assert sdk.inventory.__name__ == "inventory"


def test_inventory_sdk_helper_does_not_shadow_inventory_module():
    inventory_module = importlib.import_module("agent_bom.inventory")

    assert agent_bom.inventory is inventory_module
    assert sdk.inventory.__name__ == "inventory"


def test_scan_delegates_to_cli_scan_runner(monkeypatch):
    report = AIBOMReport(scan_sources=["agent_discovery"])
    captured = {}

    def fake_run_default_scan(cfg, _console):
        captured["cfg"] = cfg
        return SimpleNamespace(report=report)

    monkeypatch.setattr("agent_bom.cli._scan_runner.run_default_scan", fake_run_default_scan)

    result = sdk.scan(project=".", offline=True, transitive=True)

    assert result is report
    assert captured["cfg"].project == "."
    assert captured["cfg"].offline is True
    assert captured["cfg"].resolve_transitive is True
    assert captured["cfg"].quiet is True


@pytest.mark.asyncio
async def test_async_check_returns_typed_package_result(monkeypatch):
    async def fake_scan_packages(packages: list[Package], **_kwargs):
        packages[0].vulnerabilities.append(
            Vulnerability(id="CVE-2026-0001", summary="test vuln", severity=Severity.HIGH, fixed_version="2.0.0")
        )
        return 1

    monkeypatch.setattr("agent_bom.scanners.scan_packages", fake_scan_packages)

    result = await sdk.async_check("Django@1.0.0", ecosystem="pypi", offline=True)

    assert result.package == "Django"
    assert result.version == "1.0.0"
    assert result.ecosystem == "pypi"
    assert result.status == "vulnerable"
    assert result.vulnerabilities == 1
    assert result.details[0]["id"] == "CVE-2026-0001"
    assert result.to_dict()["status"] == "vulnerable"


def test_check_rejects_nested_event_loop():
    async def run_inside_loop():
        with pytest.raises(sdk.AgentBomSDKError, match="async_check"):
            sdk.check("requests@2.31.0", ecosystem="pypi")

    import asyncio

    asyncio.run(run_inside_loop())


def test_inventory_returns_counts(tmp_path):
    path = tmp_path / "inventory.json"
    path.write_text(
        json.dumps(
            {
                "agents": [
                    {
                        "name": "agent-a",
                        "mcp_servers": [
                            {
                                "name": "server-a",
                                "packages": [
                                    {"name": "requests", "version": "2.31.0", "ecosystem": "pypi"},
                                    {"name": "express", "version": "4.18.0", "ecosystem": "npm"},
                                ],
                            }
                        ],
                    }
                ]
            }
        )
    )

    result = sdk.inventory(path)

    assert result.agent_count == 1
    assert result.server_count == 1
    assert result.package_count == 2
    assert result.to_dict()["package_count"] == 2


def test_diff_accepts_report_dicts():
    baseline = {
        "blast_radius": [
            {"vulnerability_id": "CVE-2026-OLD", "package": "oldpkg", "ecosystem": "pypi"},
        ],
        "agents": [],
    }
    current = {
        "blast_radius": [
            {"vulnerability_id": "CVE-2026-NEW", "package": "newpkg", "ecosystem": "pypi"},
        ],
        "agents": [],
    }

    result = sdk.diff(baseline, current)

    assert result.summary["new_findings"] == 1
    assert result.summary["resolved_findings"] == 1
    assert result.new_findings == 1
