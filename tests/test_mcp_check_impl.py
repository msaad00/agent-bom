"""Regression tests for MCP check tool consistency."""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, patch

import pytest

from agent_bom.mcp_tools.scanning import check_impl
from agent_bom.models import Package, Severity, Vulnerability


@pytest.mark.asyncio
async def test_check_impl_requires_explicit_os_package_version():
    result = await check_impl(
        package="ncurses-bin",
        ecosystem="deb",
        _validate_ecosystem=lambda eco: eco,
        _truncate_response=lambda response: response,
    )
    payload = json.loads(result)
    assert payload["ecosystem"] == "deb"
    assert "Explicit version required" in payload["error"]


@pytest.mark.asyncio
async def test_check_impl_uses_full_scan_pipeline():
    async def fake_scan(packages: list[Package]):
        packages[0].vulnerabilities.append(Vulnerability(id="CVE-2026-TEST", summary="test", severity=Severity.HIGH))

    with patch("agent_bom.scanners.scan_packages", side_effect=fake_scan):
        result = await check_impl(
            package="Django@3.2.0",
            ecosystem="pypi",
            _validate_ecosystem=lambda eco: eco,
            _truncate_response=lambda response: response,
        )

    payload = json.loads(result)
    assert payload["package"] == "Django"
    assert payload["version"] == "3.2.0"
    assert payload["vulnerabilities"] == 1


@pytest.mark.asyncio
async def test_check_impl_marks_os_packages_incomplete_when_context_missing():
    with (
        patch("agent_bom.parsers.os_parsers.enrich_os_package_context", return_value=False),
        patch("agent_bom.scanners.scan_packages", new=AsyncMock()),
    ):
        result = await check_impl(
            package="ncurses-bin@6.5+20250216-2",
            ecosystem="deb",
            _validate_ecosystem=lambda eco: eco,
            _truncate_response=lambda response: response,
        )

    payload = json.loads(result)
    assert payload["status"] == "incomplete"
    assert payload["vulnerabilities"] == 0
