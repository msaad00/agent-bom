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
    async def fake_scan(packages: list[Package], **_kwargs):
        packages[0].vulnerabilities.append(
            Vulnerability(
                id="CVE-2026-TEST",
                summary="test",
                severity=Severity.HIGH,
                cvss_score=9.1,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                epss_score=0.87,
                is_kev=True,
            )
        )

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
    detail = payload["details"][0]
    assert detail["is_kev"] is True
    assert detail["epss_score"] == 0.87
    assert detail["cvss_vector"].startswith("CVSS:3.1/")


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


@pytest.mark.asyncio
async def test_check_impl_blocks_malicious_package_without_cve_rows():
    async def fake_scan(packages: list[Package], **_kwargs):
        packages[0].is_malicious = True
        packages[0].malicious_reason = "Possible typosquat of requests"

    with patch("agent_bom.scanners.scan_packages", side_effect=fake_scan):
        result = await check_impl(
            package="reqeusts@1.0.0",
            ecosystem="pypi",
            offline=True,
            _validate_ecosystem=lambda eco: eco,
            _truncate_response=lambda response: response,
        )

    payload = json.loads(result)
    assert payload["canonical_verdict"] == "malicious"
    assert payload["status"] == "malicious"
    assert payload["is_malicious"] is True
    assert payload["malicious_reason"] == "Possible typosquat of requests"
    assert payload["vulnerability_count"] == 0
    assert payload["lookup_mode"] == "offline"
    assert payload["package_canonical_id"]


@pytest.mark.asyncio
async def test_check_impl_offline_explicit_version_never_queries_registry():
    scan = AsyncMock()
    with (
        patch("agent_bom.scanners.scan_packages", new=scan),
        patch("agent_bom.mcp_tools.scanning._version_published", new=AsyncMock()) as published,
    ):
        result = await check_impl(
            package="six==1.16.0",
            ecosystem="pypi",
            offline=True,
            _validate_ecosystem=lambda eco: eco,
            _truncate_response=lambda response: response,
        )

    payload = json.loads(result)
    assert payload["canonical_verdict"] == "clean"
    assert payload["lookup_mode"] == "offline"
    assert scan.await_args.kwargs["options"].offline is True
    published.assert_not_awaited()


@pytest.mark.asyncio
async def test_check_impl_offline_coverage_gap_is_incomplete_not_clean():
    async def fake_scan(_packages: list[Package], **_kwargs):
        from agent_bom.scanners import record_coverage_warning

        record_coverage_warning(
            {
                "kind": "offline_ecosystem_gap",
                "release": "offline:pypi",
                "detail": "Local advisory coverage is unavailable for pypi",
            }
        )

    with patch("agent_bom.scanners.scan_packages", side_effect=fake_scan):
        result = await check_impl(
            package="six==1.16.0",
            ecosystem="pypi",
            offline=True,
            _validate_ecosystem=lambda eco: eco,
            _truncate_response=lambda response: response,
        )

    payload = json.loads(result)
    assert payload["canonical_verdict"] == "incomplete"
    assert payload["status"] == "incomplete"
    assert payload["scan_warnings"] == ["Local advisory coverage is unavailable for pypi"]
