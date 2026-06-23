"""check must not read a nonexistent explicit version as clean (P1 audit fix)."""

import json
from unittest.mock import AsyncMock, patch

import pytest


def _trunc(s):
    return s


@pytest.mark.asyncio
async def test_explicit_nonexistent_version_is_unknown_not_clean():
    from agent_bom.mcp_tools import scanning

    async def _noop_scan(pkgs, **_kw):
        return 0  # finds nothing (the bogus version isn't in any advisory)

    with (
        patch("agent_bom.scanners.scan_packages", side_effect=_noop_scan),
        patch("agent_bom.mcp_tools.scanning._version_published", new=AsyncMock(return_value=False)),
    ):
        result = await scanning.check_impl(
            package="left-pad@0.0.1-doesnotexist",
            ecosystem="npm",
            _validate_ecosystem=lambda e: e,
            _truncate_response=_trunc,
        )
    data = json.loads(result)
    assert data["status"] == "unknown"
    assert data["status"] != "clean"
    assert "not found" in data["message"]


@pytest.mark.asyncio
async def test_explicit_published_clean_version_is_clean():
    from agent_bom.mcp_tools import scanning

    async def _noop_scan(pkgs, **_kw):
        return 0

    with (
        patch("agent_bom.scanners.scan_packages", side_effect=_noop_scan),
        patch("agent_bom.mcp_tools.scanning._version_published", new=AsyncMock(return_value=True)),
    ):
        result = await scanning.check_impl(
            package="six==1.16.0",
            ecosystem="pypi",
            _validate_ecosystem=lambda e: e,
            _truncate_response=_trunc,
        )
    data = json.loads(result)
    assert data["status"] == "clean"  # real published version, no vulns


@pytest.mark.asyncio
async def test_vulnerable_version_short_circuits_before_existence_check():
    from agent_bom.mcp_tools import scanning

    async def _vuln_scan(pkgs, **_kw):
        from unittest.mock import MagicMock

        pkgs[0].vulnerabilities = [MagicMock(id="CVE-2023-32681")]  # any non-empty list
        return 1

    # _version_published must NOT even be consulted when vulns are found.
    published = AsyncMock(return_value=True)
    with (
        patch("agent_bom.scanners.scan_packages", side_effect=_vuln_scan),
        patch("agent_bom.mcp_tools.scanning._version_published", new=published),
    ):
        result = await scanning.check_impl(
            package="requests==2.20.0",
            ecosystem="pypi",
            _validate_ecosystem=lambda e: e,
            _truncate_response=_trunc,
        )
    data = json.loads(result)
    assert data.get("vulnerabilities") and data["vulnerabilities"] != 0
    published.assert_not_awaited()
