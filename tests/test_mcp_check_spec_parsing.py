"""Regression: the MCP `check` tool must parse pip specifiers, not read clean.

`check_impl` previously split only on `@`, so `requests==2.20.0` left the `==`
glued to the name — which then failed to resolve (returned an error with no
status) or scanned the wrong thing (read as clean). It now normalises pip/PEP
440 specifiers to the `name@version` form and tags error responses with
``status: "error"`` so a consumer can't misread them as clean.
"""

import json
from unittest.mock import patch

import pytest


def _trunc(s):
    return s


@pytest.mark.asyncio
async def test_check_parses_pip_double_equals_spec():
    from agent_bom.mcp_tools.scanning import check_impl

    async def _noop_scan(pkgs, **_kw):
        return 0  # leave pkg.vulnerabilities empty → clean verdict on a real version

    with patch("agent_bom.scanners.scan_packages", side_effect=_noop_scan):
        result = await check_impl(
            package="requests==2.20.0",
            ecosystem="pypi",
            _validate_ecosystem=lambda e: e,
            _truncate_response=_trunc,
        )
    data = json.loads(result)
    # The `==` must have been parsed off, not glued to the name.
    assert data["package"] == "requests"
    assert data["version"] == "2.20.0"


@pytest.mark.asyncio
async def test_check_parses_pep440_range_spec():
    from agent_bom.mcp_tools.scanning import check_impl

    async def _noop_scan(pkgs, **_kw):
        return 0

    with patch("agent_bom.scanners.scan_packages", side_effect=_noop_scan):
        result = await check_impl(
            package="flask>=0.12",
            ecosystem="pypi",
            _validate_ecosystem=lambda e: e,
            _truncate_response=_trunc,
        )
    data = json.loads(result)
    assert data["package"] == "flask"
    assert data["version"] == "0.12"


@pytest.mark.asyncio
async def test_check_unresolvable_version_is_not_clean():
    from agent_bom.mcp_tools.scanning import check_impl

    async def _no_resolve(pkg, _client):
        return None  # registry cannot resolve a version

    with patch("agent_bom.resolver.resolve_package_version", side_effect=_no_resolve):
        result = await check_impl(
            package="totally-bogus-pkg-xyz",  # no version → resolve → fail
            ecosystem="pypi",
            _validate_ecosystem=lambda e: e,
            _truncate_response=_trunc,
        )
    data = json.loads(result)
    assert data.get("status") == "error"
    assert data.get("status") != "clean"
