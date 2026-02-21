"""Tests for the MCP server registry module."""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from agent_bom.models import Package
from agent_bom.registry import (
    RegistryUpdateResult,
    VersionDrift,
    _parse_version,
    compare_versions,
    detect_version_drift,
    list_registry,
    search_registry,
    update_registry_versions,
)

# ── Version comparison ──────────────────────────────────────────────────────


def test_parse_version_semver():
    assert _parse_version("1.2.3") == (1, 2, 3)


def test_parse_version_calver():
    assert _parse_version("2025.1.14") == (2025, 1, 14)


def test_parse_version_with_prefix():
    assert _parse_version("v1.0.0") == (1, 0, 0)


def test_parse_version_with_prerelease():
    assert _parse_version("1.2.3-beta.1") == (1, 2, 3)


def test_parse_version_empty():
    assert _parse_version("") is None
    assert _parse_version("latest") is None
    assert _parse_version("unknown") is None


def test_parse_version_invalid():
    assert _parse_version("abc.def.ghi") is None


def test_compare_versions_outdated():
    assert compare_versions("1.0.0", "2.0.0") == "outdated"


def test_compare_versions_current():
    assert compare_versions("2.0.0", "2.0.0") == "current"


def test_compare_versions_newer():
    assert compare_versions("3.0.0", "2.0.0") == "current"


def test_compare_versions_calver():
    assert compare_versions("2025.1.14", "2026.2.1") == "outdated"


def test_compare_versions_minor():
    assert compare_versions("1.2.0", "1.3.0") == "outdated"


def test_compare_versions_patch():
    assert compare_versions("1.2.3", "1.2.4") == "outdated"


def test_compare_versions_invalid():
    assert compare_versions("abc", "2.0.0") == "unknown"
    assert compare_versions("1.0.0", "xyz") == "unknown"


def test_compare_versions_empty():
    assert compare_versions("", "1.0.0") == "unknown"
    assert compare_versions("1.0.0", "") == "unknown"


# ── Version drift detection ─────────────────────────────────────────────────


MOCK_REGISTRY = {
    "@modelcontextprotocol/server-filesystem": {
        "package": "@modelcontextprotocol/server-filesystem",
        "ecosystem": "npm",
        "latest_version": "2.0.0",
        "category": "filesystem",
        "risk_level": "high",
    },
    "mcp-server-sqlite": {
        "package": "mcp-server-sqlite",
        "ecosystem": "pypi",
        "latest_version": "1.5.0",
        "category": "database",
        "risk_level": "medium",
    },
}


def test_detect_drift_outdated():
    packages = [
        Package(
            name="@modelcontextprotocol/server-filesystem",
            version="1.0.0",
            ecosystem="npm",
            resolved_from_registry=True,
        ),
    ]
    drift = detect_version_drift(packages, registry=MOCK_REGISTRY)
    assert len(drift) == 1
    assert drift[0].status == "outdated"
    assert drift[0].installed == "1.0.0"
    assert drift[0].latest == "2.0.0"


def test_detect_drift_current():
    packages = [
        Package(
            name="@modelcontextprotocol/server-filesystem",
            version="2.0.0",
            ecosystem="npm",
            resolved_from_registry=True,
        ),
    ]
    drift = detect_version_drift(packages, registry=MOCK_REGISTRY)
    assert len(drift) == 1
    assert drift[0].status == "current"


def test_detect_drift_only_registry_packages():
    packages = [
        Package(
            name="some-random-pkg",
            version="1.0.0",
            ecosystem="npm",
            resolved_from_registry=False,
        ),
    ]
    drift = detect_version_drift(packages, registry=MOCK_REGISTRY)
    assert len(drift) == 0


def test_detect_drift_unknown_version():
    packages = [
        Package(
            name="@modelcontextprotocol/server-filesystem",
            version="latest",
            ecosystem="npm",
            resolved_from_registry=True,
        ),
    ]
    # Registry has "latest_version" = "2.0.0", installed = "latest" -> skipped by compare_versions
    drift = detect_version_drift(packages, registry=MOCK_REGISTRY)
    # "latest" parses to None -> "unknown"
    assert len(drift) == 1
    assert drift[0].status == "unknown"


def test_detect_drift_multiple():
    packages = [
        Package(name="@modelcontextprotocol/server-filesystem", version="1.0.0", ecosystem="npm", resolved_from_registry=True),
        Package(name="mcp-server-sqlite", version="1.5.0", ecosystem="pypi", resolved_from_registry=True),
    ]
    drift = detect_version_drift(packages, registry=MOCK_REGISTRY)
    assert len(drift) == 2
    statuses = {d.package: d.status for d in drift}
    assert statuses["@modelcontextprotocol/server-filesystem"] == "outdated"
    assert statuses["mcp-server-sqlite"] == "current"


# ── Search ──────────────────────────────────────────────────────────────────


def test_search_by_name():
    results = search_registry("filesystem", registry=MOCK_REGISTRY)
    assert len(results) == 1
    assert results[0]["package"] == "@modelcontextprotocol/server-filesystem"


def test_search_by_category():
    results = search_registry("", category="database", registry=MOCK_REGISTRY)
    assert len(results) == 1
    assert results[0]["package"] == "mcp-server-sqlite"


def test_search_no_results():
    results = search_registry("zzzzz-nonexistent", registry=MOCK_REGISTRY)
    assert len(results) == 0


def test_search_case_insensitive():
    results = search_registry("FILESYSTEM", registry=MOCK_REGISTRY)
    assert len(results) == 1


def test_search_with_risk_filter():
    results = search_registry("", risk_level="high", registry=MOCK_REGISTRY)
    assert len(results) == 1
    assert results[0]["risk_level"] == "high"


# ── List ────────────────────────────────────────────────────────────────────


def test_list_all():
    entries = list_registry(registry=MOCK_REGISTRY)
    assert len(entries) == 2


def test_list_filter_ecosystem():
    entries = list_registry(ecosystem="pypi", registry=MOCK_REGISTRY)
    assert len(entries) == 1
    assert entries[0]["ecosystem"] == "pypi"


def test_list_filter_risk():
    entries = list_registry(risk_level="high", registry=MOCK_REGISTRY)
    assert len(entries) == 1
    assert entries[0]["risk_level"] == "high"


def test_list_filter_category():
    entries = list_registry(category="database", registry=MOCK_REGISTRY)
    assert len(entries) == 1
    assert entries[0]["category"] == "database"


def test_list_sorted_by_name():
    entries = list_registry(sort_by="name", registry=MOCK_REGISTRY)
    assert entries[0]["name"] < entries[1]["name"]


def test_list_real_registry():
    """Verify the real bundled registry loads and has 108+ servers."""
    entries = list_registry()
    assert len(entries) >= 108


def test_list_real_registry_filter_npm():
    entries = list_registry(ecosystem="npm")
    assert len(entries) > 0
    assert all(e["ecosystem"] == "npm" for e in entries)


# ── Update (mocked) ────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_update_registry_versions_mock():
    """Test version update with mocked HTTP responses."""
    mock_registry = {
        "_updated": "2026-01-01",
        "_total_servers": 1,
        "servers": {
            "test-pkg": {
                "package": "test-pkg",
                "ecosystem": "npm",
                "latest_version": "1.0.0",
            },
        },
    }

    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {"version": "2.0.0"}

    with (
        patch("agent_bom.registry._load_registry_full", return_value=mock_registry),
        patch("agent_bom.registry._REGISTRY_PATH") as mock_path,
        patch("agent_bom.resolver.request_with_retry", new_callable=AsyncMock, return_value=mock_response),
    ):
        mock_path.write_text = MagicMock()
        result = await update_registry_versions(dry_run=True)

    assert result.total == 1
    assert result.updated == 1
    assert result.details[0]["new"] == "2.0.0"


@pytest.mark.asyncio
async def test_update_registry_handles_errors():
    """Test that network errors are handled gracefully."""
    mock_registry = {
        "_updated": "2026-01-01",
        "_total_servers": 1,
        "servers": {
            "bad-pkg": {
                "package": "bad-pkg",
                "ecosystem": "npm",
                "latest_version": "1.0.0",
            },
        },
    }

    with (
        patch("agent_bom.registry._load_registry_full", return_value=mock_registry),
        patch("agent_bom.resolver.request_with_retry", new_callable=AsyncMock, return_value=None),
    ):
        result = await update_registry_versions(dry_run=True)

    assert result.total == 1
    assert result.failed == 1


# ── CLI commands ────────────────────────────────────────────────────────────


def test_cli_registry_help():
    from click.testing import CliRunner

    from agent_bom.cli import main

    runner = CliRunner()
    result = runner.invoke(main, ["registry", "--help"])
    assert result.exit_code == 0
    assert "update" in result.output
    assert "list" in result.output
    assert "search" in result.output


def test_cli_registry_list():
    from click.testing import CliRunner

    from agent_bom.cli import main

    runner = CliRunner()
    result = runner.invoke(main, ["registry", "list"])
    assert result.exit_code == 0
    # Should contain table header or server names
    assert "filesystem" in result.output.lower() or "Name" in result.output


def test_cli_registry_list_json():
    from click.testing import CliRunner

    from agent_bom.cli import main

    runner = CliRunner()
    result = runner.invoke(main, ["registry", "list", "-f", "json"])
    assert result.exit_code == 0
    data = json.loads(result.output)
    assert isinstance(data, list)
    assert len(data) >= 100


def test_cli_registry_search_finds_results():
    from click.testing import CliRunner

    from agent_bom.cli import main

    runner = CliRunner()
    result = runner.invoke(main, ["registry", "search", "filesystem"])
    assert result.exit_code == 0
    assert "filesystem" in result.output.lower()


def test_cli_registry_search_no_match():
    from click.testing import CliRunner

    from agent_bom.cli import main

    runner = CliRunner()
    result = runner.invoke(main, ["registry", "search", "zzzzz-nonexistent-pkg"])
    assert result.exit_code == 0
    assert "No results" in result.output or "0" in result.output


# ── Dataclass construction ──────────────────────────────────────────────────


def test_version_drift_dataclass():
    d = VersionDrift(
        package="test", ecosystem="npm",
        installed="1.0.0", latest="2.0.0", status="outdated",
    )
    assert d.package == "test"
    assert d.status == "outdated"


def test_registry_update_result_dataclass():
    r = RegistryUpdateResult(total=10, updated=3, failed=1, unchanged=6)
    assert r.total == 10
    assert r.updated == 3


# ── API bridge tests ────────────────────────────────────────────────────────


def test_api_bridge_normalizes_packages():
    """Verify the API bridge normalizes package+ecosystem into packages array."""
    from agent_bom.api.server import _load_registry

    _load_registry.cache_clear()
    servers = _load_registry()
    for srv in servers:
        assert isinstance(srv["packages"], list)
        if srv["packages"]:
            assert "name" in srv["packages"][0]
            assert "ecosystem" in srv["packages"][0]


def test_api_bridge_injects_id():
    """Verify the dict key becomes item['id']."""
    from agent_bom.api.server import _load_registry

    _load_registry.cache_clear()
    servers = _load_registry()
    assert len(servers) >= 108
    ids = {s["id"] for s in servers}
    assert "@modelcontextprotocol/server-filesystem" in ids


def test_api_bridge_risk_justification():
    """Spot-check that entries have non-empty risk_justification."""
    from agent_bom.api.server import _load_registry

    _load_registry.cache_clear()
    servers = _load_registry()
    has_justification = sum(1 for s in servers if s.get("risk_justification"))
    # At minimum 100 entries should have risk_justification
    assert has_justification >= 100


def test_api_bridge_tools_list():
    """Verify tools field is always a list."""
    from agent_bom.api.server import _load_registry

    _load_registry.cache_clear()
    servers = _load_registry()
    for srv in servers:
        assert isinstance(srv["tools"], list)


def test_new_servers_present():
    """Verify the 7 new servers from v0.16.0 are present."""
    from agent_bom.api.server import _load_registry

    _load_registry.cache_clear()
    servers = _load_registry()
    ids = {s["id"] for s in servers}
    expected_new = [
        "figma-mcp",
        "rovo-mcp",
        "@prisma/mcp-server",
        "@upstash/mcp-server-redis",
        "resend-mcp",
        "@browserbase/mcp-server-browserbase",
        "@e2b/mcp-server",
    ]
    for key in expected_new:
        assert key in ids, f"Missing new server: {key}"
