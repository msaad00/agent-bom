"""Tests for OSV ecosystem mapping across Maven, Go, NuGet, Cargo, and RubyGems.

O2 gap: scanner ECOSYSTEM_MAP maps these ecosystems but test fixtures only
covered PyPI/npm. These tests verify correct OSV query construction and
vulnerability assignment for all supported ecosystems.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from agent_bom.models import Package
from agent_bom.scanners import ECOSYSTEM_MAP

# ─── ECOSYSTEM_MAP coverage ──────────────────────────────────────────────────


@pytest.mark.parametrize(
    "ecosystem, expected_osv",
    [
        ("pypi", "PyPI"),
        ("npm", "npm"),
        ("go", "Go"),
        ("maven", "Maven"),
        ("nuget", "NuGet"),
        ("cargo", "crates.io"),
        ("rubygems", "RubyGems"),
    ],
)
def test_ecosystem_map_all_entries(ecosystem: str, expected_osv: str):
    """Every supported ecosystem maps to the correct OSV ecosystem name."""
    assert ecosystem in ECOSYSTEM_MAP
    assert ECOSYSTEM_MAP[ecosystem] == expected_osv


def test_ecosystem_map_unknown_returns_none():
    """Unknown ecosystems return None (Package will be skipped in scan)."""
    assert ECOSYSTEM_MAP.get("unknown_ecosystem") is None
    assert ECOSYSTEM_MAP.get("pip") is None  # PyPI uses 'pypi' key, not 'pip'
    assert ECOSYSTEM_MAP.get("") is None


# ─── Maven package fixtures ───────────────────────────────────────────────────


def _maven_pkg(group: str, artifact: str, version: str) -> Package:
    """Create a Maven Package with group:artifact coordinate as name."""
    return Package(name=f"{group}:{artifact}", version=version, ecosystem="maven")


def test_maven_package_maps_to_osv():
    """Maven package ecosystem maps to 'Maven' in ECOSYSTEM_MAP."""
    pkg = _maven_pkg("org.apache.logging.log4j", "log4j-core", "2.14.1")
    assert ECOSYSTEM_MAP.get(pkg.ecosystem) == "Maven"


def test_maven_log4shell_fixture():
    """log4j 2.14.1 is a known vulnerable version (Log4Shell / CVE-2021-44228)."""
    pkg = _maven_pkg("org.apache.logging.log4j", "log4j-core", "2.14.1")
    assert pkg.name == "org.apache.logging.log4j:log4j-core"
    assert pkg.ecosystem == "maven"
    assert pkg.version == "2.14.1"
    # OSV query would use ecosystem="Maven", name="org.apache.logging.log4j:log4j-core"
    osv_eco = ECOSYSTEM_MAP.get(pkg.ecosystem)
    assert osv_eco == "Maven"


def test_maven_spring_fixture():
    """Spring Framework package maps correctly."""
    pkg = _maven_pkg("org.springframework", "spring-webmvc", "5.3.18")
    assert ECOSYSTEM_MAP.get(pkg.ecosystem) == "Maven"


# ─── Go module fixtures ───────────────────────────────────────────────────────


def _go_pkg(module: str, version: str) -> Package:
    """Create a Go Package with module path as name."""
    return Package(name=module, version=version, ecosystem="go")


def test_go_package_maps_to_osv():
    """Go package ecosystem maps to 'Go' in ECOSYSTEM_MAP."""
    pkg = _go_pkg("github.com/gin-gonic/gin", "v1.9.0")
    assert ECOSYSTEM_MAP.get(pkg.ecosystem) == "Go"


def test_go_stdlib_fixture():
    """Go standard library module."""
    pkg = _go_pkg("stdlib", "1.21.0")
    assert pkg.ecosystem == "go"
    assert ECOSYSTEM_MAP.get("go") == "Go"


def test_go_grpc_fixture():
    """gRPC Go package."""
    pkg = _go_pkg("google.golang.org/grpc", "v1.54.0")
    assert ECOSYSTEM_MAP.get(pkg.ecosystem) == "Go"


# ─── NuGet fixtures ───────────────────────────────────────────────────────────


def _nuget_pkg(name: str, version: str) -> Package:
    return Package(name=name, version=version, ecosystem="nuget")


def test_nuget_package_maps_to_osv():
    """NuGet package ecosystem maps to 'NuGet' in ECOSYSTEM_MAP."""
    pkg = _nuget_pkg("Newtonsoft.Json", "13.0.1")
    assert ECOSYSTEM_MAP.get(pkg.ecosystem) == "NuGet"


def test_nuget_aspnetcore_fixture():
    """ASP.NET Core package."""
    pkg = _nuget_pkg("Microsoft.AspNetCore.App.Runtime.linux-x64", "8.0.0")
    assert ECOSYSTEM_MAP.get(pkg.ecosystem) == "NuGet"


# ─── Cargo (Rust) fixtures ────────────────────────────────────────────────────


def _cargo_pkg(name: str, version: str) -> Package:
    return Package(name=name, version=version, ecosystem="cargo")


def test_cargo_package_maps_to_osv():
    """Cargo package ecosystem maps to 'crates.io' in ECOSYSTEM_MAP."""
    pkg = _cargo_pkg("tokio", "1.28.0")
    assert ECOSYSTEM_MAP.get(pkg.ecosystem) == "crates.io"


def test_cargo_serde_fixture():
    pkg = _cargo_pkg("serde", "1.0.163")
    assert ECOSYSTEM_MAP.get(pkg.ecosystem) == "crates.io"


# ─── OSV query construction with mocked API ───────────────────────────────────


@pytest.mark.asyncio
async def test_scan_packages_maven_go_query_construction():
    """scan_packages builds correct OSV queries for Maven and Go packages."""
    from agent_bom.scanners import scan_packages

    maven_pkg = _maven_pkg("org.apache.logging.log4j", "log4j-core", "2.14.1")
    go_pkg = _go_pkg("github.com/gin-gonic/gin", "v1.9.0")
    nuget_pkg = _nuget_pkg("Newtonsoft.Json", "13.0.1")

    captured_queries: list[dict] = []

    async def mock_request_with_retry(client, method, url, json=None, **kwargs):
        if json and "queries" in json:
            captured_queries.extend(json["queries"])
        resp = MagicMock()
        resp.status_code = 200
        resp.json.return_value = {"results": [{"vulns": []}, {"vulns": []}, {"vulns": []}]}
        return resp

    with (
        patch("agent_bom.scanners._get_scan_cache", return_value=None),
        patch("agent_bom.scanners.request_with_retry", side_effect=mock_request_with_retry),
        patch("agent_bom.scanners.create_client") as mock_create_client,
    ):
        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=None)
        mock_create_client.return_value = mock_client

        await scan_packages([maven_pkg, go_pkg, nuget_pkg])

    # Verify queries were built for each ecosystem
    ecosystems_queried = {q["package"]["ecosystem"] for q in captured_queries}
    assert "Maven" in ecosystems_queried, f"Maven not in queried ecosystems: {ecosystems_queried}"
    assert "Go" in ecosystems_queried, f"Go not in queried ecosystems: {ecosystems_queried}"
    assert "NuGet" in ecosystems_queried, f"NuGet not in queried ecosystems: {ecosystems_queried}"


@pytest.mark.asyncio
async def test_scan_packages_maven_vuln_attached():
    """Vulnerabilities from OSV are attached to Maven packages after scan."""
    from agent_bom.scanners import scan_packages

    pkg = _maven_pkg("org.apache.logging.log4j", "log4j-core", "2.14.1")

    mock_osv_response = {
        "results": [
            {
                "vulns": [
                    {
                        "id": "CVE-2021-44228",
                        "summary": "Log4Shell RCE in Apache Log4j2",
                        "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"}],
                        "affected": [],
                        "references": [{"url": "https://nvd.nist.gov/vuln/detail/CVE-2021-44228"}],
                    }
                ]
            }
        ]
    }

    async def mock_request(client, method, url, json=None, **kwargs):
        resp = MagicMock()
        resp.status_code = 200
        resp.json.return_value = mock_osv_response
        return resp

    with (
        patch("agent_bom.scanners._get_scan_cache", return_value=None),
        patch("agent_bom.scanners.request_with_retry", side_effect=mock_request),
        patch("agent_bom.scanners.create_client") as mock_create_client,
    ):
        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=None)
        mock_create_client.return_value = mock_client

        await scan_packages([pkg])

    assert len(pkg.vulnerabilities) >= 1
    vuln_ids = [v.id for v in pkg.vulnerabilities]
    assert "CVE-2021-44228" in vuln_ids
