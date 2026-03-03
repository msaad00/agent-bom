"""Tests for deps.dev API client — transitive dependency resolution and license enrichment."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

import agent_bom.deps_dev as _dd
from agent_bom.deps_dev import (
    ECOSYSTEM_MAP,
    _encode_package_name,
    _system_to_ecosystem,
    enrich_licenses_deps_dev,
    get_dependencies,
    get_package_info,
    resolve_transitive_deps_dev,
)
from agent_bom.models import Package


@pytest.fixture(autouse=True)
def _clear_caches():
    """Clear deps.dev module caches between tests."""
    _dd._info_cache.clear()
    _dd._deps_cache.clear()
    yield
    _dd._info_cache.clear()
    _dd._deps_cache.clear()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _pkg(
    name: str = "express",
    version: str = "4.18.2",
    ecosystem: str = "npm",
    is_direct: bool = True,
    license: str | None = None,
) -> Package:
    return Package(
        name=name,
        version=version,
        ecosystem=ecosystem,
        purl=f"pkg:{ecosystem}/{name}@{version}",
        is_direct=is_direct,
        license=license,
    )


def _mock_response(status_code: int = 200, json_data: dict | None = None):
    resp = MagicMock()
    resp.status_code = status_code
    resp.json.return_value = json_data or {}
    return resp


# ---------------------------------------------------------------------------
# TestEcosystemMapping
# ---------------------------------------------------------------------------


class TestEcosystemMapping:
    def test_all_ecosystems_mapped(self):
        for eco in ("npm", "pypi", "go", "cargo", "maven", "nuget"):
            assert eco in ECOSYSTEM_MAP

    def test_unsupported_ecosystem_not_mapped(self):
        assert "rubygems" not in ECOSYSTEM_MAP

    def test_system_to_ecosystem_roundtrip(self):
        for eco, system in ECOSYSTEM_MAP.items():
            assert _system_to_ecosystem(system) == eco

    def test_system_to_ecosystem_unknown(self):
        assert _system_to_ecosystem("UNKNOWN") == "unknown"

    def test_encode_scoped_npm(self):
        assert _encode_package_name("@scope/package", "npm") == "@scope%2Fpackage"

    def test_encode_go_module(self):
        assert _encode_package_name("github.com/user/repo", "go") == "github.com%2Fuser%2Frepo"

    def test_encode_simple_name(self):
        assert _encode_package_name("express", "npm") == "express"


# ---------------------------------------------------------------------------
# TestGetPackageInfo
# ---------------------------------------------------------------------------


class TestGetPackageInfo:
    @pytest.mark.asyncio
    async def test_valid_package(self):
        mock_data = {
            "versionKey": {"system": "NPM", "name": "express", "version": "4.18.2"},
            "licenses": ["MIT"],
            "links": [{"label": "SOURCE_REPO", "url": "https://github.com/expressjs/express"}],
        }
        with patch("agent_bom.deps_dev.request_with_retry", new_callable=AsyncMock) as mock_req:
            mock_req.return_value = _mock_response(200, mock_data)
            result = await get_package_info("npm", "express", "4.18.2", MagicMock())
            assert result is not None
            assert result["licenses"] == ["MIT"]

    @pytest.mark.asyncio
    async def test_unknown_package(self):
        with patch("agent_bom.deps_dev.request_with_retry", new_callable=AsyncMock) as mock_req:
            mock_req.return_value = _mock_response(404)
            result = await get_package_info("npm", "nonexistent-pkg-xyz", "1.0.0", MagicMock())
            assert result is None

    @pytest.mark.asyncio
    async def test_unsupported_ecosystem(self):
        result = await get_package_info("rubygems", "rails", "7.0.0", MagicMock())
        assert result is None

    @pytest.mark.asyncio
    async def test_version_not_found(self):
        with patch("agent_bom.deps_dev.request_with_retry", new_callable=AsyncMock) as mock_req:
            mock_req.return_value = _mock_response(404)
            result = await get_package_info("npm", "express", "99.99.99", MagicMock())
            assert result is None

    @pytest.mark.asyncio
    async def test_caches_result(self):
        mock_data = {"versionKey": {"system": "NPM", "name": "cache-test-pkg", "version": "1.0.0"}, "licenses": ["MIT"]}
        with patch("agent_bom.deps_dev.request_with_retry", new_callable=AsyncMock) as mock_req:
            mock_req.return_value = _mock_response(200, mock_data)
            client = MagicMock()
            # First call hits API
            await get_package_info("npm", "cache-test-pkg", "1.0.0", client)
            assert mock_req.call_count == 1
            # Second call should use cache (no new HTTP call)
            await get_package_info("npm", "cache-test-pkg", "1.0.0", client)
            assert mock_req.call_count == 1


# ---------------------------------------------------------------------------
# TestGetDependencies
# ---------------------------------------------------------------------------


class TestGetDependencies:
    @pytest.mark.asyncio
    async def test_returns_dependencies(self):
        mock_data = {
            "nodes": [
                {"versionKey": {"system": "NPM", "name": "express", "version": "4.18.2"}, "relation": "SELF"},
                {"versionKey": {"system": "NPM", "name": "body-parser", "version": "1.20.1"}, "relation": "DIRECT"},
                {"versionKey": {"system": "NPM", "name": "raw-body", "version": "2.5.1"}, "relation": "INDIRECT"},
            ]
        }
        with patch("agent_bom.deps_dev.request_with_retry", new_callable=AsyncMock) as mock_req:
            mock_req.return_value = _mock_response(200, mock_data)
            deps = await get_dependencies("npm", "express", "4.18.2", MagicMock())
            assert len(deps) == 2  # SELF excluded
            assert deps[0]["name"] == "body-parser"
            assert deps[0]["relation"] == "DIRECT"
            assert deps[1]["name"] == "raw-body"
            assert deps[1]["relation"] == "INDIRECT"

    @pytest.mark.asyncio
    async def test_empty_dependencies(self):
        mock_data = {
            "nodes": [
                {"versionKey": {"system": "NPM", "name": "is-number", "version": "7.0.0"}, "relation": "SELF"},
            ]
        }
        with patch("agent_bom.deps_dev.request_with_retry", new_callable=AsyncMock) as mock_req:
            mock_req.return_value = _mock_response(200, mock_data)
            deps = await get_dependencies("npm", "is-number", "7.0.0", MagicMock())
            assert deps == []

    @pytest.mark.asyncio
    async def test_unsupported_ecosystem(self):
        deps = await get_dependencies("rubygems", "rails", "7.0.0", MagicMock())
        assert deps == []

    @pytest.mark.asyncio
    async def test_api_failure(self):
        with patch("agent_bom.deps_dev.request_with_retry", new_callable=AsyncMock) as mock_req:
            mock_req.return_value = _mock_response(500)
            deps = await get_dependencies("npm", "express", "4.18.2", MagicMock())
            assert deps == []


# ---------------------------------------------------------------------------
# TestResolveTransitive
# ---------------------------------------------------------------------------


class TestResolveTransitive:
    @pytest.mark.asyncio
    async def test_resolves_npm_tree(self):
        mock_deps = {
            "nodes": [
                {"versionKey": {"system": "NPM", "name": "express", "version": "4.18.2"}, "relation": "SELF"},
                {"versionKey": {"system": "NPM", "name": "body-parser", "version": "1.20.1"}, "relation": "DIRECT"},
                {"versionKey": {"system": "NPM", "name": "accepts", "version": "1.3.8"}, "relation": "INDIRECT"},
            ]
        }
        with patch("agent_bom.deps_dev.request_with_retry", new_callable=AsyncMock) as mock_req:
            mock_req.return_value = _mock_response(200, mock_deps)
            pkgs = [_pkg("express", "4.18.2", "npm")]
            result = await resolve_transitive_deps_dev(pkgs, max_depth=3)
            assert len(result) == 2
            names = {p.name for p in result}
            assert "body-parser" in names
            assert "accepts" in names
            for p in result:
                assert p.is_direct is False
                assert p.parent_package == "express"
                assert p.deps_dev_resolved is True

    @pytest.mark.asyncio
    async def test_resolves_pypi_tree(self):
        mock_deps = {
            "nodes": [
                {"versionKey": {"system": "PYPI", "name": "requests", "version": "2.31.0"}, "relation": "SELF"},
                {"versionKey": {"system": "PYPI", "name": "urllib3", "version": "2.1.0"}, "relation": "DIRECT"},
                {"versionKey": {"system": "PYPI", "name": "certifi", "version": "2024.2.2"}, "relation": "DIRECT"},
            ]
        }
        with patch("agent_bom.deps_dev.request_with_retry", new_callable=AsyncMock) as mock_req:
            mock_req.return_value = _mock_response(200, mock_deps)
            pkgs = [_pkg("requests", "2.31.0", "pypi")]
            result = await resolve_transitive_deps_dev(pkgs, max_depth=3)
            assert len(result) == 2
            ecosystems = {p.ecosystem for p in result}
            assert ecosystems == {"pypi"}

    @pytest.mark.asyncio
    async def test_deduplication(self):
        """Same transitive dep from two parents should appear once."""
        mock_deps_a = {
            "nodes": [
                {"versionKey": {"system": "NPM", "name": "pkg-a", "version": "1.0.0"}, "relation": "SELF"},
                {"versionKey": {"system": "NPM", "name": "shared", "version": "2.0.0"}, "relation": "DIRECT"},
            ]
        }
        mock_deps_b = {
            "nodes": [
                {"versionKey": {"system": "NPM", "name": "pkg-b", "version": "1.0.0"}, "relation": "SELF"},
                {"versionKey": {"system": "NPM", "name": "shared", "version": "2.0.0"}, "relation": "DIRECT"},
            ]
        }
        call_count = 0

        async def _mock_req(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            url = args[2] if len(args) > 2 else kwargs.get("url", "")
            if "pkg-a" in url:
                return _mock_response(200, mock_deps_a)
            if "pkg-b" in url:
                return _mock_response(200, mock_deps_b)
            return _mock_response(404)

        with patch("agent_bom.deps_dev.request_with_retry", side_effect=_mock_req):
            pkgs = [
                _pkg("pkg-a", "1.0.0", "npm"),
                _pkg("pkg-b", "1.0.0", "npm"),
            ]
            result = await resolve_transitive_deps_dev(pkgs, max_depth=3)
            shared_pkgs = [p for p in result if p.name == "shared"]
            assert len(shared_pkgs) == 1

    @pytest.mark.asyncio
    async def test_skips_latest_version(self):
        pkgs = [_pkg("express", "latest", "npm")]
        result = await resolve_transitive_deps_dev(pkgs, max_depth=3)
        assert result == []

    @pytest.mark.asyncio
    async def test_skips_unsupported_ecosystem(self):
        pkgs = [_pkg("rails", "7.0.0", "rubygems")]
        result = await resolve_transitive_deps_dev(pkgs, max_depth=3)
        assert result == []

    @pytest.mark.asyncio
    async def test_skips_transitive_inputs(self):
        """Only direct packages should be resolved."""
        pkgs = [_pkg("express", "4.18.2", "npm", is_direct=False)]
        result = await resolve_transitive_deps_dev(pkgs, max_depth=3)
        assert result == []

    @pytest.mark.asyncio
    async def test_max_depth_respected(self):
        """INDIRECT deps at depth > max_depth should be excluded."""
        mock_deps = {
            "nodes": [
                {"versionKey": {"system": "NPM", "name": "express", "version": "4.18.2"}, "relation": "SELF"},
                {"versionKey": {"system": "NPM", "name": "direct-dep", "version": "1.0.0"}, "relation": "DIRECT"},
                {"versionKey": {"system": "NPM", "name": "deep-dep", "version": "1.0.0"}, "relation": "INDIRECT"},
            ]
        }
        with patch("agent_bom.deps_dev.request_with_retry", new_callable=AsyncMock) as mock_req:
            mock_req.return_value = _mock_response(200, mock_deps)
            pkgs = [_pkg("express", "4.18.2", "npm")]
            result = await resolve_transitive_deps_dev(pkgs, max_depth=1)
            names = {p.name for p in result}
            assert "direct-dep" in names
            assert "deep-dep" not in names

    @pytest.mark.asyncio
    async def test_go_module_resolution(self):
        mock_deps = {
            "nodes": [
                {"versionKey": {"system": "GO", "name": "github.com/gin-gonic/gin", "version": "v1.9.1"}, "relation": "SELF"},
                {"versionKey": {"system": "GO", "name": "github.com/gin-contrib/sse", "version": "v0.1.0"}, "relation": "DIRECT"},
            ]
        }
        with patch("agent_bom.deps_dev.request_with_retry", new_callable=AsyncMock) as mock_req:
            mock_req.return_value = _mock_response(200, mock_deps)
            pkgs = [_pkg("github.com/gin-gonic/gin", "v1.9.1", "go")]
            result = await resolve_transitive_deps_dev(pkgs, max_depth=3)
            assert len(result) == 1
            assert result[0].ecosystem == "go"
            assert result[0].name == "github.com/gin-contrib/sse"

    @pytest.mark.asyncio
    async def test_parent_package_tracking(self):
        mock_deps = {
            "nodes": [
                {"versionKey": {"system": "NPM", "name": "express", "version": "4.18.2"}, "relation": "SELF"},
                {"versionKey": {"system": "NPM", "name": "body-parser", "version": "1.20.1"}, "relation": "DIRECT"},
            ]
        }
        with patch("agent_bom.deps_dev.request_with_retry", new_callable=AsyncMock) as mock_req:
            mock_req.return_value = _mock_response(200, mock_deps)
            pkgs = [_pkg("express", "4.18.2", "npm")]
            result = await resolve_transitive_deps_dev(pkgs, max_depth=3)
            assert result[0].parent_package == "express"


# ---------------------------------------------------------------------------
# TestEnrichLicenses
# ---------------------------------------------------------------------------


class TestEnrichLicenses:
    @pytest.mark.asyncio
    async def test_enriches_missing_license(self):
        mock_info = {"licenses": ["MIT"], "versionKey": {"system": "NPM", "name": "express", "version": "4.18.2"}}
        with patch("agent_bom.deps_dev.request_with_retry", new_callable=AsyncMock) as mock_req:
            mock_req.return_value = _mock_response(200, mock_info)
            pkgs = [_pkg("express", "4.18.2", "npm", license=None)]
            count = await enrich_licenses_deps_dev(pkgs)
            assert count == 1
            assert pkgs[0].license == "MIT"
            assert pkgs[0].license_expression == "MIT"

    @pytest.mark.asyncio
    async def test_skips_already_licensed(self):
        pkgs = [_pkg("express", "4.18.2", "npm", license="MIT")]
        count = await enrich_licenses_deps_dev(pkgs)
        assert count == 0

    @pytest.mark.asyncio
    async def test_skips_latest_version(self):
        pkgs = [_pkg("express", "latest", "npm")]
        count = await enrich_licenses_deps_dev(pkgs)
        assert count == 0

    @pytest.mark.asyncio
    async def test_skips_unsupported_ecosystem(self):
        pkgs = [_pkg("rails", "7.0.0", "rubygems")]
        count = await enrich_licenses_deps_dev(pkgs)
        assert count == 0

    @pytest.mark.asyncio
    async def test_multiple_licenses_expression(self):
        """deps.dev may return multiple SPDX identifiers."""
        mock_info = {"licenses": ["Apache-2.0", "MIT"]}
        with patch("agent_bom.deps_dev.request_with_retry", new_callable=AsyncMock) as mock_req:
            mock_req.return_value = _mock_response(200, mock_info)
            pkgs = [_pkg("dual-licensed", "1.0.0", "npm")]
            count = await enrich_licenses_deps_dev(pkgs)
            assert count == 1
            assert pkgs[0].license == "Apache-2.0"
            assert pkgs[0].license_expression == "Apache-2.0 AND MIT"

    @pytest.mark.asyncio
    async def test_no_license_from_api(self):
        mock_info = {"licenses": [], "versionKey": {"system": "NPM", "name": "obscure", "version": "0.1.0"}}
        with patch("agent_bom.deps_dev.request_with_retry", new_callable=AsyncMock) as mock_req:
            mock_req.return_value = _mock_response(200, mock_info)
            pkgs = [_pkg("obscure", "0.1.0", "npm")]
            count = await enrich_licenses_deps_dev(pkgs)
            assert count == 0
            assert pkgs[0].license is None

    @pytest.mark.asyncio
    async def test_api_failure_graceful(self):
        with patch("agent_bom.deps_dev.request_with_retry", new_callable=AsyncMock) as mock_req:
            mock_req.return_value = _mock_response(500)
            pkgs = [_pkg("express", "4.18.2", "npm")]
            count = await enrich_licenses_deps_dev(pkgs)
            assert count == 0

    @pytest.mark.asyncio
    async def test_enriches_go_package(self):
        mock_info = {"licenses": ["BSD-3-Clause"]}
        with patch("agent_bom.deps_dev.request_with_retry", new_callable=AsyncMock) as mock_req:
            mock_req.return_value = _mock_response(200, mock_info)
            pkgs = [_pkg("github.com/gin-gonic/gin", "v1.9.1", "go")]
            count = await enrich_licenses_deps_dev(pkgs)
            assert count == 1
            assert pkgs[0].license == "BSD-3-Clause"

    @pytest.mark.asyncio
    async def test_enriches_cargo_package(self):
        mock_info = {"licenses": ["MIT"]}
        with patch("agent_bom.deps_dev.request_with_retry", new_callable=AsyncMock) as mock_req:
            mock_req.return_value = _mock_response(200, mock_info)
            pkgs = [_pkg("serde", "1.0.195", "cargo")]
            count = await enrich_licenses_deps_dev(pkgs)
            assert count == 1
            assert pkgs[0].license == "MIT"


# ---------------------------------------------------------------------------
# TestSyncWrappers
# ---------------------------------------------------------------------------


class TestSyncWrappers:
    def test_resolve_sync(self):
        with patch("agent_bom.deps_dev.request_with_retry", new_callable=AsyncMock) as mock_req:
            mock_req.return_value = _mock_response(200, {"nodes": []})
            from agent_bom.deps_dev import resolve_transitive_deps_dev_sync

            result = resolve_transitive_deps_dev_sync([_pkg()], max_depth=3)
            assert result == []

    def test_enrich_sync(self):
        from agent_bom.deps_dev import enrich_licenses_deps_dev_sync

        # No eligible packages
        result = enrich_licenses_deps_dev_sync([_pkg(license="MIT")])
        assert result == 0
