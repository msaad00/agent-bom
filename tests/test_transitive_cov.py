"""Tests for transitive dependency resolution module — coverage expansion."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from agent_bom.models import Package
from agent_bom.transitive import (
    _cache_put,
    _is_prerelease,
    _resolve_npm_version,
    _resolve_pip_version,
    fetch_npm_metadata,
    fetch_pypi_metadata,
    resolve_npm_dependencies,
    resolve_pypi_dependencies,
    resolve_transitive_dependencies,
    resolve_transitive_dependencies_sync,
)

# -- Helper cache tests ---


class TestCachePut:
    def test_basic_put(self):
        cache: dict[str, dict] = {}
        _cache_put(cache, "a", {"val": 1})
        assert cache["a"] == {"val": 1}

    def test_eviction_when_full(self):
        cache: dict[str, dict] = {}
        for i in range(5001):
            _cache_put(cache, str(i), {"v": i})
        assert len(cache) <= 5000


class TestIsPrerelease:
    def test_stable_version(self):
        assert not _is_prerelease("1.0.0")

    def test_beta_version(self):
        assert _is_prerelease("1.0.0-beta.1")

    def test_alpha_version(self):
        assert _is_prerelease("2.0.0-alpha")

    def test_rc_version(self):
        assert _is_prerelease("3.0.0-rc.1")

    def test_build_metadata_no_prerelease(self):
        assert not _is_prerelease("1.0.0+build123")

    def test_prerelease_with_build_metadata(self):
        assert _is_prerelease("1.0.0-beta+build123")


class TestResolveNpmVersion:
    def test_latest_tag(self):
        pkg_data = {"dist-tags": {"latest": "1.2.3"}, "versions": {"1.2.3": {}}}
        assert _resolve_npm_version("latest", pkg_data) == "1.2.3"

    def test_empty_range(self):
        pkg_data = {"dist-tags": {"latest": "1.2.3"}, "versions": {"1.2.3": {}}}
        assert _resolve_npm_version("", pkg_data) == "1.2.3"

    def test_star_range(self):
        pkg_data = {"dist-tags": {"latest": "1.2.3"}, "versions": {"1.2.3": {}}}
        assert _resolve_npm_version("*", pkg_data) == "1.2.3"

    def test_caret_range(self):
        pkg_data = {
            "dist-tags": {"latest": "1.5.0"},
            "versions": {"1.0.0": {}, "1.2.0": {}, "1.5.0": {}, "2.0.0": {}},
        }
        result = _resolve_npm_version("^1.2.0", pkg_data)
        assert result == "1.5.0"

    def test_tilde_range(self):
        pkg_data = {
            "dist-tags": {"latest": "1.5.0"},
            "versions": {"1.2.0": {}, "1.2.3": {}, "1.3.0": {}, "1.5.0": {}},
        }
        result = _resolve_npm_version("~1.2.0", pkg_data)
        assert result == "1.2.3"

    def test_gte_range(self):
        pkg_data = {
            "dist-tags": {"latest": "3.0.0"},
            "versions": {"1.0.0": {}, "2.0.0": {}, "3.0.0": {}},
        }
        result = _resolve_npm_version(">=2.0.0", pkg_data)
        assert result == "3.0.0"

    def test_no_versions(self):
        pkg_data = {"dist-tags": {"latest": "1.0.0"}, "versions": {}}
        assert _resolve_npm_version("^1.0.0", pkg_data) == "1.0.0"

    def test_exact_version_fallback(self):
        pkg_data = {"dist-tags": {"latest": "1.0.0"}, "versions": {"1.0.0": {}}}
        assert _resolve_npm_version("1.0.0", pkg_data) == "1.0.0"

    def test_caret_skips_prerelease(self):
        pkg_data = {
            "dist-tags": {"latest": "1.2.0"},
            "versions": {"1.0.0": {}, "1.1.0-beta.1": {}, "1.2.0": {}},
        }
        result = _resolve_npm_version("^1.0.0", pkg_data)
        assert result == "1.2.0"

    def test_invalid_version_parts(self):
        pkg_data = {"dist-tags": {"latest": "1.0.0"}, "versions": {"1.0.0": {}, "abc": {}}}
        result = _resolve_npm_version("^1.0.0", pkg_data)
        assert result == "1.0.0"


class TestResolvePipVersion:
    def test_empty_spec(self):
        releases = {"1.0.0": [], "2.0.0": []}
        result = _resolve_pip_version("", releases)
        assert result in ("1.0.0", "2.0.0")

    def test_latest_spec(self):
        releases = {"1.0.0": [], "2.0.0": []}
        result = _resolve_pip_version("latest", releases)
        assert result in ("1.0.0", "2.0.0")

    def test_unknown_spec(self):
        releases = {"1.0.0": []}
        result = _resolve_pip_version("unknown", releases)
        assert result == "1.0.0"

    def test_empty_releases(self):
        result = _resolve_pip_version("", {})
        assert result == "unknown"

    def test_gte_spec_with_packaging(self):
        releases = {"1.0.0": [], "2.0.0": [], "3.0.0": []}
        result = _resolve_pip_version(">=2.0.0", releases)
        assert result == "3.0.0"

    def test_exact_spec(self):
        releases = {"1.0.0": [], "2.0.0": []}
        result = _resolve_pip_version("==1.0.0", releases)
        assert result == "1.0.0"

    def test_fallback_strip_operators(self):
        result = _resolve_pip_version(">=2.0.0", {})
        assert isinstance(result, str)


# -- Async metadata fetch tests --


class TestFetchNpmMetadata:
    @pytest.mark.asyncio
    async def test_range_version_fetches_full_registry(self):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "dist-tags": {"latest": "1.0.0"},
            "versions": {"1.0.0": {"name": "test-pkg", "version": "1.0.0"}},
        }
        client = AsyncMock()
        with patch("agent_bom.transitive.request_with_retry", return_value=mock_response):
            from agent_bom.transitive import _npm_cache

            _npm_cache.clear()
            result = await fetch_npm_metadata("test-pkg", "^1.0.0", client)
            assert result is not None
            assert result["name"] == "test-pkg"

    @pytest.mark.asyncio
    async def test_exact_version_fetches_specific(self):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"name": "express", "version": "4.18.2"}
        client = AsyncMock()
        with patch("agent_bom.transitive.request_with_retry", return_value=mock_response):
            from agent_bom.transitive import _npm_cache

            _npm_cache.clear()
            result = await fetch_npm_metadata("express", "4.18.2", client)
            assert result is not None
            assert result["version"] == "4.18.2"

    @pytest.mark.asyncio
    async def test_cache_hit(self):
        from agent_bom.transitive import _npm_cache

        _npm_cache["cached-pkg@1.0.0"] = {"name": "cached-pkg"}
        client = AsyncMock()
        result = await fetch_npm_metadata("cached-pkg", "1.0.0", client)
        assert result == {"name": "cached-pkg"}
        _npm_cache.clear()

    @pytest.mark.asyncio
    async def test_failed_response_returns_none(self):
        mock_response = MagicMock()
        mock_response.status_code = 404
        client = AsyncMock()
        with patch("agent_bom.transitive.request_with_retry", return_value=mock_response):
            from agent_bom.transitive import _npm_cache

            _npm_cache.clear()
            result = await fetch_npm_metadata("nonexistent", "1.0.0", client)
            assert result is None

    @pytest.mark.asyncio
    async def test_null_response_returns_none(self):
        client = AsyncMock()
        with patch("agent_bom.transitive.request_with_retry", return_value=None):
            from agent_bom.transitive import _npm_cache

            _npm_cache.clear()
            result = await fetch_npm_metadata("pkg", "latest", client)
            assert result is None


class TestFetchPypiMetadata:
    @pytest.mark.asyncio
    async def test_range_version(self):
        mock_resp1 = MagicMock()
        mock_resp1.status_code = 200
        mock_resp1.json.return_value = {
            "info": {"name": "requests"},
            "releases": {"2.28.0": [], "2.31.0": []},
        }
        mock_resp2 = MagicMock()
        mock_resp2.status_code = 200
        mock_resp2.json.return_value = {"info": {"name": "requests", "version": "2.31.0"}}

        client = AsyncMock()
        with patch(
            "agent_bom.transitive.request_with_retry",
            side_effect=[mock_resp1, mock_resp2],
        ):
            from agent_bom.transitive import _pypi_cache

            _pypi_cache.clear()
            result = await fetch_pypi_metadata("requests", ">=2.28.0", client)
            assert result is not None

    @pytest.mark.asyncio
    async def test_exact_version(self):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"info": {"name": "flask", "version": "2.0.0"}}
        client = AsyncMock()
        with patch("agent_bom.transitive.request_with_retry", return_value=mock_response):
            from agent_bom.transitive import _pypi_cache

            _pypi_cache.clear()
            result = await fetch_pypi_metadata("flask", "2.0.0", client)
            assert result is not None

    @pytest.mark.asyncio
    async def test_cache_hit(self):
        from agent_bom.transitive import _pypi_cache

        _pypi_cache["cached@1.0"] = {"info": {"name": "cached"}}
        client = AsyncMock()
        result = await fetch_pypi_metadata("cached", "1.0", client)
        assert result == {"info": {"name": "cached"}}
        _pypi_cache.clear()


class TestResolveNpmDependencies:
    @pytest.mark.asyncio
    async def test_basic_resolution(self):
        pkg = Package(name="express", version="4.18.2", ecosystem="npm")
        mock_metadata = {"dependencies": {"body-parser": "^1.20.0"}}
        client = AsyncMock()
        with patch("agent_bom.transitive.fetch_npm_metadata", return_value=mock_metadata):
            result = await resolve_npm_dependencies(pkg, client, max_depth=1)
            assert len(result) == 1
            assert result[0].name == "body-parser"
            assert result[0].is_direct is False
            assert result[0].parent_package == "express"
            assert result[0].dependency_scope == "runtime"
            assert result[0].reachability_evidence == "runtime_dependency"

    @pytest.mark.asyncio
    async def test_optional_and_peer_dependencies_are_declaration_evidence(self):
        pkg = Package(name="plugin-host", version="1.0.0", ecosystem="npm")
        mock_metadata = {
            "dependencies": {"runtime-lib": "^1.0.0"},
            "optionalDependencies": {"optional-lib": "^2.0.0"},
            "peerDependencies": {"react": "^19.0.0"},
        }
        client = AsyncMock()
        with patch("agent_bom.transitive.fetch_npm_metadata", return_value=mock_metadata):
            result = await resolve_npm_dependencies(pkg, client, max_depth=1)

        by_name = {p.name: p for p in result}
        assert by_name["runtime-lib"].dependency_scope == "runtime"
        assert by_name["runtime-lib"].reachability_evidence == "runtime_dependency"
        assert by_name["optional-lib"].dependency_scope == "optional"
        assert by_name["optional-lib"].reachability_evidence == "declaration_only"
        assert by_name["react"].dependency_scope == "peer"
        assert by_name["react"].reachability_evidence == "declaration_only"

    @pytest.mark.asyncio
    async def test_max_depth_stops_recursion(self):
        pkg = Package(name="express", version="4.18.2", ecosystem="npm")
        client = AsyncMock()
        result = await resolve_npm_dependencies(pkg, client, max_depth=1, current_depth=1)
        assert result == []

    @pytest.mark.asyncio
    async def test_seen_prevents_loops(self):
        pkg = Package(name="express", version="4.18.2", ecosystem="npm")
        client = AsyncMock()
        seen = {"express@4.18.2"}
        result = await resolve_npm_dependencies(pkg, client, max_depth=3, seen=seen)
        assert result == []

    @pytest.mark.asyncio
    async def test_no_metadata_returns_empty(self):
        pkg = Package(name="nonexistent", version="1.0.0", ecosystem="npm")
        client = AsyncMock()
        with patch("agent_bom.transitive.fetch_npm_metadata", return_value=None):
            result = await resolve_npm_dependencies(pkg, client)
            assert result == []


class TestResolvePypiDependencies:
    @pytest.mark.asyncio
    async def test_basic_resolution(self):
        pkg = Package(name="requests", version="2.31.0", ecosystem="pypi")
        mock_metadata = {
            "info": {
                "requires_dist": ["urllib3>=1.21.1,<3", "certifi>=2017.4.17"],
            }
        }
        client = AsyncMock()
        with patch("agent_bom.transitive.fetch_pypi_metadata", return_value=mock_metadata):
            result = await resolve_pypi_dependencies(pkg, client, max_depth=1)
            names = [p.name for p in result]
            assert "urllib3" in names
            assert "certifi" in names

    @pytest.mark.asyncio
    async def test_marks_extras_as_declaration_only(self):
        pkg = Package(name="requests", version="2.31.0", ecosystem="pypi")
        mock_metadata = {
            "info": {
                "requires_dist": [
                    "urllib3>=1.21.1",
                    "PySocks>=1.5.6; extra == 'socks'",
                ],
            }
        }
        client = AsyncMock()
        with patch("agent_bom.transitive.fetch_pypi_metadata", return_value=mock_metadata):
            result = await resolve_pypi_dependencies(pkg, client, max_depth=1)
            by_name = {p.name: p for p in result}
            assert by_name["urllib3"].dependency_scope == "runtime"
            assert by_name["urllib3"].reachability_evidence == "runtime_dependency"
            assert by_name["PySocks"].dependency_scope == "extra"
            assert by_name["PySocks"].reachability_evidence == "declaration_only"

    @pytest.mark.asyncio
    async def test_strips_env_markers(self):
        pkg = Package(name="test", version="1.0", ecosystem="pypi")
        mock_metadata = {
            "info": {
                "requires_dist": [
                    'typing-extensions>=3.7; python_version < "3.8"',
                ],
            }
        }
        client = AsyncMock()
        with patch("agent_bom.transitive.fetch_pypi_metadata", return_value=mock_metadata):
            result = await resolve_pypi_dependencies(pkg, client, max_depth=1)
            assert len(result) == 1
            assert result[0].name == "typing-extensions"
            assert result[0].dependency_scope == "conditional"
            assert result[0].reachability_evidence == "declaration_only"

    @pytest.mark.asyncio
    async def test_empty_requires_dist(self):
        pkg = Package(name="test", version="1.0", ecosystem="pypi")
        mock_metadata = {"info": {"requires_dist": []}}
        client = AsyncMock()
        with patch("agent_bom.transitive.fetch_pypi_metadata", return_value=mock_metadata):
            result = await resolve_pypi_dependencies(pkg, client, max_depth=1)
            assert result == []

    @pytest.mark.asyncio
    async def test_none_requires_dist(self):
        pkg = Package(name="test", version="1.0", ecosystem="pypi")
        mock_metadata = {"info": {"requires_dist": None}}
        client = AsyncMock()
        with patch("agent_bom.transitive.fetch_pypi_metadata", return_value=mock_metadata):
            result = await resolve_pypi_dependencies(pkg, client, max_depth=1)
            assert result == []


class TestResolveTransitiveDependencies:
    @pytest.mark.asyncio
    async def test_npm_and_pypi_combined(self):
        npm_pkg = Package(name="express", version="4.18.2", ecosystem="npm")
        pypi_pkg = Package(name="requests", version="2.31.0", ecosystem="pypi")

        async def mock_npm_resolve(pkg, client, max_depth):
            return [Package(name="body-parser", version="1.20.0", ecosystem="npm")]

        async def mock_pypi_resolve(pkg, client, max_depth):
            return [Package(name="urllib3", version="2.0.0", ecosystem="pypi")]

        with (
            patch("agent_bom.transitive.resolve_npm_dependencies", side_effect=mock_npm_resolve),
            patch("agent_bom.transitive.resolve_pypi_dependencies", side_effect=mock_pypi_resolve),
            patch("agent_bom.transitive.create_client"),
        ):
            result = await resolve_transitive_dependencies([npm_pkg, pypi_pkg])
            names = [p.name for p in result]
            assert "body-parser" in names
            assert "urllib3" in names

    @pytest.mark.asyncio
    async def test_deduplicates(self):
        npm_pkg1 = Package(name="a", version="1.0.0", ecosystem="npm")
        npm_pkg2 = Package(name="b", version="1.0.0", ecosystem="npm")

        dep = Package(name="shared", version="1.0.0", ecosystem="npm")

        async def mock_resolve(pkg, client, max_depth):
            return [dep]

        with (
            patch("agent_bom.transitive.resolve_npm_dependencies", side_effect=mock_resolve),
            patch("agent_bom.transitive.create_client"),
        ):
            result = await resolve_transitive_dependencies([npm_pkg1, npm_pkg2])
            assert len(result) == 1
            assert result[0].name == "shared"

    @pytest.mark.asyncio
    async def test_exception_in_resolve_handled(self):
        npm_pkg = Package(name="express", version="4.18.2", ecosystem="npm")

        async def mock_resolve(pkg, client, max_depth):
            raise RuntimeError("network error")

        with (
            patch("agent_bom.transitive.resolve_npm_dependencies", side_effect=mock_resolve),
            patch("agent_bom.transitive.create_client"),
        ):
            result = await resolve_transitive_dependencies([npm_pkg])
            assert result == []

    def test_sync_wrapper(self):
        with patch("agent_bom.transitive.resolve_transitive_dependencies", return_value=[]):
            result = resolve_transitive_dependencies_sync([])
            assert result == []
