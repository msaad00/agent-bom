"""Tests for Go transitive dependency resolution in transitive.py."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from agent_bom.models import Package
from agent_bom.transitive import (
    _go_cache,
    _go_encode_module,
    _parse_go_mod_requires,
    fetch_go_mod,
    resolve_go_dependencies,
    resolve_transitive_dependencies,
)

# ---------------------------------------------------------------------------
# _go_encode_module
# ---------------------------------------------------------------------------


class TestGoEncodeModule:
    def test_all_lowercase_unchanged(self):
        assert _go_encode_module("github.com/user/repo") == "github.com/user/repo"

    def test_uppercase_encoded(self):
        assert _go_encode_module("GitHub.com/User/Repo") == "!git!hub.com/!user/!repo"

    def test_empty_string(self):
        assert _go_encode_module("") == ""

    def test_single_uppercase(self):
        assert _go_encode_module("A") == "!a"


# ---------------------------------------------------------------------------
# _parse_go_mod_requires
# ---------------------------------------------------------------------------


class TestParseGoModRequires:
    def test_single_line_require(self):
        go_mod = "module example.com/m\n\nrequire github.com/foo/bar v1.2.3\n"
        result = _parse_go_mod_requires(go_mod)
        assert ("github.com/foo/bar", "v1.2.3") in result

    def test_block_require(self):
        go_mod = "module example.com/m\n\nrequire (\n    github.com/foo/bar v1.2.3\n    github.com/baz/qux v0.5.0\n)\n"
        result = _parse_go_mod_requires(go_mod)
        assert ("github.com/foo/bar", "v1.2.3") in result
        assert ("github.com/baz/qux", "v0.5.0") in result

    def test_indirect_comment_stripped(self):
        go_mod = "require (\n    github.com/foo/bar v1.0.0 // indirect\n)\n"
        result = _parse_go_mod_requires(go_mod)
        assert ("github.com/foo/bar", "v1.0.0") in result

    def test_empty_mod_returns_empty(self):
        assert _parse_go_mod_requires("module example.com/m\n\ngo 1.21\n") == []

    def test_mixed_single_and_block(self):
        go_mod = "module example.com/m\n\nrequire github.com/single v1.0.0\n\nrequire (\n    github.com/block v2.0.0\n)\n"
        result = _parse_go_mod_requires(go_mod)
        assert ("github.com/single", "v1.0.0") in result
        assert ("github.com/block", "v2.0.0") in result


# ---------------------------------------------------------------------------
# fetch_go_mod
# ---------------------------------------------------------------------------


class TestFetchGoMod:
    @pytest.mark.asyncio
    async def test_success_returns_text(self):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = "module github.com/foo/bar\n\nrequire github.com/dep v1.0.0\n"
        client = AsyncMock()
        _go_cache.clear()
        with patch("agent_bom.transitive.request_with_retry", return_value=mock_response):
            result = await fetch_go_mod("github.com/foo/bar", "v1.2.3", client)
        assert result is not None
        assert "require" in result

    @pytest.mark.asyncio
    async def test_cache_hit(self):
        _go_cache.clear()
        _go_cache["github.com/foo/bar@v1.2.3"] = "module github.com/foo/bar\n"
        client = AsyncMock()
        result = await fetch_go_mod("github.com/foo/bar", "v1.2.3", client)
        assert result == "module github.com/foo/bar\n"
        _go_cache.clear()

    @pytest.mark.asyncio
    async def test_404_returns_none(self):
        mock_response = MagicMock()
        mock_response.status_code = 404
        client = AsyncMock()
        _go_cache.clear()
        with patch("agent_bom.transitive.request_with_retry", return_value=mock_response):
            result = await fetch_go_mod("github.com/nonexistent/pkg", "v0.0.1", client)
        assert result is None

    @pytest.mark.asyncio
    async def test_null_response_returns_none(self):
        client = AsyncMock()
        _go_cache.clear()
        with patch("agent_bom.transitive.request_with_retry", return_value=None):
            result = await fetch_go_mod("github.com/foo/bar", "v1.0.0", client)
        assert result is None


# ---------------------------------------------------------------------------
# resolve_go_dependencies
# ---------------------------------------------------------------------------


class TestResolveGoDependencies:
    @pytest.mark.asyncio
    async def test_resolve_go_dependencies_success(self):
        """Mock a go.mod with 2 require lines and verify correct Package objects returned."""
        go_mod_content = (
            "module github.com/example/myapp\n\ngo 1.21\n\nrequire (\n    github.com/pkg/errors v0.9.1\n    golang.org/x/sync v0.6.0\n)\n"
        )
        pkg = Package(name="github.com/example/myapp", version="v1.0.0", ecosystem="go")
        client = AsyncMock()
        with patch("agent_bom.transitive.fetch_go_mod", return_value=go_mod_content):
            result = await resolve_go_dependencies(pkg, client, max_depth=1)

        assert len(result) == 2
        names = [p.name for p in result]
        assert "github.com/pkg/errors" in names
        assert "golang.org/x/sync" in names

        errors_pkg = next(p for p in result if p.name == "github.com/pkg/errors")
        assert errors_pkg.version == "v0.9.1"
        assert errors_pkg.ecosystem == "go"
        assert errors_pkg.is_direct is False
        assert errors_pkg.parent_package == "github.com/example/myapp"
        assert errors_pkg.dependency_depth == 1
        assert errors_pkg.resolved_from_registry is True
        assert "pkg:golang/" in errors_pkg.purl

    @pytest.mark.asyncio
    async def test_resolve_go_dependencies_error(self):
        """Mock HTTP error — verify returns empty list with no exception."""
        pkg = Package(name="github.com/example/myapp", version="v1.0.0", ecosystem="go")
        client = AsyncMock()
        with patch("agent_bom.transitive.fetch_go_mod", return_value=None):
            result = await resolve_go_dependencies(pkg, client, max_depth=3)
        assert result == []

    @pytest.mark.asyncio
    async def test_max_depth_stops_recursion(self):
        pkg = Package(name="github.com/foo/bar", version="v1.0.0", ecosystem="go")
        client = AsyncMock()
        result = await resolve_go_dependencies(pkg, client, max_depth=1, current_depth=1)
        assert result == []

    @pytest.mark.asyncio
    async def test_seen_prevents_loops(self):
        pkg = Package(name="github.com/foo/bar", version="v1.0.0", ecosystem="go")
        client = AsyncMock()
        seen = {"github.com/foo/bar@v1.0.0"}
        result = await resolve_go_dependencies(pkg, client, max_depth=3, seen=seen)
        assert result == []

    @pytest.mark.asyncio
    async def test_empty_go_mod_returns_empty(self):
        pkg = Package(name="github.com/foo/bar", version="v1.0.0", ecosystem="go")
        client = AsyncMock()
        with patch("agent_bom.transitive.fetch_go_mod", return_value="module github.com/foo/bar\n\ngo 1.21\n"):
            result = await resolve_go_dependencies(pkg, client, max_depth=1)
        assert result == []


# ---------------------------------------------------------------------------
# resolve_transitive_dependencies — Go dispatcher branch
# ---------------------------------------------------------------------------


class TestResolveTransitiveDependenciesGo:
    @pytest.mark.asyncio
    async def test_go_ecosystem_dispatched(self):
        go_pkg = Package(name="github.com/foo/bar", version="v1.0.0", ecosystem="go")

        async def mock_go_resolve(pkg, client, max_depth):
            return [Package(name="github.com/dep/one", version="v0.1.0", ecosystem="go")]

        with (
            patch("agent_bom.transitive.resolve_go_dependencies", side_effect=mock_go_resolve),
            patch("agent_bom.transitive.create_client"),
        ):
            result = await resolve_transitive_dependencies([go_pkg])
        names = [p.name for p in result]
        assert "github.com/dep/one" in names

    @pytest.mark.asyncio
    async def test_golang_ecosystem_alias_dispatched(self):
        go_pkg = Package(name="github.com/foo/bar", version="v1.0.0", ecosystem="golang")

        async def mock_go_resolve(pkg, client, max_depth):
            return [Package(name="github.com/dep/two", version="v0.2.0", ecosystem="go")]

        with (
            patch("agent_bom.transitive.resolve_go_dependencies", side_effect=mock_go_resolve),
            patch("agent_bom.transitive.create_client"),
        ):
            result = await resolve_transitive_dependencies([go_pkg])
        names = [p.name for p in result]
        assert "github.com/dep/two" in names
