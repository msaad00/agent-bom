"""Tests for version validation, normalization, and ecosystem resolvers."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from agent_bom.version_utils import (
    compare_versions,
    normalize_version,
    resolve_cargo_metadata,
    resolve_go_metadata,
    resolve_maven_metadata,
    strip_pip_extras,
    validate_version,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _mock_response(status_code: int = 200, json_data: dict | None = None):
    resp = MagicMock()
    resp.status_code = status_code
    resp.json.return_value = json_data or {}
    return resp


# ---------------------------------------------------------------------------
# TestValidateVersion
# ---------------------------------------------------------------------------


class TestValidateVersion:
    def test_npm_valid_semver(self):
        assert validate_version("1.0.0", "npm") is True
        assert validate_version("0.1.0", "npm") is True
        assert validate_version("10.20.30", "npm") is True
        assert validate_version("1.0.0-alpha.1", "npm") is True
        assert validate_version("1.0.0-beta+build.123", "npm") is True

    def test_npm_invalid(self):
        assert validate_version("latest", "npm") is False
        assert validate_version("unknown", "npm") is False
        assert validate_version("", "npm") is False
        assert validate_version("abc", "npm") is False

    def test_pypi_valid_pep440(self):
        assert validate_version("1.0.0", "pypi") is True
        assert validate_version("2.31", "pypi") is True
        assert validate_version("1.0a1", "pypi") is True
        assert validate_version("1.0.0.post1", "pypi") is True
        assert validate_version("1.0.0.dev0", "pypi") is True

    def test_pypi_invalid(self):
        assert validate_version("latest", "pypi") is False
        assert validate_version("", "pypi") is False

    def test_go_valid(self):
        assert validate_version("v1.9.1", "go") is True
        assert validate_version("v0.1.0", "go") is True
        assert validate_version("v1.0.0-rc.1", "go") is True

    def test_go_invalid(self):
        assert validate_version("1.9.1", "go") is False  # Missing v prefix
        assert validate_version("latest", "go") is False

    def test_cargo_valid(self):
        assert validate_version("1.0.195", "cargo") is True
        assert validate_version("0.1.0", "cargo") is True

    def test_maven_valid(self):
        assert validate_version("3.3.2", "maven") is True
        assert validate_version("2.0.0-SNAPSHOT", "maven") is True
        assert validate_version("1.0.0.RELEASE", "maven") is True

    def test_unknown_ecosystem_accepts(self):
        assert validate_version("1.0.0", "rubygems") is True


# ---------------------------------------------------------------------------
# TestNormalizeVersion
# ---------------------------------------------------------------------------


class TestNormalizeVersion:
    def test_strip_v_prefix_npm(self):
        assert normalize_version("v1.0.0", "npm") == "1.0.0"

    def test_keep_v_prefix_go(self):
        assert normalize_version("v1.0.0", "go") == "v1.0.0"

    def test_strip_whitespace(self):
        assert normalize_version("  1.0.0  ", "npm") == "1.0.0"

    def test_passthrough_latest(self):
        assert normalize_version("latest", "npm") == "latest"

    def test_pypi_alpha_normalization(self):
        result = normalize_version("1.0alpha1", "pypi")
        assert "a" in result or "alpha" in result

    def test_pypi_beta_normalization(self):
        result = normalize_version("1.0beta2", "pypi")
        assert "b" in result or "beta" in result

    def test_empty_passthrough(self):
        assert normalize_version("", "npm") == ""


# ---------------------------------------------------------------------------
# TestStripPipExtras
# ---------------------------------------------------------------------------


class TestStripPipExtras:
    def test_extras_with_version(self):
        name, ver = strip_pip_extras("requests[security]==2.31.0")
        assert name == "requests"
        assert ver == "2.31.0"

    def test_multiple_extras(self):
        name, ver = strip_pip_extras("package[extra1,extra2]>=1.0")
        assert name == "package"
        assert ver == "1.0"

    def test_no_extras(self):
        name, ver = strip_pip_extras("simple-pkg")
        assert name == "simple-pkg"
        assert ver == ""

    def test_no_version(self):
        name, ver = strip_pip_extras("package[dev]")
        assert name == "package"

    def test_with_spaces(self):
        name, ver = strip_pip_extras("requests>=2.28")
        assert name == "requests"
        assert ver == "2.28"


# ---------------------------------------------------------------------------
# TestCompareVersions
# ---------------------------------------------------------------------------


class TestCompareVersions:
    def test_fixed_newer(self):
        assert compare_versions("1.0.0", "2.0.0", "npm") is True

    def test_fixed_same(self):
        assert compare_versions("1.0.0", "1.0.0", "npm") is False

    def test_fixed_older(self):
        assert compare_versions("2.0.0", "1.0.0", "npm") is False

    def test_minor_bump(self):
        assert compare_versions("1.0.0", "1.1.0", "npm") is True

    def test_patch_bump(self):
        assert compare_versions("1.0.0", "1.0.1", "npm") is True

    def test_go_versions(self):
        assert compare_versions("v1.0.0", "v1.1.0", "go") is True

    def test_pypi_versions(self):
        assert compare_versions("2.31.0", "2.32.0", "pypi") is True


# ---------------------------------------------------------------------------
# TestGoResolver
# ---------------------------------------------------------------------------


class TestGoResolver:
    @pytest.mark.asyncio
    async def test_resolves_go_module(self):
        mock_data = {"Version": "v1.9.1", "Time": "2024-01-01T00:00:00Z"}
        with patch("agent_bom.version_utils.request_with_retry", new_callable=AsyncMock) as mock_req:
            mock_req.return_value = _mock_response(200, mock_data)
            version, lic = await resolve_go_metadata("github.com/gin-gonic/gin", MagicMock())
            assert version == "v1.9.1"
            assert lic is None

    @pytest.mark.asyncio
    async def test_go_not_found(self):
        with patch("agent_bom.version_utils.request_with_retry", new_callable=AsyncMock) as mock_req:
            mock_req.return_value = _mock_response(404)
            version, lic = await resolve_go_metadata("nonexistent/module", MagicMock())
            assert version is None


# ---------------------------------------------------------------------------
# TestCargoResolver
# ---------------------------------------------------------------------------


class TestCargoResolver:
    @pytest.mark.asyncio
    async def test_resolves_crate(self):
        mock_data = {"crate": {"newest_version": "1.0.195", "license": "MIT OR Apache-2.0"}}
        with patch("agent_bom.version_utils.request_with_retry", new_callable=AsyncMock) as mock_req:
            mock_req.return_value = _mock_response(200, mock_data)
            version, lic = await resolve_cargo_metadata("serde", MagicMock())
            assert version == "1.0.195"
            assert lic == "MIT OR Apache-2.0"

    @pytest.mark.asyncio
    async def test_crate_not_found(self):
        with patch("agent_bom.version_utils.request_with_retry", new_callable=AsyncMock) as mock_req:
            mock_req.return_value = _mock_response(404)
            version, lic = await resolve_cargo_metadata("nonexistent-crate", MagicMock())
            assert version is None

    @pytest.mark.asyncio
    async def test_crate_max_version_fallback(self):
        mock_data = {"crate": {"max_version": "2.0.0"}}
        with patch("agent_bom.version_utils.request_with_retry", new_callable=AsyncMock) as mock_req:
            mock_req.return_value = _mock_response(200, mock_data)
            version, lic = await resolve_cargo_metadata("serde", MagicMock())
            assert version == "2.0.0"


# ---------------------------------------------------------------------------
# TestMavenResolver
# ---------------------------------------------------------------------------


class TestMavenResolver:
    @pytest.mark.asyncio
    async def test_resolves_maven_artifact(self):
        mock_data = {"response": {"docs": [{"latestVersion": "3.3.2"}]}}
        with patch("agent_bom.version_utils.request_with_retry", new_callable=AsyncMock) as mock_req:
            mock_req.return_value = _mock_response(200, mock_data)
            version, lic = await resolve_maven_metadata("org.apache.commons", "commons-lang3", MagicMock())
            assert version == "3.3.2"
            assert lic is None

    @pytest.mark.asyncio
    async def test_maven_not_found(self):
        with patch("agent_bom.version_utils.request_with_retry", new_callable=AsyncMock) as mock_req:
            mock_req.return_value = _mock_response(200, {"response": {"docs": []}})
            version, lic = await resolve_maven_metadata("com.nonexistent", "artifact", MagicMock())
            assert version is None

    @pytest.mark.asyncio
    async def test_maven_api_error(self):
        with patch("agent_bom.version_utils.request_with_retry", new_callable=AsyncMock) as mock_req:
            mock_req.return_value = _mock_response(500)
            version, lic = await resolve_maven_metadata("org.apache", "test", MagicMock())
            assert version is None
