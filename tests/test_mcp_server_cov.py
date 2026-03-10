"""Tests for MCP server module — coverage expansion."""

from __future__ import annotations

import json
from unittest.mock import patch

import pytest

from agent_bom.mcp_server import (
    _get_registry_data,
    _get_registry_data_raw,
    _truncate_response,
    _validate_cve_id,
    _validate_ecosystem,
)

# ── Input validation ─────────────────────────────────────────────────────────


class TestValidateEcosystem:
    def test_valid_ecosystems(self):
        for eco in ("npm", "pypi", "go", "cargo", "maven", "nuget", "rubygems"):
            assert _validate_ecosystem(eco) == eco

    def test_case_insensitive(self):
        assert _validate_ecosystem("NPM") == "npm"
        assert _validate_ecosystem("  PyPI  ") == "pypi"

    def test_invalid_ecosystem(self):
        with pytest.raises(ValueError, match="Invalid ecosystem"):
            _validate_ecosystem("invalid")


class TestValidateCveId:
    def test_valid_cve(self):
        assert _validate_cve_id("CVE-2024-12345") == "CVE-2024-12345"

    def test_valid_ghsa(self):
        assert _validate_cve_id("GHSA-abcd-efgh-ijkl") == "GHSA-abcd-efgh-ijkl"

    def test_strips_whitespace(self):
        assert _validate_cve_id("  CVE-2024-12345  ") == "CVE-2024-12345"

    def test_empty_raises(self):
        with pytest.raises(ValueError, match="cannot be empty"):
            _validate_cve_id("")

    def test_invalid_format_raises(self):
        with pytest.raises(ValueError, match="Invalid CVE ID format"):
            _validate_cve_id("not-a-cve")


class TestTruncateResponse:
    def test_short_response_unchanged(self):
        text = "short"
        assert _truncate_response(text) == text

    def test_long_response_truncated(self):
        text = "x" * 600_000
        result = _truncate_response(text)
        assert len(result) < len(text)
        assert '"_truncated": true' in result


# ── Registry cache ───────────────────────────────────────────────────────────


class TestRegistryCache:
    def test_get_registry_data_returns_dict(self):
        import agent_bom.mcp_server as mod

        old = mod._registry_cache
        try:
            mod._registry_cache = None
            result = _get_registry_data()
            assert isinstance(result, dict)
        finally:
            mod._registry_cache = old

    def test_get_registry_data_raw_returns_str(self):
        import agent_bom.mcp_server as mod

        old = mod._registry_raw_cache
        try:
            mod._registry_raw_cache = None
            result = _get_registry_data_raw()
            assert isinstance(result, str)
            # Should be valid JSON
            json.loads(result)
        finally:
            mod._registry_raw_cache = old

    def test_cache_reuse(self):
        import agent_bom.mcp_server as mod

        old = mod._registry_cache
        try:
            mod._registry_cache = None
            first = _get_registry_data()
            second = _get_registry_data()
            assert first is second  # Same cached object
        finally:
            mod._registry_cache = old


# ── _safe_path ───────────────────────────────────────────────────────────────


class TestSafePath:
    def test_valid_home_path(self, tmp_path):
        test_file = tmp_path / "test.json"
        test_file.write_text("{}")
        from agent_bom.mcp_server import _safe_path

        with patch("agent_bom.security.validate_path", return_value=test_file):
            result = _safe_path(str(test_file))
            assert result == test_file

    def test_traversal_raises(self):
        from agent_bom.mcp_server import _safe_path
        from agent_bom.security import SecurityError

        with patch("agent_bom.security.validate_path", side_effect=SecurityError("blocked")):
            with pytest.raises(ValueError, match="blocked"):
                _safe_path("/etc/passwd")


# ── _check_mcp_sdk ──────────────────────────────────────────────────────────


class TestCheckMcpSdk:
    def test_available(self):
        from agent_bom.mcp_server import _check_mcp_sdk

        # Should not raise (mcp is installed in test env)
        _check_mcp_sdk()

    def test_missing_raises(self):
        from agent_bom.mcp_server import _check_mcp_sdk

        with patch.dict("sys.modules", {"mcp": None}):
            with pytest.raises(ImportError, match="mcp SDK is required"):
                _check_mcp_sdk()
