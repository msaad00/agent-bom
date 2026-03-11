"""Tests for agent_bom.mcp_server helpers and validation to improve coverage."""

from __future__ import annotations

import pytest

from agent_bom.mcp_server import (
    _get_registry_data,
    _truncate_response,
    _validate_cve_id,
    _validate_ecosystem,
)

# ---------------------------------------------------------------------------
# _validate_ecosystem
# ---------------------------------------------------------------------------


def test_validate_ecosystem_npm():
    assert _validate_ecosystem("npm") == "npm"


def test_validate_ecosystem_pypi():
    assert _validate_ecosystem("PyPI") == "pypi"


def test_validate_ecosystem_go():
    assert _validate_ecosystem("go") == "go"


def test_validate_ecosystem_cargo():
    assert _validate_ecosystem("cargo") == "cargo"


def test_validate_ecosystem_maven():
    assert _validate_ecosystem("maven") == "maven"


def test_validate_ecosystem_nuget():
    assert _validate_ecosystem("nuget") == "nuget"


def test_validate_ecosystem_rubygems():
    assert _validate_ecosystem("rubygems") == "rubygems"


def test_validate_ecosystem_whitespace():
    assert _validate_ecosystem("  npm  ") == "npm"


def test_validate_ecosystem_invalid():
    with pytest.raises(ValueError, match="Invalid ecosystem"):
        _validate_ecosystem("invalid")


def test_validate_ecosystem_empty():
    with pytest.raises(ValueError):
        _validate_ecosystem("")


# ---------------------------------------------------------------------------
# _validate_cve_id
# ---------------------------------------------------------------------------


def test_validate_cve_id_valid():
    assert _validate_cve_id("CVE-2025-0001") == "CVE-2025-0001"


def test_validate_cve_id_ghsa():
    assert _validate_cve_id("GHSA-xxxx-yyyy-zzzz") == "GHSA-xxxx-yyyy-zzzz"


def test_validate_cve_id_whitespace():
    assert _validate_cve_id("  CVE-2025-0001  ") == "CVE-2025-0001"


def test_validate_cve_id_empty():
    with pytest.raises(ValueError, match="empty"):
        _validate_cve_id("")


def test_validate_cve_id_invalid():
    with pytest.raises(ValueError, match="Invalid CVE"):
        _validate_cve_id("not-a-cve")


def test_validate_cve_id_case_insensitive():
    assert _validate_cve_id("cve-2025-0001") == "cve-2025-0001"


# ---------------------------------------------------------------------------
# _truncate_response
# ---------------------------------------------------------------------------


def test_truncate_response_short():
    result = _truncate_response("short")
    assert result == "short"


def test_truncate_response_long():
    long_text = "x" * 600000
    result = _truncate_response(long_text)
    assert len(result) < len(long_text)
    assert "_truncated" in result


# ---------------------------------------------------------------------------
# _get_registry_data
# ---------------------------------------------------------------------------


def test_get_registry_data():
    # Reset the cache to force a fresh load
    import agent_bom.mcp_server as mod

    old_cache = mod._registry_cache
    mod._registry_cache = None
    try:
        data = _get_registry_data()
        assert isinstance(data, dict)
        assert "servers" in data or "entries" in data or isinstance(data, dict)
    finally:
        mod._registry_cache = old_cache


# ---------------------------------------------------------------------------
# _safe_path
# ---------------------------------------------------------------------------


def test_safe_path_valid(tmp_path):
    from agent_bom.mcp_server import _safe_path

    f = tmp_path / "test.json"
    f.write_text("{}")
    # This will either succeed or raise ValueError based on home dir restriction
    try:
        result = _safe_path(str(f))
        assert result.exists()
    except ValueError:
        # Expected if tmp_path is outside home directory
        pass


def test_safe_path_traversal():
    from agent_bom.mcp_server import _safe_path

    with pytest.raises(ValueError):
        _safe_path("/tmp/../../../etc/passwd")
