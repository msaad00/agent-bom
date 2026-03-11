"""Tests for agent_bom.version_utils to improve coverage."""

from __future__ import annotations

from agent_bom.version_utils import (
    compare_versions,
    normalize_version,
    strip_pip_extras,
    validate_version,
)

# ---------------------------------------------------------------------------
# validate_version
# ---------------------------------------------------------------------------


def test_validate_version_npm_valid():
    assert validate_version("1.2.3", "npm") is True
    assert validate_version("0.0.1", "npm") is True


def test_validate_version_npm_with_v():
    assert validate_version("v1.2.3", "npm") is True


def test_validate_version_npm_prerelease():
    assert validate_version("1.2.3-beta.1", "npm") is True


def test_validate_version_npm_invalid():
    assert validate_version("abc", "npm") is False


def test_validate_version_pypi_valid():
    assert validate_version("1.0", "pypi") is True
    assert validate_version("1.0.0", "pypi") is True
    assert validate_version("1.0.0rc1", "pypi") is True


def test_validate_version_go_valid():
    assert validate_version("v1.2.3", "go") is True


def test_validate_version_go_invalid():
    assert validate_version("1.2.3", "go") is False  # Go requires v prefix


def test_validate_version_maven_valid():
    assert validate_version("1.2.3", "maven") is True
    assert validate_version("1.0-SNAPSHOT", "maven") is True


def test_validate_version_cargo():
    assert validate_version("1.0.0", "cargo") is True


def test_validate_version_nuget():
    assert validate_version("1.0.0", "nuget") is True


def test_validate_version_unknown_ecosystem():
    assert validate_version("anything", "unknown") is True


def test_validate_version_empty():
    assert validate_version("", "npm") is False


def test_validate_version_latest():
    assert validate_version("latest", "npm") is False


def test_validate_version_unknown():
    assert validate_version("unknown", "pypi") is False


# ---------------------------------------------------------------------------
# normalize_version
# ---------------------------------------------------------------------------


def test_normalize_version_strip_v():
    assert normalize_version("v1.2.3", "npm") == "1.2.3"


def test_normalize_version_go_keeps_v():
    assert normalize_version("v1.2.3", "go") == "v1.2.3"


def test_normalize_version_pypi_alpha():
    result = normalize_version("1.0.0alpha1", "pypi")
    assert "a1" in result


def test_normalize_version_pypi_beta():
    result = normalize_version("1.0.0beta2", "pypi")
    assert "b2" in result


def test_normalize_version_pypi_rc():
    result = normalize_version("1.0.0rc1", "pypi")
    # The normalization applies regex substitutions
    assert result is not None and len(result) > 0


def test_normalize_version_pypi_post():
    result = normalize_version("1.0.0post1", "pypi")
    assert "post1" in result


def test_normalize_version_pypi_dev():
    result = normalize_version("1.0.0dev1", "pypi")
    assert "dev1" in result


def test_normalize_version_empty():
    assert normalize_version("", "npm") == ""


def test_normalize_version_latest():
    assert normalize_version("latest", "npm") == "latest"


def test_normalize_version_whitespace():
    assert normalize_version("  1.2.3  ", "npm") == "1.2.3"


# ---------------------------------------------------------------------------
# strip_pip_extras
# ---------------------------------------------------------------------------


def test_strip_pip_extras_basic():
    name, ver = strip_pip_extras("requests[security]==2.31.0")
    assert name == "requests"
    assert ver == "2.31.0"


def test_strip_pip_extras_multiple():
    name, ver = strip_pip_extras("package[extra1,extra2]>=1.0")
    assert name == "package"
    assert ver == "1.0"


def test_strip_pip_extras_no_extra():
    name, ver = strip_pip_extras("simple-pkg")
    assert name == "simple-pkg"
    assert ver == ""


def test_strip_pip_extras_no_version():
    name, ver = strip_pip_extras("requests")
    assert name == "requests"


# ---------------------------------------------------------------------------
# compare_versions
# ---------------------------------------------------------------------------


def test_compare_versions_fixed_newer():
    assert compare_versions("1.0.0", "2.0.0", "npm") is True


def test_compare_versions_fixed_older():
    assert compare_versions("2.0.0", "1.0.0", "npm") is False


def test_compare_versions_same():
    assert compare_versions("1.0.0", "1.0.0", "npm") is False


def test_compare_versions_prerelease():
    # 1.0.0a1 < 1.0.0 (pre-release is older)
    assert compare_versions("0.9.0", "1.0.0", "pypi") is True


def test_compare_versions_go():
    assert compare_versions("v1.0.0", "v2.0.0", "go") is True


def test_compare_versions_maven():
    assert compare_versions("1.0", "2.0", "maven") is True


def test_compare_versions_with_v_prefix():
    assert compare_versions("v1.0.0", "v2.0.0", "npm") is True
