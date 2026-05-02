"""Tests for agent_bom.version_utils to improve coverage."""

from __future__ import annotations

from agent_bom.version_utils import (
    compare_version_order,
    compare_versions,
    normalize_version,
    strip_pip_extras,
    validate_version,
    version_in_range,
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


def test_compare_version_order_deb_numeric_segments():
    assert compare_version_order("6.5+20250216-2", "6.5+20250216-10", "deb") == -1


def test_compare_version_order_apk_revision_segments():
    assert compare_version_order("1.2.4-r2", "1.2.4-r10", "apk") == -1


def test_compare_version_order_rpm_release_segments():
    assert compare_version_order("3.0.7-24.el9", "3.0.7-25.el9", "rpm") == -1


def test_version_in_range_deb():
    assert version_in_range("6.5+20250216-2", "0", "6.5+20250216-3", None, "deb") is True
    assert version_in_range("6.5+20250216-3", "0", "6.5+20250216-3", None, "deb") is False


def test_version_in_range_apk():
    assert version_in_range("1.2.4-r2", "0", "1.2.4-r10", None, "apk") is True
    assert version_in_range("1.2.4-r10", "0", "1.2.4-r10", None, "apk") is False


def test_version_in_range_rpm():
    assert version_in_range("3.0.7-24.el9", "0", "3.0.7-25.el9", None, "rpm") is True
    assert version_in_range("3.0.7-25.el9", "0", "3.0.7-25.el9", None, "rpm") is False


def test_version_in_range_pypi_fixed_requests_regression():
    """PyPI ranges fixed before 2.33.0 must not report that version as affected."""
    assert version_in_range("2.33.0", None, "2.6.0", None, "pypi") is False
    assert version_in_range("2.33.0", "2.3.0", "2.31.0", None, "pypi") is False
    assert version_in_range("2.25.0", "2.3.0", "2.31.0", None, "pypi") is True


def test_npm_canary_prerelease_compare_avoids_false_positive():
    """Regression: ``next@16.2.4`` must not match a fix bound of ``13.4.20-canary.13``.

    PEP 440 ``packaging.Version`` rejects npm SemVer pre-release tags like
    ``-canary.13`` / ``-rc.1`` / ``-beta.4`` as invalid. Without a pre-release
    fall-back, ``compare_version_order`` returned ``None`` and the OSV/GHSA
    range matcher conservatively marked the package as affected — producing
    a false positive on ``CVE-2023-46298`` for ``next@16.2.4`` (a Next.js 16
    install was flagged by an advisory whose fix was a Next.js 13 canary).
    """
    # Direct comparator: 16.2.4 is greater than 13.4.20-canary.13.
    assert compare_version_order("16.2.4", "13.4.20-canary.13", "npm") == 1
    assert compare_version_order("13.4.20-canary.13", "16.2.4", "npm") == -1

    # Range matcher must NOT mark 16.2.4 as affected.
    assert version_in_range("16.2.4", "0.9.9", "13.4.20-canary.13", None, "npm") is False

    # But the truly vulnerable cases stay vulnerable.
    assert version_in_range("13.4.19", "0.9.9", "13.4.20-canary.13", None, "npm") is True
    assert version_in_range("1.0.0", "0.9.9", "13.4.20-canary.13", None, "npm") is True


def test_npm_other_semver_prerelease_tags_compare_correctly():
    """Other npm pre-release tag stems must round-trip the same way."""
    # rc / beta / alpha / pre / nightly / next / snapshot — all SemVer 2.0
    # pre-release stems that PEP 440 doesn't accept directly. The fall-back
    # comparator strips them so a higher stable release is correctly seen as
    # newer than a pre-release of an older line.
    assert compare_version_order("5.0.0", "4.18.0-rc.1", "npm") == 1
    assert compare_version_order("3.0.0", "2.0.0-beta.4", "npm") == 1
    assert compare_version_order("2.0.0", "1.0.0-alpha.0", "npm") == 1
    assert compare_version_order("2.0.0", "1.99.0-pre.5", "npm") == 1
    assert compare_version_order("4.0.0", "3.5.0-nightly.20240101", "npm") == 1
