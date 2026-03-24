"""Tests for cross-package fix-version bleed guards in parse_fixed_version."""

from __future__ import annotations

from agent_bom.scanners import parse_fixed_version

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _osv_affected(pkg_name: str, pkg_eco: str, fixed: str) -> dict:
    """Build a minimal OSV affected block."""
    return {
        "package": {"name": pkg_name, "ecosystem": pkg_eco},
        "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": fixed}]}],
    }


def _osv_affected_no_name(pkg_eco: str, fixed: str) -> dict:
    """Build an OSV affected block with an empty package name (simulates bad data)."""
    return {
        "package": {"ecosystem": pkg_eco},
        "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": fixed}]}],
    }


# ---------------------------------------------------------------------------
# Guard 1 — empty package name in affected block must be skipped
# ---------------------------------------------------------------------------


def test_empty_package_name_skipped():
    """An affected entry with no package name must not contribute a fix version."""
    vuln_data = {
        "id": "CVE-2023-4863",
        "affected": [
            # Block with no name — should be skipped entirely
            _osv_affected_no_name("PyPI", "0.1.8"),
        ],
    }
    result = parse_fixed_version(vuln_data, "pillow", "PyPI", current_version="9.5.0")
    assert result is None


def test_empty_package_name_skipped_even_without_current_version():
    """Empty-name guard fires even when current_version is not supplied."""
    vuln_data = {
        "id": "CVE-2023-4863",
        "affected": [
            _osv_affected_no_name("PyPI", "0.1.8"),
        ],
    }
    result = parse_fixed_version(vuln_data, "pillow", "PyPI")
    assert result is None


def test_correct_package_still_matched_when_other_entry_has_no_name():
    """When one affected entry has no name and another has the correct name, the
    correct entry is still matched and its fix version returned."""
    vuln_data = {
        "id": "CVE-2023-4863",
        "affected": [
            # Sibling entry with no name — must not steal the fix
            _osv_affected_no_name("PyPI", "0.1.8"),
            # Real pillow entry
            _osv_affected("Pillow", "PyPI", "10.0.1"),
        ],
    }
    result = parse_fixed_version(vuln_data, "Pillow", "PyPI", current_version="9.5.0")
    assert result == "10.0.1"


# ---------------------------------------------------------------------------
# Guard 2 — fix version lower than current version must be skipped
# ---------------------------------------------------------------------------


def test_fix_lower_than_current_skipped():
    """A fix version that is lower than the installed version must be skipped
    (it almost certainly belongs to a different package in the same advisory)."""
    vuln_data = {
        "id": "CVE-2023-4863",
        "affected": [
            _osv_affected("pillow", "PyPI", "0.1.8"),
        ],
    }
    # pillow 9.5.0 is installed; fix 0.1.8 is a downgrade — should be skipped
    result = parse_fixed_version(vuln_data, "pillow", "PyPI", current_version="9.5.0")
    assert result is None


def test_fix_equal_to_current_returned():
    """In OSV semantics, 'fixed' is the first version that is NOT affected.
    If fix == current_version the installed package is exactly at the fix boundary
    and may or may not be vulnerable depending on inclusive/exclusive range
    semantics.  We leave this to downstream callers and return the fix version
    rather than silently dropping it."""
    vuln_data = {
        "id": "GHSA-test-0001",
        "affected": [
            _osv_affected("requests", "PyPI", "2.28.0"),
        ],
    }
    result = parse_fixed_version(vuln_data, "requests", "PyPI", current_version="2.28.0")
    assert result == "2.28.0"


def test_fix_higher_than_current_returned():
    """A valid fix version higher than the installed version must be returned."""
    vuln_data = {
        "id": "GHSA-test-0002",
        "affected": [
            _osv_affected("requests", "PyPI", "2.31.0"),
        ],
    }
    result = parse_fixed_version(vuln_data, "requests", "PyPI", current_version="2.28.0")
    assert result == "2.31.0"


def test_fix_returned_when_no_current_version():
    """When no current_version is supplied the fix version is returned as-is
    (existing behaviour must not regress)."""
    vuln_data = {
        "id": "GHSA-test-0003",
        "affected": [
            _osv_affected("requests", "PyPI", "2.31.0"),
        ],
    }
    result = parse_fixed_version(vuln_data, "requests", "PyPI")
    assert result == "2.31.0"


def test_fix_returned_when_current_version_unknown():
    """'unknown' current_version must not trigger the downgrade guard."""
    vuln_data = {
        "id": "GHSA-test-0004",
        "affected": [
            _osv_affected("requests", "PyPI", "2.31.0"),
        ],
    }
    result = parse_fixed_version(vuln_data, "requests", "PyPI", current_version="unknown")
    assert result == "2.31.0"


def test_fix_returned_when_current_version_latest():
    """'latest' current_version must not trigger the downgrade guard."""
    vuln_data = {
        "id": "GHSA-test-0005",
        "affected": [
            _osv_affected("requests", "PyPI", "2.31.0"),
        ],
    }
    result = parse_fixed_version(vuln_data, "requests", "PyPI", current_version="latest")
    assert result == "2.31.0"


# ---------------------------------------------------------------------------
# Guard 3 — git SHA filtering (existing behaviour regression test)
# ---------------------------------------------------------------------------


def test_git_sha_skipped():
    """A 40-char hex git SHA must not be returned as a fix version."""
    sha = "a" * 40
    vuln_data = {
        "id": "GHSA-sha-test",
        "affected": [
            _osv_affected("some-package", "PyPI", sha),
        ],
    }
    result = parse_fixed_version(vuln_data, "some-package", "PyPI", current_version="1.0.0")
    assert result is None


def test_short_sha_skipped():
    """A short 7-char hex SHA must not be returned as a fix version."""
    short_sha = "abc1234"
    vuln_data = {
        "id": "GHSA-short-sha",
        "affected": [
            _osv_affected("some-package", "PyPI", short_sha),
        ],
    }
    result = parse_fixed_version(vuln_data, "some-package", "PyPI", current_version="1.0.0")
    assert result is None


# ---------------------------------------------------------------------------
# Real-world CVE-2023-4863 scenario
# ---------------------------------------------------------------------------


def test_cve_2023_4863_pillow_no_bleed():
    """Simulate CVE-2023-4863 where libwebp fix 0.1.8 must not leak into pillow.

    The advisory has two affected entries:
    - libwebp  fix = 0.1.8  (a libwebp semver, meaningless for pillow)
    - Pillow   fix = 10.0.1
    Pillow 9.5.0 is installed; 0.1.8 < 9.5.0 so the downgrade guard fires and
    10.0.1 is returned instead.
    """
    vuln_data = {
        "id": "CVE-2023-4863",
        "affected": [
            # libwebp entry — has a name, but fix is lower than pillow's version
            _osv_affected("libwebp", "npm", "0.1.8"),
            # Pillow entry with correct fix
            _osv_affected("Pillow", "PyPI", "10.0.1"),
        ],
    }
    result = parse_fixed_version(vuln_data, "Pillow", "PyPI", current_version="9.5.0")
    assert result == "10.0.1"


def test_cve_2023_4863_pillow_no_bleed_no_name_variant():
    """Same scenario but libwebp block has no name (worst-case bad OSV data)."""
    vuln_data = {
        "id": "CVE-2023-4863",
        "affected": [
            _osv_affected_no_name("npm", "0.1.8"),
            _osv_affected("Pillow", "PyPI", "10.0.1"),
        ],
    }
    result = parse_fixed_version(vuln_data, "Pillow", "PyPI", current_version="9.5.0")
    assert result == "10.0.1"
