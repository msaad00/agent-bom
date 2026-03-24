"""Regression tests for fix-version parsing — cross-package bleed prevention."""

from agent_bom.scanners import parse_fixed_version


def _vuln(affected_entries):
    return {"id": "TEST-001", "affected": affected_entries}


def _affected(name="", ecosystem="", fixed="1.0.0"):
    return {
        "package": {"name": name, "ecosystem": ecosystem},
        "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": fixed}]}],
    }


def test_empty_name_skipped():
    """Affected entries with no package name should be skipped."""
    vuln = _vuln([_affected(name="", ecosystem="PyPI", fixed="0.1.8")])
    assert parse_fixed_version(vuln, "pillow", "PyPI") is None


def test_correct_package_matched_alongside_empty():
    """When one entry has no name and another matches, the match wins."""
    vuln = _vuln(
        [
            _affected(name="", ecosystem="", fixed="0.1.8"),
            _affected(name="pillow", ecosystem="PyPI", fixed="10.2.0"),
        ]
    )
    assert parse_fixed_version(vuln, "pillow", "PyPI") == "10.2.0"


def test_fix_lower_than_current_skipped():
    """Fix version lower than current belongs to a sibling package — skip it."""
    vuln = _vuln([_affected(name="pillow", ecosystem="PyPI", fixed="0.1.8")])
    result = parse_fixed_version(vuln, "pillow", "PyPI", current_version="9.0.0")
    assert result is None


def test_fix_equal_to_current_returned():
    """OSV 'fixed' means first non-affected — equal to current is valid."""
    vuln = _vuln([_affected(name="pillow", ecosystem="PyPI", fixed="9.0.0")])
    # Equal means "this version is the fix" — should NOT be skipped
    # Actually 9.0.0 < 9.0.0 is False, so it passes through
    result = parse_fixed_version(vuln, "pillow", "PyPI", current_version="9.0.0")
    assert result == "9.0.0"


def test_fix_higher_than_current_returned():
    """Normal case: fix version is an upgrade."""
    vuln = _vuln([_affected(name="requests", ecosystem="PyPI", fixed="2.32.0")])
    result = parse_fixed_version(vuln, "requests", "PyPI", current_version="2.28.0")
    assert result == "2.32.0"


def test_no_current_version_skips_guard():
    """When current_version is empty, downgrade guard is bypassed."""
    vuln = _vuln([_affected(name="pillow", ecosystem="PyPI", fixed="0.1.8")])
    result = parse_fixed_version(vuln, "pillow", "PyPI", current_version="")
    assert result == "0.1.8"


def test_current_version_unknown_skips_guard():
    """When current_version is 'unknown', downgrade guard is bypassed."""
    vuln = _vuln([_affected(name="pillow", ecosystem="PyPI", fixed="0.1.8")])
    result = parse_fixed_version(vuln, "pillow", "PyPI", current_version="unknown")
    assert result == "0.1.8"


def test_current_version_latest_skips_guard():
    """When current_version is 'latest', downgrade guard is bypassed."""
    vuln = _vuln([_affected(name="pillow", ecosystem="PyPI", fixed="0.1.8")])
    result = parse_fixed_version(vuln, "pillow", "PyPI", current_version="latest")
    assert result == "0.1.8"


def test_git_sha_filtered():
    """40-char hex git SHAs should not be returned as fix versions."""
    vuln = _vuln([_affected(name="libwebp", ecosystem="", fixed="ca332209cb5567c9b249c86788cb2dbf8847e760")])
    result = parse_fixed_version(vuln, "libwebp", "")
    assert result is None


def test_short_sha_filtered():
    """Short commit hashes should not be returned."""
    vuln = _vuln([_affected(name="libwebp", ecosystem="", fixed="abcdef1234")])
    result = parse_fixed_version(vuln, "libwebp", "")
    assert result is None


def test_cve_2023_4863_scenario():
    """CVE-2023-4863: libwebp has no ecosystem, pillow should not get its fix."""
    vuln = _vuln(
        [
            # Entry 1: no name/ecosystem, git SHA fix
            _affected(name="", ecosystem="", fixed="ca332209cb5567c9b249c86788cb2dbf8847e760"),
            # Entry 2: pillow with real fix
            _affected(name="Pillow", ecosystem="PyPI", fixed="10.0.1"),
        ]
    )
    result = parse_fixed_version(vuln, "pillow", "PyPI", current_version="9.0.0")
    assert result == "10.0.1"


def test_cve_2023_4863_no_pillow_entry():
    """CVE-2023-4863: if only the unnamed entry exists, pillow gets no fix."""
    vuln = _vuln(
        [
            _affected(name="", ecosystem="", fixed="ca332209cb5567c9b249c86788cb2dbf8847e760"),
        ]
    )
    result = parse_fixed_version(vuln, "pillow", "PyPI", current_version="9.0.0")
    assert result is None
