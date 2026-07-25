"""Range matching must not lose vulnerable versions.

Two independent defects, both silent false negatives:

* A range that fixes several release branches encodes them as alternating
  ``introduced``/``fixed`` events. Treating each ``introduced`` as a reset
  discards an earlier window that already matched.
* Date-style versions (``20230311``) are all-hex-digit strings, so the
  abbreviated-commit-SHA heuristic claimed them. Comparison then returns
  ``None`` and the bound fails closed — the package looks unaffected.
"""

from __future__ import annotations

import pytest

from agent_bom.db.lookup import _version_match_state
from agent_bom.version_utils import _looks_like_commit_sha, compare_version_order, version_in_range


def _osv_range(*events: dict) -> list[dict]:
    return [{"type": "ECOSYSTEM", "events": list(events)}]


# ── multi-window ranges ──────────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("version", "expected"),
    [
        ("1.2", True),  # inside the first window — the regression case
        ("1.7", False),  # between windows: fixed in 1.5, not yet reintroduced
        ("2.2", True),  # inside the second window
        ("2.5", False),  # fixed
        ("0.9", False),  # before anything was introduced
    ],
)
def test_multi_window_range_matches_every_window(version: str, expected: bool) -> None:
    from agent_bom.scanners.package_scan import _is_version_affected

    vuln = {
        "affected": [
            {
                "package": {"ecosystem": "PyPI", "name": "widget"},
                "ranges": _osv_range(
                    {"introduced": "1.0"},
                    {"fixed": "1.5"},
                    {"introduced": "2.0"},
                    {"fixed": "2.5"},
                ),
            }
        ]
    }

    assert _is_version_affected(vuln, "widget", version, "PyPI") is expected


def test_window_reopened_without_a_fix_stays_affected() -> None:
    """A trailing ``introduced`` with no ``fixed`` is vulnerable through latest."""
    from agent_bom.scanners.package_scan import _is_version_affected

    vuln = {
        "affected": [
            {
                "package": {"ecosystem": "PyPI", "name": "widget"},
                "ranges": _osv_range({"introduced": "1.0"}, {"fixed": "1.5"}, {"introduced": "2.0"}),
            }
        ]
    }

    assert _is_version_affected(vuln, "widget", "3.0", "PyPI") is True
    assert _is_version_affected(vuln, "widget", "1.7", "PyPI") is False


# ── date versions vs commit SHAs ─────────────────────────────────────────────


@pytest.mark.parametrize("version", ["20230311", "20240226", "1234567"])
def test_all_digit_tokens_are_versions_not_shas(version: str) -> None:
    assert _looks_like_commit_sha(version) is False


@pytest.mark.parametrize("sha", ["deadbeef", "a1b2c3d", "0" * 39 + "a", "f" * 40])
def test_real_abbreviated_shas_are_still_detected(sha: str) -> None:
    assert _looks_like_commit_sha(sha) is True


def test_date_versioned_package_inside_range_is_affected() -> None:
    """An apk date version below the fix must compare, not fail closed."""
    assert compare_version_order("20230311", "20240226-r0", "apk") is not None
    assert version_in_range("20230311", "0", "20240226-r0", None, "apk") is True


def test_date_versioned_package_at_the_fix_is_clean() -> None:
    assert version_in_range("20240226-r0", "0", "20240226-r0", None, "apk") is False


def test_both_range_engines_agree_on_date_versions() -> None:
    """``version_in_range`` and the DB lookup must not answer differently.

    They are separate implementations reached by the live-OSV and local-DB
    paths respectively; a scan and a cached lookup of the same package must
    not disagree about whether it is vulnerable.
    """
    assert version_in_range("20230311", "0", "20240226-r0", None, "apk") is True
    assert _version_match_state("20230311", "0", "20240226-r0", None, "apk") == "affected"

    assert version_in_range("20240226-r0", "0", "20240226-r0", None, "apk") is False
    assert _version_match_state("20240226-r0", "0", "20240226-r0", None, "apk") == "unaffected"
