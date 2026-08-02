"""``introduced: "0"`` is a sentinel, not a version to compare against.

The OSV schema defines it as "a version that sorts before any other version"
(https://ossf.github.io/osv-schema/). Comparing a real version against the
literal string ``"0"`` therefore gives the wrong answer whenever the version
sorts BELOW ``0`` in its ecosystem's own order — which is exactly what a Go
pseudo-version does: ``v0.0.0-20200622213623-75b288015ac9`` is a pre-release of
``0.0.0``, so semver puts it under ``0``.

Every Go module pinned to a pseudo-version (the default for any dependency
without a tagged release, and for every ``replace``/untagged commit) then fell
out of every advisory window opening at the sentinel — a silent, total recall
loss. Measured on ``golang.org/x/crypto@v0.0.0-20200622213623-75b288015ac9``:
24 advisories that OSV reports for that exact version, 0 reported by the local
DB read path.

``package_scan._version_in_window`` already stripped the sentinel, so the OSV
API path was correct while the local-DB path was not: the same package got
opposite verdicts depending on which engine served the query.
"""

from __future__ import annotations

import pytest

from agent_bom.db.lookup import _version_match_state
from agent_bom.scanners.package_scan import _is_version_affected
from agent_bom.version_utils import normalize_introduced, version_in_range

PSEUDO = "v0.0.0-20200622213623-75b288015ac9"


def test_normalize_introduced_resolves_the_sentinel() -> None:
    assert normalize_introduced("0") is None
    assert normalize_introduced("") is None
    assert normalize_introduced(None) is None


def test_normalize_introduced_keeps_real_bounds() -> None:
    assert normalize_introduced("0.1.0") == "0.1.0"
    assert normalize_introduced("0.0.0") == "0.0.0"
    assert normalize_introduced("1.2.3") == "1.2.3"


# ── the measured recall hole ────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("fixed", "expected"),
    [
        # GHSA-45x7-px36-x8w8 / GHSA-3vm4-22fp-5rfm shapes: a sentinel-opened
        # window closed by a later pseudo-version or by a tagged release.
        ("0.0.0-20231218163308-9d2ee975ef9f", True),
        ("0.17.0", True),
        ("0.52.0", True),
        # Closed BEFORE the pinned pseudo-version: genuinely not affected.
        ("0.0.0-20200124225646-8b5121be2f68", False),
    ],
)
def test_go_pseudo_version_matches_sentinel_window(fixed: str, expected: bool) -> None:
    assert version_in_range(PSEUDO, "0", fixed, None, "go") is expected


@pytest.mark.parametrize(
    ("fixed", "expected"),
    [
        ("0.0.0-20231218163308-9d2ee975ef9f", "affected"),
        ("0.17.0", "affected"),
        ("0.0.0-20200124225646-8b5121be2f68", "unaffected"),
    ],
)
def test_local_db_read_path_matches_sentinel_window(fixed: str, expected: str) -> None:
    assert _version_match_state(PSEUDO, "0", fixed, "", "go") == expected


def test_both_engines_agree_on_the_sentinel() -> None:
    """The OSV walker and the DB read path must not disagree on one advisory."""
    advisory = {
        "id": "GHSA-45x7-px36-x8w8",
        "affected": [
            {
                "package": {"ecosystem": "Go", "name": "golang.org/x/crypto"},
                "ranges": [
                    {
                        "type": "SEMVER",
                        "events": [{"introduced": "0"}, {"fixed": "0.0.0-20231218163308-9d2ee975ef9f"}],
                    }
                ],
            }
        ],
    }
    walker = _is_version_affected(advisory, "golang.org/x/crypto", PSEUDO, "Go")
    read_path = _version_match_state(PSEUDO, "0", "0.0.0-20231218163308-9d2ee975ef9f", "", "go") == "affected"
    assert walker is True
    assert read_path is True


# ── the sentinel must not widen anything else ───────────────────────────────


def test_real_lower_bound_still_excludes_the_pseudo_version() -> None:
    """Only ``"0"`` is a sentinel; ``0.1.0`` is a bound and must still hold."""
    assert version_in_range(PSEUDO, "0.1.0", "0.17.0", None, "go") is False
    assert _version_match_state(PSEUDO, "0.1.0", "0.17.0", "", "go") == "unaffected"


def test_sentinel_does_not_leak_into_upper_bounds() -> None:
    """``fixed``/``last_affected`` keep their literal meaning.

    ``fixed: "0"`` is not a sentinel — nothing is "fixed before every version" —
    so it must stay a comparison, not silently become "unbounded above".
    """
    assert version_in_range("1.2.3", None, "0", None, "npm") is False
    assert _version_match_state("1.2.3", "", "0", "", "npm") == "unaffected"


@pytest.mark.parametrize("ecosystem", ["npm", "pypi", "maven", "crates.io", "go"])
def test_sentinel_window_matches_ordinary_versions_in_every_ecosystem(ecosystem: str) -> None:
    assert version_in_range("1.2.3", "0", "2.0.0", None, ecosystem) is True
    assert version_in_range("2.0.0", "0", "2.0.0", None, ecosystem) is False
