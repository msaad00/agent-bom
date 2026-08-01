"""``affected[].versions`` enumerates known releases; it does not bound the range.

OSV writes ``versions[]`` from the releases that existed when the advisory was
imported. It goes stale the moment a new patch release ships, and importers
often write it with a different spelling than the ranges use (``v10.4.9`` vs
``10.4.9``). The matcher treated a non-empty list as exhaustive — if the
installed version was not in it, the block's ``ranges`` were never evaluated —
so a version squarely inside ``[10.0.0, 10.4.48)`` was reported CLEAN.

Measured against live OSV: ``typo3/cms-core@10.4.35`` lost all 29 of its
advisories this way, ``magento/community-edition@2.4.4-p9`` lost 8, and
``Newtonsoft.Json@13.0.0-beta2`` lost its only one.

The list stays authoritative when it is the block's ONLY version statement, and
a GIT tag walk never becomes a catch-all — both pinned below.
"""

from __future__ import annotations

from agent_bom.scanners.package_scan import _is_version_affected

ECOSYSTEM = "Packagist"
NAME = "typo3/cms-core"


def _advisory(*, versions: list[str] | None = None, ranges: list[dict] | None = None) -> dict:
    block: dict = {"package": {"name": NAME, "ecosystem": ECOSYSTEM}}
    if versions is not None:
        block["versions"] = versions
    if ranges is not None:
        block["ranges"] = ranges
    return {"id": "GHSA-test", "affected": [block]}


_WINDOW = [{"type": "ECOSYSTEM", "events": [{"introduced": "10.0.0"}, {"fixed": "10.4.48"}]}]
# A stale enumeration: real releases exist above v10.4.9 that it never names.
_STALE_LIST = ["v10.0.0", "v10.4.8", "v10.4.9"]


def test_range_still_matches_when_the_versions_list_is_stale() -> None:
    assert _is_version_affected(_advisory(versions=_STALE_LIST, ranges=_WINDOW), NAME, "10.4.35", ECOSYSTEM) is True


def test_range_bounds_still_exclude_versions_outside_the_window() -> None:
    """The fix must not turn a stale list into a catch-all."""
    advisory = _advisory(versions=_STALE_LIST, ranges=_WINDOW)
    assert _is_version_affected(advisory, NAME, "10.4.48", ECOSYSTEM) is False
    assert _is_version_affected(advisory, NAME, "11.0.0", ECOSYSTEM) is False
    assert _is_version_affected(advisory, NAME, "9.5.49", ECOSYSTEM) is False


def test_a_listed_version_still_matches() -> None:
    assert _is_version_affected(_advisory(versions=_STALE_LIST, ranges=_WINDOW), NAME, "10.4.8", ECOSYSTEM) is True


def test_a_versions_only_block_keeps_the_list_authoritative() -> None:
    """With no ranges, the enumeration is the whole statement — don't widen it."""
    advisory = _advisory(versions=_STALE_LIST)
    assert _is_version_affected(advisory, NAME, "10.4.35", ECOSYSTEM) is False
    assert _is_version_affected(advisory, NAME, "10.4.8", ECOSYSTEM) is True


def test_a_block_with_neither_ranges_nor_versions_stays_conservative() -> None:
    assert _is_version_affected(_advisory(), NAME, "10.4.35", ECOSYSTEM) is True


def test_a_git_tag_walk_never_becomes_a_catch_all() -> None:
    """A GIT range cannot place an ecosystem version, so it must not widen one.

    ``introduced: 0`` on a GIT range with no comparable upper bound would match
    every version in existence if it were consulted as a fallback.
    """
    git_only = [{"type": "GIT", "events": [{"introduced": "0"}]}]
    advisory = _advisory(versions=_STALE_LIST, ranges=git_only)
    assert _is_version_affected(advisory, NAME, "99.0.0", ECOSYSTEM) is False
    assert _is_version_affected(advisory, NAME, "10.4.8", ECOSYSTEM) is True
