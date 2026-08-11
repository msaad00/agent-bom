"""KEV is on the executive headline; it must be reachable from the list.

The exec view leads with a KEV count — "actively exploited, fix these first" is
the single strongest prioritisation signal a security tool has. `is_kev` is
carried on every finding row and rendered per finding. `/v1/findings` had no
parameter to filter on it, so the headline was a dead end: a reader could see
that N findings are known-exploited and had no way to ask for those N.

The predicate goes into `row_matches_scope`, the single source of truth shared
by the route's in-memory scan findings and the hub store's bulk-ingested rows,
so the two paths cannot diverge on what "KEV" selects.

``kev=true`` narrows to known-exploited findings. ``kev=false`` is the useful
inverse (everything not known-exploited) rather than a no-op, and omitting the
parameter changes nothing — a filter that cannot be turned off is not a filter.
"""

from __future__ import annotations

import pytest

from agent_bom.finding_scope import row_matches_scope


def row(**overrides: object) -> dict:
    base: dict = {
        "id": "f1",
        "title": "CVE-2026-0001 in left-pad",
        "severity": "critical",
        "finding_type": "CVE",
        "source": "OSV",
        "cve_id": "CVE-2026-0001",
        "is_kev": True,
    }
    base.update(overrides)
    return base


def test_kev_true_keeps_a_known_exploited_finding() -> None:
    assert row_matches_scope(row(), {"kev": "true"}) is True


def test_kev_true_drops_a_finding_that_is_not_known_exploited() -> None:
    assert row_matches_scope(row(is_kev=False), {"kev": "true"}) is False


def test_kev_true_drops_a_finding_with_no_kev_verdict() -> None:
    """Absent is not the same as true. A row we never checked must not be
    presented as actively exploited."""
    assert row_matches_scope(row(is_kev=None), {"kev": "true"}) is False
    unknown = row()
    del unknown["is_kev"]
    assert row_matches_scope(unknown, {"kev": "true"}) is False


def test_kev_false_is_the_inverse_not_a_no_op() -> None:
    assert row_matches_scope(row(is_kev=False), {"kev": "false"}) is True
    assert row_matches_scope(row(), {"kev": "false"}) is False


def test_no_kev_filter_changes_nothing() -> None:
    for value in (True, False, None):
        assert row_matches_scope(row(is_kev=value), {}) is True


def test_kev_composes_with_the_other_scope_filters() -> None:
    """Filters intersect; KEV must not widen a scoped read."""
    scoped = row(provider="aws", environment="prod")
    assert row_matches_scope(scoped, {"kev": "true", "provider": "aws"}) is True
    assert row_matches_scope(scoped, {"kev": "true", "provider": "gcp"}) is False


@pytest.mark.parametrize("truthy", ["true", "True", "1", "yes"])
def test_common_truthy_spellings_are_accepted(truthy: str) -> None:
    """The value is canonicalised by the route, but the predicate is shared and
    reached directly by the store, so it must not be brittle about spelling."""
    assert row_matches_scope(row(), {"kev": truthy}) is True
