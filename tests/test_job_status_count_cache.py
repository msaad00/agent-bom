"""Job status counts are cached because the dashboard polls them forever.

``count_summary_by_status`` is an unbounded ``GROUP BY`` over ``scan_jobs`` —
measured at ~342ms across 200k rows — and the activity feed requests it every
few seconds for every open dashboard. The search variant is worse: its
``LOWER(CONCAT_WS(...)) LIKE`` predicate cannot use an index at all.

A short TTL keeps repeated polls off the database while a write invalidates
immediately, so a job that finishes never sits behind a stale count.
"""

from __future__ import annotations

from agent_bom.api import job_status_count_cache as cache


def setup_function() -> None:
    cache.reset()


def test_a_miss_reports_nothing_cached() -> None:
    assert cache.get_counts("t1", None) is None


def test_a_stored_count_is_returned() -> None:
    cache.set_counts("t1", None, {"done": 3, "failed": 1})

    assert cache.get_counts("t1", None) == {"done": 3, "failed": 1}


def test_tenants_do_not_share_counts() -> None:
    cache.set_counts("t1", None, {"done": 3})
    cache.set_counts("t2", None, {"done": 99})

    assert cache.get_counts("t1", None) == {"done": 3}
    assert cache.get_counts("t2", None) == {"done": 99}


def test_a_search_term_keys_separately() -> None:
    """A filtered count must never be served as the unfiltered one."""
    cache.set_counts("t1", None, {"done": 10})
    cache.set_counts("t1", "nightly", {"done": 2})

    assert cache.get_counts("t1", None) == {"done": 10}
    assert cache.get_counts("t1", "nightly") == {"done": 2}


def test_search_terms_are_normalized() -> None:
    cache.set_counts("t1", "Nightly", {"done": 2})

    assert cache.get_counts("t1", "  nightly ") == {"done": 2}


def test_expiry_drops_the_entry() -> None:
    cache.set_counts("t1", None, {"done": 3})
    cache.expire_all_for_test()

    assert cache.get_counts("t1", None) is None


def test_writing_a_job_invalidates_only_that_tenant() -> None:
    cache.set_counts("t1", None, {"done": 3})
    cache.set_counts("t1", "nightly", {"done": 1})
    cache.set_counts("t2", None, {"done": 7})

    cache.invalidate_tenant("t1")

    assert cache.get_counts("t1", None) is None
    assert cache.get_counts("t1", "nightly") is None
    assert cache.get_counts("t2", None) == {"done": 7}


def test_returned_counts_cannot_be_mutated_by_a_caller() -> None:
    """A caller editing the response must not corrupt the cached entry."""
    cache.set_counts("t1", None, {"done": 3})

    first = cache.get_counts("t1", None)
    assert first is not None
    first["done"] = 999

    assert cache.get_counts("t1", None) == {"done": 3}
