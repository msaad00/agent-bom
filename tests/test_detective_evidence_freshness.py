"""Detective-control freshness must fail CLOSED.

A detective control passes only because a completed, in-window scan IS the
control operating. That claim rests entirely on the scan's timestamp, so every
path where the timestamp cannot be trusted was scoring ``pass``:

* no timestamp at all      -> pass
* an unparseable timestamp -> pass
* a timestamp in the FUTURE -> pass, and fresh forever (a +10y clock skew
  never ages out of the window)

Undateable evidence is not fresh evidence; it is evidence whose age is unknown,
which is not a basis for asserting continuous monitoring operates. The 89/90/91
day boundary itself is correct and deliberately unchanged.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from agent_bom.evidence.control_modes import detective_control_status

_NOW = datetime(2026, 7, 31, 12, 0, 0, tzinfo=timezone.utc)


def _status(latest_scan: str | None, *, scan_count: int = 1) -> tuple[str, str]:
    return detective_control_status(scan_count=scan_count, latest_scan=latest_scan, now=_NOW, max_age_days=90)


def test_no_completed_scan_is_still_not_assessed() -> None:
    assert _status(None, scan_count=0) == ("not_assessed", "no_completed_scan")


def test_a_fresh_scan_still_passes() -> None:
    status, reason = _status((_NOW - timedelta(days=1)).isoformat())
    assert (status, reason) == ("pass", "fresh_scan_evidence")


def test_a_stale_scan_still_fails() -> None:
    status, reason = _status((_NOW - timedelta(days=91)).isoformat())
    assert (status, reason) == ("fail", "stale_scan_evidence")


def test_the_ninety_day_boundary_is_unchanged() -> None:
    assert _status((_NOW - timedelta(days=89)).isoformat())[0] == "pass"
    assert _status((_NOW - timedelta(days=90)).isoformat())[0] == "pass"
    assert _status((_NOW - timedelta(days=91)).isoformat())[0] == "fail"


@pytest.mark.parametrize("value", [None, "", "not-a-timestamp", "2026-13-45T99:99:99"])
def test_undateable_evidence_is_not_assessed_never_a_pass(value: str | None) -> None:
    """A scan we cannot date cannot evidence that monitoring is CURRENT."""
    status, reason = _status(value)
    assert status == "not_assessed", f"undateable evidence ({value!r}) scored {status}"
    assert reason == "scan_evidence_age_unknown"


def test_a_future_dated_scan_fails_instead_of_passing_forever() -> None:
    """Clock skew must not buy permanent freshness.

    ``reference - completed`` is negative for a future timestamp, so it can
    never exceed the window — a scan dated +10 years read as fresh on every
    future request.
    """
    status, reason = _status((_NOW + timedelta(days=3650)).isoformat())
    assert status == "fail", "a future-dated scan passed"
    assert reason == "future_scan_evidence"


def test_small_forward_clock_skew_is_tolerated() -> None:
    """Ordinary NTP drift between a scanner and the control plane is not fraud."""
    status, _ = _status((_NOW + timedelta(minutes=2)).isoformat())
    assert status == "pass"


def test_a_disabled_window_does_not_resurrect_the_fail_open_paths() -> None:
    """max_age_days<=0 disables the staleness check, not the honesty checks."""
    disabled = detective_control_status(scan_count=1, latest_scan=None, now=_NOW, max_age_days=0)
    assert disabled[0] == "pass"
