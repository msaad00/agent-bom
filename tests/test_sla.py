"""Unit tests for the finding SLA remediation-deadline policy."""

from __future__ import annotations

from datetime import datetime, timezone

from agent_bom.sla import (
    SEVERITY_SLA_DAYS,
    UNASSIGNED_OWNER,
    finding_owner,
    sla_due_at,
)


def _dt(text: str) -> datetime:
    return datetime.fromisoformat(text.replace("Z", "+00:00"))


def test_critical_due_date_is_first_seen_plus_policy() -> None:
    due = sla_due_at("critical", "2026-08-01T00:00:00+00:00")
    assert due is not None
    delta = _dt(due) - _dt("2026-08-01T00:00:00+00:00")
    assert delta.days == SEVERITY_SLA_DAYS["critical"]


def test_each_rated_severity_maps_to_its_policy_window() -> None:
    anchor = "2026-01-01T00:00:00+00:00"
    for severity, days in SEVERITY_SLA_DAYS.items():
        due = sla_due_at(severity, anchor)
        assert due is not None, severity
        assert (_dt(due) - _dt(anchor)).days == days, severity


def test_severity_input_is_normalized() -> None:
    assert sla_due_at("CRITICAL", "2026-08-01T00:00:00+00:00") == sla_due_at("critical", "2026-08-01T00:00:00+00:00")
    assert sla_due_at("Informational", "2026-08-01T00:00:00+00:00") is None


def test_unknown_or_info_severity_has_no_deadline() -> None:
    assert sla_due_at("info", "2026-08-01T00:00:00+00:00") is None
    assert sla_due_at("bogus", "2026-08-01T00:00:00+00:00") is None
    assert sla_due_at(None, "2026-08-01T00:00:00+00:00") is None


def test_missing_anchor_yields_none_when_no_kev() -> None:
    # Honest unknown: cannot compute a deadline without an observation anchor.
    assert sla_due_at("critical", None) is None
    assert sla_due_at("critical", "") is None
    assert sla_due_at("critical", "not-a-date") is None


def test_kev_due_date_overrides_when_earlier() -> None:
    # high policy = 30d from first_seen would land 2026-08-31; KEV deadline is
    # earlier, so the more-urgent KEV date governs.
    due = sla_due_at("high", "2026-08-01T00:00:00+00:00", kev_due_date="2026-08-10")
    assert due is not None
    assert _dt(due) == _dt("2026-08-10T00:00:00+00:00")


def test_kev_due_date_ignored_when_policy_is_earlier() -> None:
    # critical policy = 7d -> 2026-08-08; a later KEV date must not relax it.
    due = sla_due_at("critical", "2026-08-01T00:00:00+00:00", kev_due_date="2026-12-31")
    assert due is not None
    assert _dt(due) == _dt("2026-08-08T00:00:00+00:00")


def test_kev_due_date_used_when_no_policy_anchor() -> None:
    # No usable first_seen but a real KEV deadline: honor the KEV date.
    due = sla_due_at("info", None, kev_due_date="2026-08-10")
    assert due is not None
    assert _dt(due) == _dt("2026-08-10T00:00:00+00:00")


def test_due_date_is_full_iso_datetime_with_timezone() -> None:
    due = sla_due_at("medium", "2026-08-01")
    assert due is not None
    parsed = _dt(due)
    assert parsed.tzinfo is not None
    # Date-only anchor is normalized to a tz-aware midnight.
    assert parsed == datetime(2026, 8, 1, tzinfo=timezone.utc) + (_dt(due) - datetime(2026, 8, 1, tzinfo=timezone.utc))


def test_finding_owner_prefers_assignee() -> None:
    assert finding_owner("alice@example.com") == "alice@example.com"
    assert finding_owner("  bob  ") == "bob"


def test_finding_owner_defaults_to_unassigned() -> None:
    assert finding_owner(None) == UNASSIGNED_OWNER
    assert finding_owner("") == UNASSIGNED_OWNER
    assert finding_owner("   ") == UNASSIGNED_OWNER
    assert finding_owner(123) == UNASSIGNED_OWNER  # type: ignore[arg-type]
