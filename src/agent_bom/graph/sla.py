"""Finding-level remediation SLA policy — one source of truth for every surface.

A finding's ``sla_due_at`` is a *derived* field: the report spine
(:meth:`agent_bom.finding.Finding.to_dict`) and the API projection
(:func:`agent_bom.finding_scope.canonical_finding_payload`) both call
:func:`sla_due_at` so the CLI table, ``/v1/findings``, the JSON/SARIF/CDX/SPDX
exports, and the UI cannot disagree about the same finding's deadline.

The policy is deliberately simple (severity → fixed remediation window from the
finding's first-seen anchor). A KEV-listed finding honors the earlier of its
severity window and the CISA BOD 22-01 deadline, because the most urgent binding
deadline is the one that actually governs. When neither a policy window nor a KEV
deadline can be computed the deadline is an explicit ``None`` — an honest
"unknown", never a fabricated date.
"""

from __future__ import annotations

from datetime import datetime, timezone

from agent_bom.graph.severity import normalize_severity

# Severity → remediation window in days from the finding's first-seen anchor.
# Conservative, industry-typical defaults; ``info``/``unknown`` intentionally
# carry no fixed deadline (an SLA there would be a fabricated claim).
SEVERITY_SLA_DAYS: dict[str, int] = {
    "critical": 7,
    "high": 30,
    "medium": 90,
    "low": 180,
}

def _parse_iso(value: object) -> datetime | None:
    """Parse a date or datetime string into a tz-aware UTC datetime, or None.

    Accepts full ISO-8601 datetimes and bare ``YYYY-MM-DD`` dates (CISA KEV due
    dates are date-only). Naive values are treated as UTC.
    """
    if not isinstance(value, str):
        return None
    text = value.strip()
    if not text:
        return None
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def sla_due_at(
    severity: object,
    first_seen: object,
    *,
    kev_due_date: object = None,
) -> str | None:
    """Return the ISO-8601 remediation deadline for a finding, or ``None``.

    ``first_seen`` anchors the severity window; ``kev_due_date`` (when present)
    competes as an alternative deadline and the *earlier* of the two wins. The
    result is a full tz-aware ISO datetime so it round-trips through the finding
    response timestamp validators. ``None`` means no deadline could be honestly
    derived (unrated severity and no KEV deadline, or no usable anchor).
    """
    candidates: list[datetime] = []

    days = SEVERITY_SLA_DAYS.get(normalize_severity(severity if isinstance(severity, str) else None))
    anchor = _parse_iso(first_seen)
    if days is not None and anchor is not None:
        from datetime import timedelta

        candidates.append(anchor + timedelta(days=days))

    kev = _parse_iso(kev_due_date)
    if kev is not None:
        candidates.append(kev)

    if not candidates:
        return None
    return min(candidates).isoformat()


def finding_owner(assignee: object) -> str | None:
    """Return the finding owner: the triage assignee, else ``None``.

    The simple ownership cut surfaces the existing triage ``assignee`` as the
    finding's owner. The *data* layer carries an explicit ``None`` when nobody
    is assigned — an honest absence the API contract and every export
    (JSON/SARIF/CDX/SPDX) preserve, so a machine consumer never sees a fake
    owner. The CLI and UI render that ``None`` as "Unassigned" at the
    presentation layer only.
    """
    if isinstance(assignee, str) and assignee.strip():
        return assignee.strip()
    return None


__all__ = ["SEVERITY_SLA_DAYS", "finding_owner", "sla_due_at"]
