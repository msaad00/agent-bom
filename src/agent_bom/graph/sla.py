"""Finding-level remediation SLA policy — one source of truth for every surface.

Finding projections share deadline resolution and source metadata. Known policy
values are derived from the first-seen anchor; explicit and unattributed legacy
assignments remain intact. A source marker identifies how a value was supplied,
not whether a human approved it.

The policy is deliberately simple (severity → fixed remediation window from the
finding's first-seen anchor). Under the built-in policy, an available KEV
target competes with the severity window and the earlier date is used. This
product default does not determine an organization's regulatory obligations.
When neither a policy window nor a KEV deadline can be computed the deadline is an explicit ``None`` — an honest
"unknown", never a fabricated date.
"""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime, timezone
from typing import Any

from agent_bom.graph.severity import normalize_severity

# Severity → remediation window in days from the finding's first-seen anchor.
# Built-in product defaults; ``info``/``unknown`` intentionally
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


# Versioned source identity lets current-state projections distinguish a computed
# deadline from an explicit assignment without guessing from the date itself.
SLA_POLICY_SOURCE = "severity-kev/v1"
SLA_DUE_SOURCES = frozenset({SLA_POLICY_SOURCE, "explicit", "unknown", "unavailable"})


def finding_sla_fields(payload: Mapping[str, Any]) -> dict[str, Any]:
    """Resolve a deadline and its source; preserve opaque legacy assignments."""
    due = payload.get("sla_due_at")
    source = payload.get("sla_due_at_source")
    evidence = payload.get("evidence")
    kev = payload.get("kev_due_date")
    if kev is None and isinstance(evidence, Mapping):
        kev = evidence.get("kev_due_date")
    parsed_kev = _parse_iso(kev)
    kev = parsed_kev.isoformat() if parsed_kev is not None else None
    if due is not None and source != SLA_POLICY_SOURCE:
        return {"sla_due_at": due, "sla_due_at_source": "explicit" if source == "explicit" else "unknown", "kev_due_date": kev}
    due = sla_due_at(payload.get("effective_severity") or payload.get("severity"), payload.get("first_seen"), kev_due_date=kev)
    return {"sla_due_at": due, "sla_due_at_source": SLA_POLICY_SOURCE if due is not None else "unavailable", "kev_due_date": kev}


def carry_finding_sla(payload: Mapping[str, Any], previous: Mapping[str, Any]) -> dict[str, Any]:
    """Keep existing explicit or unattributed dates before ledger replacement."""
    merged = dict(payload)
    previous_due = previous.get("sla_due_at")
    previous_source = previous.get("sla_due_at_source")
    if previous_due is not None and previous_source != SLA_POLICY_SOURCE and merged.get("sla_due_at_source") != "explicit":
        merged["sla_due_at"] = previous_due
        merged["sla_due_at_source"] = "explicit" if previous_source == "explicit" else "unknown"
    return merged


def merge_finding_sla(payload: Mapping[str, Any], previous: Mapping[str, Any], *, first_seen: str) -> dict[str, Any]:
    """Carry current assignments and derive only from canonical first sighting."""
    merged = carry_finding_sla(payload, previous)
    # The built-in policy retains an earlier KEV target when a subsequent scan
    # omits the advisory enrichment. This is separate from a manual assignment.
    kevs = [value for row in (payload, previous) if (value := _parse_iso(finding_sla_fields(row).get("kev_due_date"))) is not None]
    if kevs:
        merged["kev_due_date"] = min(kevs).isoformat()
    merged["first_seen"] = first_seen
    merged.update(finding_sla_fields(merged))
    return merged


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
