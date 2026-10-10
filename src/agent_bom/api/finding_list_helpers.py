"""Sort, facet and grouping helpers for the findings list routes."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime, timezone
from typing import Any

from fastapi import HTTPException

from agent_bom.api.finding_list_projection import project_list_row
from agent_bom.finding_scope import FINDING_SEVERITY_FILTERS

_ALLOWED_FINDING_SORTS = ("effective_reach", "cvss", "severity")
# Lifecycle-status filter (default ``open`` = live posture). ``open`` maps to
# status IN (open, reopened) in the store; ``resolved`` to status = resolved;
# ``all`` applies no lifecycle predicate.
_ALLOWED_FINDING_STATUSES = ("open", "resolved", "all")
_DEFAULT_FINDING_STATUS = "open"
_ALLOWED_FINDING_SEVERITIES = FINDING_SEVERITY_FILTERS


def _normalize_finding_sort(sort: str) -> str:
    sort_key = sort.lower().strip() if isinstance(sort, str) else "effective_reach"
    if sort_key not in _ALLOWED_FINDING_SORTS:
        raise HTTPException(
            status_code=422,
            detail=f"invalid sort '{sort}'; accepted values: {', '.join(_ALLOWED_FINDING_SORTS)}",
        )
    return sort_key


_FRESHNESS_BUCKETS = ("last_24_hours", "last_7_days", "last_30_days", "older", "unavailable")


def _freshness_bucket(row: Mapping[str, Any], *, now: datetime | None = None) -> str:
    """Classify only an observed timestamp; missing/invalid evidence is unavailable."""
    raw = row.get("last_observed") or row.get("last_seen")
    if not isinstance(raw, str) or not raw.strip():
        return "unavailable"
    try:
        observed = datetime.fromisoformat(raw.strip().replace("Z", "+00:00"))
    except ValueError:
        return "unavailable"
    if observed.tzinfo is None:
        observed = observed.replace(tzinfo=timezone.utc)
    current = now or datetime.now(timezone.utc)
    age_seconds = max(0.0, (current.astimezone(timezone.utc) - observed.astimezone(timezone.utc)).total_seconds())
    if age_seconds <= 24 * 60 * 60:
        return "last_24_hours"
    if age_seconds <= 7 * 24 * 60 * 60:
        return "last_7_days"
    if age_seconds <= 30 * 24 * 60 * 60:
        return "last_30_days"
    return "older"


def _normalize_facet_severity(raw: Any) -> str:
    """Fold a stored severity string into the facet histogram's bands."""
    value = str(raw or "unknown").strip().lower()
    if value == "informational":
        value = "info"
    if value not in ("critical", "high", "medium", "low", "info", "unknown"):
        value = "unknown"
    return value


# Scope keys that live in the finding payload (or are computed from it) and so
# cannot be expressed as a predicate on the current-state table's materialised
# columns. Their presence disables the severity aggregate below.
_FACET_PAYLOAD_SCOPE_KEYS = ("provider", "account_ref", "environment", "domain", "finding_class", "q")

# Bands whose filter value equals the persisted string exactly, so the store's
# ``LOWER(severity) = %s`` predicate selects the same rows the Python walk keeps.
# ``info`` is excluded because it also folds the persisted ``informational``
# alias, and ``unknown`` because it also absorbs blank/unrecognised severities —
# for those two the store predicate is narrower than the walk, so pushing them
# down would silently drop rows.
_FACET_LITERAL_SEVERITY_BANDS = frozenset({"critical", "high", "medium", "low"})


_FINDING_GROUP_MAX_OCCURRENCES = 50_000
_FINDING_GROUP_OCCURRENCE_SAMPLE = 25


def _finding_occurrence_summary(row: dict[str, Any]) -> dict[str, Any]:
    """Project the bounded fields needed to expand a grouped issue row."""
    return {
        key: row.get(key)
        for key in (
            "finding_id",
            "occurrence_id",
            "canonical_id",
            "asset",
            "severity",
            "package_version",
            "scan_id",
            "status",
            "owner",
            "sla_due_at",
            "sla_due_at_source",
            "last_seen",
            "last_observed",
            "observation_status",
            "reconfirmation",
            "graph_reachable",
            "graph_min_hop_distance",
        )
        if row.get(key) is not None
    }


def _serialize_finding_group(group: dict[str, Any]) -> dict[str, Any]:
    """Sanitize one selected group and its bounded occurrence sample.

    Grouping may inspect tens of thousands of canonical rows, but only the
    selected page crosses the API boundary. Raw rows stay private until this
    point so response redaction runs once for data the caller can receive.
    """
    from agent_bom.finding_scope import safe_finding_response_payload

    public = safe_finding_response_payload(project_list_row(group))
    public["finding_group_id"] = str(group.get("finding_group_id") or "")
    public["finding_group_key"] = str(group.get("finding_group_key") or "")
    public["occurrence_count"] = int(group.get("occurrence_count") or 0)
    public["unreconfirmed_occurrence_count"] = int(group.get("unreconfirmed_occurrence_count") or 0)
    public["occurrences_truncated"] = bool(group.get("occurrences_truncated"))
    samples = group.get("_occurrence_rows")
    public["occurrences"] = [
        _finding_occurrence_summary(safe_finding_response_payload(row))
        for row in (samples if isinstance(samples, list) else [])
        if isinstance(row, dict)
    ]
    return public
