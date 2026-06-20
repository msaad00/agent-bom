"""Credential expiry / rotation governance for control-plane and discovered NHIs.

The secret *posture* surface in ``secret_lifecycle`` answers "is this
control-plane secret configured and is it past its rotation interval?". That
covers operator-mounted secrets, but it does not classify credentials that carry
an explicit ``credential_expires_at`` (for example service-account client
secrets and API tokens surfaced by non-human-identity discovery).

This module ties the two together into a single expiry/rotation governance
verdict. It is **reference-only**: it consumes ages, rotation timestamps, and
expiry timestamps and never touches secret values. NHI discovery records are
passed in by the caller as plain dicts so this module never imports the
discovery connectors (which live in separate, unmerged work).

Classification states (worst-first priority):

* ``overdue``       — past a hard expiry AND/or beyond the configured max age.
* ``expired``       — ``credential_expires_at`` is in the past.
* ``rotation_due``  — age has reached the configured rotation interval.
* ``near_expiry``   — within the near-expiry window of ``credential_expires_at``.
* ``unknown_age``   — configured/known to exist but no usable rotation/expiry date.
* ``ok``            — has a usable date and is comfortably within bounds.
"""

from __future__ import annotations

import os
from datetime import datetime, timezone
from typing import Any, Iterable

DEFAULT_NEAR_EXPIRY_DAYS = 14

# State ordering used to surface the most urgent credentials first and to roll a
# collection up into a single posture verdict.
_STATE_PRIORITY: dict[str, int] = {
    "overdue": 0,
    "expired": 1,
    "rotation_due": 2,
    "near_expiry": 3,
    "unknown_age": 4,
    "ok": 9,
}

# States that should block / draw operator attention.
_BLOCKING_STATES = frozenset({"overdue", "expired"})
_WARNING_STATES = frozenset({"rotation_due", "near_expiry", "unknown_age"})


def _env_int(name: str, default: int | None = None) -> int | None:
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    try:
        parsed = int(raw)
    except ValueError:
        return default
    return parsed if parsed >= 0 else default


def near_expiry_days() -> int:
    """Configured near-expiry warning window in days (default 14)."""
    value = _env_int("AGENT_BOM_CRED_NEAR_EXPIRY_DAYS", DEFAULT_NEAR_EXPIRY_DAYS)
    return value if value is not None else DEFAULT_NEAR_EXPIRY_DAYS


def max_age_days() -> int | None:
    """Configured hard maximum credential age in days, or ``None`` if unset."""
    return _env_int("AGENT_BOM_CRED_MAX_AGE_DAYS")


def rotation_interval_days() -> int | None:
    """Configured rotation interval in days, or ``None`` if unset."""
    return _env_int("AGENT_BOM_CRED_ROTATION_DAYS")


def _parse_timestamp(raw: Any) -> datetime | None:
    if not isinstance(raw, str):
        return None
    text = raw.strip()
    if not text:
        return None
    # Tolerate the trailing-Z form some IdPs emit.
    if text.endswith("Z"):
        text = f"{text[:-1]}+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def _days_between(earlier: datetime, later: datetime) -> int:
    return int((later - earlier).total_seconds() // 86400)


def classify_credential(
    record: dict[str, Any],
    *,
    near_days: int | None = None,
    rotation_days: int | None = None,
    hard_max_age_days: int | None = None,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Classify one credential record into an expiry/rotation state.

    ``record`` is a generic mapping. Recognized keys: ``id``, ``name``,
    ``credential_expires_at`` (ISO-8601), ``last_rotated`` (ISO-8601). Unknown
    keys are ignored so discovered-NHI dicts can be passed through unchanged.

    Thresholds default to the env-configured values but can be overridden per
    call (used by control-plane callers that already track per-secret limits).
    """
    now = now or datetime.now(timezone.utc)
    near = near_days if near_days is not None else near_expiry_days()
    # Per-record limits (e.g. a control-plane secret's own rotation window) take
    # precedence over the call/env defaults so each credential is judged against
    # the policy that actually governs it.
    record_rotation = record.get("rotation_days")
    record_max_age = record.get("max_age_days")
    rotate = (
        record_rotation if isinstance(record_rotation, int) else (rotation_days if rotation_days is not None else rotation_interval_days())
    )
    hard_max = (
        record_max_age if isinstance(record_max_age, int) else (hard_max_age_days if hard_max_age_days is not None else max_age_days())
    )

    cred_id = record.get("id") or record.get("identity_id")
    name = record.get("name") or (str(cred_id) if cred_id is not None else None)

    expires_at = _parse_timestamp(record.get("credential_expires_at"))
    last_rotated = _parse_timestamp(record.get("last_rotated") or record.get("last_rotated_at"))

    age_days = _days_between(last_rotated, now) if last_rotated is not None else None
    if age_days is not None and age_days < 0:
        # A rotation timestamp in the future is not a usable age signal.
        age_days = None

    days_until_expiry = _days_between(now, expires_at) if expires_at is not None else None

    reasons: list[str] = []
    state = "unknown_age"

    # Hard expiry takes precedence: an expired credential is the strongest signal.
    if expires_at is not None and days_until_expiry is not None and days_until_expiry < 0:
        state = "expired"
        reasons.append(f"credential expired {abs(days_until_expiry)} day(s) ago")

    # Max-age breach (overdue) overrides expired only insofar as it is reported as
    # the worst class; we keep both reasons but escalate the state.
    if hard_max is not None and age_days is not None and age_days >= hard_max:
        state = "overdue"
        reasons.append(f"age {age_days}d exceeds max age {hard_max}d")

    if state in {"expired", "overdue"}:
        pass
    elif rotate is not None and age_days is not None and age_days >= rotate:
        state = "rotation_due"
        reasons.append(f"age {age_days}d past rotation interval {rotate}d")
    elif expires_at is not None and days_until_expiry is not None and days_until_expiry <= near:
        state = "near_expiry"
        reasons.append(f"expires in {days_until_expiry} day(s), within {near}d window")
    elif age_days is not None or expires_at is not None:
        state = "ok"
        if days_until_expiry is not None:
            reasons.append(f"expires in {days_until_expiry} day(s)")
        elif age_days is not None:
            reasons.append(f"age {age_days}d within configured bounds")
    else:
        reasons.append("no rotation timestamp or expiry date available")

    return {
        "id": str(cred_id) if cred_id is not None else None,
        "name": name,
        "provider": record.get("provider"),
        "identity_type": record.get("identity_type"),
        "state": state,
        "priority": _STATE_PRIORITY.get(state, 5),
        "blocking": state in _BLOCKING_STATES,
        "age_days": age_days,
        "days_until_expiry": days_until_expiry,
        "credential_expires_at": expires_at.isoformat() if expires_at else None,
        "last_rotated": last_rotated.isoformat() if last_rotated else None,
        "near_expiry_days": near,
        "rotation_days": rotate,
        "max_age_days": hard_max,
        "reasons": reasons,
    }


def evaluate_credentials(
    records: Iterable[dict[str, Any]],
    *,
    near_days: int | None = None,
    rotation_days: int | None = None,
    hard_max_age_days: int | None = None,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Classify a collection of credential records into a governance report.

    Returns a non-secret report with per-credential classifications, the worst
    rolled-up state, and grouped blocker/warning id lists. Never raises on
    empty input or missing/invalid dates.
    """
    now = now or datetime.now(timezone.utc)
    classified = [
        classify_credential(
            record if isinstance(record, dict) else {},
            near_days=near_days,
            rotation_days=rotation_days,
            hard_max_age_days=hard_max_age_days,
            now=now,
        )
        for record in records
    ]
    classified.sort(key=lambda item: (int(item["priority"]), str(item.get("name") or "")))

    counts: dict[str, int] = {state: 0 for state in _STATE_PRIORITY}
    for item in classified:
        counts[item["state"]] = counts.get(item["state"], 0) + 1

    blockers = [item["name"] or item["id"] for item in classified if item["state"] in _BLOCKING_STATES]
    warnings = [item["name"] or item["id"] for item in classified if item["state"] in _WARNING_STATES]
    action_required = [item for item in classified if item["state"] in _BLOCKING_STATES | _WARNING_STATES]

    if blockers:
        status = "blocked"
        message = "One or more credentials are expired or past their maximum age."
    elif warnings:
        status = "attention_required"
        message = "One or more credentials are nearing expiry, due for rotation, or have an unknown age."
    else:
        status = "ok"
        message = "All evaluated credentials are within rotation and expiry bounds."

    return {
        "status": status,
        "secret_values_included": False,
        "evaluated": len(classified),
        "counts": counts,
        "blockers": blockers,
        "warnings": warnings,
        "thresholds": {
            "near_expiry_days": near_days if near_days is not None else near_expiry_days(),
            "rotation_days": rotation_days if rotation_days is not None else rotation_interval_days(),
            "max_age_days": hard_max_age_days if hard_max_age_days is not None else max_age_days(),
        },
        "credentials": classified,
        "action_required": action_required,
        "message": message,
    }


def _control_plane_records(posture: dict[str, Any]) -> list[dict[str, Any]]:
    """Project configured control-plane secrets into expiry-evaluator records.

    Control-plane secrets carry ``last_rotated`` (age) rather than an explicit
    ``credential_expires_at``, so they exercise the rotation-interval/max-age
    branches of the classifier alongside discovered NHIs that carry expiry.
    """
    secrets = posture.get("secrets")
    if not isinstance(secrets, dict):
        return []
    records: list[dict[str, Any]] = []
    for name, value in secrets.items():
        if not isinstance(value, dict):
            continue
        if not value.get("configured"):
            continue
        records.append(
            {
                "id": name,
                "name": name,
                "provider": "control_plane",
                "identity_type": "secret",
                "last_rotated": value.get("last_rotated"),
                "rotation_days": value.get("rotation_days"),
                "max_age_days": value.get("max_age_days"),
            }
        )
    return records


def describe_credential_expiry_posture(
    discovered_credentials: Iterable[dict[str, Any]] | None = None,
    *,
    include_control_plane: bool = True,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Return the consolidated, non-secret credential-expiry governance posture.

    Combines configured control-plane secrets (age-based) with any caller-passed
    discovered-NHI credential records (expiry-based) into one verdict. Callers
    that have discovered NHIs pass them in as ``{id, name, credential_expires_at,
    last_rotated}`` dicts; this module never imports the discovery connectors.
    """
    records: list[dict[str, Any]] = []
    if include_control_plane:
        from agent_bom.api.secret_lifecycle import describe_secret_lifecycle_posture

        records.extend(_control_plane_records(describe_secret_lifecycle_posture()))

    if discovered_credentials:
        records.extend(record for record in discovered_credentials if isinstance(record, dict))

    report = evaluate_credentials(records, now=now)
    report["generated_from"] = "/v1/auth/secrets/credential-expiry"
    report["control_plane_included"] = include_control_plane
    report["discovered_credential_count"] = sum(1 for record in (discovered_credentials or []) if isinstance(record, dict))
    return report
