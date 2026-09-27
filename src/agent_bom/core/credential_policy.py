"""Pure credential expiry/rotation decisions with explicit time and policy inputs."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, NamedTuple

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


class CredentialPolicy(NamedTuple):
    """Resolved thresholds; adapters own configuration and clock access."""

    near_days: int = DEFAULT_NEAR_EXPIRY_DAYS
    rotation_days: int | None = None
    hard_max_age_days: int | None = None

    def as_dict(self) -> dict[str, int | None]:
        return {"near_expiry_days": self.near_days, "rotation_days": self.rotation_days, "max_age_days": self.hard_max_age_days}


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


def _credential_state(
    age_days: int | None, days_until_expiry: int | None, near: int, rotate: int | None, hard_max: int | None
) -> tuple[str, list[str]]:
    reasons: list[str] = []
    state = "unknown_age"

    # Hard expiry takes precedence: an expired credential is the strongest signal.
    if days_until_expiry is not None and days_until_expiry < 0:
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
    elif days_until_expiry is not None and days_until_expiry <= near:
        state = "near_expiry"
        reasons.append(f"expires in {days_until_expiry} day(s), within {near}d window")
    elif age_days is not None or days_until_expiry is not None:
        state = "ok"
        if days_until_expiry is not None:
            reasons.append(f"expires in {days_until_expiry} day(s)")
        elif age_days is not None:
            reasons.append(f"age {age_days}d within configured bounds")
    else:
        reasons.append("no rotation timestamp or expiry date available")

    return state, reasons


def classify_credential_record(record: dict[str, Any], *, policy: CredentialPolicy, now: datetime) -> dict[str, Any]:
    """Classify reference metadata without consulting clocks, settings or secrets."""
    rotation = record.get("rotation_days")
    max_age = record.get("max_age_days")
    rotate = rotation if isinstance(rotation, int) else policy.rotation_days
    hard_max = max_age if isinstance(max_age, int) else policy.hard_max_age_days
    cred_id = record.get("id") or record.get("identity_id")
    name = record.get("name") or (str(cred_id) if cred_id is not None else None)

    expires_at = _parse_timestamp(record.get("credential_expires_at"))
    last_rotated = _parse_timestamp(record.get("last_rotated") or record.get("last_rotated_at"))

    age_days = _days_between(last_rotated, now) if last_rotated is not None else None
    if age_days is not None and age_days < 0:
        # A rotation timestamp in the future is not a usable age signal.
        age_days = None

    days_until_expiry = _days_between(now, expires_at) if expires_at is not None else None

    state, reasons = _credential_state(age_days, days_until_expiry, policy.near_days, rotate, hard_max)

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
        "near_expiry_days": policy.near_days,
        "rotation_days": rotate,
        "max_age_days": hard_max,
        "reasons": reasons,
    }


def credential_governance_summary(classified: list[dict[str, Any]], *, policy: CredentialPolicy) -> dict[str, Any]:
    """Roll up classified reference records without mutating the supplied order."""
    classified = list(classified)
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
        "thresholds": policy.as_dict(),
        "credentials": classified,
        "action_required": action_required,
        "message": message,
    }
