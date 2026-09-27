"""Credential policy settings and clock adapter shared by graph and API callers."""

from __future__ import annotations

import os
from datetime import datetime, timezone
from typing import Any, Iterable

from agent_bom.core.credential_policy import (
    DEFAULT_NEAR_EXPIRY_DAYS,
    CredentialPolicy,
    classify_credential_record,
    credential_governance_summary,
)


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


def _configured_policy(near_days: int | None, rotation_days: int | None, hard_max_age_days: int | None) -> CredentialPolicy:
    return CredentialPolicy(
        near_days if near_days is not None else near_expiry_days(),
        rotation_days if rotation_days is not None else rotation_interval_days(),
        hard_max_age_days if hard_max_age_days is not None else max_age_days(),
    )


def classify_credential(
    record: dict[str, Any],
    *,
    near_days: int | None = None,
    rotation_days: int | None = None,
    hard_max_age_days: int | None = None,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Classify a reference record with per-call and lazily read environment defaults."""
    moment = now or datetime.now(timezone.utc)
    return classify_credential_record(
        record,
        policy=_configured_policy(near_days, rotation_days, hard_max_age_days),
        now=moment,
    )


def evaluate_credentials(
    records: Iterable[dict[str, Any]],
    *,
    near_days: int | None = None,
    rotation_days: int | None = None,
    hard_max_age_days: int | None = None,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Evaluate records using one clock instant and the existing per-record settings lifecycle."""
    moment = now or datetime.now(timezone.utc)
    classified = [
        classify_credential(
            record if isinstance(record, dict) else {},
            near_days=near_days,
            rotation_days=rotation_days,
            hard_max_age_days=hard_max_age_days,
            now=moment,
        )
        for record in records
    ]
    return credential_governance_summary(classified, policy=_configured_policy(near_days, rotation_days, hard_max_age_days))
