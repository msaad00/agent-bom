"""Control-plane credential collection and compatibility exports of shared policy.

Classification lives in the pure core; the identity adapter resolves settings
and time. This API adapter combines control-plane and discovered reference records.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Iterable

from agent_bom.core.credential_policy import _BLOCKING_STATES as _BLOCKING_STATES
from agent_bom.core.credential_policy import _STATE_PRIORITY as _STATE_PRIORITY
from agent_bom.core.credential_policy import _WARNING_STATES as _WARNING_STATES
from agent_bom.core.credential_policy import DEFAULT_NEAR_EXPIRY_DAYS as DEFAULT_NEAR_EXPIRY_DAYS
from agent_bom.core.credential_policy import _days_between as _days_between
from agent_bom.core.credential_policy import _parse_timestamp as _parse_timestamp
from agent_bom.identity.credential_policy import _env_int as _env_int
from agent_bom.identity.credential_policy import classify_credential as classify_credential
from agent_bom.identity.credential_policy import evaluate_credentials as evaluate_credentials
from agent_bom.identity.credential_policy import max_age_days as max_age_days
from agent_bom.identity.credential_policy import near_expiry_days as near_expiry_days
from agent_bom.identity.credential_policy import rotation_interval_days as rotation_interval_days


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
