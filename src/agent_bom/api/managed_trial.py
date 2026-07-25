"""Opt-in policy boundary for a small operator-run managed trial.

The OSS control plane remains self-hosted by default. Setting
``AGENT_BOM_MANAGED_TRIAL_MODE=1`` enables a deliberately narrow envelope for
an operator-run evaluation environment; it never activates itself implicitly.
"""

from __future__ import annotations

import os
from typing import Final

from fastapi import HTTPException

from agent_bom.api.connection_store import INVENTORY_SCOPE_ACCOUNT, SCAN_MODE_FULL

_TRUTHY: Final = frozenset({"1", "true", "yes", "on"})

MANAGED_TRIAL_MAX_REGIONS: Final = 5
MANAGED_TRIAL_QUOTA_CAPS: Final[dict[str, int]] = {
    "active_scan_jobs": 1,
    "retained_scan_jobs": 20,
    "cloud_connections": 2,
    "cloud_connections_per_provider": 2,
    "scan_credits_24h": 8,
}

# Intended for the invitation/session layer. These scopes add fine-grained
# ceilings without changing the long-standing self-hosted role contract.
MANAGED_TRIAL_ANALYST_SCOPES: Final[tuple[str, ...]] = (
    "cloud.connection:read",
    "cloud.connection:write",
    "finding:read",
    "graph:read",
)


def managed_trial_enabled() -> bool:
    """Return whether the operator explicitly enabled managed-trial policy."""

    return os.environ.get("AGENT_BOM_MANAGED_TRIAL_MODE", "").strip().lower() in _TRUTHY


def enforce_connection_envelope(
    *,
    provider: str,
    regions: list[str],
    inventory_scope: str,
    scan_mode: str,
    scan_interval_minutes: int | None,
) -> None:
    """Reject connection settings outside the managed-trial blast radius."""

    if not managed_trial_enabled():
        return
    if provider != "aws":
        raise HTTPException(status_code=403, detail="Managed trial connections are limited to AWS.")
    if inventory_scope != INVENTORY_SCOPE_ACCOUNT:
        raise HTTPException(status_code=403, detail="Managed trial connections are limited to account scope.")
    if scan_mode != SCAN_MODE_FULL:
        raise HTTPException(status_code=403, detail="Continuous connection scanning is disabled in managed trial mode.")
    if scan_interval_minutes is not None:
        raise HTTPException(status_code=403, detail="Connection schedules are disabled in managed trial mode.")
    if not regions or "all" in regions:
        raise HTTPException(status_code=403, detail="Managed trial connections require explicitly selected AWS regions.")
    if len(regions) > MANAGED_TRIAL_MAX_REGIONS:
        raise HTTPException(
            status_code=403,
            detail=f"Managed trial connections allow at most {MANAGED_TRIAL_MAX_REGIONS} AWS regions.",
        )


def require_managed_trial_feature(feature: str) -> None:
    """Deny a feature that is outside the managed-trial product envelope."""

    if managed_trial_enabled():
        raise HTTPException(status_code=403, detail=f"{feature} is disabled in managed trial mode.")
