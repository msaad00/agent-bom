"""Opt-in policy boundary for a small operator-run managed trial.

The OSS control plane remains self-hosted by default. Setting
``AGENT_BOM_MANAGED_TRIAL_MODE=1`` enables a deliberately narrow envelope for
an operator-run evaluation environment; it never activates itself implicitly.
"""

from __future__ import annotations

import os
from typing import Final, Protocol

from fastapi import HTTPException

from agent_bom.api.connection_store import INVENTORY_SCOPE_ACCOUNT, SCAN_MODE_FULL

_TRUTHY: Final = frozenset({"1", "true", "yes", "on"})

MANAGED_TRIAL_MAX_REGIONS: Final = 5
MANAGED_TRIAL_PROVIDERS: Final[tuple[str, ...]] = ("aws",)
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

_MANAGED_TRIAL_AUTH_ROUTES: Final[frozenset[tuple[str, str]]] = frozenset(
    {
        ("GET", "/v1/auth/me"),
        ("POST", "/v1/auth/session"),
        ("DELETE", "/v1/auth/session"),
        ("GET", "/v1/auth/oidc/login"),
        ("GET", "/v1/auth/oidc/callback"),
        ("POST", "/v1/auth/trial/oidc/start"),
        ("POST", "/v1/auth/trial/oidc/start-form"),
        ("POST", "/v1/auth/trial-invitations"),
    }
)
_CONNECTIONS_PATH: Final = "/v1/cloud/connections"
_GRAPH_PATH: Final = "/v1/graph"


class StoredConnection(Protocol):
    """Minimum persisted connection shape needed by request and worker gates."""

    provider: str
    regions: list[str]
    inventory_scope: str
    scan_mode: str
    scan_interval_minutes: int | None


def managed_trial_enabled() -> bool:
    """Return whether the operator explicitly enabled managed-trial policy."""

    return os.environ.get("AGENT_BOM_MANAGED_TRIAL_MODE", "").strip().lower() in _TRUTHY


def managed_trial_envelope() -> dict[str, object] | None:
    """Return the active managed-trial product boundary for UI clients.

    The API is the source of truth for both route enforcement and presentation.
    Returning ``None`` outside trial mode prevents self-hosted clients from
    mistaking trial defaults for deployment-wide limits.
    """

    if not managed_trial_enabled():
        return None
    return {
        "providers": list(MANAGED_TRIAL_PROVIDERS),
        "inventory_scope": INVENTORY_SCOPE_ACCOUNT,
        "max_regions": MANAGED_TRIAL_MAX_REGIONS,
        **MANAGED_TRIAL_QUOTA_CAPS,
        "auto_scan_on_create": False,
        "schedules": False,
        "continuous_scans": False,
    }


def managed_trial_route_allowed(method: str, path: str) -> bool:
    """Return whether an API route belongs to the managed-trial surface.

    This is intentionally a pure allowlist independent of principal type. The
    authentication middleware applies it before resolving API keys, OIDC
    bearers, or browser sessions, so no broader role can reopen a denied route.
    Non-API paths remain governed by the normal dashboard/static/health rules.
    """

    normalized_method = method.upper()
    if normalized_method == "HEAD":
        normalized_method = "GET"
    if normalized_method == "OPTIONS":
        return True
    if not (path == "/v1" or path.startswith("/v1/") or path == "/scim" or path.startswith("/scim/")):
        return True
    if (normalized_method, path) in _MANAGED_TRIAL_AUTH_ROUTES:
        return True
    if path.startswith("/v1/auth/trial-tenants/"):
        return normalized_method in {"GET", "POST"}
    if normalized_method == "GET" and (path == _GRAPH_PATH or path.startswith(f"{_GRAPH_PATH}/")):
        return True
    if normalized_method == "POST" and path in {"/v1/graph/query", "/v1/graph/should-i-deploy"}:
        return True
    if normalized_method == "GET" and path == "/v1/findings":
        return True
    if path == _CONNECTIONS_PATH:
        return normalized_method in {"GET", "POST"}
    if path.startswith(f"{_CONNECTIONS_PATH}/"):
        suffix = path.removeprefix(f"{_CONNECTIONS_PATH}/")
        parts = suffix.split("/")
        if normalized_method == "GET":
            return len(parts) == 1 and bool(parts[0])
        return normalized_method == "POST" and len(parts) == 2 and bool(parts[0]) and parts[1] in {"test", "scan"}
    return False


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


def enforce_stored_connection_envelope(record: StoredConnection) -> None:
    """Revalidate persisted settings before test, enqueue, or worker execution.

    Stored rows can predate managed-trial mode or be changed by an operator.
    Callers must therefore validate the current row at every execution boundary
    instead of assuming the create-time contract is still true.
    """

    if not managed_trial_enabled():
        return
    enforce_connection_envelope(
        provider=str(record.provider or "").strip().lower(),
        regions=[str(region).strip().lower() for region in record.regions],
        inventory_scope=str(record.inventory_scope or "").strip().lower(),
        scan_mode=str(record.scan_mode or "").strip().lower(),
        scan_interval_minutes=record.scan_interval_minutes,
    )


def require_managed_trial_feature(feature: str) -> None:
    """Deny a feature that is outside the managed-trial product envelope."""

    if managed_trial_enabled():
        raise HTTPException(status_code=403, detail=f"{feature} is disabled in managed trial mode.")
