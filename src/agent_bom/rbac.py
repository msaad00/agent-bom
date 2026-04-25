"""Role-Based Access Control (RBAC) for enterprise deployments.

Provides lightweight role enforcement for multi-user API access:

Roles:
    admin    — Full access: scan, configure, manage fleet, policies, exceptions
    analyst  — Read + scan: run scans, view results, create exceptions (not approve)
    viewer   — Read-only: view results, posture, compliance (no scans or mutations)

Authentication is established by the API middleware (API key, OIDC, SAML,
browser session, SCIM, or attested trusted proxy headers). RBAC consumes the
authenticated role placed on ``request.state`` and must not trust raw client
headers directly.
"""

from __future__ import annotations

import hmac
import logging
import os
import threading
from dataclasses import dataclass
from enum import Enum
from typing import Callable

from fastapi import HTTPException, Request

logger = logging.getLogger(__name__)


class Role(str, Enum):
    ADMIN = "admin"
    ANALYST = "analyst"
    VIEWER = "viewer"


# Permission matrix — which roles can perform which action categories
_PERMISSIONS: dict[str, set[Role]] = {
    "scan": {Role.ADMIN, Role.ANALYST},
    "read": {Role.ADMIN, Role.ANALYST, Role.VIEWER},
    "fleet_write": {Role.ADMIN},
    "fleet_read": {Role.ADMIN, Role.ANALYST, Role.VIEWER},
    "policy_write": {Role.ADMIN},
    "policy_read": {Role.ADMIN, Role.ANALYST, Role.VIEWER},
    "exception_create": {Role.ADMIN, Role.ANALYST},
    "exception_approve": {Role.ADMIN},
    "exception_read": {Role.ADMIN, Role.ANALYST, Role.VIEWER},
    "alert_write": {Role.ADMIN},
    "alert_read": {Role.ADMIN, Role.ANALYST, Role.VIEWER},
    "audit_read": {Role.ADMIN, Role.ANALYST, Role.VIEWER},
    "sla_write": {Role.ADMIN},
    "sla_read": {Role.ADMIN, Role.ANALYST, Role.VIEWER},
    "config": {Role.ADMIN},
}


@dataclass(frozen=True)
class CapabilityDefinition:
    id: str
    label: str
    description: str
    minimum_role: Role


_ROLE_HIERARCHY: dict[Role, int] = {
    Role.ADMIN: 3,
    Role.ANALYST: 2,
    Role.VIEWER: 1,
}

_ROLE_DISPLAY_NAMES: dict[Role, str] = {
    Role.ADMIN: "Admin",
    Role.ANALYST: "Contributor",
    Role.VIEWER: "Viewer",
}

_ROLE_UI_NAMES: dict[Role, str] = {
    Role.ADMIN: "admin",
    Role.ANALYST: "contributor",
    Role.VIEWER: "viewer",
}

_ROLE_DESCRIPTIONS: dict[Role, str] = {
    Role.ADMIN: "Full control-plane administration, protected writes, and tenant-scoped key/policy/fleet management.",
    Role.ANALYST: "Contributor-level operator access for scans, source management, runtime ingest, and exception workflows.",
    Role.VIEWER: "Read-only operator access to inventory, findings, graph, remediation, audit, and posture surfaces.",
}

_CAPABILITY_DEFINITIONS: tuple[CapabilityDefinition, ...] = (
    CapabilityDefinition(
        id="inventory.read",
        label="View inventory, findings, graph, and audit",
        description="See agents, fleet, findings, posture, compliance, graph, governance, and audit state.",
        minimum_role=Role.VIEWER,
    ),
    CapabilityDefinition(
        id="scan.run",
        label="Run scans and imports",
        description="Start scans, compare baselines, and push approved result or trace data into the control plane.",
        minimum_role=Role.ANALYST,
    ),
    CapabilityDefinition(
        id="sources.manage",
        label="Manage sources and schedules",
        description="Create, run, test, update, and schedule control-plane sources and collection jobs.",
        minimum_role=Role.ANALYST,
    ),
    CapabilityDefinition(
        id="exceptions.manage",
        label="Create and manage exception workflows",
        description="Create false-positive and exception records and drive remediation-related control-plane actions.",
        minimum_role=Role.ANALYST,
    ),
    CapabilityDefinition(
        id="runtime.ingest",
        label="Push runtime evidence and evaluate policy",
        description="Push traces, runtime events, proxy audit, OCSF, and gateway evaluations into the tenant control plane.",
        minimum_role=Role.ANALYST,
    ),
    CapabilityDefinition(
        id="keys.manage",
        label="Manage API keys and auth policy",
        description="Create, rotate, and revoke service keys and review auth/runtime policy configuration.",
        minimum_role=Role.ADMIN,
    ),
    CapabilityDefinition(
        id="fleet.manage",
        label="Manage fleet writes and sync operations",
        description="Run fleet sync and perform protected fleet mutations that affect tenant inventory state.",
        minimum_role=Role.ADMIN,
    ),
    CapabilityDefinition(
        id="policy.manage",
        label="Manage protected policy and break-glass actions",
        description="Change gateway policy, SIEM tests, shield state, and other protected control-plane administration.",
        minimum_role=Role.ADMIN,
    ),
)

_ROLE_ACCESS_SUMMARY: dict[Role, dict[str, list[str]]] = {
    Role.ADMIN: {
        "can_see": [
            "All tenant inventory, findings, graph, fleet, runtime, and audit surfaces",
            "Auth policy, API key lifecycle, and protected admin controls",
        ],
        "can_do": [
            "Run scans, manage sources and schedules, and push runtime evidence",
            "Manage API keys, gateway policy, fleet sync, and other protected control-plane writes",
        ],
        "cannot_do": [],
    },
    Role.ANALYST: {
        "can_see": [
            "Inventory, findings, fleet, graph, remediation, audit, and governance surfaces",
            "Source registry and schedule state for the active tenant",
        ],
        "can_do": [
            "Run scans, manage sources and schedules, and create exception workflows",
            "Push runtime evidence and evaluate policy within the active tenant",
        ],
        "cannot_do": [
            "Create, rotate, or revoke API keys",
            "Change protected admin policy, fleet writes, or break-glass state",
        ],
    },
    Role.VIEWER: {
        "can_see": [
            "Read-only inventory, findings, fleet, graph, remediation, governance, posture, and audit surfaces",
        ],
        "can_do": [],
        "cannot_do": [
            "Run scans or schedule collection jobs",
            "Create or update sources, exceptions, keys, policy, or fleet state",
        ],
    },
}

# API key → role mapping (loaded from env or config)
_api_key_roles: dict[str, Role] = {}
_lock = threading.Lock()


def configure_api_keys(key_map: dict[str, str]) -> None:
    """Set API key to role mappings.

    Args:
        key_map: Dict of {api_key: role_name}
    """
    with _lock:
        _api_key_roles.clear()
        for key, role_name in key_map.items():
            try:
                _api_key_roles[key] = Role(role_name)
            except ValueError:
                logger.warning("Invalid role %r for API key, skipping", role_name)


def load_api_keys_from_env() -> None:
    """Load API keys from AGENT_BOM_API_KEYS env var.

    Format: key1:admin,key2:analyst,key3:viewer
    """
    raw = os.environ.get("AGENT_BOM_API_KEYS", "")
    if not raw:
        return
    key_map = {}
    for pair in raw.split(","):
        pair = pair.strip()
        if ":" in pair:
            key, role = pair.split(":", 1)
            key_map[key.strip()] = role.strip()
    configure_api_keys(key_map)


def resolve_role(api_key: str | None = None, role_header: str | None = None) -> Role:
    """Resolve the effective role from API key or header.

    Priority:
        1. API key lookup (if AGENT_BOM_API_KEYS configured)
        2. Default role from AGENT_BOM_DEFAULT_ROLE env var
    """
    # API key takes priority
    if api_key:
        with _lock:
            role = _api_key_roles.get(api_key)
        if role:
            return role

    if role_header:
        logger.warning("Ignoring unauthenticated X-Agent-Bom-Role header outside API middleware attestation")

    # Default role — least privilege (viewer) unless explicitly overridden
    default = os.environ.get("AGENT_BOM_DEFAULT_ROLE", "viewer")
    try:
        return Role(default)
    except ValueError:
        return Role.VIEWER


def check_permission(role: Role, action: str) -> bool:
    """Check if a role has permission for an action.

    Args:
        role: The user's role.
        action: Action category (e.g., 'scan', 'fleet_write').

    Returns:
        True if permitted.
    """
    allowed = _PERMISSIONS.get(action)
    if allowed is None:
        logger.warning("Unknown action %r — denying by default", action)
        return False
    return role in allowed


def role_rank(role: Role) -> int:
    """Return the numeric rank for a role."""
    return _ROLE_HIERARCHY.get(role, 0)


def normalize_role(value: Role | str | None) -> Role | None:
    """Normalize a role-like value into a Role enum when possible."""
    if value is None:
        return None
    if isinstance(value, Role):
        return value
    try:
        return Role(str(value).lower())
    except ValueError:
        return None


def summarize_role(value: Role | str | None) -> dict | None:
    """Return UI-facing role, capability, and access summary data."""
    role = normalize_role(value)
    if role is None:
        return None

    allowed_capabilities = [cap.id for cap in _CAPABILITY_DEFINITIONS if role_rank(role) >= role_rank(cap.minimum_role)]
    capability_matrix = [
        {
            "id": cap.id,
            "label": cap.label,
            "description": cap.description,
            "minimum_role": cap.minimum_role.value,
            "minimum_role_label": _ROLE_DISPLAY_NAMES[cap.minimum_role],
            "allowed": role_rank(role) >= role_rank(cap.minimum_role),
        }
        for cap in _CAPABILITY_DEFINITIONS
    ]
    summary = _ROLE_ACCESS_SUMMARY[role]
    return {
        "role": role.value,
        "ui_role": _ROLE_UI_NAMES[role],
        "display_name": _ROLE_DISPLAY_NAMES[role],
        "description": _ROLE_DESCRIPTIONS[role],
        "capabilities": allowed_capabilities,
        "capability_matrix": capability_matrix,
        "can_see": summary["can_see"],
        "can_do": summary["can_do"],
        "cannot_do": summary["cannot_do"],
    }


def require_permission(action: str) -> Callable:
    """FastAPI dependency factory for RBAC enforcement.

    Usage in endpoints:
        @app.get("/v1/fleet", dependencies=[Depends(require_permission("fleet_read"))])
    """
    from fastapi import Depends, Header, HTTPException

    async def _check(
        request: Request,
        x_api_key: str | None = Header(None, alias="X-Api-Key"),
    ) -> Role:
        state_role = getattr(request.state, "api_key_role", None)
        if state_role:
            try:
                role = Role(str(state_role).lower())
            except ValueError as exc:
                raise HTTPException(status_code=403, detail=f"Invalid authenticated role '{state_role}'") from exc
        else:
            role = resolve_role(api_key=x_api_key)
        if not check_permission(role, action):
            raise HTTPException(
                status_code=403,
                detail=f"Role '{role.value}' does not have '{action}' permission",
            )
        return role

    return Depends(_check)


def require_authenticated_permission(action: str) -> Callable:
    """FastAPI dependency that requires authenticated enterprise access.

    Unlike ``require_permission()``, this helper does not silently fall back to
    the default viewer role for unauthenticated requests. It accepts either:

    - a request already authenticated by APIKeyMiddleware / OIDC / SAML, or
    - a trusted reverse proxy injecting ``X-Agent-Bom-Role`` plus
      ``X-Agent-Bom-Tenant-ID``.
    """
    from fastapi import Depends, Header, HTTPException

    async def _check(
        request: Request,
        x_role: str | None = Header(None, alias="X-Agent-Bom-Role"),
        x_tenant_id: str | None = Header(None, alias="X-Agent-Bom-Tenant-ID"),
        x_proxy_secret: str | None = Header(None, alias="X-Agent-Bom-Proxy-Secret"),
    ) -> Role:
        state_role = getattr(request.state, "api_key_role", None)
        if state_role:
            try:
                role = Role(str(state_role).lower())
            except ValueError as exc:
                raise HTTPException(status_code=403, detail=f"Invalid authenticated role '{state_role}'") from exc
            if not getattr(request.state, "tenant_id", None):
                request.state.tenant_id = "default"
            return _authorize(role, action)

        trusted_proxy_enabled = os.environ.get("AGENT_BOM_TRUST_PROXY_AUTH", "").strip().lower() in {
            "1",
            "true",
            "yes",
            "on",
        }
        proxy_secret = os.environ.get("AGENT_BOM_TRUST_PROXY_AUTH_SECRET", "").strip()
        if x_role and trusted_proxy_enabled and proxy_secret and hmac.compare_digest(x_proxy_secret or "", proxy_secret):
            try:
                role = Role(x_role.lower())
            except ValueError as exc:
                raise HTTPException(status_code=403, detail=f"Invalid proxy role '{x_role}'") from exc
            if not x_tenant_id:
                raise HTTPException(
                    status_code=401,
                    detail="Authentication required — trusted proxy requests must include X-Agent-Bom-Tenant-ID",
                )
            request.state.api_key_role = role.value
            request.state.tenant_id = x_tenant_id
            request.state.api_key_name = getattr(request.state, "api_key_name", None) or "proxy-header"
            request.state.auth_method = getattr(request.state, "auth_method", None) or "proxy_header"
            request.state.proxy_auth_attested = True
            return _authorize(role, action)

        raise HTTPException(
            status_code=401,
            detail=(
                "Authentication required — provide an authenticated API key, browser session, "
                "OIDC/SAML token, or attested trusted proxy identity"
            ),
        )

    return Depends(_check)


def _authorize(role: Role, action: str) -> Role:
    """Validate that a resolved role can perform an action."""
    if not check_permission(role, action):
        raise HTTPException(
            status_code=403,
            detail=f"Role '{role.value}' does not have '{action}' permission",
        )
    return role
