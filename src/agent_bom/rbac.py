"""Role-Based Access Control (RBAC) for enterprise deployments.

Provides lightweight role enforcement for multi-user API access:

Roles:
    admin    — Full access: scan, configure, manage fleet, policies, exceptions
    analyst  — Read + scan: run scans, view results, create exceptions (not approve)
    viewer   — Read-only: view results, posture, compliance (no scans or mutations)

Authentication is delegated to the upstream reverse proxy (e.g., API gateway,
OAuth2 proxy). RBAC only checks the X-Agent-Bom-Role header or API key mapping.
"""

from __future__ import annotations

import logging
import os
import threading
from enum import Enum
from typing import Callable

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
        2. X-Agent-Bom-Role header (trusted from reverse proxy)
        3. Default role from AGENT_BOM_DEFAULT_ROLE env var
        4. admin (for backward compatibility when RBAC not configured)
    """
    # API key takes priority
    if api_key:
        with _lock:
            role = _api_key_roles.get(api_key)
        if role:
            return role

    # Header from reverse proxy
    if role_header:
        try:
            return Role(role_header.lower())
        except ValueError:
            pass

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


def require_permission(action: str) -> Callable:
    """FastAPI dependency factory for RBAC enforcement.

    Usage in endpoints:
        @app.get("/v1/fleet", dependencies=[Depends(require_permission("fleet_read"))])
    """
    from fastapi import Depends, Header, HTTPException

    async def _check(
        x_api_key: str | None = Header(None, alias="X-Api-Key"),
        x_role: str | None = Header(None, alias="X-Agent-Bom-Role"),
    ) -> Role:
        role = resolve_role(api_key=x_api_key, role_header=x_role)
        if not check_permission(role, action):
            raise HTTPException(
                status_code=403,
                detail=f"Role '{role.value}' does not have '{action}' permission",
            )
        return role

    return Depends(_check)
