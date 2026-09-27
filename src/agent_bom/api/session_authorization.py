"""Intersect a signed session's authority with its current backing key."""

from __future__ import annotations

from fastapi import HTTPException

from agent_bom.api.auth import ApiKey, Role, get_key_store, scopes_allow
from agent_bom.api.route_policy import request_scopes_allow, required_role, required_scope
from agent_bom.api.tenant_worker import run_tenant_bound
from agent_bom.rbac import role_rank


def authorize_browser_session(
    *,
    role: Role,
    scopes: list[str],
    tenant_id: str,
    key_id: str,
    auth_method: str,
    method: str,
    path: str,
) -> tuple[Role, list[str]]:
    """Resolve live key ceilings before exposing authority to route handlers."""
    if key_id:
        stored = run_tenant_bound(tenant_id, get_key_store().get, key_id)
        role, scopes = constrain_session_key(role, scopes, tenant_id, stored)
    if key_id or auth_method == "managed_trial_oidc":
        scope = required_scope(method, path)
        # Trial tokens do not use the empty-list legacy unrestricted convention.
        empty_trial = auth_method == "managed_trial_oidc" and not scopes and path != "/v1/auth/me"
        if empty_trial or not request_scopes_allow(scopes, method, path):
            detail = f"Forbidden — requires scope {scope}" if scope else "Forbidden — operation has no scope grant"
            raise HTTPException(status_code=403, detail=detail)
    minimum_role = Role(required_role(method, path))
    if role_rank(role) < role_rank(minimum_role):
        raise HTTPException(status_code=403, detail=f"Forbidden — requires {minimum_role.value} role")
    return role, scopes


def constrain_session_key(
    role: Role,
    scopes: list[str],
    tenant_id: str,
    stored: ApiKey | None,
) -> tuple[Role, list[str]]:
    """Apply current lifecycle, tenant, role and grant ceilings to a session."""
    if stored is None or stored.tenant_id != tenant_id or not stored.is_usable():
        raise HTTPException(status_code=401, detail="Unauthorized — browser session key is no longer active")
    narrowed_scopes = intersect_session_scopes(scopes, list(stored.scopes))
    if narrowed_scopes is None:
        raise HTTPException(status_code=403, detail="Forbidden — session and key grants no longer overlap")
    return min(role, stored.role, key=role_rank), narrowed_scopes


def intersect_session_scopes(session_scopes: list[str], key_scopes: list[str]) -> list[str] | None:
    """Return the narrower grants, or None when their intersection is empty.

    An empty list means legacy unrestricted access, so it must never represent
    a disjoint intersection. Family wildcards are intersected by retaining only
    candidates wholly covered by both inputs, without expanding either grant.
    """
    if not session_scopes or "*" in session_scopes:
        return list(key_scopes)
    if not key_scopes or "*" in key_scopes:
        return list(session_scopes)
    intersection = [
        scope
        for scope in dict.fromkeys([*session_scopes, *key_scopes])
        if scopes_allow(session_scopes, scope) and scopes_allow(key_scopes, scope)
    ]
    return intersection or None
