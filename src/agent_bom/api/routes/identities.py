"""Agent identity lifecycle API: issue, rotate, revoke, inspect.

Closes the agent-identity gap vs dedicated agent-IAM control planes: agent-bom
can provision time-scoped identities, rotate them with an overlap window, and
revoke them. Raw tokens are returned exactly once (issue/rotate); everything
else is metadata only.
"""

from __future__ import annotations

from typing import Any, cast

from fastapi import APIRouter, HTTPException, Request

from agent_bom.api.agent_identity_store import (
    approve_jit_grant,
    deny_jit_grant,
    get_agent_identity_store,
    issue_identity,
    issue_jit_grant,
    request_jit_grant,
    revoke_identity,
    revoke_jit_grant,
    rotate_identity,
)
from agent_bom.api.audit_log import log_action
from agent_bom.api.tenancy import require_request_tenant_id
from agent_bom.rbac import require_authenticated_permission

router = APIRouter(tags=["identity"])


def _dep(permission: str) -> Any:
    return cast(Any, require_authenticated_permission(permission))


def _tenant(request: Request) -> str:
    return require_request_tenant_id(request)


def _actor(request: Request) -> str:
    return getattr(getattr(request, "state", None), "actor", None) or "api"


def _tool_name(body: dict) -> str:
    tool_name = str(body.get("tool_name", "") or "").strip()[:120]
    if not tool_name:
        raise HTTPException(status_code=400, detail="'tool_name' is required")
    return tool_name


def _ttl_seconds(body: dict, *, default: int = 3600, max_seconds: int = 24 * 3600) -> int:
    try:
        ttl_seconds = int(body.get("ttl_seconds", default))
    except (TypeError, ValueError) as exc:
        raise HTTPException(status_code=400, detail="'ttl_seconds' must be an integer") from exc
    if ttl_seconds < 60:
        raise HTTPException(status_code=400, detail="'ttl_seconds' must be at least 60")
    if ttl_seconds > max_seconds:
        raise HTTPException(status_code=400, detail=f"'ttl_seconds' must be at most {max_seconds}")
    return ttl_seconds


def _identity_for_tenant(request: Request, identity_id: str):
    identity = get_agent_identity_store().get(identity_id)
    if identity is None or identity.tenant_id != _tenant(request):
        raise HTTPException(status_code=404, detail="Agent identity not found")
    return identity


@router.post("/v1/identities", status_code=201, dependencies=[_dep("config")])
async def issue_agent_identity(request: Request, body: dict) -> dict[str, object]:
    """Issue a new agent identity. Returns the raw token exactly once."""
    agent_id = str(body.get("agent_id", "") or "").strip()
    if not agent_id:
        raise HTTPException(status_code=400, detail="'agent_id' is required")
    role = str(body.get("role", "agent") or "agent").strip()[:60]
    blueprint_id = str(body.get("blueprint_id", "") or "").strip()[:60]
    try:
        ttl_seconds = int(body.get("ttl_seconds", 90 * 86400))
    except (TypeError, ValueError) as exc:
        raise HTTPException(status_code=400, detail="'ttl_seconds' must be an integer") from exc
    if ttl_seconds < 60:
        raise HTTPException(status_code=400, detail="'ttl_seconds' must be at least 60")
    raw_tools = body.get("allowed_tools", [])
    if not isinstance(raw_tools, list):
        raise HTTPException(status_code=400, detail="'allowed_tools' must be a list of tool names")
    allowed_tools = [str(t).strip()[:120] for t in raw_tools if str(t).strip()][:200]

    identity, raw_token = issue_identity(
        get_agent_identity_store(),
        agent_id=agent_id,
        tenant_id=_tenant(request),
        role=role,
        blueprint_id=blueprint_id,
        ttl_seconds=ttl_seconds,
        allowed_tools=allowed_tools,
    )
    log_action(
        "agent_identity.issued",
        actor=_actor(request),
        resource=f"identity/{identity.identity_id}",
        tenant_id=identity.tenant_id,
        agent_id=identity.agent_id,
        role=identity.role,
        blueprint_id=identity.blueprint_id,
        expires_at=identity.expires_at,
    )
    return {
        "schema_version": "agent.identity.v1",
        "identity": identity.to_public_dict(),
        "token": raw_token,
        "token_notice": "Store this token now; it is not retrievable later.",
    }


@router.post("/v1/identities/{identity_id}/rotate", dependencies=[_dep("config")])
async def rotate_agent_identity(request: Request, identity_id: str, body: dict | None = None) -> dict[str, object]:
    """Rotate an identity: issue a replacement and keep the old one live briefly."""
    payload = body or {}
    try:
        overlap_seconds = int(payload.get("overlap_seconds", 3600))
        ttl_seconds = int(payload.get("ttl_seconds", 90 * 86400))
    except (TypeError, ValueError) as exc:
        raise HTTPException(status_code=400, detail="overlap_seconds/ttl_seconds must be integers") from exc
    store = get_agent_identity_store()
    existing = store.get(identity_id)
    if existing is None or existing.tenant_id != _tenant(request):
        raise HTTPException(status_code=404, detail="Agent identity not found")
    result = rotate_identity(store, identity_id, overlap_seconds=max(0, overlap_seconds), ttl_seconds=ttl_seconds)
    if result is None:
        raise HTTPException(status_code=409, detail="Identity cannot be rotated (revoked)")
    new_identity, raw_token = result
    log_action(
        "agent_identity.rotated",
        actor=_actor(request),
        resource=f"identity/{new_identity.identity_id}",
        tenant_id=new_identity.tenant_id,
        agent_id=new_identity.agent_id,
        rotated_from=identity_id,
        overlap_seconds=max(0, overlap_seconds),
    )
    return {
        "schema_version": "agent.identity.v1",
        "identity": new_identity.to_public_dict(),
        "rotated_from": identity_id,
        "token": raw_token,
        "token_notice": "Store this token now; it is not retrievable later.",
    }


@router.post("/v1/identities/{identity_id}/revoke", dependencies=[_dep("config")])
async def revoke_agent_identity(request: Request, identity_id: str, body: dict | None = None) -> dict[str, object]:
    """Revoke an identity immediately; its token can no longer authenticate."""
    store = get_agent_identity_store()
    existing = store.get(identity_id)
    if existing is None or existing.tenant_id != _tenant(request):
        raise HTTPException(status_code=404, detail="Agent identity not found")
    reason = str((body or {}).get("reason", "") or "")
    revoked = revoke_identity(store, identity_id, reason=reason)
    if revoked is None:
        raise HTTPException(status_code=404, detail="Agent identity not found")
    log_action(
        "agent_identity.revoked",
        actor=_actor(request),
        resource=f"identity/{revoked.identity_id}",
        tenant_id=revoked.tenant_id,
        agent_id=revoked.agent_id,
        reason=reason,
    )
    return {"schema_version": "agent.identity.v1", "revoked": True, "identity": revoked.to_public_dict()}


@router.post("/v1/identities/{identity_id}/jit-requests", status_code=201, dependencies=[_dep("config")])
async def request_agent_identity_jit(request: Request, identity_id: str, body: dict) -> dict[str, object]:
    """Request time-bound access to one tool. Requests do not authorize calls."""
    identity = _identity_for_tenant(request, identity_id)
    tool_name = _tool_name(body)
    grant = request_jit_grant(
        get_agent_identity_store(),
        identity_id=identity.identity_id,
        agent_id=identity.agent_id,
        tenant_id=identity.tenant_id,
        tool_name=tool_name,
        requested_by=_actor(request),
        reason=str(body.get("reason", "") or ""),
        ticket_id=str(body.get("ticket_id", "") or ""),
    )
    log_action(
        "agent_identity.jit_requested",
        actor=_actor(request),
        resource=f"identity-jit/{grant.grant_id}",
        tenant_id=grant.tenant_id,
        agent_id=grant.agent_id,
        identity_id=grant.identity_id,
        tool_name=grant.tool_name,
        ticket_id=grant.ticket_id,
    )
    return {"schema_version": "agent.identity.jit.v1", "grant": grant.to_public_dict()}


@router.post("/v1/identities/{identity_id}/jit-grants", status_code=201, dependencies=[_dep("config")])
async def grant_agent_identity_jit(request: Request, identity_id: str, body: dict) -> dict[str, object]:
    """Grant one identity time-bound access to one tool."""
    identity = _identity_for_tenant(request, identity_id)
    ttl_seconds = _ttl_seconds(body)
    grant = issue_jit_grant(
        get_agent_identity_store(),
        identity_id=identity.identity_id,
        agent_id=identity.agent_id,
        tenant_id=identity.tenant_id,
        tool_name=_tool_name(body),
        ttl_seconds=ttl_seconds,
        approved_by=_actor(request),
        reason=str(body.get("reason", "") or ""),
        ticket_id=str(body.get("ticket_id", "") or ""),
    )
    log_action(
        "agent_identity.jit_granted",
        actor=_actor(request),
        resource=f"identity-jit/{grant.grant_id}",
        tenant_id=grant.tenant_id,
        agent_id=grant.agent_id,
        identity_id=grant.identity_id,
        tool_name=grant.tool_name,
        expires_at=grant.expires_at,
        ticket_id=grant.ticket_id,
    )
    return {"schema_version": "agent.identity.jit.v1", "grant": grant.to_public_dict()}


@router.post("/v1/identity-jit-grants/{grant_id}/approve", dependencies=[_dep("config")])
async def approve_agent_identity_jit(request: Request, grant_id: str, body: dict | None = None) -> dict[str, object]:
    """Approve a pending JIT request for a bounded TTL."""
    payload = body or {}
    store = get_agent_identity_store()
    existing = store.get_jit_grant(grant_id)
    if existing is None or existing.tenant_id != _tenant(request):
        raise HTTPException(status_code=404, detail="JIT grant not found")
    grant = approve_jit_grant(store, grant_id, ttl_seconds=_ttl_seconds(payload), approved_by=_actor(request))
    if grant is None:
        raise HTTPException(status_code=409, detail="JIT grant cannot be approved")
    log_action(
        "agent_identity.jit_approved",
        actor=_actor(request),
        resource=f"identity-jit/{grant.grant_id}",
        tenant_id=grant.tenant_id,
        agent_id=grant.agent_id,
        identity_id=grant.identity_id,
        tool_name=grant.tool_name,
        expires_at=grant.expires_at,
    )
    return {"schema_version": "agent.identity.jit.v1", "grant": grant.to_public_dict()}


@router.post("/v1/identity-jit-grants/{grant_id}/deny", dependencies=[_dep("config")])
async def deny_agent_identity_jit(request: Request, grant_id: str, body: dict | None = None) -> dict[str, object]:
    """Deny a pending JIT request."""
    store = get_agent_identity_store()
    existing = store.get_jit_grant(grant_id)
    if existing is None or existing.tenant_id != _tenant(request):
        raise HTTPException(status_code=404, detail="JIT grant not found")
    grant = deny_jit_grant(store, grant_id, reason=str((body or {}).get("reason", "") or ""))
    if grant is None:
        raise HTTPException(status_code=409, detail="JIT grant cannot be denied")
    log_action(
        "agent_identity.jit_denied",
        actor=_actor(request),
        resource=f"identity-jit/{grant.grant_id}",
        tenant_id=grant.tenant_id,
        agent_id=grant.agent_id,
        identity_id=grant.identity_id,
        tool_name=grant.tool_name,
    )
    return {"schema_version": "agent.identity.jit.v1", "grant": grant.to_public_dict()}


@router.post("/v1/identity-jit-grants/{grant_id}/revoke", dependencies=[_dep("config")])
async def revoke_agent_identity_jit(request: Request, grant_id: str, body: dict | None = None) -> dict[str, object]:
    """Revoke an active JIT grant immediately."""
    store = get_agent_identity_store()
    existing = store.get_jit_grant(grant_id)
    if existing is None or existing.tenant_id != _tenant(request):
        raise HTTPException(status_code=404, detail="JIT grant not found")
    grant = revoke_jit_grant(store, grant_id, reason=str((body or {}).get("reason", "") or ""))
    if grant is None:
        raise HTTPException(status_code=409, detail="JIT grant cannot be revoked")
    log_action(
        "agent_identity.jit_revoked",
        actor=_actor(request),
        resource=f"identity-jit/{grant.grant_id}",
        tenant_id=grant.tenant_id,
        agent_id=grant.agent_id,
        identity_id=grant.identity_id,
        tool_name=grant.tool_name,
    )
    return {"schema_version": "agent.identity.jit.v1", "grant": grant.to_public_dict()}


@router.get("/v1/identity-jit-grants", dependencies=[_dep("read")])
async def list_agent_identity_jit_grants(
    request: Request,
    identity_id: str | None = None,
    include_inactive: bool = False,
    limit: int = 200,
) -> dict[str, object]:
    """List JIT grants for the active tenant."""
    bounded = max(1, min(limit, 1000))
    grants = get_agent_identity_store().list_jit_grants(
        _tenant(request),
        identity_id=identity_id,
        include_inactive=include_inactive,
        limit=bounded,
    )
    return {
        "schema_version": "agent.identity.jit.v1",
        "tenant_id": _tenant(request),
        "count": len(grants),
        "grants": [g.to_public_dict() for g in grants],
    }


@router.get("/v1/identities/{identity_id}/jit-grants", dependencies=[_dep("read")])
async def list_agent_identity_jit_for_identity(
    request: Request,
    identity_id: str,
    include_inactive: bool = False,
    limit: int = 200,
) -> dict[str, object]:
    """List JIT grants attached to one identity."""
    identity = _identity_for_tenant(request, identity_id)
    bounded = max(1, min(limit, 1000))
    grants = get_agent_identity_store().list_jit_grants(
        identity.tenant_id,
        identity_id=identity.identity_id,
        include_inactive=include_inactive,
        limit=bounded,
    )
    return {
        "schema_version": "agent.identity.jit.v1",
        "tenant_id": identity.tenant_id,
        "identity_id": identity.identity_id,
        "count": len(grants),
        "grants": [g.to_public_dict() for g in grants],
    }


@router.get("/v1/identities", dependencies=[_dep("read")])
async def list_agent_identities(request: Request, include_inactive: bool = False, limit: int = 200) -> dict[str, object]:
    """List managed agent identities for the active tenant (metadata only)."""
    tenant_id = _tenant(request)
    bounded = max(1, min(limit, 1000))
    identities = get_agent_identity_store().list(tenant_id, include_inactive=include_inactive, limit=bounded)
    return {
        "schema_version": "agent.identity.v1",
        "tenant_id": tenant_id,
        "count": len(identities),
        "identities": [i.to_public_dict() for i in identities],
    }


@router.get("/v1/identities/{identity_id}", dependencies=[_dep("read")])
async def get_agent_identity(request: Request, identity_id: str) -> dict[str, object]:
    """Return one agent identity's lifecycle status (metadata only)."""
    identity = get_agent_identity_store().get(identity_id)
    if identity is None or identity.tenant_id != _tenant(request):
        raise HTTPException(status_code=404, detail="Agent identity not found")
    return {"schema_version": "agent.identity.v1", "identity": identity.to_public_dict()}
