"""Agent identity lifecycle API: issue, rotate, revoke, inspect.

Closes the agent-identity gap vs dedicated agent-IAM control planes: agent-bom
can provision time-scoped identities, rotate them with an overlap window, and
revoke them. Raw tokens are returned exactly once (issue/rotate); everything
else is metadata only.
"""

from __future__ import annotations

import ipaddress
from typing import Any, cast

from fastapi import APIRouter, HTTPException, Request

from agent_bom.api.agent_identity_store import (
    approve_jit_grant,
    create_conditional_policy,
    deny_jit_grant,
    get_agent_identity_store,
    issue_identity,
    issue_jit_grant,
    request_jit_grant,
    revoke_identity,
    revoke_jit_grant,
    rotate_identity,
    set_conditional_policy_status,
)
from agent_bom.api.audit_log import log_action
from agent_bom.api.tenancy import require_request_tenant_id
from agent_bom.api.webhook_store import emit_governance_event
from agent_bom.rbac import require_authenticated_permission

router = APIRouter(tags=["identity"])


def _dep(permission: str) -> Any:
    return cast(Any, require_authenticated_permission(permission))


def _tenant(request: Request) -> str:
    return require_request_tenant_id(request)


def _actor(request: Request) -> str:
    return getattr(getattr(request, "state", None), "actor", None) or "api"


def _emit(event_type: str, *, tenant_id: str, subject_id: str, **payload: object) -> None:
    """Fan a governance lifecycle event out to subscribed webhooks (best-effort)."""
    emit_governance_event(event_type=event_type, tenant_id=tenant_id, source="identities.api", subject_id=subject_id, payload=payload)


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
    _emit(
        "identity.issued",
        tenant_id=identity.tenant_id,
        subject_id=identity.identity_id,
        agent_id=identity.agent_id,
        role=identity.role,
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
    _emit(
        "identity.rotated",
        tenant_id=new_identity.tenant_id,
        subject_id=new_identity.identity_id,
        agent_id=new_identity.agent_id,
        rotated_from=identity_id,
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
    _emit("identity.revoked", tenant_id=revoked.tenant_id, subject_id=revoked.identity_id, agent_id=revoked.agent_id, reason=reason)
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
    _emit(
        "identity.jit_granted",
        tenant_id=grant.tenant_id,
        subject_id=grant.grant_id,
        identity_id=grant.identity_id,
        tool=grant.tool_name,
        expires_at=grant.expires_at,
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
    _emit(
        "identity.jit_revoked",
        tenant_id=grant.tenant_id,
        subject_id=grant.grant_id,
        identity_id=grant.identity_id,
        tool=grant.tool_name,
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


def _str_list(body: dict, key: str, *, max_items: int = 200, max_len: int = 120) -> list[str]:
    raw = body.get(key, [])
    if raw in (None, ""):
        return []
    if not isinstance(raw, list):
        raise HTTPException(status_code=400, detail=f"'{key}' must be a list of strings")
    return [str(v).strip()[:max_len] for v in raw if str(v).strip()][:max_items]


def _int_list(body: dict, key: str, *, lo: int, hi: int) -> list[int]:
    raw = body.get(key, [])
    if raw in (None, ""):
        return []
    if not isinstance(raw, list):
        raise HTTPException(status_code=400, detail=f"'{key}' must be a list of integers")
    out: list[int] = []
    for v in raw:
        try:
            n = int(v)
        except (TypeError, ValueError) as exc:
            raise HTTPException(status_code=400, detail=f"'{key}' must contain integers") from exc
        if not (lo <= n <= hi):
            raise HTTPException(status_code=400, detail=f"'{key}' values must be between {lo} and {hi}")
        out.append(n)
    return out


@router.post("/v1/conditional-access-policies", status_code=201, dependencies=[_dep("config")])
async def create_conditional_access_policy(request: Request, body: dict) -> dict[str, object]:
    """Create a context-aware access policy (time / CIDR / environment guardrail)."""
    name = str(body.get("name", "") or "").strip()
    if not name:
        raise HTTPException(status_code=400, detail="'name' is required")
    effect = str(body.get("effect", "require") or "require").strip()
    if effect not in ("require", "deny"):
        raise HTTPException(status_code=400, detail="'effect' must be 'require' or 'deny'")
    try:
        priority = int(body.get("priority", 100))
    except (TypeError, ValueError) as exc:
        raise HTTPException(status_code=400, detail="'priority' must be an integer") from exc
    cidrs = _str_list(body, "allowed_source_cidrs", max_len=64)
    for cidr in cidrs:
        try:
            ipaddress.ip_network(cidr, strict=False)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=f"invalid CIDR '{cidr}'") from exc

    policy = create_conditional_policy(
        get_agent_identity_store(),
        tenant_id=_tenant(request),
        name=name,
        effect=effect,
        priority=priority,
        identity_ids=_str_list(body, "identity_ids"),
        agent_ids=_str_list(body, "agent_ids"),
        tools=_str_list(body, "tools"),
        allowed_environments=_str_list(body, "allowed_environments", max_len=60),
        allowed_hours_utc=_int_list(body, "allowed_hours_utc", lo=0, hi=23),
        allowed_weekdays=_int_list(body, "allowed_weekdays", lo=0, hi=6),
        allowed_source_cidrs=cidrs,
        description=str(body.get("description", "") or ""),
    )
    log_action(
        "agent_identity.conditional_policy_created",
        actor=_actor(request),
        resource=f"conditional-access/{policy.policy_id}",
        tenant_id=policy.tenant_id,
        name=policy.name,
        effect=policy.effect,
        priority=policy.priority,
    )
    return {"schema_version": "agent.identity.conditional.v1", "policy": policy.to_public_dict()}


def _conditional_policy_for_tenant(request: Request, policy_id: str):
    policy = get_agent_identity_store().get_conditional_policy(policy_id)
    if policy is None or policy.tenant_id != _tenant(request):
        raise HTTPException(status_code=404, detail="Conditional-access policy not found")
    return policy


@router.post("/v1/conditional-access-policies/{policy_id}/disable", dependencies=[_dep("config")])
async def disable_conditional_access_policy(request: Request, policy_id: str) -> dict[str, object]:
    """Disable a conditional-access policy without deleting it."""
    _conditional_policy_for_tenant(request, policy_id)
    policy = set_conditional_policy_status(get_agent_identity_store(), policy_id, status="disabled")
    if policy is None:
        raise HTTPException(status_code=404, detail="Conditional-access policy not found")
    log_action(
        "agent_identity.conditional_policy_disabled",
        actor=_actor(request),
        resource=f"conditional-access/{policy.policy_id}",
        tenant_id=policy.tenant_id,
        name=policy.name,
    )
    return {"schema_version": "agent.identity.conditional.v1", "policy": policy.to_public_dict()}


@router.post("/v1/conditional-access-policies/{policy_id}/enable", dependencies=[_dep("config")])
async def enable_conditional_access_policy(request: Request, policy_id: str) -> dict[str, object]:
    """Re-enable a previously disabled conditional-access policy."""
    _conditional_policy_for_tenant(request, policy_id)
    policy = set_conditional_policy_status(get_agent_identity_store(), policy_id, status="active")
    if policy is None:
        raise HTTPException(status_code=404, detail="Conditional-access policy not found")
    log_action(
        "agent_identity.conditional_policy_enabled",
        actor=_actor(request),
        resource=f"conditional-access/{policy.policy_id}",
        tenant_id=policy.tenant_id,
        name=policy.name,
    )
    return {"schema_version": "agent.identity.conditional.v1", "policy": policy.to_public_dict()}


@router.get("/v1/conditional-access-policies", dependencies=[_dep("read")])
async def list_conditional_access_policies(request: Request, include_disabled: bool = False, limit: int = 200) -> dict[str, object]:
    """List conditional-access policies for the active tenant."""
    tenant_id = _tenant(request)
    bounded = max(1, min(limit, 1000))
    policies = get_agent_identity_store().list_conditional_policies(tenant_id, include_disabled=include_disabled, limit=bounded)
    return {
        "schema_version": "agent.identity.conditional.v1",
        "tenant_id": tenant_id,
        "count": len(policies),
        "policies": [p.to_public_dict() for p in policies],
    }


@router.get("/v1/conditional-access-policies/{policy_id}", dependencies=[_dep("read")])
async def get_conditional_access_policy(request: Request, policy_id: str) -> dict[str, object]:
    """Return one conditional-access policy."""
    policy = _conditional_policy_for_tenant(request, policy_id)
    return {"schema_version": "agent.identity.conditional.v1", "policy": policy.to_public_dict()}


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
