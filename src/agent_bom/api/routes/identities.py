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


@router.post("/identities", status_code=201, dependencies=[_dep("config")])
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
    # Owner-bind every issued identity. An explicit owner wins; otherwise the
    # identity is attributed to the actor that provisioned it, so an issued
    # identity is never orphaned (matching the accountability we require of
    # discovered cloud NHIs). owner_type is advisory (user | team | service).
    owner = str(body.get("owner", "") or "").strip()[:200] or _actor(request)
    owner_type = str(body.get("owner_type", "") or "").strip()[:60]

    identity, raw_token = issue_identity(
        get_agent_identity_store(),
        agent_id=agent_id,
        tenant_id=_tenant(request),
        role=role,
        blueprint_id=blueprint_id,
        ttl_seconds=ttl_seconds,
        allowed_tools=allowed_tools,
        owner=owner,
        owner_type=owner_type,
    )
    log_action(
        "agent_identity.issued",
        actor=_actor(request),
        resource=f"identity/{identity.identity_id}",
        tenant_id=identity.tenant_id,
        agent_id=identity.agent_id,
        role=identity.role,
        blueprint_id=identity.blueprint_id,
        owner=identity.owner,
        owner_type=identity.owner_type,
        expires_at=identity.expires_at,
    )
    _emit(
        "identity.issued",
        tenant_id=identity.tenant_id,
        subject_id=identity.identity_id,
        agent_id=identity.agent_id,
        role=identity.role,
        owner=identity.owner,
        expires_at=identity.expires_at,
    )
    return {
        "schema_version": "agent.identity.v1",
        "identity": identity.to_public_dict(),
        "token": raw_token,
        "token_notice": "Store this token now; it is not retrievable later.",
    }


@router.post("/identities/{identity_id}/rotate", dependencies=[_dep("config")])
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
        owner=new_identity.owner,
        owner_type=new_identity.owner_type,
        rotated_from=identity_id,
        overlap_seconds=max(0, overlap_seconds),
    )
    _emit(
        "identity.rotated",
        tenant_id=new_identity.tenant_id,
        subject_id=new_identity.identity_id,
        agent_id=new_identity.agent_id,
        owner=new_identity.owner,
        rotated_from=identity_id,
    )
    return {
        "schema_version": "agent.identity.v1",
        "identity": new_identity.to_public_dict(),
        "rotated_from": identity_id,
        "token": raw_token,
        "token_notice": "Store this token now; it is not retrievable later.",
    }


@router.post("/identities/{identity_id}/revoke", dependencies=[_dep("config")])
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
        owner=revoked.owner,
        owner_type=revoked.owner_type,
        reason=reason,
    )
    _emit("identity.revoked", tenant_id=revoked.tenant_id, subject_id=revoked.identity_id, agent_id=revoked.agent_id, reason=reason)
    return {"schema_version": "agent.identity.v1", "revoked": True, "identity": revoked.to_public_dict()}


@router.post("/identities/{identity_id}/jit-requests", status_code=201, dependencies=[_dep("config")])
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


@router.post("/identities/{identity_id}/jit-grants", status_code=201, dependencies=[_dep("config")])
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


@router.post("/identity-jit-grants/{grant_id}/approve", dependencies=[_dep("config")])
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


@router.post("/identity-jit-grants/{grant_id}/deny", dependencies=[_dep("config")])
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


@router.post("/identity-jit-grants/{grant_id}/revoke", dependencies=[_dep("config")])
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


@router.get("/identity-jit-grants", dependencies=[_dep("read")])
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


@router.get("/identities/{identity_id}/jit-grants", dependencies=[_dep("read")])
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


@router.post("/conditional-access-policies", status_code=201, dependencies=[_dep("config")])
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


@router.post("/conditional-access-policies/{policy_id}/disable", dependencies=[_dep("config")])
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


@router.post("/conditional-access-policies/{policy_id}/enable", dependencies=[_dep("config")])
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


@router.get("/conditional-access-policies", dependencies=[_dep("read")])
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


@router.get("/conditional-access-policies/{policy_id}", dependencies=[_dep("read")])
async def get_conditional_access_policy(request: Request, policy_id: str) -> dict[str, object]:
    """Return one conditional-access policy."""
    policy = _conditional_policy_for_tenant(request, policy_id)
    return {"schema_version": "agent.identity.conditional.v1", "policy": policy.to_public_dict()}


@router.post("/identities/discover", dependencies=[_dep("read")])
async def discover_non_human_identities(request: Request, body: dict | None = None) -> dict[str, object]:
    """Discover non-human identities (service accounts / principals) from IdPs.

    Read-only and reference-only: enumerates Okta service apps + API tokens and
    Entra service principals + app registrations and returns normalized metadata
    (id / name / owner / created / credential expiry / scope references) — never
    any secret material. Each provider is gated by its own ``*_DISCOVERY`` env
    flag and token; a disabled or unconfigured provider is reported in
    ``providers`` rather than failing the request. Never runs a network call for
    a provider whose flag is off.
    """
    from agent_bom.graph.nhi_overlay import merge_discovery_results
    from agent_bom.identity import (
        discover_entra_non_human_identities,
        discover_okta_non_human_identities,
    )

    payload = body or {}
    requested = payload.get("providers")
    if isinstance(requested, list) and requested:
        selected = {str(p).strip().lower() for p in requested}
    else:
        selected = {"okta", "entra"}

    results = []
    if "okta" in selected:
        results.append(discover_okta_non_human_identities())
    if "entra" in selected:
        results.append(discover_entra_non_human_identities())

    merged = merge_discovery_results(results)
    log_action(
        "identity.nhi_discovered",
        actor=_actor(request),
        resource="identities/discover",
        tenant_id=_tenant(request),
        providers=[p.get("provider") for p in merged["providers"]],
        count=len(merged["identities"]),
    )
    return {
        "schema_version": "identity.nhi.discovery.v1",
        "tenant_id": _tenant(request),
        "status": merged["status"],
        "providers": merged["providers"],
        "count": len(merged["identities"]),
        "identities": merged["identities"],
        "warnings": merged["warnings"],
    }


@router.get("/identities", dependencies=[_dep("read")])
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


# ── Access-review / recertification campaigns (NHI governance) ──────────────────
#
# These static ``/v1/identities/access-reviews...`` routes are declared before
# the ``/v1/identities/{identity_id}`` catch-all so FastAPI's in-order matching
# does not route "access-reviews" into the single-identity lookup.


def _discover_nhi_subjects() -> list[dict[str, object]]:
    """Run read-only NHI discovery and return reference-only subject dicts.

    Reuses the same Okta/Entra discovery used by ``/v1/identities/discover`` —
    never reads secret material; each provider is gated by its own env flag.
    """
    from agent_bom.graph.nhi_overlay import merge_discovery_results
    from agent_bom.identity import (
        discover_entra_non_human_identities,
        discover_okta_non_human_identities,
    )

    merged = merge_discovery_results([discover_okta_non_human_identities(), discover_entra_non_human_identities()])
    return list(merged.get("identities", []))


@router.post("/identities/access-reviews", status_code=201, dependencies=[_dep("config")])
async def create_access_review(request: Request, body: dict | None = None) -> dict[str, object]:
    """Create a scheduled access-review / recertification campaign over NHIs.

    Scope defaults to the tenant's discovered non-human identities (Okta/Entra
    service accounts / service principals) and their effective-permission
    references. The caller may instead pass an explicit reference-only
    ``subjects`` list. Reference-only — never reads or stores secret material,
    and never executes any revocation.
    """
    from agent_bom.api.access_review import (
        create_campaign,
        create_campaign_from_discovery,
        get_access_review_store,
    )

    payload = body or {}
    name = str(payload.get("name", "") or "").strip()
    if not name:
        raise HTTPException(status_code=400, detail="'name' is required")
    try:
        due_days = int(payload.get("due_days", 14))
    except (TypeError, ValueError) as exc:
        raise HTTPException(status_code=400, detail="'due_days' must be an integer") from exc
    if due_days < 1 or due_days > 365:
        raise HTTPException(status_code=400, detail="'due_days' must be between 1 and 365")
    description = str(payload.get("description", "") or "")
    tenant_id = _tenant(request)
    store = get_access_review_store()

    raw_subjects = payload.get("subjects")
    if isinstance(raw_subjects, list) and raw_subjects:
        subjects = [s for s in raw_subjects if isinstance(s, dict)]
        campaign, items = create_campaign(
            store,
            tenant_id=tenant_id,
            name=name,
            subjects=subjects,
            created_by=_actor(request),
            due_days=due_days,
            description=description,
        )
    else:
        discovered = _discover_nhi_subjects()
        campaign, items = create_campaign_from_discovery(
            store,
            tenant_id=tenant_id,
            name=name,
            discovered=discovered,
            created_by=_actor(request),
            due_days=due_days,
            description=description,
        )

    log_action(
        "identity.access_review_created",
        actor=_actor(request),
        resource=f"access-review/{campaign.campaign_id}",
        tenant_id=tenant_id,
        name=campaign.name,
        item_count=campaign.item_count,
        due_at=campaign.due_at,
    )
    _emit(
        "identity.access_review_created",
        tenant_id=tenant_id,
        subject_id=campaign.campaign_id,
        item_count=campaign.item_count,
        due_at=campaign.due_at,
    )
    return {
        "schema_version": "identity.access_review.v1",
        "campaign": campaign.to_public_dict(),
        "items": [i.to_public_dict() for i in items],
    }


@router.get("/identities/access-reviews", dependencies=[_dep("read")])
async def list_access_reviews(request: Request, limit: int = 200) -> dict[str, object]:
    """List access-review campaigns for the active tenant (overdue refreshed)."""
    from agent_bom.api.access_review import get_access_review_store, refresh_campaign_status

    tenant_id = _tenant(request)
    bounded = max(1, min(limit, 1000))
    store = get_access_review_store()
    campaigns = store.list_campaigns(tenant_id, limit=bounded)
    refreshed = [refresh_campaign_status(store, tenant_id=tenant_id, campaign_id=c.campaign_id) or c for c in campaigns]
    return {
        "schema_version": "identity.access_review.v1",
        "tenant_id": tenant_id,
        "count": len(refreshed),
        "campaigns": [c.to_public_dict() for c in refreshed],
    }


@router.get("/identities/access-reviews/{campaign_id}", dependencies=[_dep("read")])
async def get_access_review(request: Request, campaign_id: str) -> dict[str, object]:
    """Return one access-review campaign and its review items."""
    from agent_bom.api.access_review import get_access_review_store, refresh_campaign_status

    tenant_id = _tenant(request)
    store = get_access_review_store()
    campaign = refresh_campaign_status(store, tenant_id=tenant_id, campaign_id=campaign_id)
    if campaign is None:
        raise HTTPException(status_code=404, detail="Access-review campaign not found")
    items = store.list_items(campaign_id, tenant_id)
    return {
        "schema_version": "identity.access_review.v1",
        "campaign": campaign.to_public_dict(),
        "count": len(items),
        "items": [i.to_public_dict() for i in items],
    }


@router.post("/identities/access-reviews/{campaign_id}/items/{item_id}/decision", dependencies=[_dep("config")])
async def submit_access_review_decision(request: Request, campaign_id: str, item_id: str, body: dict) -> dict[str, object]:
    """Record a reviewer decision (attest / revoke_recommended / flag) on one item.

    Reference-only: a ``revoke_recommended`` decision records the recommendation
    as audited evidence and (when blocking) emits a governance event; it never
    executes a revocation on Okta/Entra or any external system.
    """
    from agent_bom.api.access_review import _VALID_DECISIONS, get_access_review_store, record_decision

    decision = str(body.get("decision", "") or "").strip()
    if decision not in _VALID_DECISIONS:
        raise HTTPException(status_code=400, detail=f"'decision' must be one of {sorted(_VALID_DECISIONS)}")
    note = str(body.get("note", "") or "")
    tenant_id = _tenant(request)
    store = get_access_review_store()

    campaign = store.get_campaign(campaign_id, tenant_id)
    if campaign is None:
        raise HTTPException(status_code=404, detail="Access-review campaign not found")
    result = record_decision(
        store,
        tenant_id=tenant_id,
        item_id=item_id,
        decision=decision,
        decided_by=_actor(request),
        note=note,
    )
    if result is None:
        raise HTTPException(status_code=404, detail="Access-review item not found")
    item, campaign = result
    log_action(
        "identity.access_review_decided",
        actor=_actor(request),
        resource=f"access-review/{campaign_id}/item/{item_id}",
        tenant_id=tenant_id,
        decision=item.decision,
        subject_id=item.subject_id,
        campaign_status=campaign.status,
    )
    if item.decision == "revoke_recommended":
        _emit(
            "identity.access_review_revoke_recommended",
            tenant_id=tenant_id,
            subject_id=item.subject_id,
            campaign_id=campaign_id,
        )
    return {
        "schema_version": "identity.access_review.v1",
        "item": item.to_public_dict(),
        "campaign": campaign.to_public_dict(),
    }


@router.get("/identities/access-reviews/{campaign_id}/evidence", dependencies=[_dep("read")])
async def export_access_review_evidence(request: Request, campaign_id: str) -> dict[str, object]:
    """Export a non-secret, signable evidence bundle for one campaign."""
    from agent_bom.api.access_review import export_evidence, get_access_review_store

    tenant_id = _tenant(request)
    bundle = export_evidence(get_access_review_store(), tenant_id=tenant_id, campaign_id=campaign_id)
    if bundle is None:
        raise HTTPException(status_code=404, detail="Access-review campaign not found")
    return bundle


# Declared last so the ``access-reviews`` static routes above take precedence
# over this single-identity catch-all.
@router.get("/identities/{identity_id}", dependencies=[_dep("read")])
async def get_agent_identity(request: Request, identity_id: str) -> dict[str, object]:
    """Return one agent identity's lifecycle status (metadata only)."""
    identity = get_agent_identity_store().get(identity_id)
    if identity is None or identity.tenant_id != _tenant(request):
        raise HTTPException(status_code=404, detail="Agent identity not found")
    return {"schema_version": "agent.identity.v1", "identity": identity.to_public_dict()}
