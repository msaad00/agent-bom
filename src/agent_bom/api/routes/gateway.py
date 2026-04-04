"""Gateway policy API routes.

Endpoints:
    GET    /v1/gateway/policies              list policies (filterable)
    POST   /v1/gateway/policies              create policy
    GET    /v1/gateway/policies/{policy_id}   get single policy
    PUT    /v1/gateway/policies/{policy_id}   update policy
    DELETE /v1/gateway/policies/{policy_id}   delete policy
    POST   /v1/gateway/evaluate              dry-run policy evaluation
    GET    /v1/gateway/audit                 policy audit log
    GET    /v1/gateway/stats                 gateway statistics
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, HTTPException, Request

from agent_bom.api.models import EvaluateRequest, PolicyCreate, PolicyUpdate
from agent_bom.api.stores import _get_policy_store

router = APIRouter()


@router.get("/v1/gateway/policies", tags=["gateway"])
async def list_gateway_policies(request: Request, enabled: bool | None = None, mode: str | None = None):
    """List all gateway policies."""
    tenant_id = getattr(request.state, "tenant_id", "default")
    policies = _get_policy_store().list_policies(tenant_id=tenant_id)
    if enabled is not None:
        policies = [p for p in policies if p.enabled == enabled]
    if mode:
        policies = [p for p in policies if p.mode.value == mode]
    return {"policies": [p.model_dump() for p in policies], "count": len(policies)}


@router.post("/v1/gateway/policies", tags=["gateway"], status_code=201)
async def create_gateway_policy(body: PolicyCreate, request: Request):
    """Create a new gateway policy."""
    from agent_bom.api.policy_store import GatewayPolicy, GatewayRule, PolicyMode

    try:
        policy_mode = PolicyMode(body.mode)
    except ValueError:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid mode: {body.mode}. Valid: {[m.value for m in PolicyMode]}",
        )
    now = datetime.now(timezone.utc).isoformat()
    rules = [GatewayRule(**r) for r in body.rules]
    policy = GatewayPolicy(
        policy_id=str(uuid.uuid4()),
        name=body.name,
        description=body.description,
        mode=policy_mode,
        rules=rules,
        bound_agents=body.bound_agents,
        bound_agent_types=body.bound_agent_types,
        bound_environments=body.bound_environments,
        enabled=body.enabled,
        created_at=now,
        updated_at=now,
        tenant_id=getattr(request.state, "tenant_id", "default"),
    )
    _get_policy_store().put_policy(policy)
    return policy.model_dump()


@router.get("/v1/gateway/policies/{policy_id}", tags=["gateway"])
async def get_gateway_policy(policy_id: str, request: Request):
    """Get a gateway policy by ID."""
    tenant_id = getattr(request.state, "tenant_id", "default")
    policy = _get_policy_store().get_policy(policy_id, tenant_id=tenant_id)
    if policy is None:
        raise HTTPException(status_code=404, detail="Policy not found")
    return policy.model_dump()


@router.put("/v1/gateway/policies/{policy_id}", tags=["gateway"])
async def update_gateway_policy(policy_id: str, body: PolicyUpdate, request: Request):
    """Update an existing gateway policy."""
    from agent_bom.api.policy_store import GatewayRule, PolicyMode

    store = _get_policy_store()
    tenant_id = getattr(request.state, "tenant_id", "default")
    policy = store.get_policy(policy_id, tenant_id=tenant_id)
    if policy is None:
        raise HTTPException(status_code=404, detail="Policy not found")
    if body.name is not None:
        policy.name = body.name
    if body.description is not None:
        policy.description = body.description
    if body.mode is not None:
        try:
            policy.mode = PolicyMode(body.mode)
        except ValueError:
            raise HTTPException(status_code=400, detail=f"Invalid mode: {body.mode}")
    if body.rules is not None:
        policy.rules = [GatewayRule(**r) for r in body.rules]
    if body.bound_agents is not None:
        policy.bound_agents = body.bound_agents
    if body.bound_agent_types is not None:
        policy.bound_agent_types = body.bound_agent_types
    if body.bound_environments is not None:
        policy.bound_environments = body.bound_environments
    if body.enabled is not None:
        policy.enabled = body.enabled
    policy.updated_at = datetime.now(timezone.utc).isoformat()
    store.put_policy(policy)
    return policy.model_dump()


@router.delete("/v1/gateway/policies/{policy_id}", tags=["gateway"])
async def delete_gateway_policy(policy_id: str, request: Request):
    """Delete a gateway policy."""
    tenant_id = getattr(request.state, "tenant_id", "default")
    if not _get_policy_store().delete_policy(policy_id, tenant_id=tenant_id):
        raise HTTPException(status_code=404, detail="Policy not found")
    return {"deleted": True, "policy_id": policy_id}


@router.post("/v1/gateway/evaluate", tags=["gateway"])
async def evaluate_gateway(body: EvaluateRequest, request: Request):
    """Dry-run evaluation of gateway policies against a tool call."""
    from agent_bom.gateway import evaluate_gateway_policies

    tenant_id = getattr(request.state, "tenant_id", "default")
    policies = _get_policy_store().list_policies(tenant_id=tenant_id)
    active = [p for p in policies if p.enabled]
    allowed, reason, policy_id = evaluate_gateway_policies(
        active,
        body.tool_name,
        body.arguments,
    )
    return {
        "allowed": allowed,
        "reason": reason,
        "policy_id": policy_id,
        "policies_evaluated": len(active),
    }


@router.get("/v1/gateway/audit", tags=["gateway"])
async def list_gateway_audit(
    request: Request,
    policy_id: str | None = None,
    agent_name: str | None = None,
    limit: int = 100,
):
    """Query the gateway policy audit log."""
    tenant_id = getattr(request.state, "tenant_id", "default")
    entries = _get_policy_store().list_audit_entries(
        policy_id=policy_id,
        agent_name=agent_name,
        limit=limit,
        tenant_id=tenant_id,
    )
    return {"entries": [e.model_dump() for e in entries], "count": len(entries)}


@router.get("/v1/gateway/stats", tags=["gateway"])
async def gateway_stats(request: Request):
    """Gateway-wide statistics."""
    tenant_id = getattr(request.state, "tenant_id", "default")
    policies = _get_policy_store().list_policies(tenant_id=tenant_id)
    audit = _get_policy_store().list_audit_entries(limit=10000, tenant_id=tenant_id)
    enforce_count = sum(1 for p in policies if p.mode.value == "enforce" and p.enabled)
    audit_count = sum(1 for p in policies if p.mode.value == "audit" and p.enabled)
    blocked = sum(1 for e in audit if e.action_taken == "blocked")
    alerted = sum(1 for e in audit if e.action_taken == "alerted")
    return {
        "total_policies": len(policies),
        "enforce_count": enforce_count,
        "audit_count": audit_count,
        "enabled_count": sum(1 for p in policies if p.enabled),
        "total_rules": sum(len(p.rules) for p in policies),
        "audit_entries": len(audit),
        "blocked_count": blocked,
        "alerted_count": alerted,
    }
