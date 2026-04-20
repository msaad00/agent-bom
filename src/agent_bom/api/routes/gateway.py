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
    GET    /v1/gateway/upstreams/discovered  MCP upstreams discovered across the fleet
"""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any, cast

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse, Response

from agent_bom.api.models import EvaluateRequest, JobStatus, PolicyCreate, PolicyUpdate
from agent_bom.api.stores import _get_policy_store, _get_store
from agent_bom.rbac import require_authenticated_permission, require_permission

if TYPE_CHECKING:
    from agent_bom.api.policy_store import GatewayPolicy

router = APIRouter()


def _dep(permission: str) -> Any:
    return cast(Any, require_permission(permission))


def _policy_collection_etag(policies: list["GatewayPolicy"]) -> str:
    payload = json.dumps([p.model_dump() for p in policies], sort_keys=True, separators=(",", ":"))
    digest = hashlib.sha256(payload.encode()).hexdigest()
    return f'"{digest}"'


@router.get("/v1/gateway/policies", tags=["gateway"], dependencies=[_dep("policy_read")])
async def list_gateway_policies(request: Request, enabled: bool | None = None, mode: str | None = None):
    """List all gateway policies."""
    tenant_id = getattr(request.state, "tenant_id", "default")
    policies = _get_policy_store().list_policies(tenant_id=tenant_id)
    if enabled is not None:
        policies = [p for p in policies if p.enabled == enabled]
    if mode:
        policies = [p for p in policies if p.mode.value == mode]
    etag = _policy_collection_etag(policies)
    if request.headers.get("if-none-match") == etag:
        return Response(status_code=304, headers={"ETag": etag, "Cache-Control": "no-store"})
    return JSONResponse(
        {"policies": [p.model_dump() for p in policies], "count": len(policies)},
        headers={"ETag": etag, "Cache-Control": "no-store"},
    )


@router.post("/v1/gateway/policies", tags=["gateway"], status_code=201, dependencies=[_dep("policy_write")])
async def create_gateway_policy(body: PolicyCreate, request: Request):
    """Create a new gateway policy."""
    from agent_bom.api.audit_log import log_action
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
    actor = getattr(request.state, "api_key_name", "unknown")
    log_action(
        "gateway.policy_created",
        actor=actor,
        resource=f"gateway-policy/{policy.policy_id}",
        name=policy.name,
        mode=policy.mode.value,
        enabled=policy.enabled,
        rule_count=len(policy.rules),
    )
    return policy.model_dump()


@router.get("/v1/gateway/policies/{policy_id}", tags=["gateway"], dependencies=[_dep("policy_read")])
async def get_gateway_policy(policy_id: str, request: Request):
    """Get a gateway policy by ID."""
    tenant_id = getattr(request.state, "tenant_id", "default")
    policy = _get_policy_store().get_policy(policy_id, tenant_id=tenant_id)
    if policy is None:
        raise HTTPException(status_code=404, detail="Policy not found")
    return policy.model_dump()


@router.put("/v1/gateway/policies/{policy_id}", tags=["gateway"], dependencies=[_dep("policy_write")])
async def update_gateway_policy(policy_id: str, body: PolicyUpdate, request: Request):
    """Update an existing gateway policy."""
    from agent_bom.api.audit_log import log_action
    from agent_bom.api.policy_store import GatewayRule, PolicyMode

    store = _get_policy_store()
    tenant_id = getattr(request.state, "tenant_id", "default")
    policy = store.get_policy(policy_id, tenant_id=tenant_id)
    if policy is None:
        raise HTTPException(status_code=404, detail="Policy not found")
    original = policy.model_dump()
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
    actor = getattr(request.state, "api_key_name", "unknown")
    updated = policy.model_dump()
    changed_fields = sorted(key for key, value in updated.items() if original.get(key) != value)
    log_action(
        "gateway.policy_updated",
        actor=actor,
        resource=f"gateway-policy/{policy.policy_id}",
        name=policy.name,
        changed_fields=changed_fields,
        enabled=policy.enabled,
        rule_count=len(policy.rules),
    )
    return policy.model_dump()


@router.delete("/v1/gateway/policies/{policy_id}", tags=["gateway"], dependencies=[_dep("policy_write")])
async def delete_gateway_policy(policy_id: str, request: Request):
    """Delete a gateway policy."""
    tenant_id = getattr(request.state, "tenant_id", "default")
    store = _get_policy_store()
    policy = store.get_policy(policy_id, tenant_id=tenant_id)
    if policy is None:
        raise HTTPException(status_code=404, detail="Policy not found")
    if not store.delete_policy(policy_id, tenant_id=tenant_id):
        raise HTTPException(status_code=404, detail="Policy not found")
    from agent_bom.api.audit_log import log_action

    actor = getattr(request.state, "api_key_name", "unknown")
    log_action(
        "gateway.policy_deleted",
        actor=actor,
        resource=f"gateway-policy/{policy_id}",
        name=policy.name,
        mode=policy.mode.value,
        rule_count=len(policy.rules),
    )
    return {"deleted": True, "policy_id": policy_id}


@router.post("/v1/gateway/evaluate", tags=["gateway"], dependencies=[_dep("policy_read")])
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


@router.get("/v1/gateway/audit", tags=["gateway"], dependencies=[_dep("audit_read")])
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


@router.get(
    "/v1/gateway/upstreams/discovered",
    tags=["gateway"],
    dependencies=[cast(Any, require_authenticated_permission("read"))],
)
async def discovered_upstreams(request: Request) -> dict:
    """Return the remote MCP servers discovered across the tenant's fleet.

    Aggregates every MCP server surfaced by the fleet-scan path (pushed
    via ``/v1/fleet/sync`` or returned from in-cluster scans) that has a
    real HTTP(S) URL — i.e. something a multi-MCP gateway can actually
    front. stdio servers are excluded because they only make sense as a
    per-workload sidecar / wrapper (``agent-bom proxy -- <cmd>``).

    Response shape matches the ``upstreams.yaml`` the gateway consumes,
    so a gateway pod can pull this endpoint at startup and every N
    seconds to auto-populate its registry without the operator hand-
    editing YAML. Auth / bearer-token wiring is still operator-supplied
    via `gateway.envFrom` because tokens live in Secrets, not scan data.

    Shape::

        {
          "generated_at": "2026-04-20T00:00:00Z",
          "tenant_id": "...",
          "source": "fleet_scan_aggregate",
          "upstreams": [
            {"name": "jira", "url": "https://...", "transport": "sse",
             "auth": "none", "source_agents": ["agent-a", ...]},
            ...
          ]
        }

    The ``auth`` field is always ``"none"`` from discovery — discovery can
    see the URL but not the credential. The gateway operator decides per
    upstream whether to switch it to ``bearer`` + ``token_env`` when
    merging with their authored overrides.
    """
    tenant_id = getattr(request.state, "tenant_id", "default")
    jobs = _get_store().list_all(tenant_id=tenant_id)

    # name -> merged upstream record
    by_name: dict[str, dict[str, Any]] = {}
    for job in jobs:
        if job.status != JobStatus.DONE or not job.result:
            continue
        agents = job.result.get("agents") or []
        for agent in agents:
            agent_name = agent.get("name") or agent.get("agent_name") or ""
            for server in agent.get("servers") or []:
                url = server.get("url") or ""
                if not url.startswith(("http://", "https://")):
                    # Skip stdio MCPs — they're per-workload sidecar territory.
                    continue
                name = server.get("name") or ""
                if not name:
                    continue
                transport = server.get("transport") or "http"
                record = by_name.setdefault(
                    name,
                    {
                        "name": name,
                        "url": url,
                        "transport": transport,
                        "auth": "none",
                        "source_agents": [],
                    },
                )
                # First URL wins; record every distinct agent that reports it.
                if agent_name and agent_name not in record["source_agents"]:
                    record["source_agents"].append(agent_name)

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "tenant_id": tenant_id,
        "source": "fleet_scan_aggregate",
        "upstreams": sorted(by_name.values(), key=lambda r: r["name"]),
    }


@router.get("/v1/gateway/stats", tags=["gateway"], dependencies=[_dep("audit_read")])
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
