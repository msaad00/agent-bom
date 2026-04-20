"""Fleet management API routes.

Endpoints:
    GET   /v1/fleet                   list fleet agents (filterable)
    GET   /v1/fleet/stats             fleet-wide statistics
    GET   /v1/fleet/{agent_id}        single agent with trust breakdown
    POST  /v1/fleet/sync              discovery + sync to fleet registry
    PUT   /v1/fleet/{agent_id}/state  update lifecycle state
    PUT   /v1/fleet/{agent_id}        update agent metadata
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, HTTPException, Request

from agent_bom.api.models import FleetAgentUpdate, PushPayload, StateUpdate
from agent_bom.api.stores import _get_fleet_store, _get_idempotency_store
from agent_bom.api.tenant_quota import enforce_fleet_agents_quota

router = APIRouter()


def _request_header(request: Request, key: str) -> str:
    headers = getattr(request, "headers", None)
    if headers is None:
        return ""
    return str(headers.get(key, "") or "")


@router.get("/v1/fleet", tags=["fleet"])
async def list_fleet(
    request: Request,
    state: str | None = None,
    environment: str | None = None,
    min_trust: float | None = None,
    include_quarantined: bool = False,
    limit: int = 50,
    offset: int = 0,
):
    """List all agents in the fleet registry.

    Supports pagination via ``limit`` (default 50, max 200) and ``offset``.
    Quarantined and decommissioned agents are excluded by default —
    pass ``include_quarantined=true`` to include them.
    """
    limit = max(1, min(limit, 200))
    offset = max(0, offset)
    tenant_id = getattr(request.state, "tenant_id", "default")
    agents = _get_fleet_store().list_by_tenant(tenant_id)
    if not include_quarantined:
        agents = [a for a in agents if a.lifecycle_state.value not in ("quarantined", "decommissioned")]
    if state:
        agents = [a for a in agents if a.lifecycle_state.value == state]
    if environment:
        agents = [a for a in agents if a.environment == environment]
    if min_trust is not None:
        _threshold = float(min_trust)
        agents = [a for a in agents if (a.trust_score or 0.0) >= _threshold]
    total = len(agents)
    page = agents[offset : offset + limit]
    return {
        "agents": [a.model_dump() for a in page],
        "count": len(page),
        "total": total,
        "limit": limit,
        "offset": offset,
    }


@router.get("/v1/fleet/stats", tags=["fleet"])
async def fleet_stats(request: Request):
    """Fleet-wide statistics."""
    tenant_id = getattr(request.state, "tenant_id", "default")
    agents = _get_fleet_store().list_by_tenant(tenant_id)
    by_state: dict[str, int] = {}
    by_env: dict[str, int] = {}
    trust_scores: list[float] = []
    for a in agents:
        state_value = getattr(a.lifecycle_state, "value", str(a.lifecycle_state))
        by_state[state_value] = by_state.get(state_value, 0) + 1
        env = a.environment or "unset"
        by_env[env] = by_env.get(env, 0) + 1
        trust_scores.append(float(getattr(a, "trust_score", 0.0) or 0.0))
    return {
        "total": len(agents),
        "by_state": by_state,
        "by_environment": by_env,
        "avg_trust_score": round(sum(trust_scores) / len(trust_scores), 1) if trust_scores else 0.0,
        "low_trust_count": sum(1 for s in trust_scores if s < 50),
    }


@router.get("/v1/fleet/{agent_id}", tags=["fleet"])
async def get_fleet_agent(request: Request, agent_id: str):
    """Get a single fleet agent with trust score breakdown."""
    agent = _get_fleet_store().get(agent_id)
    tenant_id = getattr(request.state, "tenant_id", "default")
    if agent is None or agent.tenant_id != tenant_id:
        raise HTTPException(status_code=404, detail="Fleet agent not found")
    return agent.model_dump()


def _server_counts(agent) -> tuple[int, int, int, int]:
    server_count = len(agent.mcp_servers)
    pkg_count = sum(len(s.packages) for s in agent.mcp_servers)
    cred_count = sum(len(s.credential_names) for s in agent.mcp_servers)
    vuln_count = sum(s.total_vulnerabilities for s in agent.mcp_servers)
    return server_count, pkg_count, cred_count, vuln_count


def _payload_counts(agent: dict) -> tuple[int, int, int, int]:
    servers = agent.get("mcp_servers", []) or []
    server_count = len(servers)
    pkg_count = 0
    cred_count = 0
    vuln_count = 0
    for server in servers:
        pkg_count += len(server.get("packages", []) or [])
        cred_count += len(server.get("credential_names", []) or [])
        vuln_count += int(server.get("total_vulnerabilities", 0) or 0)
    return server_count, pkg_count, cred_count, vuln_count


@router.post("/v1/fleet/sync", tags=["fleet"])
async def sync_fleet(request: Request, body: PushPayload | None = None):
    """Run discovery and sync results into the fleet registry.

    New agents -> state=DISCOVERED. Existing agents -> counts updated.
    Trust scores are recomputed for all synced agents.
    """
    from agent_bom.api.audit_log import log_action
    from agent_bom.api.fleet_store import FleetAgent, FleetLifecycleState
    from agent_bom.discovery import discover_all
    from agent_bom.fleet.trust_scoring import compute_trust_score

    store = _get_fleet_store()
    tenant_id = getattr(request.state, "tenant_id", "default")
    actor = getattr(request.state, "api_key_name", "") or "system"
    now = datetime.now(timezone.utc).isoformat()
    source_id = (body.source_id if body else "") or _request_header(request, "X-Agent-Bom-Source-Id") or "server-discovery"
    idem_key = (body.idempotency_key if body else "") or _request_header(request, "Idempotency-Key")
    if idem_key:
        cached = _get_idempotency_store().get("/v1/fleet/sync", tenant_id, source_id, idem_key)
        if cached is not None:
            cached["idempotent_replay"] = True
            return cached
    new_count = 0
    updated_count = 0

    if body and body.agents:
        payload_agents = body.agents
        existing_by_name = {agent.name: agent for agent in store.list_by_tenant(tenant_id)}
        new_names = {str(agent.get("name", "unknown-agent")) for agent in payload_agents} - set(existing_by_name)
        enforce_fleet_agents_quota(tenant_id, attempted=len(new_names))
        for payload_agent in payload_agents:
            name = payload_agent.get("name", "unknown-agent")
            existing = existing_by_name.get(name)
            server_count, pkg_count, cred_count, vuln_count = _payload_counts(payload_agent)
            score = float(payload_agent.get("trust_score", 0.0) or 0.0)
            factors = dict(payload_agent.get("trust_factors", {}) or {})
            if existing:
                existing.server_count = server_count
                existing.package_count = pkg_count
                existing.credential_count = cred_count
                existing.vuln_count = vuln_count
                existing.trust_score = score
                existing.trust_factors = factors
                existing.last_discovery = now
                existing.updated_at = now
                existing.config_path = ""
                existing.agent_type = str(payload_agent.get("agent_type", existing.agent_type))
                store.put(existing)
                updated_count += 1
            else:
                fleet_agent = FleetAgent(
                    agent_id=str(uuid.uuid4()),
                    name=name,
                    agent_type=str(payload_agent.get("agent_type", "unknown")),
                    config_path="",
                    lifecycle_state=FleetLifecycleState.DISCOVERED,
                    trust_score=score,
                    trust_factors=factors,
                    server_count=server_count,
                    package_count=pkg_count,
                    credential_count=cred_count,
                    vuln_count=vuln_count,
                    tenant_id=tenant_id,
                    last_discovery=now,
                    created_at=now,
                    updated_at=now,
                )
                store.put(fleet_agent)
                new_count += 1
    else:
        discovered = discover_all()
        existing_by_name = {agent.name: agent for agent in store.list_by_tenant(tenant_id)}
        discovered_names = {agent.name for agent in discovered}
        new_names = discovered_names - set(existing_by_name)
        enforce_fleet_agents_quota(tenant_id, attempted=len(new_names))
        for discovered_agent in discovered:
            existing = existing_by_name.get(discovered_agent.name)
            server_count, pkg_count, cred_count, vuln_count = _server_counts(discovered_agent)
            score, factors = compute_trust_score(discovered_agent)

            if existing:
                existing.server_count = server_count
                existing.package_count = pkg_count
                existing.credential_count = cred_count
                existing.vuln_count = vuln_count
                existing.trust_score = score
                existing.trust_factors = factors
                existing.last_discovery = now
                existing.updated_at = now
                existing.config_path = discovered_agent.config_path or ""
                store.put(existing)
                updated_count += 1
            else:
                fleet_agent = FleetAgent(
                    agent_id=str(uuid.uuid4()),
                    name=discovered_agent.name,
                    agent_type=(
                        discovered_agent.agent_type.value
                        if hasattr(discovered_agent.agent_type, "value")
                        else str(discovered_agent.agent_type)
                    ),
                    config_path=discovered_agent.config_path or "",
                    lifecycle_state=FleetLifecycleState.DISCOVERED,
                    trust_score=score,
                    trust_factors=factors,
                    server_count=server_count,
                    package_count=pkg_count,
                    credential_count=cred_count,
                    vuln_count=vuln_count,
                    tenant_id=tenant_id,
                    last_discovery=now,
                    created_at=now,
                    updated_at=now,
                )
                store.put(fleet_agent)
                new_count += 1

    response = {
        "synced": new_count + updated_count,
        "new": new_count,
        "updated": updated_count,
        "source_id": source_id,
    }
    log_action(
        "fleet.sync",
        actor=actor,
        resource="fleet/sync",
        tenant_id=tenant_id,
        synced=response["synced"],
        new=response["new"],
        updated=response["updated"],
        source_id=source_id,
    )
    if idem_key:
        _get_idempotency_store().put("/v1/fleet/sync", tenant_id, source_id, idem_key, response)
    return response


@router.put("/v1/fleet/{agent_id}/state", tags=["fleet"])
async def update_fleet_state(request: Request, agent_id: str, body: StateUpdate):
    """Update agent lifecycle state."""
    from agent_bom.api.audit_log import log_action
    from agent_bom.api.fleet_store import FleetLifecycleState

    try:
        new_state = FleetLifecycleState(body.state)
    except ValueError:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid state: {body.state}. Valid: {[s.value for s in FleetLifecycleState]}",
        )
    store = _get_fleet_store()
    tenant_id = getattr(request.state, "tenant_id", "default")
    actor = getattr(request.state, "api_key_name", "") or "system"
    agent = store.get(agent_id)
    if agent is None or agent.tenant_id != tenant_id:
        raise HTTPException(status_code=404, detail="Fleet agent not found")
    store.update_state(agent_id, new_state)
    log_action(
        "fleet.state_update",
        actor=actor,
        resource=f"fleet/{agent_id}",
        tenant_id=tenant_id,
        lifecycle_state=new_state.value,
    )
    return {"agent_id": agent_id, "lifecycle_state": new_state.value}


@router.put("/v1/fleet/{agent_id}", tags=["fleet"])
async def update_fleet_agent(request: Request, agent_id: str, body: FleetAgentUpdate):
    """Update agent metadata (owner, environment, tags, notes)."""
    from agent_bom.api.audit_log import log_action

    store = _get_fleet_store()
    agent = store.get(agent_id)
    tenant_id = getattr(request.state, "tenant_id", "default")
    actor = getattr(request.state, "api_key_name", "") or "system"
    if agent is None or agent.tenant_id != tenant_id:
        raise HTTPException(status_code=404, detail="Fleet agent not found")
    if body.owner is not None:
        agent.owner = body.owner
    if body.environment is not None:
        agent.environment = body.environment
    if body.tags is not None:
        agent.tags = body.tags
    if body.notes is not None:
        agent.notes = body.notes
    agent.updated_at = datetime.now(timezone.utc).isoformat()
    store.put(agent)
    log_action(
        "fleet.agent_update",
        actor=actor,
        resource=f"fleet/{agent_id}",
        tenant_id=tenant_id,
        owner=agent.owner,
        environment=agent.environment,
        tags=agent.tags,
    )
    return agent.model_dump()
