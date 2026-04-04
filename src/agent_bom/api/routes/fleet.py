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

from agent_bom.api.models import FleetAgentUpdate, StateUpdate
from agent_bom.api.stores import _get_fleet_store

router = APIRouter()


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
        by_state[a.lifecycle_state.value] = by_state.get(a.lifecycle_state.value, 0) + 1
        env = a.environment or "unset"
        by_env[env] = by_env.get(env, 0) + 1
        trust_scores.append(a.trust_score)
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


@router.post("/v1/fleet/sync", tags=["fleet"])
async def sync_fleet(request: Request):
    """Run discovery and sync results into the fleet registry.

    New agents -> state=DISCOVERED. Existing agents -> counts updated.
    Trust scores are recomputed for all synced agents.
    """
    from agent_bom.api.fleet_store import FleetAgent, FleetLifecycleState
    from agent_bom.discovery import discover_all
    from agent_bom.fleet.trust_scoring import compute_trust_score

    discovered = discover_all()
    store = _get_fleet_store()
    tenant_id = getattr(request.state, "tenant_id", "default")
    now = datetime.now(timezone.utc).isoformat()
    new_count = 0
    updated_count = 0

    for agent in discovered:
        existing = next((a for a in store.list_by_tenant(tenant_id) if a.name == agent.name), None)
        server_count = len(agent.mcp_servers)
        pkg_count = sum(len(s.packages) for s in agent.mcp_servers)
        cred_count = sum(len(s.credential_names) for s in agent.mcp_servers)
        vuln_count = sum(s.total_vulnerabilities for s in agent.mcp_servers)

        score, factors = compute_trust_score(agent)

        if existing:
            existing.server_count = server_count
            existing.package_count = pkg_count
            existing.credential_count = cred_count
            existing.vuln_count = vuln_count
            existing.trust_score = score
            existing.trust_factors = factors
            existing.last_discovery = now
            existing.updated_at = now
            existing.config_path = agent.config_path or ""
            store.put(existing)
            updated_count += 1
        else:
            fleet_agent = FleetAgent(
                agent_id=str(uuid.uuid4()),
                name=agent.name,
                agent_type=agent.agent_type.value if hasattr(agent.agent_type, "value") else str(agent.agent_type),
                config_path=agent.config_path or "",
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

    return {
        "synced": new_count + updated_count,
        "new": new_count,
        "updated": updated_count,
    }


@router.put("/v1/fleet/{agent_id}/state", tags=["fleet"])
async def update_fleet_state(request: Request, agent_id: str, body: StateUpdate):
    """Update agent lifecycle state."""
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
    agent = store.get(agent_id)
    if agent is None or agent.tenant_id != tenant_id:
        raise HTTPException(status_code=404, detail="Fleet agent not found")
    store.update_state(agent_id, new_state)
    return {"agent_id": agent_id, "lifecycle_state": new_state.value}


@router.put("/v1/fleet/{agent_id}", tags=["fleet"])
async def update_fleet_agent(request: Request, agent_id: str, body: FleetAgentUpdate):
    """Update agent metadata (owner, environment, tags, notes)."""
    store = _get_fleet_store()
    agent = store.get(agent_id)
    tenant_id = getattr(request.state, "tenant_id", "default")
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
    return agent.model_dump()
