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

from agent_bom.api.mcp_observation_store import MCPObservation, merge_observations
from agent_bom.api.models import FleetAgentUpdate, PushPayload, StateUpdate
from agent_bom.api.stores import _get_fleet_store, _get_idempotency_store, _get_mcp_observation_store
from agent_bom.api.tenant_quota import enforce_fleet_agents_quota, tenant_quota_guard

router = APIRouter()


def _state_value(agent) -> str:
    state = getattr(agent, "lifecycle_state", "")
    return str(getattr(state, "value", state) or "")


def _agent_text(value) -> str:
    return str(value or "").lower()


def _query_fleet_fallback(
    agents: list,
    *,
    state: str | None,
    environment: str | None,
    min_trust: float | None,
    search: str | None,
    include_quarantined: bool,
    limit: int,
    offset: int,
) -> tuple[list, int]:
    filtered = list(agents)
    if not include_quarantined and state is None:
        filtered = [a for a in filtered if _state_value(a) not in ("quarantined", "decommissioned")]
    if state:
        filtered = [a for a in filtered if _state_value(a) == state]
    if environment:
        filtered = [a for a in filtered if getattr(a, "environment", None) == environment]
    if min_trust is not None:
        filtered = [a for a in filtered if float(getattr(a, "trust_score", 0.0) or 0.0) >= min_trust]
    if search:
        needle = search.lower()
        filtered = [
            a
            for a in filtered
            if needle in _agent_text(getattr(a, "name", ""))
            or needle in _agent_text(getattr(a, "owner", ""))
            or needle in _agent_text(getattr(a, "environment", ""))
            or any(needle in _agent_text(tag) for tag in getattr(a, "tags", []) or [])
        ]
    filtered = sorted(filtered, key=lambda a: (_agent_text(getattr(a, "name", "")), str(getattr(a, "agent_id", ""))))
    total = len(filtered)
    return filtered[offset : offset + limit], total


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
    search: str | None = None,
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
    min_trust_value = float(min_trust) if min_trust is not None else None
    search_value = (search or "").strip() or None
    store = _get_fleet_store()
    result = None
    query_by_tenant = getattr(store, "query_by_tenant", None)
    if callable(query_by_tenant):
        result = query_by_tenant(
            tenant_id,
            state=state,
            environment=environment,
            min_trust=min_trust_value,
            search=search_value,
            include_quarantined=include_quarantined,
            limit=limit,
            offset=offset,
        )
    if isinstance(result, tuple) and len(result) == 2:
        page, total = result
    else:
        page, total = _query_fleet_fallback(
            store.list_by_tenant(tenant_id),
            state=state,
            environment=environment,
            min_trust=min_trust_value,
            search=search_value,
            include_quarantined=include_quarantined,
            limit=limit,
            offset=offset,
        )
    return {
        "agents": [a.model_dump() for a in page],
        "count": len(page),
        "total": total,
        "limit": limit,
        "offset": offset,
        "has_more": offset + len(page) < total,
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
    tenant_id = getattr(request.state, "tenant_id", "default")
    agent = _get_fleet_store().get(agent_id, tenant_id=tenant_id)
    if agent is None:
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


def _payload_tags(agent: dict) -> list[str]:
    return sorted({str(tag).strip() for tag in list(agent.get("tags", []) or []) if str(tag).strip()})


def _persist_payload_observations(tenant_id: str, agent: dict, *, last_discovery: str, last_synced: str) -> None:
    store = _get_mcp_observation_store()
    agent_name = str(agent.get("name", "unknown-agent"))
    for idx, server in enumerate(agent.get("mcp_servers", []) or []):
        server_name = str(server.get("name") or f"server-{idx}")
        server_url = str(server.get("url") or "") or None
        credential_names = list(server.get("credential_names", []) or [])
        auth_mode = str(server.get("auth_mode") or "")
        if not auth_mode:
            if credential_names:
                auth_mode = "env-credentials"
            elif server_url and "@" in server_url:
                auth_mode = "url-embedded-credentials"
            elif server_url:
                auth_mode = "network-no-auth-observed"
            else:
                auth_mode = "local-stdio"
        transport = str(server.get("transport") or "")
        stable_id = str(server.get("stable_id") or f"{server_name}:{server.get('command', '')}")
        observation_id = f"{agent_name}:{stable_id}"
        candidate = MCPObservation(
            tenant_id=tenant_id,
            observation_id=observation_id,
            server_stable_id=stable_id,
            server_fingerprint=str(server.get("fingerprint") or stable_id),
            server_name=server_name,
            agent_name=agent_name,
            transport=transport,
            url=server_url,
            auth_mode=auth_mode,
            command=str(server.get("command") or ""),
            args=list(server.get("args", []) or []),
            config_path=server.get("config_path"),
            credential_env_vars=credential_names,
            security_warnings=list(server.get("security_warnings", []) or []),
            observed_via=["fleet_sync"],
            observed_scopes=["endpoint"],
            scan_sources=[],
            source_agents=[agent_name] if server_url and transport.lower() in {"http", "https", "sse"} else [],
            configured_locally=False,
            fleet_present=True,
            gateway_registered=bool(server_url and transport.lower() in {"http", "https", "sse"}),
            runtime_observed=False,
            first_seen=last_discovery,
            last_seen=last_discovery,
            last_synced=last_synced,
        )
        store.put(merge_observations(store.get(tenant_id, observation_id), candidate))


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

        # Hold the per-tenant quota guard across the (check + insert
        # loop) pair so concurrent fleet-sync POSTs serialise per
        # tenant — without this, two replicas can both pass the
        # enforce_fleet_agents_quota check and overshoot the quota by
        # `num_replicas` (audit-5 P1 fleet race fix).
        with tenant_quota_guard(
            tenant_id,
            lambda: enforce_fleet_agents_quota(tenant_id, attempted=len(new_names)),
        ):
            for payload_agent in payload_agents:
                name = payload_agent.get("name", "unknown-agent")
                existing = existing_by_name.get(name)
                server_count, pkg_count, cred_count, vuln_count = _payload_counts(payload_agent)
                score = float(payload_agent.get("trust_score", 0.0) or 0.0)
                factors = dict(payload_agent.get("trust_factors", {}) or {})
                payload_source_id = str(payload_agent.get("source_id") or source_id or "")
                payload_enrollment_name = str(payload_agent.get("enrollment_name") or "")
                payload_mdm_provider = str(payload_agent.get("mdm_provider") or "")
                payload_owner = payload_agent.get("owner")
                payload_environment = payload_agent.get("environment")
                payload_tags = _payload_tags(payload_agent)
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
                    existing.source_id = payload_source_id or existing.source_id
                    existing.enrollment_name = payload_enrollment_name or existing.enrollment_name
                    existing.mdm_provider = payload_mdm_provider or existing.mdm_provider
                    if payload_owner is not None:
                        existing.owner = str(payload_owner or "")
                    if payload_environment is not None:
                        existing.environment = str(payload_environment or "")
                    if payload_tags:
                        existing.tags = payload_tags
                    store.put(existing)
                    updated_count += 1
                else:
                    fleet_agent = FleetAgent(
                        agent_id=str(uuid.uuid4()),
                        name=name,
                        agent_type=str(payload_agent.get("agent_type", "unknown")),
                        config_path="",
                        source_id=payload_source_id,
                        enrollment_name=payload_enrollment_name,
                        mdm_provider=payload_mdm_provider,
                        lifecycle_state=FleetLifecycleState.DISCOVERED,
                        owner=str(payload_owner or "") or None,
                        environment=str(payload_environment or "") or None,
                        tags=payload_tags,
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
                _persist_payload_observations(tenant_id, payload_agent, last_discovery=now, last_synced=now)
    else:
        discovered = discover_all()
        existing_by_name = {agent.name: agent for agent in store.list_by_tenant(tenant_id)}
        discovered_names = {agent.name for agent in discovered}
        new_names = discovered_names - set(existing_by_name)
        # Same per-tenant quota guard as the payload-agents branch.
        with tenant_quota_guard(
            tenant_id,
            lambda: enforce_fleet_agents_quota(tenant_id, attempted=len(new_names)),
        ):
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
    agent = store.get(agent_id, tenant_id=tenant_id)
    if agent is None:
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
    tenant_id = getattr(request.state, "tenant_id", "default")
    actor = getattr(request.state, "api_key_name", "") or "system"
    agent = store.get(agent_id, tenant_id=tenant_id)
    if agent is None:
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
