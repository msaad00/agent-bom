"""Tenant isolation tests for fleet and schedule routes."""

from __future__ import annotations

from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import patch

import pytest
from fastapi import HTTPException

from agent_bom.api.fleet_store import FleetAgent, FleetLifecycleState, InMemoryFleetStore
from agent_bom.api.models import FleetAgentUpdate, ScheduleCreate, StateUpdate
from agent_bom.api.routes import fleet as fleet_routes
from agent_bom.api.routes import schedules as schedule_routes
from agent_bom.api.schedule_store import InMemoryScheduleStore, ScanSchedule
from agent_bom.api.stores import set_fleet_store, set_schedule_store


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _request(tenant_id: str) -> SimpleNamespace:
    return SimpleNamespace(state=SimpleNamespace(tenant_id=tenant_id))


def _fleet_agent(agent_id: str, tenant_id: str, name: str = "agent") -> FleetAgent:
    ts = _now()
    return FleetAgent(
        agent_id=agent_id,
        name=name,
        agent_type="claude-desktop",
        lifecycle_state=FleetLifecycleState.DISCOVERED,
        trust_score=75.0,
        tenant_id=tenant_id,
        created_at=ts,
        updated_at=ts,
    )


def _schedule(schedule_id: str, tenant_id: str) -> ScanSchedule:
    ts = _now()
    return ScanSchedule(
        schedule_id=schedule_id,
        name=f"{tenant_id}-scan",
        cron_expression="0 */6 * * *",
        scan_config={"path": "."},
        enabled=True,
        next_run=ts,
        created_at=ts,
        updated_at=ts,
        tenant_id=tenant_id,
    )


@pytest.mark.asyncio
async def test_fleet_routes_are_tenant_scoped():
    store = InMemoryFleetStore()
    set_fleet_store(store)
    store.put(_fleet_agent("alpha-1", "tenant-alpha", "alpha"))
    store.put(_fleet_agent("beta-1", "tenant-beta", "beta"))

    req = _request("tenant-alpha")

    data = await fleet_routes.list_fleet(req)
    assert data["count"] == 1
    assert data["agents"][0]["agent_id"] == "alpha-1"

    stats = await fleet_routes.fleet_stats(req)
    assert stats["total"] == 1

    got = await fleet_routes.get_fleet_agent(req, "alpha-1")
    assert got["agent_id"] == "alpha-1"

    with pytest.raises(HTTPException) as exc:
        await fleet_routes.get_fleet_agent(req, "beta-1")
    assert exc.value.status_code == 404

    with pytest.raises(HTTPException) as exc:
        await fleet_routes.update_fleet_state(req, "beta-1", StateUpdate(state="approved"))
    assert exc.value.status_code == 404

    with pytest.raises(HTTPException) as exc:
        await fleet_routes.update_fleet_agent(req, "beta-1", FleetAgentUpdate(owner="alice"))
    assert exc.value.status_code == 404


@pytest.mark.asyncio
async def test_fleet_sync_assigns_request_tenant():
    store = InMemoryFleetStore()
    set_fleet_store(store)
    req = _request("tenant-alpha")

    class _Discovered:
        name = "alpha"
        agent_type = "claude-desktop"
        config_path = "/tmp/alpha.json"
        mcp_servers = []
        version = "1.0"

    with patch("agent_bom.discovery.discover_all", return_value=[_Discovered()]):
        resp = await fleet_routes.sync_fleet(req)

    assert resp["synced"] == 1
    agents = store.list_by_tenant("tenant-alpha")
    assert len(agents) == 1
    assert agents[0].tenant_id == "tenant-alpha"


@pytest.mark.asyncio
async def test_schedule_routes_are_tenant_scoped():
    store = InMemoryScheduleStore()
    set_schedule_store(store)
    store.put(_schedule("sched-alpha", "tenant-alpha"))
    store.put(_schedule("sched-beta", "tenant-beta"))

    req = _request("tenant-alpha")

    items = await schedule_routes.list_schedules(req)
    assert [s["schedule_id"] for s in items] == ["sched-alpha"]

    got = await schedule_routes.get_schedule(req, "sched-alpha")
    assert got["schedule_id"] == "sched-alpha"

    with pytest.raises(HTTPException) as exc:
        await schedule_routes.get_schedule(req, "sched-beta")
    assert exc.value.status_code == 404

    with pytest.raises(HTTPException) as exc:
        await schedule_routes.delete_schedule(req, "sched-beta")
    assert exc.value.status_code == 404

    with pytest.raises(HTTPException) as exc:
        await schedule_routes.toggle_schedule(req, "sched-beta")
    assert exc.value.status_code == 404


@pytest.mark.asyncio
async def test_schedule_create_uses_authenticated_tenant():
    store = InMemoryScheduleStore()
    set_schedule_store(store)
    req = _request("tenant-alpha")

    with pytest.raises(HTTPException) as exc:
        await schedule_routes.create_schedule(
            req,
            ScheduleCreate(
                name="alpha-scan",
                cron_expression="0 */6 * * *",
                scan_config={"path": "."},
                tenant_id="tenant-beta",
            ),
        )
    assert exc.value.status_code == 403

    created = await schedule_routes.create_schedule(
        req,
        ScheduleCreate(
            name="alpha-scan",
            cron_expression="0 */6 * * *",
            scan_config={"path": "."},
        ),
    )
    assert created["tenant_id"] == "tenant-alpha"
