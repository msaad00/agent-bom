"""Tenant isolation tests for fleet, schedule, and scan job routes."""

from __future__ import annotations

from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import patch

import pytest
from fastapi import HTTPException

from agent_bom.api.fleet_store import FleetAgent, FleetLifecycleState, InMemoryFleetStore
from agent_bom.api.models import FleetAgentUpdate, JobStatus, PushPayload, ScanJob, ScanRequest, ScheduleCreate, StateUpdate
from agent_bom.api.routes import fleet as fleet_routes
from agent_bom.api.routes import observability as observability_routes
from agent_bom.api.routes import scan as scan_routes
from agent_bom.api.routes import schedules as schedule_routes
from agent_bom.api.schedule_store import InMemoryScheduleStore, ScanSchedule
from agent_bom.api.store import InMemoryJobStore
from agent_bom.api.stores import _jobs, set_fleet_store, set_job_store, set_schedule_store


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


@pytest.mark.asyncio
async def test_scan_routes_are_tenant_scoped():
    store = InMemoryJobStore()
    set_job_store(store)
    _jobs.clear()

    alpha_job = ScanJob(
        job_id="job-alpha",
        tenant_id="tenant-alpha",
        status=JobStatus.DONE,
        created_at=_now(),
        request=ScanRequest(),
    )
    beta_job = ScanJob(
        job_id="job-beta",
        tenant_id="tenant-beta",
        status=JobStatus.DONE,
        created_at=_now(),
        request=ScanRequest(),
    )
    store.put(alpha_job)
    store.put(beta_job)
    _jobs_put = _jobs.__setitem__
    _jobs_put(alpha_job.job_id, alpha_job)
    _jobs_put(beta_job.job_id, beta_job)

    req = _request("tenant-alpha")

    listed = await scan_routes.list_jobs(req)
    assert [j["job_id"] for j in listed["jobs"]] == ["job-alpha"]
    assert listed["jobs"][0]["tenant_id"] == "tenant-alpha"
    assert listed["jobs"][0]["request"] == {}
    assert listed["jobs"][0]["summary"] is None

    got = await scan_routes.get_scan(req, "job-alpha")
    assert got.job_id == "job-alpha"
    assert got.tenant_id == "tenant-alpha"

    with pytest.raises(HTTPException) as exc:
        await scan_routes.get_scan(req, "job-beta")
    assert exc.value.status_code == 404


@pytest.mark.asyncio
async def test_create_scan_and_push_stamp_request_tenant(monkeypatch):
    store = InMemoryJobStore()
    set_job_store(store)
    _jobs.clear()
    req = _request("tenant-alpha")

    class _Loop:
        def run_in_executor(self, *_args, **_kwargs):
            return None

    monkeypatch.setattr(scan_routes.asyncio, "get_running_loop", lambda: _Loop())

    created = await scan_routes.create_scan(req, ScanRequest())
    assert created.tenant_id == "tenant-alpha"

    pushed = await observability_routes.receive_push(
        req,
        PushPayload(
            source_id="source-a",
            agents=[],
            blast_radii=[],
            warnings=[],
            summary={"total_packages": 12, "total_vulnerabilities": 55},
            posture_scorecard={"overall_score": 82},
        ),
    )
    pushed_job = store.get(pushed["job_id"])
    assert pushed_job is not None
    assert pushed_job.tenant_id == "tenant-alpha"
    assert pushed_job.result["summary"]["total_packages"] == 12
    assert pushed_job.result["posture_scorecard"]["overall_score"] == 82

    listed = await scan_routes.list_jobs(req)
    pushed_summary = next(job for job in listed["jobs"] if job["job_id"] == pushed["job_id"])
    assert "summary" not in pushed_summary
    assert listed["jobs"][0]["request"] == {}

    hydrated = await scan_routes.list_jobs(req, include_details=True)
    pushed_hydrated = next(job for job in hydrated["jobs"] if job["job_id"] == pushed["job_id"])
    assert pushed_hydrated["summary"]["total_packages"] == 12


@pytest.mark.asyncio
async def test_list_jobs_is_summary_first_and_opt_in_for_hydration():
    class _Store:
        def __init__(self) -> None:
            self.get_calls = 0

        def list_summary(self) -> list[dict]:
            return [
                {
                    "job_id": "job-alpha",
                    "tenant_id": "tenant-alpha",
                    "status": JobStatus.DONE,
                    "created_at": _now(),
                    "completed_at": _now(),
                }
            ]

        def get(self, job_id: str) -> ScanJob | None:
            self.get_calls += 1
            return ScanJob(
                job_id=job_id,
                tenant_id="tenant-alpha",
                status=JobStatus.DONE,
                created_at=_now(),
                completed_at=_now(),
                request=ScanRequest(images=["example:latest"]),
                result={"summary": {"total_packages": 12, "total_vulnerabilities": 3}},
            )

    req = _request("tenant-alpha")
    store = _Store()

    with patch.object(scan_routes, "_get_store", return_value=store):
        listed = await scan_routes.list_jobs(req)
        assert store.get_calls == 0
        assert listed["jobs"][0]["job_id"] == "job-alpha"
        assert "request" not in listed["jobs"][0]
        assert "summary" not in listed["jobs"][0]

        hydrated = await scan_routes.list_jobs(req, include_details=True)
        assert store.get_calls == 1
        assert hydrated["jobs"][0]["request"] == {"images": ["example:latest"]}
        assert hydrated["jobs"][0]["summary"]["total_packages"] == 12
