"""Tenant isolation tests for fleet, schedule, and scan job routes."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import patch

import pytest
from fastapi import HTTPException

from agent_bom.api import tenant_quota as tenant_quota_module
from agent_bom.api.audit_log import InMemoryAuditLog, get_audit_log, set_audit_log
from agent_bom.api.fleet_store import FleetAgent, FleetLifecycleState, InMemoryFleetStore
from agent_bom.api.graph_store import SQLiteGraphStore
from agent_bom.api.models import FleetAgentUpdate, JobStatus, PushPayload, ScanJob, ScanRequest, ScheduleCreate, StateUpdate
from agent_bom.api.pipeline import _sync_scan_agents_to_fleet
from agent_bom.api.policy_store import GatewayPolicy, InMemoryPolicyStore
from agent_bom.api.routes import assets as asset_routes
from agent_bom.api.routes import compliance as compliance_routes
from agent_bom.api.routes import discovery as discovery_routes
from agent_bom.api.routes import fleet as fleet_routes
from agent_bom.api.routes import observability as observability_routes
from agent_bom.api.routes import scan as scan_routes
from agent_bom.api.routes import schedules as schedule_routes
from agent_bom.api.schedule_store import InMemoryScheduleStore, ScanSchedule
from agent_bom.api.store import InMemoryJobStore, SQLiteJobStore
from agent_bom.api.stores import _jobs, set_fleet_store, set_graph_store, set_job_store, set_policy_store, set_schedule_store
from agent_bom.asset_tracker import AssetTracker


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _request(tenant_id: str) -> SimpleNamespace:
    return SimpleNamespace(state=SimpleNamespace(tenant_id=tenant_id, api_key_name="tenant-actor"))


@pytest.fixture
def isolated_audit_log():
    original = get_audit_log()
    store = InMemoryAuditLog()
    set_audit_log(store)
    try:
        yield store
    finally:
        set_audit_log(original)


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
async def test_fleet_sync_audit_logs_request_tenant(isolated_audit_log):
    store = InMemoryFleetStore()
    set_fleet_store(store)
    req = _request("tenant-alpha")

    payload = PushPayload(
        source_id="collector-1",
        agents=[{"name": "alpha", "agent_type": "claude-desktop", "trust_score": 70.0, "trust_factors": {}}],
    )

    resp = await fleet_routes.sync_fleet(req, payload)

    assert resp["synced"] == 1
    entries = isolated_audit_log.list_entries()
    assert entries[0].action == "fleet.sync"
    assert entries[0].details["tenant_id"] == "tenant-alpha"


def test_pipeline_fleet_sync_uses_job_tenant_scope():
    store = InMemoryFleetStore()
    set_fleet_store(store)
    store.put(_fleet_agent("beta-1", "tenant-beta", "shared-agent"))

    class _Discovered:
        name = "shared-agent"
        agent_type = "claude-desktop"
        config_path = "/tmp/shared.json"
        mcp_servers = []
        version = "1.0"

    _sync_scan_agents_to_fleet([_Discovered()], tenant_id="tenant-alpha")

    alpha_agents = store.list_by_tenant("tenant-alpha")
    beta_agents = store.list_by_tenant("tenant-beta")
    assert len(alpha_agents) == 1
    assert alpha_agents[0].name == "shared-agent"
    assert alpha_agents[0].tenant_id == "tenant-alpha"
    assert len(beta_agents) == 1
    assert beta_agents[0].agent_id == "beta-1"


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


def test_schedule_store_list_all_accepts_tenant_scope():
    store = InMemoryScheduleStore()
    store.put(_schedule("sched-alpha", "tenant-alpha"))
    store.put(_schedule("sched-beta", "tenant-beta"))

    assert [s.schedule_id for s in store.list_all(tenant_id="tenant-alpha")] == ["sched-alpha"]


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
async def test_schedule_create_audit_logs_authenticated_tenant(isolated_audit_log):
    store = InMemoryScheduleStore()
    set_schedule_store(store)
    req = _request("tenant-alpha")

    await schedule_routes.create_schedule(
        req,
        ScheduleCreate(
            name="alpha-scan",
            cron_expression="0 */6 * * *",
            scan_config={"path": "."},
        ),
    )

    entries = isolated_audit_log.list_entries()
    assert entries[0].action == "schedule.create"
    assert entries[0].details["tenant_id"] == "tenant-alpha"


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
    assert listed["jobs"][0]["error"] is None

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
    req.state.api_key_name = "analyst@example.com"
    req.state.auth_method = "api_key"

    class _Loop:
        def run_in_executor(self, *_args, **_kwargs):
            return None

    monkeypatch.setattr(scan_routes.asyncio, "get_running_loop", lambda: _Loop())

    created = await scan_routes.create_scan(req, ScanRequest())
    assert created.tenant_id == "tenant-alpha"
    assert created.triggered_by == "analyst@example.com"

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
    assert pushed_job.triggered_by == "analyst@example.com:source-a"
    assert pushed_job.completed_at is not None
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
async def test_receive_push_normalizes_report_contract_and_persists_graph(tmp_path):
    store = InMemoryJobStore()
    set_job_store(store)
    set_graph_store(SQLiteGraphStore(tmp_path / "graph.db"))
    _jobs.clear()
    req = _request("tenant-alpha")

    pushed = await observability_routes.receive_push(
        req,
        PushPayload(
            source_id="source-a",
            agents=[
                {
                    "name": "claude-desktop",
                    "agent_type": "claude-desktop",
                    "status": "configured",
                    "mcp_servers": [
                        {
                            "name": "filesystem",
                            "command": "npx",
                            "packages": [
                                {
                                    "name": "pillow",
                                    "ecosystem": "pypi",
                                    "version": "9.0.0",
                                }
                            ],
                            "env": {"OPENAI_API_KEY": "redacted"},
                        }
                    ],
                }
            ],
            blast_radii=[
                {
                    "vulnerability_id": "CVE-2026-0001",
                    "severity": "high",
                    "package": "pillow@9.0.0",
                    "package_name": "pillow",
                    "package_version": "9.0.0",
                    "ecosystem": "pypi",
                    "affected_agents": ["claude-desktop"],
                    "affected_servers": ["filesystem"],
                }
            ],
            warnings=[],
            summary={"total_packages": 1, "total_vulnerabilities": 1},
        ),
    )

    pushed_job = store.get(pushed["job_id"])
    assert pushed_job is not None
    assert pushed_job.result["scan_id"] == pushed["job_id"]
    assert pushed_job.result["blast_radius"][0]["vulnerability_id"] == "CVE-2026-0001"
    assert pushed_job.result["blast_radii"][0]["vulnerability_id"] == "CVE-2026-0001"
    assert pushed_job.result["agents"][0]["type"] == "claude-desktop"
    assert pushed_job.result["agents"][0]["agent_type"] == "claude-desktop"

    graph_store = SQLiteGraphStore(tmp_path / "graph.db")
    snapshots = graph_store.list_snapshots(tenant_id="tenant-alpha")
    assert [snapshot["scan_id"] for snapshot in snapshots] == [pushed["job_id"]]

    graph = graph_store.load_graph(tenant_id="tenant-alpha", scan_id=pushed["job_id"])
    assert "agent:claude-desktop" in graph.nodes
    assert "vuln:CVE-2026-0001" in graph.nodes


@pytest.mark.asyncio
async def test_scan_routes_enforce_active_and_retained_job_quotas(monkeypatch):
    store = InMemoryJobStore()
    set_job_store(store)
    _jobs.clear()
    req = _request("tenant-alpha")

    class _Loop:
        def run_in_executor(self, *_args, **_kwargs):
            return None

    monkeypatch.setattr(scan_routes.asyncio, "get_running_loop", lambda: _Loop())

    pending = ScanJob(
        job_id="job-alpha",
        tenant_id="tenant-alpha",
        status=JobStatus.PENDING,
        created_at=_now(),
        request=ScanRequest(),
    )
    store.put(pending)
    monkeypatch.setattr(tenant_quota_module, "API_MAX_ACTIVE_SCAN_JOBS_PER_TENANT", 1)
    with pytest.raises(HTTPException) as exc:
        await scan_routes.create_scan(req, ScanRequest())
    assert exc.value.status_code == 429
    assert "concurrent scan jobs" in exc.value.detail.lower()

    store = InMemoryJobStore()
    set_job_store(store)
    _jobs.clear()
    completed = ScanJob(
        job_id="job-retained",
        tenant_id="tenant-alpha",
        status=JobStatus.DONE,
        created_at=_now(),
        completed_at=_now(),
        request=ScanRequest(),
    )
    store.put(completed)
    monkeypatch.setattr(tenant_quota_module, "API_MAX_ACTIVE_SCAN_JOBS_PER_TENANT", 10)
    monkeypatch.setattr(tenant_quota_module, "API_MAX_RETAINED_JOBS_PER_TENANT", 1)
    with pytest.raises(HTTPException) as exc:
        await scan_routes.create_scan(req, ScanRequest())
    assert exc.value.status_code == 429
    assert "retained_scan_jobs" in exc.value.detail


@pytest.mark.asyncio
async def test_pushed_results_enforce_retained_job_quota(monkeypatch):
    store = InMemoryJobStore()
    set_job_store(store)
    req = _request("tenant-alpha")
    existing = ScanJob(
        job_id="job-retained",
        tenant_id="tenant-alpha",
        status=JobStatus.DONE,
        created_at=_now(),
        completed_at=_now(),
        request=ScanRequest(),
    )
    store.put(existing)
    monkeypatch.setattr(tenant_quota_module, "API_MAX_RETAINED_JOBS_PER_TENANT", 1)

    with pytest.raises(HTTPException) as exc:
        await observability_routes.receive_push(
            req,
            PushPayload(
                source_id="source-a",
                agents=[],
                blast_radii=[],
                warnings=[],
                summary={"total_packages": 1, "total_vulnerabilities": 1},
            ),
        )
    assert exc.value.status_code == 429
    assert "retained_scan_jobs" in exc.value.detail


@pytest.mark.asyncio
async def test_list_jobs_is_summary_first_and_opt_in_for_hydration():
    class _Store:
        def __init__(self) -> None:
            self.get_calls = 0

        def list_summary(self, tenant_id: str | None = None) -> list[dict]:
            assert tenant_id == "tenant-alpha"
            return [
                {
                    "job_id": "job-alpha",
                    "tenant_id": "tenant-alpha",
                    "status": JobStatus.DONE,
                    "created_at": _now(),
                    "completed_at": _now(),
                    "error": "summary error",
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
        assert listed["jobs"][0]["error"] == "summary error"

        hydrated = await scan_routes.list_jobs(req, include_details=True)
        assert store.get_calls == 1
        assert hydrated["jobs"][0]["request"] == {"images": ["example:latest"]}
        assert hydrated["jobs"][0]["summary"]["total_packages"] == 12


@pytest.mark.asyncio
async def test_schedule_routes_enforce_tenant_schedule_quota(monkeypatch):
    store = InMemoryScheduleStore()
    set_schedule_store(store)
    req = _request("tenant-alpha")
    store.put(_schedule("sched-alpha", "tenant-alpha"))
    monkeypatch.setattr(tenant_quota_module, "API_MAX_SCHEDULES_PER_TENANT", 1)

    with pytest.raises(HTTPException) as exc:
        await schedule_routes.create_schedule(
            req,
            ScheduleCreate(
                name="alpha-scan",
                cron_expression="0 */6 * * *",
                scan_config={"path": "."},
            ),
        )
    assert exc.value.status_code == 429
    assert "schedules" in exc.value.detail


def test_sqlite_job_store_filters_by_tenant(tmp_path):
    store = SQLiteJobStore(str(tmp_path / "jobs.db"))
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

    assert [job.job_id for job in store.list_all(tenant_id="tenant-alpha")] == ["job-alpha"]
    assert [row["job_id"] for row in store.list_summary(tenant_id="tenant-alpha")] == ["job-alpha"]


@pytest.mark.asyncio
async def test_compliance_routes_are_tenant_scoped():
    store = InMemoryJobStore()
    set_job_store(store)
    alpha_job = ScanJob(
        job_id="job-alpha",
        tenant_id="tenant-alpha",
        status=JobStatus.DONE,
        created_at=_now(),
        completed_at=_now(),
        request=ScanRequest(),
        result={
            "blast_radius": [
                {
                    "vulnerability_id": "CVE-alpha",
                    "severity": "critical",
                    "package": "alpha@1.0.0",
                    "affected_agents": ["alpha-agent"],
                    "owasp_tags": ["LLM01"],
                }
            ],
            "summary": {"total_agents": 1, "total_packages": 1},
            "posture_scorecard": {"grade": "A", "score": 97},
            "credential_risk_ranking": [{"name": "ALPHA_KEY"}],
            "incident_correlation": [{"agent": "alpha-agent"}],
        },
    )
    beta_job = ScanJob(
        job_id="job-beta",
        tenant_id="tenant-beta",
        status=JobStatus.DONE,
        created_at=_now(),
        completed_at=_now(),
        request=ScanRequest(),
        result={
            "blast_radius": [
                {
                    "vulnerability_id": "CVE-beta",
                    "severity": "high",
                    "package": "beta@1.0.0",
                    "affected_agents": ["beta-agent"],
                    "owasp_tags": ["LLM01"],
                }
            ],
            "summary": {"total_agents": 1, "total_packages": 1},
            "posture_scorecard": {"grade": "F", "score": 10},
            "credential_risk_ranking": [{"name": "BETA_KEY"}],
            "incident_correlation": [{"agent": "beta-agent"}],
        },
    )
    store.put(alpha_job)
    store.put(beta_job)

    req = _request("tenant-alpha")

    compliance = await compliance_routes.get_compliance(req)
    assert compliance["scan_count"] == 1
    llm01 = next(control for control in compliance["owasp_llm_top10"] if control["code"] == "LLM01")
    assert llm01["affected_agents"] == ["alpha-agent"]

    scorecard = await compliance_routes.get_posture_scorecard(req)
    assert scorecard["score"] == 97

    counts = await compliance_routes.get_posture_counts(req)
    assert counts["critical"] == 1
    assert counts["high"] == 0

    creds = await compliance_routes.get_credential_risk_ranking(req)
    assert creds["credentials"] == [{"name": "ALPHA_KEY"}]

    incidents = await compliance_routes.get_incident_correlation(req)
    assert incidents["incidents"] == [{"agent": "alpha-agent"}]


@pytest.mark.asyncio
async def test_discovery_and_traces_are_tenant_scoped():
    store = InMemoryJobStore()
    set_job_store(store)
    alpha_job = ScanJob(
        job_id="job-alpha",
        tenant_id="tenant-alpha",
        status=JobStatus.DONE,
        created_at=_now(),
        completed_at=_now(),
        request=ScanRequest(),
        result={
            "blast_radius": [
                {
                    "vulnerability_id": "CVE-alpha",
                    "severity": "critical",
                    "package": "langchain",
                    "affected_agents": ["alpha"],
                    "affected_servers": ["sqlite-mcp"],
                }
            ]
        },
    )
    beta_job = ScanJob(
        job_id="job-beta",
        tenant_id="tenant-beta",
        status=JobStatus.DONE,
        created_at=_now(),
        completed_at=_now(),
        request=ScanRequest(),
        result={
            "blast_radius": [
                {
                    "vulnerability_id": "CVE-beta",
                    "severity": "high",
                    "package": "requests",
                    "affected_agents": ["beta"],
                    "affected_servers": ["beta-mcp"],
                }
            ]
        },
    )
    store.put(alpha_job)
    store.put(beta_job)

    req = _request("tenant-alpha")

    @dataclass
    class _Server:
        name: str = "sqlite-mcp"
        packages: list = field(default_factory=list)
        tools: list = field(default_factory=list)
        credential_names: list[str] = field(default_factory=list)
        env: dict = field(default_factory=dict)
        transport: str = "stdio"

    @dataclass
    class _Agent:
        name: str = "alpha"
        agent_type: str = "claude-desktop"
        mcp_servers: list[_Server] = field(default_factory=lambda: [_Server()])

    with patch("agent_bom.discovery.discover_all", return_value=[_Agent()]):
        with patch("agent_bom.parsers.extract_packages", return_value=[]):
            detail = await discovery_routes.get_agent_detail(req, "alpha")
            assert [item["vulnerability_id"] for item in detail["blast_radius"]] == ["CVE-alpha"]

    def _parse(_body: dict) -> list:
        from agent_bom.otel_ingest import ToolCallTrace

        return [ToolCallTrace(trace_id="t1", span_id="s1", tool_name="read_file", server_name="sqlite-mcp", package_name="langchain")]

    def _flag(_traces, vuln_packages, vuln_servers):
        assert vuln_packages == {"langchain": ["CVE-alpha"]}
        assert vuln_servers == {"sqlite-mcp": ["CVE-alpha"]}
        from agent_bom.otel_ingest import FlaggedCall, ToolCallTrace

        return [
            FlaggedCall(
                trace=ToolCallTrace(
                    trace_id="t1",
                    span_id="s1",
                    tool_name="read_file",
                    server_name="sqlite-mcp",
                    package_name="langchain",
                ),
                reason="Tool hit package langchain with known CVE",
                severity="high",
                server="sqlite-mcp",
                package_name="langchain",
                matched_cves=["CVE-alpha"],
            )
        ]

    class _Analytics:
        def __init__(self):
            self.events = []
            self.event_tenants: list[str] = []

        def record_events(self, events, *, tenant_id: str = "default"):
            self.events.extend(events)
            self.event_tenants.append(tenant_id)

        def record_event(self, event, *, tenant_id: str = "default"):
            self.events.append(event)
            self.event_tenants.append(tenant_id)

    analytics = _Analytics()

    with patch("agent_bom.otel_ingest.parse_otel_traces", side_effect=_parse):
        with patch("agent_bom.otel_ingest.flag_vulnerable_tool_calls", side_effect=_flag):
            with patch("agent_bom.api.routes.observability._get_analytics_store", return_value=analytics):
                result = await observability_routes.ingest_traces(req, {"resourceSpans": []})
    assert result["traces"] == 1
    assert result["persisted_events"] == 1
    assert analytics.events[0]["event_type"] == "vulnerable_tool_call"
    assert analytics.events[0]["detector"] == "otel_vulnerable_tool_call"
    # Trace analytics ingest must carry the authed tenant through to
    # ClickHouse so cross-tenant queries cannot see each other's events.
    assert analytics.event_tenants[0] == req.state.tenant_id


@pytest.mark.asyncio
async def test_asset_routes_are_tenant_scoped(tmp_path, monkeypatch):
    db_path = tmp_path / "assets.db"
    monkeypatch.setattr("agent_bom.asset_tracker.DEFAULT_DB_PATH", db_path)

    alpha = AssetTracker(db_path=db_path, tenant_id="tenant-alpha")
    beta = AssetTracker(db_path=db_path, tenant_id="tenant-beta")
    try:
        alpha.record_scan(
            {
                "blast_radius": [
                    {
                        "vulnerability_id": "CVE-alpha",
                        "package": "langchain",
                        "ecosystem": "pip",
                        "severity": "critical",
                    }
                ]
            }
        )
        beta.record_scan(
            {
                "blast_radius": [
                    {
                        "vulnerability_id": "CVE-beta",
                        "package": "requests",
                        "ecosystem": "pip",
                        "severity": "high",
                    }
                ]
            }
        )

        req = _request("tenant-alpha")
        data = await asset_routes.list_assets(req)
        assert data["count"] == 1
        assert [asset["vuln_id"] for asset in data["assets"]] == ["CVE-alpha"]

        stats = await asset_routes.get_asset_stats(req)
        assert stats["stats"]["total"] == 1
        assert stats["stats"]["critical_open"] == 1
    finally:
        alpha.close()
        beta.close()


@pytest.mark.asyncio
async def test_ocsf_ingest_is_tenant_scoped_and_audited(isolated_audit_log):
    req = _request("tenant-alpha")

    class _Analytics:
        def __init__(self):
            self.events = []
            self.event_tenants: list[str] = []

        def record_events(self, events, *, tenant_id: str = "default"):
            self.events.extend(events)
            self.event_tenants.append(tenant_id)

    analytics = _Analytics()
    payload = {
        "events": [
            {
                "class_uid": 2004,
                "class_name": "Detection Finding",
                "severity_id": 4,
                "message": "Prompt injection detected",
                "time": 1_746_033_600_000,
                "finding_info": {
                    "uid": "finding-1",
                    "types": ["prompt_injection"],
                    "analytic": {"name": "prompt_injection"},
                },
                "resources": [{"name": "github-mcp"}],
                "metadata": {"product": {"name": "splunk"}},
            },
            {
                "class_uid": 4001,
                "class_name": "Network Activity",
                "severity": "Low",
                "time": 1_746_033_601_000,
                "message": "Outbound MCP request observed",
                "resources": [{"name": "proxy-relay"}],
                "metadata": {"product": {"name": "datadog"}},
            },
        ]
    }

    with patch("agent_bom.api.routes.observability._get_analytics_store", return_value=analytics):
        result = await observability_routes.ingest_ocsf(req, payload)

    assert result == {
        "ingested": 2,
        "tenant_id": "tenant-alpha",
        "class_counts": {"2004": 1, "4001": 1},
        "sources": ["datadog", "splunk"],
    }
    assert analytics.event_tenants == ["tenant-alpha"]
    assert analytics.events[0]["tenant_id"] == "tenant-alpha"
    assert analytics.events[0]["event_type"] == "ocsf_detection_finding"
    assert analytics.events[0]["detector"] == "prompt_injection"
    assert analytics.events[0]["tool_name"] == "github-mcp"
    assert analytics.events[0]["source_id"] == "splunk"
    assert analytics.events[1]["event_type"] == "ocsf_network_activity"
    assert analytics.events[1]["severity"] == "low"
    entries = isolated_audit_log.list_entries()
    assert entries[0].action == "ocsf.ingest"
    assert entries[0].details["tenant_id"] == "tenant-alpha"
    assert entries[0].details["batch_size"] == 2
    assert entries[0].details["class_counts"] == {"2004": 1, "4001": 1}


@pytest.mark.asyncio
async def test_ocsf_ingest_rejects_non_event_payload():
    req = _request("tenant-alpha")

    with pytest.raises(HTTPException) as exc:
        await observability_routes.ingest_ocsf(req, {"unsupported": True})

    assert exc.value.status_code == 400
    assert "expects a single event" in exc.value.detail


@pytest.mark.asyncio
async def test_posture_counts_include_deployment_context_by_tenant():
    job_store = InMemoryJobStore()
    fleet_store = InMemoryFleetStore()
    policy_store = InMemoryPolicyStore()
    set_job_store(job_store)
    set_fleet_store(fleet_store)
    set_policy_store(policy_store)

    alpha_job = ScanJob(
        job_id="job-alpha-context",
        tenant_id="tenant-alpha",
        status=JobStatus.DONE,
        created_at=_now(),
        completed_at=_now(),
        request=ScanRequest(),
        result={
            "blast_radius": [
                {
                    "vulnerability_id": "CVE-alpha",
                    "severity": "critical",
                    "package": "alpha@1.0.0",
                    "cisa_kev": True,
                    "reachable_tools": ["exec"],
                    "affected_agents": ["alpha-agent"],
                }
            ],
            "has_mcp_context": True,
            "has_agent_context": True,
            "scan_sources": ["agent_discovery", "github_actions", "k8s", "sbom"],
            "runtime_session_graph": {"node_count": 3, "edge_count": 2},
        },
    )
    beta_job = ScanJob(
        job_id="job-beta-context",
        tenant_id="tenant-beta",
        status=JobStatus.DONE,
        created_at=_now(),
        completed_at=_now(),
        request=ScanRequest(),
        result={
            "blast_radius": [
                {
                    "vulnerability_id": "CVE-beta",
                    "severity": "high",
                    "package": "beta@1.0.0",
                    "affected_agents": ["beta-agent"],
                }
            ],
            "scan_sources": ["sbom"],
        },
    )
    job_store.put(alpha_job)
    job_store.put(beta_job)

    alpha_fleet = _fleet_agent("alpha-fleet-1", "tenant-alpha", "alpha-agent")
    alpha_fleet.environment = "eks"
    fleet_store.put(alpha_fleet)
    policy_store.put_policy(
        GatewayPolicy(
            policy_id="policy-alpha",
            name="alpha-gateway",
            tenant_id="tenant-alpha",
            bound_agents=["alpha-agent"],
        )
    )

    counts = await compliance_routes.get_posture_counts(_request("tenant-alpha"))

    assert counts["critical"] == 1
    assert counts["deployment_mode"] == "hybrid"
    assert counts["has_local_scan"] is True
    assert counts["has_fleet_ingest"] is True
    assert counts["has_cluster_scan"] is True
    assert counts["has_ci_cd_scan"] is True
    assert counts["has_gateway"] is True
    assert counts["has_proxy"] is True
    assert counts["has_traces"] is True
    assert counts["has_registry"] is True
    assert counts["scan_count"] == 1
