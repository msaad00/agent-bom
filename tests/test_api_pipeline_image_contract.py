from __future__ import annotations

import json

from agent_bom.api.models import JobStatus, ScanJob, ScanRequest
from agent_bom.api.pipeline import _run_scan_sync
from agent_bom.models import BlastRadius, Package, Severity, Vulnerability


class _DummyStore:
    def __init__(self) -> None:
        self.jobs: list[ScanJob] = []

    def put(self, job: ScanJob) -> None:
        self.jobs.append(job)


def test_api_pipeline_image_scan_uses_container_surface(monkeypatch):
    store = _DummyStore()
    job = ScanJob(
        job_id="img-123",
        created_at="2026-03-25T12:00:00Z",
        request=ScanRequest(images=["agentbom/agent-bom:latest"], enrich=False),
    )

    monkeypatch.setattr("agent_bom.api.pipeline._get_store", lambda: store)
    monkeypatch.setattr("agent_bom.api.pipeline._sync_scan_agents_to_fleet", lambda _agents, tenant_id="default": None)
    monkeypatch.setattr("agent_bom.discovery.discover_all", lambda *args, **kwargs: [])
    monkeypatch.setattr(
        "agent_bom.image.scan_image",
        lambda image_ref: ([Package(name="openssl", version="3.0.16", ecosystem="deb")], "native"),
    )
    monkeypatch.setattr("agent_bom.scanners.scan_agents_sync", lambda agents, enable_enrichment=False, **kwargs: [])

    _run_scan_sync(job)

    assert job.status == JobStatus.DONE
    assert store.jobs[-1].job_id == "img-123"
    assert job.result is not None
    assert job.result["summary"]["total_agents"] == 1
    assert job.result["agents"][0]["source"] == "image"
    assert job.result["agents"][0]["mcp_servers"][0]["surface"] == "container-image"


def test_api_pipeline_persists_clickhouse_analytics(monkeypatch):
    store = _DummyStore()
    job = ScanJob(
        job_id="clickhouse-123",
        tenant_id="tenant-blue",
        created_at="2026-03-25T12:00:00Z",
        request=ScanRequest(images=["agentbom/agent-bom:latest"], enrich=False),
    )

    class _AnalyticsStore:
        def __init__(self) -> None:
            self.scan_calls: list[tuple[str, str, list[dict], str]] = []
            self.metadata_calls: list[tuple[dict, str]] = []
            self.posture_calls: list[tuple[str, dict, str]] = []
            self.fleet_calls: list[dict] = []
            self.compliance_calls: list[tuple[dict, str]] = []
            self.cis_check_calls: list[tuple[list[dict], str]] = []

        def record_scan(
            self,
            scan_id: str,
            agent_name: str,
            findings: list[dict],
            *,
            tenant_id: str = "default",
        ) -> None:
            self.scan_calls.append((scan_id, agent_name, findings, tenant_id))

        def record_scan_metadata(self, metadata: dict, *, tenant_id: str = "default") -> None:
            self.metadata_calls.append((metadata, tenant_id))

        def record_posture(self, agent_name: str, snapshot: dict, *, tenant_id: str = "default") -> None:
            self.posture_calls.append((agent_name, snapshot, tenant_id))

        def record_fleet_snapshot(self, snapshot: dict) -> None:
            self.fleet_calls.append(snapshot)

        def record_compliance_control(self, control: dict, *, tenant_id: str = "default") -> None:
            self.compliance_calls.append((control, tenant_id))

        def record_cis_benchmark_checks(self, checks: list[dict], *, tenant_id: str = "default") -> None:
            self.cis_check_calls.append((checks, tenant_id))

    analytics = _AnalyticsStore()

    monkeypatch.setattr("agent_bom.api.pipeline._get_store", lambda: store)
    monkeypatch.setattr("agent_bom.api.pipeline._get_analytics_store", lambda: analytics)
    monkeypatch.setattr("agent_bom.api.pipeline._sync_scan_agents_to_fleet", lambda _agents, tenant_id="default": None)
    monkeypatch.setattr("agent_bom.discovery.discover_all", lambda *args, **kwargs: [])
    monkeypatch.setattr(
        "agent_bom.image.scan_image",
        lambda image_ref: ([Package(name="openssl", version="3.0.16", ecosystem="deb")], "native"),
    )

    def _fake_scan(agents, enable_enrichment=False, **kwargs):
        assert kwargs.get("offline") is False
        agent = agents[0]
        server = agent.mcp_servers[0]
        pkg = server.packages[0]
        vuln = Vulnerability(
            id="CVE-2026-0001",
            summary="test vuln",
            severity=Severity.HIGH,
            cvss_score=8.1,
            epss_score=0.42,
            advisory_sources=["osv", "nvd"],
        )
        pkg.vulnerabilities = [vuln]
        br = BlastRadius(
            vulnerability=vuln,
            package=pkg,
            affected_servers=[server],
            affected_agents=[agent],
            exposed_credentials=[],
            exposed_tools=[],
            cmmc_tags=["RA.L2-3.11.2"],
        )
        br.calculate_risk_score()
        return [br]

    monkeypatch.setattr("agent_bom.scanners.scan_agents_sync", _fake_scan)

    _run_scan_sync(job)

    assert job.status == JobStatus.DONE
    assert analytics.scan_calls
    assert analytics.metadata_calls
    assert analytics.posture_calls
    assert analytics.fleet_calls
    assert analytics.compliance_calls

    scan_id, agent_name, findings, scan_tenant = analytics.scan_calls[0]
    assert scan_id == "clickhouse-123"
    assert agent_name == "image:agentbom/agent-bom:latest"
    assert findings[0]["package_name"] == "openssl"
    assert findings[0]["source"] == "osv"
    assert scan_tenant == "tenant-blue"

    metadata, metadata_tenant = analytics.metadata_calls[0]
    assert metadata["scan_id"] == "clickhouse-123"
    assert metadata["source"] == "api"
    assert metadata["agent_count"] == 1
    assert metadata["vuln_count"] == 1
    assert metadata_tenant == "tenant-blue"

    posture_agent, snapshot, posture_tenant = analytics.posture_calls[0]
    assert posture_agent == "image:agentbom/agent-bom:latest"
    assert snapshot["high"] == 1
    assert snapshot["total_packages"] == 1
    assert posture_tenant == "tenant-blue"

    # Compliance controls also carry the scan tenant through to the store
    for _, control_tenant in analytics.compliance_calls:
        assert control_tenant == "tenant-blue"

    assert analytics.fleet_calls[0]["agent_name"] == "image:agentbom/agent-bom:latest"
    assert analytics.fleet_calls[0]["lifecycle_state"] == "discovered"
    assert analytics.fleet_calls[0]["tenant_id"] == "tenant-blue"
    assert any(control["framework"] == "owasp-llm-top10" for control, _ in analytics.compliance_calls)


def test_api_pipeline_persists_unified_graph_snapshot(monkeypatch):
    store = _DummyStore()
    job = ScanJob(
        job_id="graph-123",
        tenant_id="tenant-blue",
        created_at="2026-03-25T12:00:00Z",
        request=ScanRequest(images=["agentbom/agent-bom:latest"], enrich=False),
    )
    persisted: list[tuple[str, str]] = []

    monkeypatch.setattr("agent_bom.api.pipeline._get_store", lambda: store)
    monkeypatch.setattr("agent_bom.api.pipeline._sync_scan_agents_to_fleet", lambda _agents, tenant_id="default": None)
    monkeypatch.setattr(
        "agent_bom.api.pipeline._persist_graph_snapshot",
        lambda j, report_json, lock=None: persisted.append((j.tenant_id, report_json["scan_id"])),
    )
    monkeypatch.setattr("agent_bom.discovery.discover_all", lambda *args, **kwargs: [])
    monkeypatch.setattr(
        "agent_bom.image.scan_image",
        lambda image_ref: ([Package(name="openssl", version="3.0.16", ecosystem="deb")], "native"),
    )
    monkeypatch.setattr("agent_bom.scanners.scan_agents_sync", lambda agents, enable_enrichment=False, **kwargs: [])

    _run_scan_sync(job)

    assert job.status == JobStatus.DONE
    assert persisted == [("tenant-blue", "graph-123")]


def test_api_pipeline_reports_enrichment_as_part_of_scanning(monkeypatch):
    store = _DummyStore()
    job = ScanJob(
        job_id="enrich-123",
        tenant_id="tenant-blue",
        created_at="2026-03-25T12:00:00Z",
        request=ScanRequest(images=["agentbom/agent-bom:latest"], enrich=True),
    )

    monkeypatch.setattr("agent_bom.api.pipeline._get_store", lambda: store)
    monkeypatch.setattr("agent_bom.api.pipeline._sync_scan_agents_to_fleet", lambda _agents, tenant_id="default": None)
    monkeypatch.setattr("agent_bom.api.pipeline._persist_graph_snapshot", lambda *_args, **_kwargs: None)
    monkeypatch.setattr("agent_bom.discovery.discover_all", lambda *args, **kwargs: [])
    monkeypatch.setattr(
        "agent_bom.image.scan_image",
        lambda image_ref: ([Package(name="openssl", version="3.0.16", ecosystem="deb")], "native"),
    )

    def _fake_scan(agents, enable_enrichment=False, **kwargs):
        assert enable_enrichment is True
        assert kwargs.get("offline") is False
        return []

    monkeypatch.setattr("agent_bom.scanners.scan_agents_sync", _fake_scan)

    _run_scan_sync(job)

    events = [json.loads(line) for line in job.progress if line.startswith("{")]
    enrichment_events = [event for event in events if event["step_id"] == "enrichment"]
    scanning_events = [event for event in events if event["step_id"] == "scanning"]

    assert job.status == JobStatus.DONE
    assert not any(event["status"] == "running" for event in enrichment_events)
    assert enrichment_events[-1]["status"] == "done"
    assert enrichment_events[-1]["message"] == "Enrichment completed during scanning"
    assert enrichment_events[-1]["stats"]["executed_in_step"] == "scanning"
    assert any("with vulnerability enrichment" in event["message"] for event in scanning_events)
