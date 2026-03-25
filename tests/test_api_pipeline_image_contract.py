from __future__ import annotations

from agent_bom.api.models import JobStatus, ScanJob, ScanRequest
from agent_bom.api.pipeline import _run_scan_sync
from agent_bom.models import Package


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
    monkeypatch.setattr("agent_bom.api.pipeline._sync_scan_agents_to_fleet", lambda _agents: None)
    monkeypatch.setattr("agent_bom.discovery.discover_all", lambda *args, **kwargs: [])
    monkeypatch.setattr(
        "agent_bom.image.scan_image",
        lambda image_ref: ([Package(name="openssl", version="3.0.16", ecosystem="deb")], "native"),
    )
    monkeypatch.setattr("agent_bom.scanners.scan_agents_sync", lambda agents, enable_enrichment=False: [])

    _run_scan_sync(job)

    assert job.status == JobStatus.DONE
    assert store.jobs[-1].job_id == "img-123"
    assert job.result is not None
    assert job.result["summary"]["total_agents"] == 1
    assert job.result["agents"][0]["source"] == "image"
    assert job.result["agents"][0]["mcp_servers"][0]["surface"] == "container-image"
