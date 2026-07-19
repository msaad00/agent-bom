"""The hosted scan path must not sweep the server host's ambient MCP configs
into a tenant's scan. Discovery is scoped to the request's own project paths;
ambient host-wide discovery is opt-in via `discover_host`.
"""

from __future__ import annotations

import uuid

from agent_bom.api.models import JobStatus, ScanJob, ScanRequest
from agent_bom.api.pipeline import _run_scan_sync
from agent_bom.api.store import InMemoryJobStore


def _record_discovery(monkeypatch, store):
    """Patch the pipeline's heavy deps and record every discover_all project_dir."""
    calls: list[str | None] = []

    def fake_discover_all(*args, project_dir=None, **kwargs):
        calls.append(project_dir)
        return []

    monkeypatch.setattr("agent_bom.discovery.discover_all", fake_discover_all)
    monkeypatch.setattr("agent_bom.api.pipeline._get_store", lambda: store)
    monkeypatch.setattr(
        "agent_bom.api.pipeline._sync_scan_agents_to_fleet",
        lambda _agents, tenant_id="default": None,
    )
    monkeypatch.setattr(
        "agent_bom.scanners.scan_agents_sync",
        lambda agents, enable_enrichment=False, **kwargs: [],
    )
    return calls


def _run(store, request):
    job = ScanJob(
        job_id=str(uuid.uuid4()),
        tenant_id="tenant-a",
        status=JobStatus.RUNNING,
        created_at="2026-07-19T00:00:00Z",
        request=request,
    )
    store.put(job)
    _run_scan_sync(job)
    return store.get(job.job_id, tenant_id="tenant-a")


def test_scan_with_projects_scopes_discovery_and_never_touches_host(monkeypatch, tmp_path):
    store = InMemoryJobStore()
    calls = _record_discovery(monkeypatch, store)
    proj = tmp_path / "tenant-project"
    proj.mkdir()

    _run(store, ScanRequest(agent_projects=[str(proj)], offline=True, enrich=False))

    # Discovery is scoped to the submitted project; the host (project_dir=None)
    # is never swept.
    assert str(proj) in calls
    assert None not in calls, "hosted scan must not run ambient host-wide discovery"


def test_scan_without_scope_does_not_sweep_host_by_default(monkeypatch):
    store = InMemoryJobStore()
    calls = _record_discovery(monkeypatch, store)

    _run(store, ScanRequest(offline=True, enrich=False))

    assert None not in calls, "ambient host discovery must be opt-in, not the default"


def test_scan_opts_into_host_discovery_explicitly(monkeypatch):
    store = InMemoryJobStore()
    calls = _record_discovery(monkeypatch, store)

    _run(store, ScanRequest(offline=True, enrich=False, discover_host=True))

    assert None in calls, "discover_host=True must run ambient host-wide discovery"
