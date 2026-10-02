"""API project and filesystem scans run the same secret scan as `agent-bom scan -p`."""

from __future__ import annotations

import uuid

import pytest

from agent_bom.api.models import JobStatus, ScanJob, ScanRequest
from agent_bom.api.pipeline import _run_scan_sync
from agent_bom.api.store import InMemoryJobStore

OPENAI_KEY = "sk-proj-" + "Abc123DefGhi456JklMno789PqrStu012VwxYz345"


def _patch(monkeypatch, store):
    monkeypatch.setattr("agent_bom.discovery.discover_all", lambda *a, **k: [])
    monkeypatch.setattr("agent_bom.api.pipeline._get_store", lambda: store)
    monkeypatch.setattr("agent_bom.api.pipeline._sync_scan_agents_to_fleet", lambda _agents, tenant_id="default": None)
    monkeypatch.setattr("agent_bom.scanners.scan_agents_sync", lambda agents, enable_enrichment=False, **kwargs: [])


def _run(store, request):
    job = ScanJob(
        job_id=str(uuid.uuid4()),
        tenant_id="tenant-a",
        status=JobStatus.RUNNING,
        created_at="2026-09-26T00:00:00Z",
        request=request,
    )
    store.put(job)
    _run_scan_sync(job)
    return store.get(job.job_id, tenant_id="tenant-a")


@pytest.mark.parametrize("field", ["agent_projects", "filesystem_paths"])
@pytest.mark.parametrize("with_packages", [False, True])
def test_local_path_scan_reports_hardcoded_secret(monkeypatch, tmp_path, field, with_packages):
    store = InMemoryJobStore()
    _patch(monkeypatch, store)
    project = tmp_path / "proj"
    (project / "app").mkdir(parents=True)
    (project / "app" / "main.py").write_text(f'OPENAI_KEY = "{OPENAI_KEY}"\n', encoding="utf-8")
    if with_packages:
        (project / "requirements.txt").write_text("requests==2.31.0\n", encoding="utf-8")

    job = _run(store, ScanRequest(**{field: [str(project)]}, offline=True, enrich=False))

    assert job is not None and job.status == JobStatus.DONE, job and job.error
    secrets = job.result["ai_inventory"]["secrets"]
    assert secrets["total"] == 1
    assert secrets["complete"] is True
    assert [(f["file"], f["type"], f["severity"]) for f in secrets["findings"]] == [("app/main.py", "OpenAI API Key", "critical")]
    credential_findings = [f for f in job.result["findings"] if f["finding_type"] == "CREDENTIAL_EXPOSURE"]
    assert len(credential_findings) == 1
    assert credential_findings[0]["title"] == "Hardcoded credential: OpenAI API Key"
    assert OPENAI_KEY not in str(job.result)


def test_clean_local_path_scan_records_coverage_without_findings(monkeypatch, tmp_path):
    store = InMemoryJobStore()
    _patch(monkeypatch, store)
    project = tmp_path / "proj"
    project.mkdir()
    (project / "main.py").write_text("print('hi')\n", encoding="utf-8")

    job = _run(store, ScanRequest(agent_projects=[str(project)], offline=True, enrich=False))

    secrets = job.result["ai_inventory"]["secrets"]
    assert secrets["total"] == 0
    assert secrets["files_scanned"] == 1
    assert secrets["complete"] is True


def test_multiple_roots_keep_findings_distinguishable(monkeypatch, tmp_path):
    store = InMemoryJobStore()
    _patch(monkeypatch, store)
    roots = []
    for name in ("alpha", "beta"):
        root = tmp_path / name
        root.mkdir()
        (root / "main.py").write_text(f'KEY = "{OPENAI_KEY}"\n', encoding="utf-8")
        roots.append(str(root))

    job = _run(store, ScanRequest(agent_projects=roots, offline=True, enrich=False))

    files = sorted(f["file"] for f in job.result["ai_inventory"]["secrets"]["findings"])
    assert files == ["alpha/main.py", "beta/main.py"]


@pytest.mark.parametrize("field", ["agent_projects", "filesystem_paths"])
def test_pii_only_warning_does_not_claim_credentials(monkeypatch, tmp_path, field):
    store = InMemoryJobStore()
    _patch(monkeypatch, store)
    (tmp_path / "config.yaml").write_text("customer_email: alice@example.com\n")
    job = _run(store, ScanRequest(**{field: [str(tmp_path)]}, offline=True, enrich=False))
    assert job.status == JobStatus.DONE
    assert job.result["ai_inventory"]["secrets"]["by_category"] == {"pii": 1}
    warnings = "\n".join(job.result["warnings"])
    assert "1 PII pattern(s)" in warnings
    assert "hardcoded secret(s)" not in warnings
    assert "credential pattern(s)" not in warnings


def test_successful_zero_cve_scan_does_not_invent_network_failure(monkeypatch, tmp_path):
    store = InMemoryJobStore()
    _patch(monkeypatch, store)
    from agent_bom.models import Agent, AgentType, MCPServer, Package

    agent = Agent(
        name="fixture",
        agent_type=AgentType.CUSTOM,
        config_path="fixture",
        mcp_servers=[MCPServer(name="fixture", packages=[Package(name="requests", version="2.31.0", ecosystem="pypi")])],
    )
    monkeypatch.setattr("agent_bom.discovery.discover_all", lambda *a, **k: [agent])
    job = _run(store, ScanRequest(agent_projects=[str(tmp_path)], enrich=False))
    assert job.status == JobStatus.DONE
    assert job.result["summary"]["total_packages"] > 0
    assert not any("network issue" in warning for warning in job.result["warnings"])


def test_actual_lookup_failure_keeps_structured_coverage_warning(monkeypatch, tmp_path):
    from agent_bom.models import Agent, AgentType, MCPServer, Package
    from agent_bom.scanners.state import record_coverage_warning

    store = InMemoryJobStore()
    _patch(monkeypatch, store)
    agent = Agent(
        name="fixture",
        agent_type=AgentType.CUSTOM,
        config_path="fixture",
        mcp_servers=[MCPServer(name="fixture", packages=[Package(name="requests", version="2.31.0", ecosystem="pypi")])],
    )
    monkeypatch.setattr("agent_bom.discovery.discover_all", lambda *a, **k: [agent])

    def failed_lookup(*args, **kwargs):
        record_coverage_warning({"kind": "remote_lookup_error", "release": "pkg:pypi/requests@2.31.0", "message": "OSV lookup unavailable"})
        return []

    monkeypatch.setattr("agent_bom.scanners.scan_agents_sync", failed_lookup)
    job = _run(store, ScanRequest(agent_projects=[str(tmp_path)], enrich=False))
    assert job.status == JobStatus.DONE
    assert job.result["coverage_warnings"][0]["kind"] == "remote_lookup_error"
