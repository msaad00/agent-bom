"""A cold ``/v1/posture`` parses each persisted job payload once per request.

Job payloads can be tens of megabytes. Every aggregate on the posture path
(latest-scan selection, the overview fold, the current-graph resolver, the
finding spine) reads the tenant's jobs; within one request they must share a
single parse of each exact payload, while separate requests and reads outside
an aggregate scope still get independent objects.
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest
from starlette.testclient import TestClient

from agent_bom.api.finding_read_context import finding_read_scope
from agent_bom.api.models import JobStatus, ScanJob, ScanRequest
from agent_bom.api.server import app, set_job_store
from agent_bom.api.store import InMemoryJobStore, SQLiteJobStore
from agent_bom.finding import Asset, Finding, FindingSource, FindingType
from tests.auth_helpers import disable_trusted_proxy_env, enable_trusted_proxy_env, proxy_headers

TENANT = "posture-cold-reads"


def setup_module() -> None:
    enable_trusted_proxy_env()


def teardown_module() -> None:
    disable_trusted_proxy_env()
    set_job_store(InMemoryJobStore())


def _job(tenant: str, job_id: str = "cold-scan") -> ScanJob:
    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    job = ScanJob(job_id=job_id, tenant_id=tenant, created_at=stamp, request=ScanRequest())
    job.status = JobStatus.DONE
    job.completed_at = stamp
    job.result = {
        "summary": {"total_packages": 1, "total_findings": 1},
        "findings": [
            Finding(
                finding_type=FindingType.CVE,
                source=FindingSource.MCP_SCAN,
                asset=Asset(name="requests", asset_type="package", identifier="pkg:pypi/requests@2.0.0"),
                severity="critical",
                cve_id="CVE-2026-7000",
            ).to_dict()
        ],
        "posture_scorecard": {"grade": "C", "score": 70.0, "summary": "scan", "dimensions": {}},
    }
    return job


@pytest.fixture
def parses(monkeypatch):
    calls: list[str] = []
    original = ScanJob.model_validate_json.__func__  # type: ignore[attr-defined]

    def counting(cls, data, *args, **kwargs):
        calls.append(cls.__name__)
        return original(cls, data, *args, **kwargs)

    monkeypatch.setattr(ScanJob, "model_validate_json", classmethod(counting))
    return calls


@pytest.fixture
def sqlite_store(tmp_path):
    store = SQLiteJobStore(str(tmp_path / "jobs.db"))
    set_job_store(store)
    yield store
    set_job_store(InMemoryJobStore())


def _reset_read_caches() -> None:
    from agent_bom.api.compliance_hub_store import get_compliance_hub_store
    from agent_bom.api.routes import compliance, overview

    get_compliance_hub_store().clear(TENANT)
    compliance._POSTURE_COUNTS_CACHE.clear()
    overview._reset_overview_cache()


def test_cold_posture_request_parses_the_job_payload_once(sqlite_store, parses) -> None:
    sqlite_store.put(_job(TENANT))
    _reset_read_caches()
    client = TestClient(app)
    parses.clear()

    response = client.get("/v1/posture", headers=proxy_headers(role="analyst", tenant=TENANT))

    assert response.status_code == 200
    assert response.json()["basis"] == "exec_posture"
    assert len(parses) <= 1, parses


def test_scoped_reads_share_one_parse_of_an_unchanged_payload(sqlite_store, parses) -> None:
    sqlite_store.put(_job(TENANT))
    with finding_read_scope():
        listed = sqlite_store.list_all(tenant_id=TENANT)
        again = sqlite_store.list_all(tenant_id=TENANT)
        fetched = sqlite_store.get("cold-scan", tenant_id=TENANT)
    assert listed[0] is again[0] is fetched
    assert len(parses) == 1


def test_a_write_inside_the_scope_is_read_back(sqlite_store) -> None:
    sqlite_store.put(_job(TENANT))
    with finding_read_scope():
        before = sqlite_store.list_all(tenant_id=TENANT)[0]
        changed = _job(TENANT)
        changed.result = {**(changed.result or {}), "summary": {"total_packages": 9}}
        sqlite_store.put(changed)
        after = sqlite_store.list_all(tenant_id=TENANT)[0]
    assert after is not before
    assert (after.result or {})["summary"] == {"total_packages": 9}


def test_unscoped_reads_return_independent_objects(sqlite_store, parses) -> None:
    sqlite_store.put(_job(TENANT))
    first = sqlite_store.list_all(tenant_id=TENANT)[0]
    first.result["summary"] = "mutated"  # type: ignore[index]
    assert sqlite_store.list_all(tenant_id=TENANT)[0].result["summary"] == {"total_packages": 1, "total_findings": 1}  # type: ignore[index]
    assert len(parses) == 2


def test_scoped_reads_never_cross_tenants(sqlite_store) -> None:
    other = TENANT + "-other"
    sqlite_store.put(_job(TENANT))
    sqlite_store.put(_job(other))
    with finding_read_scope():
        mine = sqlite_store.list_all(tenant_id=TENANT)
        theirs = sqlite_store.list_all(tenant_id=other)
        assert sqlite_store.get("cold-scan", tenant_id=other).tenant_id == other  # type: ignore[union-attr]
    assert [job.tenant_id for job in mine] == [TENANT]
    assert [job.tenant_id for job in theirs] == [other]


def test_warm_posture_does_not_parse_jobs_and_write_invalidates(sqlite_store, parses):
    sqlite_store.put(_job(TENANT))
    _reset_read_caches()
    client = TestClient(app)
    headers = proxy_headers(role="analyst", tenant=TENANT)
    first = client.get("/v1/posture", headers=headers)
    assert first.status_code == 200
    parses.clear()
    assert client.get("/v1/posture", headers=headers).json() == first.json()
    assert parses == []
    changed = _job(TENANT)
    changed.result["posture_scorecard"]["summary"] = "updated scan"
    sqlite_store.put(changed)
    response = client.get("/v1/posture", headers=headers)
    assert response.json()["scan_scorecard"]["summary"] == "updated scan"
    assert parses


def test_posture_projection_is_detached_and_tenant_scoped(sqlite_store):
    from agent_bom.api.posture_scan_snapshot import scan_posture_inputs

    sqlite_store.put(_job(TENANT))

    def load():
        return sqlite_store.list_all(tenant_id=TENANT)

    projection = scan_posture_inputs(sqlite_store, TENANT, load)
    projection["summary"]["total_packages"] = -1
    assert scan_posture_inputs(sqlite_store, TENANT, load)["summary"]["total_packages"] == 1
    assert scan_posture_inputs(sqlite_store, TENANT + "-empty", lambda: []) is None


def test_demo_probe_and_orphan_sweep_do_not_parse_done_jobs(sqlite_store, parses, monkeypatch):
    from agent_bom.api.scan_job_reconciliation import fail_orphaned_active_scan_jobs
    from agent_bom.demo_estate.bootstrap import _tenant_has_demo_jobs

    monkeypatch.setenv("AGENT_BOM_DISTRIBUTED_SCANS", "false")
    job = _job(TENANT)
    job.triggered_by = "demo-estate-bootstrap"
    sqlite_store.put(job)
    parses.clear()
    assert _tenant_has_demo_jobs(sqlite_store, TENANT)
    assert not _tenant_has_demo_jobs(sqlite_store, TENANT + "-empty")
    assert fail_orphaned_active_scan_jobs(sqlite_store) == 0
    assert parses == []
    job.result["findings"] = []
    sqlite_store.put(job)
    assert not _tenant_has_demo_jobs(sqlite_store, TENANT)
    job.result["vulnerabilities"] = [{"id": "example"}]
    sqlite_store.put(job)
    assert _tenant_has_demo_jobs(sqlite_store, TENANT)
    job.status = JobStatus.FAILED
    sqlite_store.put(job)
    assert not _tenant_has_demo_jobs(sqlite_store, TENANT)
