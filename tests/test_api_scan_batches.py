from __future__ import annotations

from agent_bom.api.models import JobStatus, ScanRequest
from agent_bom.api.routes import scan as scan_routes
from agent_bom.api.store import InMemoryJobStore
from agent_bom.api.stores import _jobs, set_job_store, set_tenant_quota_store
from agent_bom.api.tenant_quota_store import InMemoryTenantQuotaStore


def _reset_store() -> InMemoryJobStore:
    store = InMemoryJobStore()
    set_job_store(store)
    set_tenant_quota_store(InMemoryTenantQuotaStore())
    _jobs.clear()
    return store


def test_multi_target_scan_request_creates_parent_and_child_jobs(monkeypatch):
    store = _reset_store()
    submitted: list[str] = []
    monkeypatch.setattr(scan_routes, "submit_scan_job", lambda job: submitted.append(job.job_id))

    parent = scan_routes.enqueue_scan_job(
        tenant_id="tenant-a",
        triggered_by="api-test",
        request_body=ScanRequest(images=["repo/a:latest", "repo/b:latest"], tf_dirs=["infra"], offline=True, no_scan=True),
    )

    assert parent.parent_job_id is None
    assert parent.batch_id
    assert parent.status == JobStatus.RUNNING
    assert len(parent.child_job_ids) == 3
    assert submitted == parent.child_job_ids

    children = [store.get(job_id, tenant_id="tenant-a") for job_id in parent.child_job_ids]
    assert all(child is not None for child in children)
    assert {child.parent_job_id for child in children if child} == {parent.job_id}
    assert {child.batch_id for child in children if child} == {parent.batch_id}
    assert [child.target_index for child in children if child] == [1, 2, 3]
    assert [child.target["field"] for child in children if child] == ["images", "images", "tf_dirs"]
    assert children[0].request.images == ["repo/a:latest"]
    assert children[0].request.tf_dirs == []
    assert children[2].request.images == []
    assert children[2].request.tf_dirs == ["infra"]

    stored_parent = store.get(parent.job_id, tenant_id="tenant-a")
    assert stored_parent is not None
    assert stored_parent.result["batch"]["target_count"] == 3
    assert stored_parent.result["batch"]["pending_targets"] == 3


def test_batch_parent_rolls_up_child_results_without_failing_partial_batch(monkeypatch):
    store = _reset_store()
    monkeypatch.setattr(scan_routes, "submit_scan_job", lambda job: None)
    parent = scan_routes.enqueue_scan_job(
        tenant_id="tenant-a",
        triggered_by="api-test",
        request_body=ScanRequest(images=["repo/a:latest", "repo/b:latest"], no_scan=True),
    )

    child_ok = store.get(parent.child_job_ids[0], tenant_id="tenant-a")
    child_failed = store.get(parent.child_job_ids[1], tenant_id="tenant-a")
    assert child_ok is not None
    assert child_failed is not None

    child_ok.status = JobStatus.DONE
    child_ok.completed_at = "2026-06-24T00:00:01+00:00"
    child_ok.result = {"summary": {"total_agents": 1}, "agents": [{"name": "image:a"}]}
    store.put(child_ok)

    child_failed.status = JobStatus.FAILED
    child_failed.completed_at = "2026-06-24T00:00:02+00:00"
    child_failed.error = "image scan failed"
    store.put(child_failed)

    refreshed = scan_routes.refresh_batch_parent(parent.job_id, tenant_id="tenant-a")

    assert refreshed is not None
    assert refreshed.status == JobStatus.DONE
    assert refreshed.completed_at == "2026-06-24T00:00:02+00:00"
    batch = refreshed.result["batch"]
    assert batch["completed_targets"] == 2
    assert batch["succeeded_targets"] == 1
    assert batch["failed_targets"] == 1
    assert batch["children"][0]["result"]["summary"]["total_agents"] == 1
    assert batch["children"][1]["error"] == "image scan failed"


def test_single_target_scan_request_keeps_single_job_shape(monkeypatch):
    _reset_store()
    submitted: list[str] = []
    monkeypatch.setattr(scan_routes, "submit_scan_job", lambda job: submitted.append(job.job_id))

    job = scan_routes.enqueue_scan_job(
        tenant_id="tenant-a",
        triggered_by="api-test",
        request_body=ScanRequest(images=["repo/a:latest"], no_scan=True),
    )

    assert job.batch_id is None
    assert job.parent_job_id is None
    assert job.child_job_ids == []
    assert submitted == [job.job_id]
