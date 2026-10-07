"""Cache warmth cannot change the documented lightweight job-list contract."""

from types import SimpleNamespace

import pytest

from agent_bom.api import stores
from agent_bom.api.models import JobStatus, ScanJob, ScanRequest
from agent_bom.api.routes.scan import _list_jobs_impl
from agent_bom.api.store import InMemoryJobStore, SQLiteJobStore


@pytest.mark.parametrize("persistent", [False, True])
@pytest.mark.parametrize("compact", [False, True])
def test_lightweight_list_is_identical_with_warm_or_cold_cache(monkeypatch, tmp_path, persistent, compact):
    store = SQLiteJobStore(str(tmp_path / "jobs.db")) if persistent else InMemoryJobStore()
    job = ScanJob(
        job_id="job-a",
        tenant_id="tenant-a",
        status=JobStatus.DONE,
        created_at="2026-10-06T00:00:00Z",
        request=ScanRequest(),
        triggered_by="operator",
        result={"summary": {"total_packages": 3}},
    )
    store.put(job)
    monkeypatch.setattr(stores, "_store", store)
    monkeypatch.setattr(stores, "_jobs", {})
    request = SimpleNamespace(state=SimpleNamespace(tenant_id="tenant-a"))
    cold = _list_jobs_impl(request, 50, 0, False, None, None)
    stores._jobs_put(job.job_id, job, compact_terminal=compact)
    warm = _list_jobs_impl(request, 50, 0, False, None, None)
    assert warm["jobs"] == cold["jobs"]
    assert "request" not in warm["jobs"][0]
    assert warm["jobs"][0]["triggered_by"] == "operator"
