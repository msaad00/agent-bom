"""Every scan worker thread runs bound to the submitting job's tenant.

``submit_claimed_scan_job`` was already correct, but the HTTP-triggered and
scheduler-triggered submissions handed ``_run_scan_sync`` straight to the pool,
so the worker thread had no tenant contextvar and the pipeline's durable
persistence (``PostgresJobStore.put``) wrote as the default tenant instead of
the job's own — silently, and against the RLS ``WITH CHECK`` contract.
"""

from __future__ import annotations

import asyncio

import pytest

from agent_bom.api import pipeline as pipeline_module
from agent_bom.api.models import ScanJob, ScanRequest
from agent_bom.api.postgres_common import _current_tenant


def _job(tenant_id: str) -> ScanJob:
    return ScanJob(
        job_id="job-1",
        tenant_id=tenant_id,
        created_at="2026-07-30T00:00:00Z",
        request=ScanRequest(),
    )


@pytest.fixture
def observed_tenants(monkeypatch) -> list[str]:
    seen: list[str] = []

    def _fake_run(job: ScanJob) -> None:
        seen.append(_current_tenant.get())

    monkeypatch.setattr(pipeline_module, "_run_scan_sync", _fake_run)
    return seen


def test_http_submitted_scan_runs_under_the_job_tenant(observed_tenants) -> None:
    pipeline_module.submit_scan_job(_job("acme-corp"))
    pipeline_module.shutdown_scan_executor(wait=True, cancel_futures=False)
    assert observed_tenants == ["acme-corp"]


def test_scheduled_scan_runs_under_the_job_tenant(observed_tenants) -> None:
    async def _submit() -> None:
        loop = asyncio.get_running_loop()
        pipeline_module.submit_scheduled_scan_job(loop, _job("acme-corp"))

    asyncio.run(_submit())
    pipeline_module.shutdown_scan_executor(wait=True, cancel_futures=False)
    assert observed_tenants == ["acme-corp"]


def test_claimed_scan_still_runs_under_the_job_tenant(observed_tenants) -> None:
    pipeline_module.submit_claimed_scan_job(_job("acme-corp"), lambda job_id: None)
    pipeline_module.shutdown_scan_executor(wait=True, cancel_futures=False)
    assert observed_tenants == ["acme-corp"]


@pytest.mark.parametrize("tenant_id", ["", "   "])
@pytest.mark.parametrize("submission", ["http", "scheduled", "claimed"])
def test_missing_job_tenant_is_rejected_before_submission(observed_tenants, monkeypatch, tenant_id, submission) -> None:
    from unittest.mock import Mock

    executor = Mock()
    monkeypatch.setattr(pipeline_module, "_executor_active_jobs", 0)
    monkeypatch.setattr(pipeline_module, "_executor_for_submission_locked", lambda: executor)
    job = _job(tenant_id)
    with pytest.raises(ValueError, match="tenant"):
        if submission == "http":
            pipeline_module.submit_scan_job(job)
        elif submission == "scheduled":
            loop = Mock()
            pipeline_module.submit_scheduled_scan_job(loop, job)
        else:
            pipeline_module.submit_claimed_scan_job(job, Mock())
    executor.submit.assert_not_called()
    assert pipeline_module._executor_active_jobs == 0
    if submission == "scheduled":
        loop.run_in_executor.assert_not_called()
    assert observed_tenants == []


def test_explicit_default_job_tenant_remains_supported(observed_tenants) -> None:
    pipeline_module.submit_scan_job(_job("default"))
    pipeline_module.shutdown_scan_executor(wait=True, cancel_futures=False)
    assert observed_tenants == ["default"]


def test_worker_tenant_does_not_leak_into_the_next_job(observed_tenants) -> None:
    pipeline_module.submit_scan_job(_job("acme-corp"))
    pipeline_module.shutdown_scan_executor(wait=True, cancel_futures=False)
    pipeline_module.submit_scan_job(_job("other-corp"))
    pipeline_module.shutdown_scan_executor(wait=True, cancel_futures=False)
    assert observed_tenants == ["acme-corp", "other-corp"]
