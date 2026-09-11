"""Tenant context must cross every background-worker boundary."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from agent_bom.api.postgres_common import _current_tenant
from agent_bom.api.tenant_worker import run_tenant_bound, submit_tenant_bound


def test_run_tenant_bound_sets_and_restores_context() -> None:
    token = _current_tenant.set("outer-tenant")
    try:
        observed = run_tenant_bound("worker-tenant", _current_tenant.get)
        assert observed == "worker-tenant"
        assert _current_tenant.get() == "outer-tenant"
    finally:
        _current_tenant.reset(token)


def test_run_tenant_bound_restores_context_after_failure() -> None:
    token = _current_tenant.set("outer-tenant")

    def _fail() -> None:
        assert _current_tenant.get() == "worker-tenant"
        raise RuntimeError("expected failure")

    try:
        with pytest.raises(RuntimeError, match="expected failure"):
            run_tenant_bound("worker-tenant", _fail)
        assert _current_tenant.get() == "outer-tenant"
    finally:
        _current_tenant.reset(token)


def test_submit_tenant_bound_does_not_inherit_or_leak_pool_context() -> None:
    with ThreadPoolExecutor(max_workers=1) as executor:
        first = submit_tenant_bound(executor, "tenant-a", _current_tenant.get)
        second = executor.submit(_current_tenant.get)

        assert first.result(timeout=2) == "tenant-a"
        assert second.result(timeout=2) == "default"


def test_report_submission_runs_with_explicit_tenant(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    from agent_bom.api import report_worker
    from agent_bom.api.models import ReportJob
    from agent_bom.api.report_job_store import SQLiteReportJobStore
    from agent_bom.api.report_queue import ReportWorker

    observed: list[str] = []
    store = SQLiteReportJobStore(str(tmp_path / "reports.db"))
    store.enqueue(ReportJob(job_id="job-1", tenant_id="tenant-report", created_at="2026-09-11"), 5)
    monkeypatch.setattr(report_worker, "run_claimed_report", lambda *_args: observed.append(_current_tenant.get()))
    worker = ReportWorker(store, max_workers=1)
    worker.tick()
    for future in worker._inflight:
        future.result(timeout=2)
    worker._executor.shutdown()
    assert observed == ["tenant-report"]
    assert _current_tenant.get() == "default"


def test_background_export_submit_sites_use_tenant_wrapper() -> None:
    repo_root = Path(__file__).resolve().parent.parent
    for relative_path in (
        "src/agent_bom/api/report_queue.py",
        "src/agent_bom/api/routes/exports.py",
    ):
        source = (repo_root / relative_path).read_text(encoding="utf-8")
        assert "submit_tenant_bound(" in source
        assert "get_executor().submit(" not in source
