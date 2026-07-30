"""Tenant context must cross every background-worker boundary."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

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


def test_report_submission_runs_with_explicit_tenant(monkeypatch: pytest.MonkeyPatch) -> None:
    from agent_bom.api import report_worker

    observed: list[str] = []

    class _ImmediateExecutor:
        def submit(self, function: Any, /, *args: Any, **kwargs: Any) -> None:
            function(*args, **kwargs)

    monkeypatch.setattr(report_worker, "get_executor", _ImmediateExecutor)
    monkeypatch.setattr(
        report_worker,
        "_run_report_job_sync",
        lambda _job_id, _tenant_id: observed.append(_current_tenant.get()),
    )

    report_worker.submit_report_job("job-1", "tenant-report")

    assert observed == ["tenant-report"]
    assert _current_tenant.get() == "default"


def test_background_export_submit_sites_use_tenant_wrapper() -> None:
    repo_root = Path(__file__).resolve().parent.parent
    for relative_path in (
        "src/agent_bom/api/report_worker.py",
        "src/agent_bom/api/routes/exports.py",
    ):
        source = (repo_root / relative_path).read_text(encoding="utf-8")
        assert "submit_tenant_bound(" in source
        assert "get_executor().submit(" not in source
