"""Durable export admission, ownership and restart contracts."""

from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace

import pytest

from agent_bom.api.models import JobStatus, ReportJob


def job(name="export-1", tenant="tenant-a"):
    return ReportJob(job_id=name, tenant_id=tenant, created_at="2026-09-11T00:00:00Z")


def stores(tmp_path):
    from agent_bom.api.report_job_store import SQLiteReportJobStore

    path = str(tmp_path / "reports.db")
    return SQLiteReportJobStore(path), SQLiteReportJobStore(path)


def test_report_survives_new_store_and_remains_tenant_scoped(tmp_path):
    first, second = stores(tmp_path)
    assert first.enqueue(job(), 5)
    assert second.get("export-1", "tenant-a") == job()
    assert second.get("export-1", "tenant-b") is None


def test_report_admission_is_atomic_across_replicas(tmp_path):
    first, second = stores(tmp_path)
    with ThreadPoolExecutor(max_workers=8) as pool:
        accepted = list(pool.map(lambda i: (first if i % 2 else second).enqueue(job(str(i)), 2), range(16)))
    assert sum(accepted) == 2
    assert second.enqueue(job("other", "tenant-b"), 2)


def test_only_one_replica_claims_each_report(tmp_path):
    first, second = stores(tmp_path)
    first.enqueue(job(), 5)
    with ThreadPoolExecutor(max_workers=2) as pool:
        claims = list(pool.map(lambda store: store.claim_next(60, 3), (first, second)))
    assert sum(claim is not None for claim in claims) == 1


def test_expired_owner_cannot_renew_or_publish_after_reclaim(tmp_path, monkeypatch):
    first, second = stores(tmp_path)
    monkeypatch.setattr("agent_bom.api.report_job_store.time.time", lambda: 1000)
    first.enqueue(job(), 5)
    stale = first.claim_next(60, 3)
    monkeypatch.setattr("agent_bom.api.report_job_store.time.time", lambda: 1061)
    current = second.claim_next(60, 3)
    assert current.token != stale.token
    done = job().model_copy(update={"status": JobStatus.DONE})
    assert not first.renew(stale, 60)
    assert not first.finish(done, stale)
    assert not second.finish(done, replace(current, tenant_id="tenant-b"))
    assert second.finish(done, current)
    assert first.get("export-1", "tenant-a").status == JobStatus.DONE


def test_abandoned_exports_have_bounded_attempts(tmp_path, monkeypatch):
    first, second = stores(tmp_path)
    monkeypatch.setattr("agent_bom.api.report_job_store.time.time", lambda: 1000)
    first.enqueue(job(), 5)
    assert first.claim_next(60, 1)
    monkeypatch.setattr("agent_bom.api.report_job_store.time.time", lambda: 1061)
    assert second.claim_next(60, 1) is None
    failed = second.get("export-1", "tenant-a")
    assert failed.status == JobStatus.FAILED
    assert "attempt" in failed.error.lower()
    assert second.enqueue(job("replacement"), 1)


@pytest.mark.parametrize("snowflake_account", [None, "configured-account"])
def test_store_selection_fails_closed(monkeypatch, snowflake_account):
    from agent_bom.api import report_job_store

    report_job_store.reset_report_job_store()
    if snowflake_account:
        monkeypatch.setenv("SNOWFLAKE_ACCOUNT", snowflake_account)
    else:
        monkeypatch.delenv("SNOWFLAKE_ACCOUNT", raising=False)
    monkeypatch.setenv("AGENT_BOM_POSTGRES_URL", "postgresql://unavailable/reports")
    monkeypatch.setattr(
        "agent_bom.api.postgres_report_jobs.PostgresReportJobStore", lambda: (_ for _ in ()).throw(RuntimeError("unavailable"))
    )
    with pytest.raises(RuntimeError, match="unavailable"):
        report_job_store.get_report_job_store()


def test_job_identifiers_do_not_collide_across_tenants(tmp_path):
    first, second = stores(tmp_path)
    assert first.enqueue(job("same", "tenant-a"), 2)
    assert second.enqueue(job("same", "tenant-b"), 2)
    assert first.get("same", "tenant-a").tenant_id == "tenant-a"
    assert second.get("same", "tenant-b").tenant_id == "tenant-b"
