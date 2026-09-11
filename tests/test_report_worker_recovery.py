"""Export worker capacity, artifact ownership, failure and restart proofs."""

import asyncio
import gzip
import threading

import pytest

from agent_bom.api.models import JobStatus, ReportJob
from agent_bom.api.report_job_store import SQLiteReportJobStore
from agent_bom.api.report_queue import ReportWorker
from agent_bom.api.report_worker import resolve_report_artifact, run_claimed_report


def pending(name):
    return ReportJob(job_id=name, tenant_id="tenant-a", created_at="2026-09-11T00:00:00Z")


@pytest.mark.asyncio
async def test_fresh_worker_recovers_queued_report_and_download_survives_restart(tmp_path, monkeypatch):
    monkeypatch.setenv("AGENT_BOM_REPORT_ARTIFACT_DIR", str(tmp_path / "artifacts"))
    monkeypatch.setattr("agent_bom.export.runner.iter_current_findings", lambda *a, **k: iter([{"id": "persisted-finding"}]))
    db = str(tmp_path / "reports.db")
    first = SQLiteReportJobStore(db)
    first.enqueue(pending("restart"), 5)
    first.close()  # process exits after enqueue, before any local handoff
    second = SQLiteReportJobStore(db)
    worker = ReportWorker(second, max_workers=1)
    await worker.start()
    try:
        for _ in range(100):
            done = second.get("restart", "tenant-a")
            if done.status == JobStatus.DONE:
                break
            await asyncio.sleep(0.02)
        assert done.status == JobStatus.DONE
    finally:
        await worker.stop()
    second.close()
    restarted = SQLiteReportJobStore(db).get("restart", "tenant-a")
    assert b"persisted-finding" in gzip.decompress(resolve_report_artifact(restarted).read_bytes())


def test_worker_never_builds_an_unbounded_local_executor_queue(tmp_path, monkeypatch):
    entered, release = threading.Event(), threading.Event()

    def blocked(*_args):
        entered.set()
        assert release.wait(5)

    monkeypatch.setattr("agent_bom.api.report_worker.run_claimed_report", blocked)
    store = SQLiteReportJobStore(str(tmp_path / "reports.db"))
    for i in range(20):
        store.enqueue(pending(str(i)), 25)
    worker = ReportWorker(store, max_workers=1)
    try:
        worker.tick()
        assert entered.wait(2)
        worker.tick()
        assert len(worker._inflight) == 1
        assert sum(store.get(str(i), "tenant-a").status == JobStatus.PENDING for i in range(20)) == 19
    finally:
        release.set()
        worker._executor.shutdown()


def test_failed_export_removes_partial_artifact(tmp_path, monkeypatch):
    monkeypatch.setenv("AGENT_BOM_REPORT_ARTIFACT_DIR", str(tmp_path / "artifacts"))

    def broken(*a, **k):
        yield {"id": "first"}
        raise RuntimeError("postgres://private:secret@host/database")

    monkeypatch.setattr("agent_bom.export.runner.iter_current_findings", broken)
    store = SQLiteReportJobStore(str(tmp_path / "reports.db"))
    store.enqueue(pending("broken"), 5)
    run_claimed_report(store, store.claim_next(60, 3), threading.Event())
    failed = store.get("broken", "tenant-a")
    assert failed.status == JobStatus.FAILED
    assert "secret" not in failed.error
    assert list((tmp_path / "artifacts").rglob("*.gz")) == []


def test_lost_attempt_cannot_overwrite_winning_artifact(tmp_path, monkeypatch):
    from agent_bom.api import report_worker

    monkeypatch.setenv("AGENT_BOM_REPORT_ARTIFACT_DIR", str(tmp_path / "artifacts"))
    monkeypatch.setattr("agent_bom.export.runner.iter_current_findings", lambda *a, **k: iter([{"id": "winner"}]))
    store = SQLiteReportJobStore(str(tmp_path / "reports.db"))
    store.enqueue(pending("fenced"), 5)
    old = store.claim_next(60, 3)
    store._conn.execute("UPDATE report_jobs SET lease_expires_at = 0")
    store._conn.commit()
    winner = store.claim_next(60, 3)
    run_claimed_report(store, winner, threading.Event())
    winning_path = resolve_report_artifact(store.get("fenced", "tenant-a"))
    winning_bytes = winning_path.read_bytes()
    monkeypatch.setattr("agent_bom.export.runner.iter_current_findings", lambda *a, **k: iter([{"id": "stale"}]))
    report_worker.run_claimed_report(store, old, threading.Event())
    assert winning_path.read_bytes() == winning_bytes
    assert resolve_report_artifact(store.get("fenced", "tenant-a")) == winning_path
    assert len(list((tmp_path / "artifacts").rglob("*.gz"))) == 1


def test_clustered_export_requires_shared_artifacts(monkeypatch):
    from agent_bom.api.report_artifact_store import validate_report_artifact_sharing

    monkeypatch.setenv("AGENT_BOM_CONTROL_PLANE_REPLICAS", "2")
    monkeypatch.setenv("AGENT_BOM_POSTGRES_URL", "postgresql://configured/db")
    monkeypatch.delenv("AGENT_BOM_REPORT_S3_BUCKET", raising=False)
    monkeypatch.delenv("AGENT_BOM_REPORT_ARTIFACT_SHARED", raising=False)
    with pytest.raises(RuntimeError, match="shared report"):
        validate_report_artifact_sharing()
    monkeypatch.setenv("AGENT_BOM_REPORT_ARTIFACT_SHARED", "1")
    monkeypatch.setenv("AGENT_BOM_REPORT_ARTIFACT_DIR", "/mnt/shared/reports")
    validate_report_artifact_sharing()
