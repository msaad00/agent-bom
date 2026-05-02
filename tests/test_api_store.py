"""Tests for agent_bom.api.store — job storage backends."""

from __future__ import annotations

import tempfile
from pathlib import Path
from types import SimpleNamespace

from agent_bom.api.server import JobStatus, ScanJob, ScanRequest
from agent_bom.api.store import InMemoryJobStore, SQLiteJobStore


def _make_job(job_id: str = "test-123", status: JobStatus = JobStatus.PENDING, **kwargs) -> ScanJob:
    return ScanJob(
        job_id=job_id,
        created_at="2026-02-23T12:00:00+00:00",
        request=ScanRequest(),
        status=status,
        **kwargs,
    )


# ── InMemoryJobStore ─────────────────────────────────────────────────────────


def test_in_memory_put_and_get():
    store = InMemoryJobStore()
    job = _make_job()
    store.put(job)
    assert store.get("test-123") is not None
    assert store.get("test-123").job_id == "test-123"


def test_in_memory_get_missing():
    store = InMemoryJobStore()
    assert store.get("nonexistent") is None


def test_in_memory_delete():
    store = InMemoryJobStore()
    store.put(_make_job())
    assert store.delete("test-123") is True
    assert store.get("test-123") is None
    assert store.delete("test-123") is False


def test_in_memory_list_all():
    store = InMemoryJobStore()
    store.put(_make_job("j1"))
    store.put(_make_job("j2"))
    assert len(store.list_all()) == 2


def test_in_memory_list_summary():
    store = InMemoryJobStore()
    store.put(_make_job("j1"))
    summary = store.list_summary()
    assert len(summary) == 1
    assert summary[0]["job_id"] == "j1"
    assert "status" in summary[0]


def test_in_memory_cleanup():
    store = InMemoryJobStore()
    store.put(_make_job("j1", status=JobStatus.DONE, completed_at="2020-01-01T00:00:00+00:00"))
    store.put(_make_job("j2", status=JobStatus.RUNNING))
    removed = store.cleanup_expired(ttl_seconds=1)
    assert removed == 1
    assert store.get("j1") is None
    assert store.get("j2") is not None


def test_in_memory_retention_evicts_oldest_completed_jobs():
    store = InMemoryJobStore(max_retained_jobs=2)
    old = _make_job("old", status=JobStatus.DONE, completed_at="2026-02-23T12:00:00+00:00")
    running = _make_job("running", status=JobStatus.RUNNING)
    new = _make_job("new", status=JobStatus.DONE, completed_at="2026-02-23T12:01:00+00:00")

    store.put(old)
    store.put(running)
    store.put(new)

    assert store.get("old") is None
    assert store.get("running") is not None
    assert store.get("new") is not None


def test_completed_scan_refreshes_bounded_hot_cache(monkeypatch):
    from agent_bom.api import stores
    from agent_bom.api.pipeline import _run_scan_sync

    monkeypatch.setattr(stores, "_MAX_IN_MEMORY_JOBS", 3)
    stores._jobs.clear()
    stores._job_locks.clear()
    store = InMemoryJobStore(max_retained_jobs=3)
    stores.set_job_store(store)

    jobs = []
    for idx in range(5):
        job = _make_job(f"job-{idx}")
        job.request = ScanRequest(dry_run=True, no_scan=True)
        jobs.append(job)
        store.put(job)
        stores._jobs_put(job.job_id, job)

    for job in jobs:
        _run_scan_sync(job)

    assert len(store.list_all()) == 3
    assert len(stores._jobs) == 3
    assert sorted(stores._jobs) == ["job-2", "job-3", "job-4"]
    assert all(stores._jobs_is_compacted(job) for job in stores._jobs.values())
    assert all(store.get(job_id).result for job_id in ["job-2", "job-3", "job-4"])


def test_scan_memory_release_is_best_effort(monkeypatch):
    from agent_bom.api import pipeline

    monkeypatch.setattr(pipeline.gc, "collect", lambda: 0)
    monkeypatch.setattr(pipeline.ctypes, "CDLL", lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("missing libc")))

    pipeline._release_scan_memory()


def test_compacted_hot_cache_job_hydrates_full_scan_response(monkeypatch):
    from agent_bom.api import stores
    from agent_bom.api.pipeline import _run_scan_sync
    from agent_bom.api.routes.scan import _job_for_request

    stores._jobs.clear()
    stores._job_locks.clear()
    store = InMemoryJobStore(max_retained_jobs=3)
    stores.set_job_store(store)

    job = _make_job("full-job")
    job.request = ScanRequest(dry_run=True, no_scan=True)
    store.put(job)
    stores._jobs_put(job.job_id, job)
    _run_scan_sync(job)

    cached = stores._jobs["full-job"]
    assert stores._jobs_is_compacted(cached)
    assert cached.result != store.get("full-job").result

    request = SimpleNamespace(state=SimpleNamespace(tenant_id="default"))
    hydrated = _job_for_request(request, "full-job")
    assert hydrated.result == store.get("full-job").result


def test_scan_job_progress_is_bounded(monkeypatch):
    monkeypatch.setattr("agent_bom.config.API_MAX_JOB_PROGRESS_EVENTS", 3)
    job = _make_job("progress")

    for idx in range(5):
        job.progress.append(f"event-{idx}")

    assert job.progress == ["event-2", "event-3", "event-4"]


# ── SQLiteJobStore ───────────────────────────────────────────────────────────


def test_sqlite_put_and_get():
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name
    try:
        store = SQLiteJobStore(db_path=db_path)
        job = _make_job()
        store.put(job)

        retrieved = store.get("test-123")
        assert retrieved is not None
        assert retrieved.job_id == "test-123"
        assert retrieved.status == JobStatus.PENDING
    finally:
        Path(db_path).unlink(missing_ok=True)


def test_sqlite_bounds_connection_cache():
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name
    try:
        store = SQLiteJobStore(db_path=db_path)

        assert store._conn.execute("PRAGMA cache_size").fetchone()[0] == -2048
        assert store._conn.execute("PRAGMA temp_store").fetchone()[0] == 1
        assert store._conn.execute("PRAGMA mmap_size").fetchone()[0] == 0
    finally:
        Path(db_path).unlink(missing_ok=True)


def test_sqlite_get_missing():
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name
    try:
        store = SQLiteJobStore(db_path=db_path)
        assert store.get("nonexistent") is None
    finally:
        Path(db_path).unlink(missing_ok=True)


def test_sqlite_upsert():
    """put() should update existing job."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name
    try:
        store = SQLiteJobStore(db_path=db_path)
        job = _make_job()
        store.put(job)

        job.status = JobStatus.DONE
        job.completed_at = "2026-02-23T13:00:00+00:00"
        store.put(job)

        retrieved = store.get("test-123")
        assert retrieved.status == JobStatus.DONE
        assert retrieved.completed_at == "2026-02-23T13:00:00+00:00"
        assert len(store.list_all()) == 1
    finally:
        Path(db_path).unlink(missing_ok=True)


def test_sqlite_delete():
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name
    try:
        store = SQLiteJobStore(db_path=db_path)
        store.put(_make_job())
        assert store.delete("test-123") is True
        assert store.get("test-123") is None
        assert store.delete("test-123") is False
    finally:
        Path(db_path).unlink(missing_ok=True)


def test_sqlite_list_all():
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name
    try:
        store = SQLiteJobStore(db_path=db_path)
        store.put(_make_job("j1"))
        store.put(_make_job("j2"))
        jobs = store.list_all()
        assert len(jobs) == 2
        ids = {j.job_id for j in jobs}
        assert ids == {"j1", "j2"}
    finally:
        Path(db_path).unlink(missing_ok=True)


def test_sqlite_list_summary():
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name
    try:
        store = SQLiteJobStore(db_path=db_path)
        store.put(_make_job("j1", triggered_by="api-user"))
        summary = store.list_summary()
        assert len(summary) == 1
        assert summary[0]["job_id"] == "j1"
        assert summary[0]["triggered_by"] == "api-user"
        assert "status" in summary[0]
        assert "created_at" in summary[0]
    finally:
        Path(db_path).unlink(missing_ok=True)


def test_sqlite_list_summary_does_not_hydrate_full_result(monkeypatch):
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name
    try:
        store = SQLiteJobStore(db_path=db_path)
        job = _make_job("j1", status=JobStatus.DONE, triggered_by="api-user")
        job.result = {"blob": "x" * 1_000_000}
        store.put(job)

        def fail_deserialize(_data: str) -> ScanJob:
            raise AssertionError("list_summary should not deserialize full job data")

        monkeypatch.setattr(store, "_deserialize", fail_deserialize)
        summary = store.list_summary()
        assert summary[0]["job_id"] == "j1"
        assert summary[0]["triggered_by"] == "api-user"
    finally:
        Path(db_path).unlink(missing_ok=True)


def test_sqlite_cleanup_expired():
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name
    try:
        store = SQLiteJobStore(db_path=db_path)
        store.put(_make_job("j1", status=JobStatus.DONE, completed_at="2020-01-01T00:00:00+00:00"))
        store.put(_make_job("j2", status=JobStatus.RUNNING))
        store.put(_make_job("j3", status=JobStatus.FAILED, completed_at="2020-01-01T00:00:00+00:00"))

        removed = store.cleanup_expired(ttl_seconds=1)
        assert removed == 2
        assert store.get("j1") is None
        assert store.get("j2") is not None
        assert store.get("j3") is None
    finally:
        Path(db_path).unlink(missing_ok=True)


def test_sqlite_persistence_across_instances():
    """Data should survive store re-creation with same DB path."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name
    try:
        store1 = SQLiteJobStore(db_path=db_path)
        store1.put(_make_job("persistent-job", status=JobStatus.DONE))

        # Create new store instance pointing to same DB
        store2 = SQLiteJobStore(db_path=db_path)
        retrieved = store2.get("persistent-job")
        assert retrieved is not None
        assert retrieved.job_id == "persistent-job"
        assert retrieved.status == JobStatus.DONE
    finally:
        Path(db_path).unlink(missing_ok=True)


def test_sqlite_preserves_result_data():
    """Large result dicts should round-trip through JSON serialization."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name
    try:
        store = SQLiteJobStore(db_path=db_path)
        job = _make_job(status=JobStatus.DONE)
        job.result = {
            "agents": [{"name": "test-agent", "servers": 3}],
            "vulnerabilities": [{"id": "CVE-2025-0001", "severity": "critical"}],
            "blast_radius": [{"package": "express", "risk_score": 8.5}],
        }
        job.progress = ["Starting scan...", "Found 1 agent", "Scan complete."]
        store.put(job)

        retrieved = store.get("test-123")
        assert retrieved.result["agents"][0]["name"] == "test-agent"
        assert len(retrieved.result["vulnerabilities"]) == 1
        assert retrieved.progress == ["Starting scan...", "Found 1 agent", "Scan complete."]
    finally:
        Path(db_path).unlink(missing_ok=True)
