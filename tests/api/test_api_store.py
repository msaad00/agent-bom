"""Tests for agent_bom.api.store — job storage backends."""

from __future__ import annotations

import asyncio
import tempfile
from pathlib import Path
from types import SimpleNamespace

import pytest

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
    assert store.get("test-123", all_tenants=True) is not None
    assert store.get("test-123", all_tenants=True).job_id == "test-123"


def test_in_memory_atomic_job_batch_rejects_cross_tenant_without_partial_write() -> None:
    store = InMemoryJobStore()
    with pytest.raises(ValueError, match="one tenant"):
        store.put_many_atomic(
            [
                _make_job("tenant-a-job", tenant_id="tenant-a"),
                _make_job("tenant-b-job", tenant_id="tenant-b"),
            ]
        )
    assert store.list_all(all_tenants=True) == []


def test_sqlite_atomic_job_batch_rolls_back_every_row_when_one_insert_aborts(tmp_path: Path) -> None:
    store = SQLiteJobStore(str(tmp_path / "atomic-jobs.db"))
    store._conn.execute(  # noqa: SLF001
        """CREATE TRIGGER fail_second_atomic_job BEFORE INSERT ON jobs
           WHEN NEW.job_id = 'child-fail'
           BEGIN SELECT RAISE(ABORT, 'injected atomic write failure'); END"""
    )
    store._conn.commit()  # noqa: SLF001

    with pytest.raises(Exception, match="injected atomic write failure"):
        store.put_many_atomic(
            [
                _make_job("parent", tenant_id="tenant-a", child_job_ids=["child-fail"]),
                _make_job("child-fail", tenant_id="tenant-a", parent_job_id="parent"),
            ]
        )

    assert store.list_all(tenant_id="tenant-a") == []


@pytest.mark.parametrize("backend", ["memory", "sqlite"])
def test_atomic_repair_insert_returns_only_new_rows_and_preserves_winner(tmp_path: Path, backend: str) -> None:
    store = InMemoryJobStore() if backend == "memory" else SQLiteJobStore(str(tmp_path / "repair-jobs.db"))
    winner = _make_job("repair-child", tenant_id="tenant-a", target_index=1)
    loser = _make_job("repair-child", tenant_id="tenant-a", target_index=99)

    assert store.put_many_if_absent_atomic([winner]) == ["repair-child"]
    assert store.put_many_if_absent_atomic([loser]) == []

    persisted = store.get("repair-child", tenant_id="tenant-a")
    assert persisted is not None
    assert persisted.target_index == 1


def test_in_memory_get_missing():
    store = InMemoryJobStore()
    assert store.get("nonexistent", all_tenants=True) is None


def test_in_memory_delete():
    store = InMemoryJobStore()
    store.put(_make_job())
    assert store.delete("test-123", all_tenants=True) is True
    assert store.get("test-123", all_tenants=True) is None
    assert store.delete("test-123", all_tenants=True) is False


def test_in_memory_list_all():
    store = InMemoryJobStore()
    store.put(_make_job("j1"))
    store.put(_make_job("j2"))
    assert len(store.list_all(all_tenants=True)) == 2


def test_in_memory_list_summary():
    store = InMemoryJobStore()
    store.put(_make_job("j1"))
    summary = store.list_summary(all_tenants=True)
    assert len(summary) == 1
    assert summary[0]["job_id"] == "j1"
    assert "status" in summary[0]


def test_in_memory_list_summary_filters_before_pagination_and_counts():
    store = InMemoryJobStore()
    store.put(_make_job("alpha-running", status=JobStatus.RUNNING, triggered_by="connection:alpha"))
    store.put(_make_job("alpha-done", status=JobStatus.DONE, triggered_by="connection:alpha"))
    store.put(_make_job("beta-done", status=JobStatus.DONE, triggered_by="connection:beta"))

    rows = store.list_summary(all_tenants=True, query="alpha", status=JobStatus.DONE, limit=1, offset=0)

    assert [row["job_id"] for row in rows] == ["alpha-done"]
    assert store.count_summary(query="alpha", status=JobStatus.DONE) == 1
    assert store.count_summary_by_status(query="alpha") == {"running": 1, "done": 1}


def test_in_memory_list_summary_pages_beyond_two_hundred_after_filtering():
    store = InMemoryJobStore(max_retained_jobs=None)
    for index in range(225):
        store.put(_make_job(f"bulk-{index:03d}", status=JobStatus.DONE, triggered_by="bulk-source"))

    rows = store.list_summary(all_tenants=True, query="bulk-source", limit=25, offset=200)

    assert len(rows) == 25
    assert store.count_summary(query="bulk-source") == 225


def test_in_memory_count_active_is_tenant_scoped_and_excludes_terminal_jobs():
    store = InMemoryJobStore()
    store.put(_make_job("a-pending", tenant_id="tenant-a", status=JobStatus.PENDING))
    store.put(_make_job("a-running", tenant_id="tenant-a", status=JobStatus.RUNNING))
    store.put(_make_job("a-done", tenant_id="tenant-a", status=JobStatus.DONE))
    store.put(_make_job("b-running", tenant_id="tenant-b", status=JobStatus.RUNNING))

    assert store.count_active(tenant_id="tenant-a") == 2
    assert store.count_active(tenant_id="tenant-b") == 1
    assert store.count_active(all_tenants=True) == 3


def test_in_memory_cleanup():
    store = InMemoryJobStore()
    store.put(_make_job("j1", status=JobStatus.DONE, completed_at="2020-01-01T00:00:00+00:00"))
    store.put(_make_job("j2", status=JobStatus.RUNNING))
    removed = store.cleanup_expired(ttl_seconds=1)
    assert removed == 1
    assert store.get("j1", all_tenants=True) is None
    assert store.get("j2", all_tenants=True) is not None


def test_in_memory_cleanup_preserves_demo_estate_jobs():
    from agent_bom.api.store import DEMO_ESTATE_TRIGGERED_BY

    store = InMemoryJobStore()
    store.put(
        _make_job(
            "demo",
            status=JobStatus.DONE,
            completed_at="2020-01-01T00:00:00+00:00",
            triggered_by=DEMO_ESTATE_TRIGGERED_BY,
        )
    )
    store.put(_make_job("other", status=JobStatus.DONE, completed_at="2020-01-01T00:00:00+00:00"))
    removed = store.cleanup_expired(ttl_seconds=1)
    assert removed == 1
    assert store.get("demo", all_tenants=True) is not None
    assert store.get("other", all_tenants=True) is None


def test_in_memory_retention_evicts_oldest_completed_jobs():
    store = InMemoryJobStore(max_retained_jobs=2)
    old = _make_job("old", status=JobStatus.DONE, completed_at="2026-02-23T12:00:00+00:00")
    running = _make_job("running", status=JobStatus.RUNNING)
    new = _make_job("new", status=JobStatus.DONE, completed_at="2026-02-23T12:01:00+00:00")

    store.put(old)
    store.put(running)
    store.put(new)

    assert store.get("old", all_tenants=True) is None
    assert store.get("running", all_tenants=True) is not None
    assert store.get("new", all_tenants=True) is not None


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

    assert len(store.list_all(all_tenants=True)) == 3
    assert len(stores._jobs) == 3
    assert sorted(stores._jobs) == ["job-2", "job-3", "job-4"]
    assert all(stores._jobs_is_compacted(job) for job in stores._jobs.values())
    assert all(store.get(job_id, all_tenants=True).result for job_id in ["job-2", "job-3", "job-4"])


def test_scan_memory_release_is_best_effort(monkeypatch):
    from agent_bom.api import pipeline

    monkeypatch.setattr(pipeline.gc, "collect", lambda: 0)
    monkeypatch.setattr(pipeline.ctypes, "CDLL", lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("missing libc")))

    pipeline._release_scan_memory()


def test_scan_executor_recreates_after_shutdown() -> None:
    from agent_bom.api import pipeline

    pipeline.shutdown_scan_executor(wait=True, cancel_futures=False)

    executor = pipeline.get_executor()

    assert executor._max_workers >= 1
    assert not executor._shutdown


def test_scan_executor_rejects_submissions_while_draining() -> None:
    from agent_bom.api import pipeline

    with pipeline._executor_lock:
        pipeline._executor_draining = True
    try:
        with pytest.raises(RuntimeError, match="scan executor is draining"):
            pipeline.submit_scan_job(_make_job("during-drain"))
    finally:
        with pipeline._executor_lock:
            pipeline._executor_draining = False


def test_scheduled_scan_submission_uses_shared_lifecycle(monkeypatch) -> None:
    from agent_bom.api import pipeline

    completed: list[str] = []
    monkeypatch.setattr(pipeline, "_run_scan_sync", lambda job: completed.append(job.job_id))

    async def _run() -> None:
        pipeline.shutdown_scan_executor(wait=True, cancel_futures=False)
        loop = asyncio.get_running_loop()
        pipeline.submit_scheduled_scan_job(loop, _make_job("scheduled-after-shutdown"))
        for _ in range(20):
            if completed:
                return
            await asyncio.sleep(0.01)

    asyncio.run(_run())

    assert completed == ["scheduled-after-shutdown"]


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
    assert cached.result != store.get("full-job", all_tenants=True).result

    request = SimpleNamespace(state=SimpleNamespace(tenant_id="default"))
    hydrated = _job_for_request(request, "full-job")
    assert hydrated.result == store.get("full-job", all_tenants=True).result


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

        retrieved = store.get("test-123", all_tenants=True)
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
        assert store.get("nonexistent", all_tenants=True) is None
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

        retrieved = store.get("test-123", all_tenants=True)
        assert retrieved.status == JobStatus.DONE
        assert retrieved.completed_at == "2026-02-23T13:00:00+00:00"
        assert len(store.list_all(all_tenants=True)) == 1
    finally:
        Path(db_path).unlink(missing_ok=True)


def test_sqlite_delete():
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name
    try:
        store = SQLiteJobStore(db_path=db_path)
        store.put(_make_job())
        assert store.delete("test-123", all_tenants=True) is True
        assert store.get("test-123", all_tenants=True) is None
        assert store.delete("test-123", all_tenants=True) is False
    finally:
        Path(db_path).unlink(missing_ok=True)


def test_sqlite_list_all():
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name
    try:
        store = SQLiteJobStore(db_path=db_path)
        store.put(_make_job("j1"))
        store.put(_make_job("j2"))
        jobs = store.list_all(all_tenants=True)
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
        for idx in range(3):
            store.put(_make_job(f"j{idx}", triggered_by="api-user"))
        assert store.count_summary() == 3
        summary = store.list_summary(all_tenants=True, limit=2, offset=1)
        assert len(summary) == 2
        assert summary[0]["job_id"] == "j1"
        assert summary[0]["triggered_by"] == "api-user"
        assert "status" in summary[0]
        assert "created_at" in summary[0]
    finally:
        Path(db_path).unlink(missing_ok=True)


def test_sqlite_list_summary_filters_before_pagination_and_counts():
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name
    try:
        store = SQLiteJobStore(db_path=db_path)
        store.put(_make_job("alpha-running", status=JobStatus.RUNNING, triggered_by="connection:alpha"))
        store.put(_make_job("alpha-done", status=JobStatus.DONE, triggered_by="connection:alpha"))
        store.put(_make_job("beta-done", status=JobStatus.DONE, triggered_by="connection:beta"))

        rows = store.list_summary(all_tenants=True, query="alpha", status=JobStatus.DONE, limit=1, offset=0)

        assert [row["job_id"] for row in rows] == ["alpha-done"]
        assert store.count_summary(query="alpha", status=JobStatus.DONE) == 1
        assert store.count_summary_by_status(query="alpha") == {"done": 1, "running": 1}
        assert store.count_summary(query="%") == 0
    finally:
        Path(db_path).unlink(missing_ok=True)


def test_sqlite_count_active_is_tenant_scoped_and_excludes_terminal_jobs():
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name
    try:
        store = SQLiteJobStore(db_path=db_path)
        store.put(_make_job("a-pending", tenant_id="tenant-a", status=JobStatus.PENDING))
        store.put(_make_job("a-running", tenant_id="tenant-a", status=JobStatus.RUNNING))
        store.put(_make_job("a-done", tenant_id="tenant-a", status=JobStatus.DONE))
        store.put(_make_job("b-running", tenant_id="tenant-b", status=JobStatus.RUNNING))

        assert store.count_active(tenant_id="tenant-a") == 2
        assert store.count_active(tenant_id="tenant-b") == 1
        assert store.count_active(all_tenants=True) == 3
    finally:
        Path(db_path).unlink(missing_ok=True)


def test_sqlite_list_summary_includes_scan_batch_metadata():
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name
    try:
        store = SQLiteJobStore(db_path=db_path)
        job = _make_job(
            "child-1",
            batch_id="batch-1",
            parent_job_id="parent-1",
            target={"field": "images", "value": "repo/a:latest", "ordinal": 0},
            target_index=1,
            target_count=2,
        )
        store.put(job)

        summary = store.list_summary(all_tenants=True)

        assert summary[0]["batch_id"] == "batch-1"
        assert summary[0]["parent_job_id"] == "parent-1"
        assert summary[0]["target"] == {"field": "images", "value": "repo/a:latest", "ordinal": 0}
        assert summary[0]["target_index"] == 1
        assert summary[0]["target_count"] == 2
        assert summary[0]["child_job_ids"] == []
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
        summary = store.list_summary(all_tenants=True)
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
        assert store.get("j1", all_tenants=True) is None
        assert store.get("j2", all_tenants=True) is not None
        assert store.get("j3", all_tenants=True) is None
    finally:
        Path(db_path).unlink(missing_ok=True)


def test_sqlite_cleanup_preserves_demo_estate_jobs():
    from agent_bom.api.store import DEMO_ESTATE_TRIGGERED_BY

    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name
    try:
        store = SQLiteJobStore(db_path=db_path)
        store.put(
            _make_job(
                "demo",
                status=JobStatus.DONE,
                completed_at="2020-01-01T00:00:00+00:00",
                triggered_by=DEMO_ESTATE_TRIGGERED_BY,
            )
        )
        store.put(_make_job("other", status=JobStatus.DONE, completed_at="2020-01-01T00:00:00+00:00"))
        removed = store.cleanup_expired(ttl_seconds=1)
        assert removed == 1
        assert store.get("demo", all_tenants=True) is not None
        assert store.get("other", all_tenants=True) is None
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
        retrieved = store2.get("persistent-job", all_tenants=True)
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

        retrieved = store.get("test-123", all_tenants=True)
        assert retrieved.result["agents"][0]["name"] == "test-agent"
        assert len(retrieved.result["vulnerabilities"]) == 1
        assert retrieved.progress == ["Starting scan...", "Found 1 agent", "Scan complete."]
    finally:
        Path(db_path).unlink(missing_ok=True)


# ── Tenant isolation guard (fail-closed on None tenant_id) ───────────────────


@pytest.mark.parametrize(
    "method",
    ["get", "delete", "list_all", "list_summary"],
)
def test_in_memory_rejects_none_tenant_without_opt_in(method: str):
    store = InMemoryJobStore()
    store.put(_make_job("j1", tenant_id="tenant-a"))
    store.put(_make_job("j2", tenant_id="tenant-b"))

    fn = getattr(store, method)
    if method in ("get", "delete"):
        with pytest.raises(ValueError, match="requires a tenant_id"):
            fn("j1")
    else:
        with pytest.raises(ValueError, match="requires a tenant_id"):
            fn()


def test_in_memory_all_tenants_opt_in_returns_cross_tenant():
    store = InMemoryJobStore()
    store.put(_make_job("j1", tenant_id="tenant-a"))
    store.put(_make_job("j2", tenant_id="tenant-b"))

    assert len(store.list_all(all_tenants=True)) == 2
    assert store.get("j1", all_tenants=True).tenant_id == "tenant-a"
    assert store.get("j2", all_tenants=True).tenant_id == "tenant-b"


def test_in_memory_tenant_scoped_read_isolates():
    store = InMemoryJobStore()
    store.put(_make_job("j1", tenant_id="tenant-a"))
    store.put(_make_job("j2", tenant_id="tenant-b"))

    assert store.get("j1", tenant_id="tenant-a") is not None
    assert store.get("j1", tenant_id="tenant-b") is None
    assert len(store.list_all(tenant_id="tenant-a")) == 1


def test_sqlite_rejects_none_tenant_without_opt_in():
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name
    try:
        store = SQLiteJobStore(db_path=db_path)
        store.put(_make_job("j1", tenant_id="tenant-a"))

        with pytest.raises(ValueError, match="requires a tenant_id"):
            store.list_all()
    finally:
        Path(db_path).unlink(missing_ok=True)


def test_sqlite_all_tenants_opt_in_returns_cross_tenant():
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name
    try:
        store = SQLiteJobStore(db_path=db_path)
        store.put(_make_job("j1", tenant_id="tenant-a"))
        store.put(_make_job("j2", tenant_id="tenant-b"))

        assert len(store.list_all(all_tenants=True)) == 2
    finally:
        Path(db_path).unlink(missing_ok=True)
