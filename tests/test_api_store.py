"""Tests for agent_bom.api.store — job storage backends."""

from __future__ import annotations

import tempfile
from pathlib import Path

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
        store.put(_make_job("j1"))
        summary = store.list_summary()
        assert len(summary) == 1
        assert summary[0]["job_id"] == "j1"
        assert "status" in summary[0]
        assert "created_at" in summary[0]
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
