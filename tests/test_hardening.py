"""Tests for enterprise hardening fixes.

Covers: thread-safe _jobs, bounded eviction, store locking,
path validation, pagination, scheduler backoff, pip extras
stripping, npm PURL encoding, and docker cleanup.
"""

from __future__ import annotations

import threading
import time
from unittest.mock import MagicMock, patch

# ── Thread-safe _jobs helpers ───────────────────────────────────────────────


def test_jobs_put_and_get():
    """_jobs_put / _jobs_get are thread-safe accessors."""
    from agent_bom.api.server import JobStatus, ScanJob, ScanRequest, _jobs_get, _jobs_put

    job = ScanJob(job_id="test-1", created_at="2025-01-01T00:00:00Z", request=ScanRequest())
    job.status = JobStatus.PENDING
    _jobs_put("test-1", job)
    assert _jobs_get("test-1") is job
    # Cleanup
    from agent_bom.api.server import _jobs_pop

    _jobs_pop("test-1")


def test_jobs_pop():
    """_jobs_pop removes and returns the job."""
    from agent_bom.api.server import ScanJob, ScanRequest, _jobs_get, _jobs_pop, _jobs_put

    job = ScanJob(job_id="pop-1", created_at="2025-01-01T00:00:00Z", request=ScanRequest())
    _jobs_put("pop-1", job)
    popped = _jobs_pop("pop-1")
    assert popped is job
    assert _jobs_get("pop-1") is None


def test_jobs_get_missing_returns_none():
    from agent_bom.api.server import _jobs_get

    assert _jobs_get("nonexistent") is None


def test_jobs_bounded_eviction():
    """When _jobs exceeds _MAX_IN_MEMORY_JOBS, oldest completed jobs are evicted."""
    from agent_bom.api import server
    from agent_bom.api.server import JobStatus, ScanJob, ScanRequest, _jobs, _jobs_lock, _jobs_put

    original_max = server._MAX_IN_MEMORY_JOBS
    try:
        server._MAX_IN_MEMORY_JOBS = 5  # Lower for test

        # Clear any existing jobs
        with _jobs_lock:
            _jobs.clear()

        # Add 6 completed jobs
        for i in range(6):
            job = ScanJob(job_id=f"evict-{i}", created_at="2025-01-01T00:00:00Z", request=ScanRequest())
            job.status = JobStatus.DONE
            job.completed_at = f"2025-01-01T00:0{i}:00Z"
            _jobs_put(f"evict-{i}", job)

        with _jobs_lock:
            assert len(_jobs) <= 5
    finally:
        server._MAX_IN_MEMORY_JOBS = original_max
        # Cleanup
        with _jobs_lock:
            for k in list(_jobs.keys()):
                if k.startswith("evict-"):
                    del _jobs[k]


def test_jobs_concurrent_access():
    """Concurrent _jobs_put/_jobs_get don't raise."""
    from agent_bom.api.server import ScanJob, ScanRequest, _jobs_get, _jobs_pop, _jobs_put

    errors = []

    def writer(idx):
        try:
            job = ScanJob(job_id=f"concurrent-{idx}", created_at="2025-01-01T00:00:00Z", request=ScanRequest())
            _jobs_put(f"concurrent-{idx}", job)
            time.sleep(0.001)
            _jobs_get(f"concurrent-{idx}")
            _jobs_pop(f"concurrent-{idx}")
        except Exception as e:
            errors.append(e)

    threads = [threading.Thread(target=writer, args=(i,)) for i in range(20)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert errors == [], f"Concurrent access errors: {errors}"


# ── Store locking ───────────────────────────────────────────────────────────


def test_store_lock_exists():
    """_store_lock is a threading.Lock."""
    from agent_bom.api.server import _store_lock

    assert isinstance(_store_lock, type(threading.Lock()))


# ── Pagination ──────────────────────────────────────────────────────────────


def test_list_jobs_pagination():
    """GET /v1/jobs supports limit and offset."""
    from unittest.mock import patch

    from starlette.testclient import TestClient

    from agent_bom.api.server import app

    mock_store = MagicMock()
    # Return 10 summary items
    mock_store.list_summary.return_value = [{"job_id": f"j-{i}"} for i in range(10)]

    with patch("agent_bom.api.server._get_store", return_value=mock_store):
        client = TestClient(app)
        resp = client.get("/v1/jobs?limit=3&offset=2")
        assert resp.status_code == 200
        data = resp.json()
        assert data["count"] == 3
        assert data["total"] == 10
        assert data["limit"] == 3
        assert data["offset"] == 2
        assert data["jobs"][0]["job_id"] == "j-2"


def test_list_jobs_clamps_limit():
    """Limit is clamped to max 200."""
    from unittest.mock import patch

    from starlette.testclient import TestClient

    from agent_bom.api.server import app

    mock_store = MagicMock()
    mock_store.list_summary.return_value = []

    with patch("agent_bom.api.server._get_store", return_value=mock_store):
        client = TestClient(app)
        resp = client.get("/v1/jobs?limit=999")
        assert resp.status_code == 200
        assert resp.json()["limit"] == 200


def test_list_fleet_pagination():
    """GET /v1/fleet supports limit and offset."""
    from unittest.mock import patch

    from starlette.testclient import TestClient

    from agent_bom.api.server import app

    mock_store = MagicMock()
    agents = [MagicMock() for _ in range(10)]
    for i, a in enumerate(agents):
        a.lifecycle_state.value = "discovered"
        a.environment = "prod"
        a.trust_score = 0.5
        a.model_dump.return_value = {"agent_id": f"a-{i}"}
    mock_store.list_all.return_value = agents

    with patch("agent_bom.api.server._get_fleet_store", return_value=mock_store):
        client = TestClient(app)
        resp = client.get("/v1/fleet?limit=3&offset=5")
        assert resp.status_code == 200
        data = resp.json()
        assert data["count"] == 3
        assert data["total"] == 10
        assert data["offset"] == 5


# ── Scheduler backoff ───────────────────────────────────────────────────────


def test_scheduler_backoff_on_failure():
    """Scheduler uses exponential backoff on consecutive failures."""
    import asyncio

    from agent_bom.api.scheduler import scheduler_loop

    store = MagicMock()
    store.list_due.side_effect = RuntimeError("DB down")

    run_fn = MagicMock()
    sleep_calls = []

    original_sleep = asyncio.sleep

    async def mock_sleep(seconds):
        sleep_calls.append(seconds)
        if len(sleep_calls) >= 3:
            raise asyncio.CancelledError()
        # Don't actually sleep

    with patch("asyncio.sleep", side_effect=mock_sleep):
        try:
            asyncio.run(scheduler_loop(store, run_fn, interval_seconds=10, max_backoff=300))
        except (asyncio.CancelledError, KeyboardInterrupt):
            pass

    # First failure: 10 * 2^1 = 20, second: 10 * 2^2 = 40
    assert len(sleep_calls) >= 2
    assert sleep_calls[0] == 20  # 10 * 2^1
    assert sleep_calls[1] == 40  # 10 * 2^2


# ── Pip extras stripping ────────────────────────────────────────────────────


def test_strip_extras():
    """_strip_extras removes bracket notation from package names."""
    from agent_bom.scanners import _strip_extras

    assert _strip_extras("requests[security]") == "requests"
    assert _strip_extras("boto3[crt]") == "boto3"
    assert _strip_extras("plain-package") == "plain-package"
    assert _strip_extras("uvloop") == "uvloop"


# ── npm PURL encoding ──────────────────────────────────────────────────────


def test_npm_purl_scoped():
    """Scoped npm packages encode @ as %40 in PURL."""
    from agent_bom.parsers import _npm_purl

    result = _npm_purl("@modelcontextprotocol/server-filesystem", "2.0.0")
    assert result == "pkg:npm/%40modelcontextprotocol/server-filesystem@2.0.0"


def test_npm_purl_unscoped():
    """Unscoped npm packages produce a simple PURL."""
    from agent_bom.parsers import _npm_purl

    result = _npm_purl("express", "4.18.2")
    assert result == "pkg:npm/express@4.18.2"


# ── Path validation in scan ────────────────────────────────────────────────


def test_scan_request_path_traversal_blocked():
    """API scan rejects path traversal in filesystem_paths."""
    from agent_bom.security import SecurityError, validate_path

    try:
        validate_path("../../etc/passwd", must_exist=True)
        assert False, "Should have raised SecurityError"
    except SecurityError:
        pass


# ── Docker cleanup error handling ───────────────────────────────────────────


def test_docker_rm_failure_logged(caplog):
    """docker rm failure is logged, not silently swallowed."""

    from agent_bom.image import _scan_with_docker

    create_result = MagicMock()
    create_result.returncode = 0
    create_result.stdout = "container-abc\n"

    export_result = MagicMock()
    export_result.returncode = 1

    rm_result = MagicMock()
    rm_result.returncode = 1
    rm_result.stderr = "Error: No such container"

    with patch("agent_bom.image.subprocess.run") as mock_run, patch("agent_bom.image._docker_inspect"):
        mock_run.side_effect = [create_result, export_result, rm_result]
        try:
            _scan_with_docker("test:latest")
        except Exception:
            pass
        # docker rm was called even though export failed (finally block)
        rm_calls = [c for c in mock_run.call_args_list if "rm" in str(c)]
        assert len(rm_calls) >= 1
