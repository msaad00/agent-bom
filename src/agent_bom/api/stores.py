"""Centralized store accessors for the agent-bom API.

All pluggable store singletons (job, fleet, policy, analytics, exception,
trend, audit-log, schedule) and the in-memory SSE job cache live here so
that both ``server.py`` and ``pipeline.py`` can import them without
circular dependencies.
"""

from __future__ import annotations

import threading
from collections import deque
from pathlib import Path
from typing import TYPE_CHECKING, Any

from agent_bom.config import API_MAX_IN_MEMORY_JOBS as _MAX_IN_MEMORY_JOBS

if TYPE_CHECKING:
    from agent_bom.api.models import ScanJob
    from agent_bom.api.schedule_store import ScheduleStore

# ─── Lazy-init lock (protects all store singletons) ─────────────────────────
_store_lock = threading.Lock()

# ─── Job store (pluggable) ───────────────────────────────────────────────────
_store: Any = None


def _get_store():
    """Get the active job store, creating InMemoryJobStore if not yet set."""
    global _store
    if _store is None:
        with _store_lock:
            if _store is None:
                from agent_bom.api.store import InMemoryJobStore

                _store = InMemoryJobStore()
    return _store


def set_job_store(store: Any) -> None:
    """Switch the job store backend. Call before server startup."""
    global _store
    _store = store


# ─── In-memory job refs for SSE streaming (bounded, thread-safe) ─────────────
_jobs: dict[str, ScanJob] = {}
_jobs_lock = threading.Lock()
_job_locks: dict[str, threading.Lock] = {}


def _job_lock(job_id: str) -> threading.Lock:
    """Get or create a per-job lock for thread-safe field access."""
    with _jobs_lock:
        if job_id not in _job_locks:
            _job_locks[job_id] = threading.Lock()
        return _job_locks[job_id]


def _jobs_put(job_id: str, job: ScanJob) -> None:
    """Add a job to _jobs with bounded eviction."""
    from agent_bom.api.models import JobStatus

    with _jobs_lock:
        _jobs[job_id] = job
        if len(_jobs) > _MAX_IN_MEMORY_JOBS:
            completed = [(jid, j) for jid, j in _jobs.items() if j.status in (JobStatus.DONE, JobStatus.FAILED, JobStatus.CANCELLED)]
            completed.sort(key=lambda x: x[1].completed_at or "")
            for jid, _ in completed[: len(_jobs) - _MAX_IN_MEMORY_JOBS]:
                _jobs.pop(jid, None)


def _jobs_get(job_id: str) -> ScanJob | None:
    """Thread-safe get from _jobs."""
    with _jobs_lock:
        return _jobs.get(job_id)


def _jobs_pop(job_id: str) -> ScanJob | None:
    """Thread-safe pop from _jobs."""
    with _jobs_lock:
        return _jobs.pop(job_id, None)


# ─── Fleet store ─────────────────────────────────────────────────────────────
_fleet_store: Any = None


def _get_fleet_store():
    """Get the active fleet store, creating InMemoryFleetStore if not set."""
    global _fleet_store
    if _fleet_store is None:
        with _store_lock:
            if _fleet_store is None:
                from agent_bom.api.fleet_store import InMemoryFleetStore

                _fleet_store = InMemoryFleetStore()
    return _fleet_store


def set_fleet_store(store: Any) -> None:
    """Switch the fleet store backend. Call before server startup."""
    global _fleet_store
    _fleet_store = store


# ─── Policy store ────────────────────────────────────────────────────────────
_policy_store: Any = None


def _get_policy_store():
    """Get the active policy store, creating InMemoryPolicyStore if not set."""
    global _policy_store
    if _policy_store is None:
        with _store_lock:
            if _policy_store is None:
                from agent_bom.api.policy_store import InMemoryPolicyStore

                _policy_store = InMemoryPolicyStore()
    return _policy_store


def set_policy_store(store: Any) -> None:
    """Switch the policy store backend. Call before server startup."""
    global _policy_store
    _policy_store = store


# ─── Analytics store (ClickHouse OLAP — optional) ────────────────────────────
_analytics_store: Any = None


def _get_analytics_store():
    """Get the active analytics store, defaulting to NullAnalyticsStore."""
    global _analytics_store
    if _analytics_store is None:
        with _store_lock:
            if _analytics_store is None:
                from agent_bom.api.clickhouse_store import NullAnalyticsStore

                _analytics_store = NullAnalyticsStore()
    return _analytics_store


def set_analytics_store(store: Any) -> None:
    """Switch the analytics store backend. Call before server startup."""
    global _analytics_store
    _analytics_store = store


# ─── Exception store ─────────────────────────────────────────────────────────
_exception_store: Any = None


def _get_exception_store():
    global _exception_store
    if _exception_store is None:
        from agent_bom.api.exception_store import InMemoryExceptionStore

        _exception_store = InMemoryExceptionStore()
    return _exception_store


# ─── Trend / Baseline store ──────────────────────────────────────────────────
_trend_store: Any = None
_last_scan_report: dict | None = None


def _get_trend_store():
    global _trend_store
    if _trend_store is None:
        from agent_bom.baseline import InMemoryTrendStore

        _trend_store = InMemoryTrendStore()
    return _trend_store


# ─── Audit log store ─────────────────────────────────────────────────────────
_audit_log_store: Any = None

# ─── Schedule store ──────────────────────────────────────────────────────────
_schedule_store: ScheduleStore | None = None


def _get_schedule_store() -> ScheduleStore:
    """Return the schedule store (must be initialized during lifespan)."""
    assert _schedule_store is not None, "Schedule store not initialized"
    return _schedule_store


# ─── Proxy alerts & metrics (ring buffer) ────────────────────────────────────
_proxy_alerts: deque[dict] = deque(maxlen=1000)
_proxy_alerts_total: int = 0
_proxy_metrics: dict | None = None


def push_proxy_alert(alert: dict) -> None:
    """Called by the proxy to record a runtime alert (in-process path)."""
    global _proxy_alerts_total
    _proxy_alerts.append(alert)
    _proxy_alerts_total += 1


def push_proxy_metrics(metrics: dict) -> None:
    """Called by the proxy to record latest metrics summary."""
    global _proxy_metrics
    _proxy_metrics = metrics


_MAX_LOG_LINES = 50_000


def _get_configured_log_path() -> Path | None:
    """Return the server-configured audit log path, if set."""
    import os

    log_env = os.environ.get("AGENT_BOM_LOG")
    if not log_env:
        return None
    path = Path(log_env).resolve()
    if not path.is_file() or path.suffix != ".jsonl":
        return None
    return path


def _read_alerts_from_log(path: Path) -> list[dict]:
    """Read runtime_alert records from a JSONL audit log."""
    import json as _json

    alerts: list[dict] = []
    try:
        with open(path) as f:
            for i, raw_line in enumerate(f):
                if i >= _MAX_LOG_LINES:
                    break
                line = raw_line.strip()
                if not line:
                    continue
                try:
                    record = _json.loads(line)
                    if record.get("type") == "runtime_alert":
                        alerts.append(record)
                except (ValueError, KeyError):
                    continue
    except OSError:
        pass
    return alerts


def _read_metrics_from_log(path: Path) -> dict | None:
    """Read the last proxy_summary record from a JSONL audit log."""
    import json as _json

    last_summary = None
    try:
        with open(path) as f:
            for i, raw_line in enumerate(f):
                if i >= _MAX_LOG_LINES:
                    break
                line = raw_line.strip()
                if not line:
                    continue
                try:
                    record = _json.loads(line)
                    if record.get("type") == "proxy_summary":
                        last_summary = record
                except (ValueError, KeyError):
                    continue
    except OSError:
        pass
    return last_summary
