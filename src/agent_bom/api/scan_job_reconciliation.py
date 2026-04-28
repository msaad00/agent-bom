"""Store-backed reconciliation for scan job lifecycle metrics."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from agent_bom.api.models import JobStatus, ScanJob

ACTIVE_SCAN_JOB_STATUSES = frozenset({JobStatus.PENDING, JobStatus.RUNNING})


def is_active_scan_job(job: ScanJob) -> bool:
    return job.status in ACTIVE_SCAN_JOB_STATUSES


def active_scan_job_count(store: Any, tenant_id: str | None = None) -> int:
    return sum(1 for job in store.list_all(tenant_id=tenant_id) if is_active_scan_job(job))


def reconcile_scan_jobs_active(store: Any, tenant_id: str | None = None) -> int:
    """Recompute the active scan gauge from the durable job store."""
    from agent_bom.api import metrics

    count = active_scan_job_count(store, tenant_id=tenant_id)
    metrics.reconcile_scan_jobs_active(count)
    return count


def _parse_created_at(job: ScanJob) -> datetime | None:
    if not job.created_at:
        return None
    try:
        return datetime.fromisoformat(job.created_at.replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None


def fail_stale_active_scan_jobs(
    store: Any,
    *,
    timeout_seconds: int,
    now: datetime | None = None,
    reason: str = "Timed out (stuck in active scan state)",
) -> int:
    """Mark active jobs older than timeout_seconds as failed."""
    current = now or datetime.now(timezone.utc)
    failed = 0
    for job in store.list_all():
        if not is_active_scan_job(job):
            continue
        created = _parse_created_at(job)
        if created is None:
            continue
        if (current - created).total_seconds() <= timeout_seconds:
            continue
        job.status = JobStatus.FAILED
        job.error = reason
        job.completed_at = current.isoformat()
        store.put(job)
        failed += 1
    return failed


def fail_orphaned_active_scan_jobs(
    store: Any,
    *,
    reason: str = "Interrupted before completion; in-process executor state was lost",
) -> int:
    """Fail active jobs found during process startup.

    Scan execution is in-process. If a new API process sees PENDING/RUNNING
    rows in the durable store, those rows belonged to a previous executor and
    will not resume automatically.
    """
    now = datetime.now(timezone.utc)
    failed = 0
    for job in store.list_all():
        if not is_active_scan_job(job):
            continue
        job.status = JobStatus.FAILED
        job.error = reason
        job.completed_at = now.isoformat()
        store.put(job)
        failed += 1
    return failed
