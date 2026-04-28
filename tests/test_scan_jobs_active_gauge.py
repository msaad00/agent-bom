"""Regression tests for the ``agent_bom_scan_jobs_active`` gauge.

The gauge feeds the KEDA scaler in `deploy/helm/agent-bom`. A miswire here
silently breaks autoscaling, so these tests pin three properties:

1. ``record_scan_enqueued`` and ``record_scan_finished`` move the gauge by
   exactly one each, in opposite directions.
2. The gauge is non-negative — ``record_scan_finished`` past zero must
   floor at 0 (a Prometheus gauge value < 0 would be rejected by the
   text-format scrape; we'd rather absorb instrumentation gaps than
   crash the metrics endpoint).
3. ``render_prometheus_lines()`` emits the gauge with the canonical
   metric name and HELP/TYPE tuple.
"""

from __future__ import annotations

import pytest

from agent_bom.api import metrics
from agent_bom.api.models import JobStatus, ScanJob, ScanRequest
from agent_bom.api.scan_job_reconciliation import (
    fail_orphaned_active_scan_jobs,
    fail_stale_active_scan_jobs,
    reconcile_scan_jobs_active,
)
from agent_bom.api.store import InMemoryJobStore


@pytest.fixture(autouse=True)
def _reset_metrics() -> None:
    metrics.reset_for_tests()


def test_enqueued_and_finished_move_gauge_symmetrically() -> None:
    assert metrics.scan_jobs_active() == 0

    metrics.record_scan_enqueued()
    metrics.record_scan_enqueued()
    metrics.record_scan_enqueued()
    assert metrics.scan_jobs_active() == 3

    metrics.record_scan_finished()
    assert metrics.scan_jobs_active() == 2

    metrics.record_scan_finished()
    metrics.record_scan_finished()
    assert metrics.scan_jobs_active() == 0


def test_finished_past_zero_floors_at_zero() -> None:
    metrics.record_scan_finished()
    metrics.record_scan_finished()
    assert metrics.scan_jobs_active() == 0

    # And subsequent enqueues still increment from the floor cleanly.
    metrics.record_scan_enqueued()
    assert metrics.scan_jobs_active() == 1


def test_render_emits_gauge_with_canonical_metric_name() -> None:
    metrics.record_scan_enqueued()
    metrics.record_scan_enqueued()

    lines = metrics.render_prometheus_lines()
    text = "\n".join(lines)

    assert "# HELP agent_bom_scan_jobs_active" in text
    assert "# TYPE agent_bom_scan_jobs_active gauge" in text
    assert "agent_bom_scan_jobs_active 2" in lines


def test_reset_for_tests_clears_gauge() -> None:
    metrics.record_scan_enqueued()
    metrics.record_scan_enqueued()
    assert metrics.scan_jobs_active() == 2

    metrics.reset_for_tests()
    assert metrics.scan_jobs_active() == 0


def _job(job_id: str, status: JobStatus, created_at: str = "2026-04-28T00:00:00+00:00") -> ScanJob:
    return ScanJob(job_id=job_id, status=status, created_at=created_at, request=ScanRequest())


def test_reconcile_sets_gauge_from_durable_active_jobs() -> None:
    store = InMemoryJobStore()
    store.put(_job("pending", JobStatus.PENDING))
    store.put(_job("running", JobStatus.RUNNING))
    store.put(_job("done", JobStatus.DONE))

    metrics.record_scan_enqueued()
    metrics.record_scan_enqueued()
    metrics.record_scan_enqueued()
    metrics.record_scan_enqueued()
    assert metrics.scan_jobs_active() == 4

    assert reconcile_scan_jobs_active(store) == 2
    assert metrics.scan_jobs_active() == 2


def test_fail_stale_active_jobs_then_reconcile_clears_leaked_gauge() -> None:
    store = InMemoryJobStore()
    store.put(_job("old-pending", JobStatus.PENDING, "2026-04-28T00:00:00+00:00"))
    store.put(_job("old-running", JobStatus.RUNNING, "2026-04-28T00:00:00+00:00"))
    store.put(_job("fresh-running", JobStatus.RUNNING, "2026-04-28T00:29:40+00:00"))

    from datetime import datetime, timezone

    failed = fail_stale_active_scan_jobs(
        store,
        timeout_seconds=1800,
        now=datetime(2026, 4, 28, 0, 30, 1, tzinfo=timezone.utc),
    )

    assert failed == 2
    assert store.get("old-pending").status == JobStatus.FAILED
    assert store.get("old-running").status == JobStatus.FAILED
    assert store.get("fresh-running").status == JobStatus.RUNNING
    assert reconcile_scan_jobs_active(store) == 1
    assert metrics.scan_jobs_active() == 1


def test_startup_orphan_cleanup_fails_active_jobs() -> None:
    store = InMemoryJobStore()
    store.put(_job("orphan-pending", JobStatus.PENDING))
    store.put(_job("orphan-running", JobStatus.RUNNING))
    store.put(_job("done", JobStatus.DONE))

    assert fail_orphaned_active_scan_jobs(store) == 2
    assert store.get("orphan-pending").status == JobStatus.FAILED
    assert store.get("orphan-running").status == JobStatus.FAILED
    assert store.get("done").status == JobStatus.DONE
    assert reconcile_scan_jobs_active(store) == 0
    assert metrics.scan_jobs_active() == 0
