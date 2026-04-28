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
