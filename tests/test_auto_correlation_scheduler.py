"""Exact-scope automatic graph-correlation scheduling contracts."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import pytest

from agent_bom.api.auto_correlation import (
    AutoCorrelationPolicy,
    auto_correlation_policy_from_env,
    reconcile_auto_correlations_once,
)
from agent_bom.api.graph_store import SQLiteGraphStore
from agent_bom.api.metrics import render_prometheus_lines, reset_for_tests
from agent_bom.api.models import JobStatus, ScanJob, ScanRequest
from agent_bom.api.store import InMemoryJobStore, JobStore, SQLiteJobStore
from agent_bom.graph.container import UnifiedGraph
from agent_bom.graph.correlation import CorrelationRunStatus
from agent_bom.graph.correlation_service import GraphCorrelationService
from agent_bom.graph.node import UnifiedNode
from agent_bom.graph.types import EntityType

NOW = datetime(2026, 9, 3, 12, 0, tzinfo=timezone.utc)


def _job(
    job_id: str,
    *,
    tenant_id: str = "tenant-a",
    batch_id: str | None = None,
    parent_job_id: str | None = None,
    child_job_ids: list[str] | None = None,
    source_id: str | None = None,
    status: JobStatus = JobStatus.DONE,
) -> ScanJob:
    return ScanJob(
        job_id=job_id,
        tenant_id=tenant_id,
        batch_id=batch_id,
        parent_job_id=parent_job_id,
        child_job_ids=child_job_ids or [],
        source_id=source_id,
        status=status,
        created_at=NOW.isoformat(),
        completed_at=NOW.isoformat() if status in {JobStatus.DONE, JobStatus.FAILED, JobStatus.CANCELLED} else None,
        request=ScanRequest(),
        result={},
    )


def _graph(scan_id: str, *, tenant_id: str = "tenant-a") -> UnifiedGraph:
    graph = UnifiedGraph(scan_id=scan_id, tenant_id=tenant_id, created_at=NOW.isoformat())
    graph.add_node(
        UnifiedNode(
            id=f"agent:{scan_id}",
            entity_type=EntityType.AGENT,
            label=scan_id,
            attributes={"canonical_id": f"runtime:{scan_id}"},
            data_sources=["test"],
        )
    )
    return graph


def _batch(store: JobStore, *, tenant_id: str = "tenant-a", batch_id: str = "batch-a") -> ScanJob:
    parent = _job(
        f"parent-{batch_id}",
        tenant_id=tenant_id,
        batch_id=batch_id,
        child_job_ids=[f"{batch_id}-repo", f"{batch_id}-image"],
        source_id="source-recurring",
    )
    store.put(parent)
    for child_id in parent.child_job_ids:
        store.put(
            _job(
                child_id,
                tenant_id=tenant_id,
                batch_id=batch_id,
                parent_job_id=parent.job_id,
                source_id="source-recurring",
            )
        )
    return parent


def test_scheduler_is_disabled_by_default_and_rejects_invalid_freshness(monkeypatch: pytest.MonkeyPatch) -> None:
    from agent_bom import config

    monkeypatch.setattr(config, "GRAPH_AUTO_CORRELATE", False)
    monkeypatch.setattr(config, "GRAPH_AUTO_CORRELATE_MAX_AGE_HOURS", 168)
    assert auto_correlation_policy_from_env().enabled is False
    with pytest.raises(ValueError, match="max_age_hours"):
        AutoCorrelationPolicy(enabled=True, max_age_hours=0)


def test_batch_refresh_preserves_durable_auto_correlation_receipt(monkeypatch: pytest.MonkeyPatch) -> None:
    from agent_bom.api import stores
    from agent_bom.api.scan_batches import refresh_batch_parent

    jobs = InMemoryJobStore()
    parent = _batch(jobs, batch_id="refresh-preserves-receipt")
    parent.result = {"auto_correlation": {"status": "scheduled", "reason": "scheduled"}}
    jobs.put(parent)
    monkeypatch.setattr(stores, "_store", jobs)
    monkeypatch.setattr(stores, "_jobs", {})
    monkeypatch.setattr(stores, "_job_locks", {})

    refreshed = refresh_batch_parent(parent.job_id, tenant_id=parent.tenant_id)

    assert refreshed is not None
    assert refreshed.result["auto_correlation"] == {"status": "scheduled", "reason": "scheduled"}


@pytest.mark.asyncio
async def test_exact_batch_is_scheduled_without_unrelated_latest_snapshots(tmp_path: Path) -> None:
    jobs = InMemoryJobStore()
    graph_store = SQLiteGraphStore(tmp_path / "graph.db")
    parent = _batch(jobs)
    for scan_id in parent.child_job_ids:
        graph_store.save_graph(_graph(scan_id))
    graph_store.save_graph(_graph("unrelated-latest"))

    service = GraphCorrelationService(graph_store, now=lambda: NOW)
    await service.start(tenants=["tenant-a"])
    try:
        decisions = await reconcile_auto_correlations_once(
            jobs,
            graph_store,
            policy=AutoCorrelationPolicy(enabled=True, max_age_hours=168),
            now=lambda: NOW,
            service=service,
        )
        assert len(decisions) == 1
        run = await service.wait("tenant-a", decisions[0]["correlation_id"], timeout_seconds=5)
    finally:
        await service.stop()

    assert run.status is CorrelationRunStatus.COMPLETE
    assert {receipt["scan_id"] for receipt in run.input_manifest} == set(parent.child_job_ids)
    assert "unrelated-latest" not in {receipt["scan_id"] for receipt in run.input_manifest}
    persisted_parent = jobs.get(parent.job_id, tenant_id="tenant-a")
    assert persisted_parent is not None
    assert persisted_parent.result["auto_correlation"]["cohort_basis"] == "batch_id"
    assert persisted_parent.result["auto_correlation"]["allow_stale"] is False


@pytest.mark.asyncio
async def test_source_id_alone_never_forms_a_cohort(tmp_path: Path) -> None:
    jobs = InMemoryJobStore()
    graph_store = SQLiteGraphStore(tmp_path / "graph.db")
    for scan_id in ("source-run-one", "source-run-two"):
        jobs.put(_job(scan_id, source_id="same-recurring-source"))
        graph_store.save_graph(_graph(scan_id))

    service = GraphCorrelationService(graph_store, now=lambda: NOW)
    await service.start(tenants=["tenant-a"])
    try:
        decisions = await reconcile_auto_correlations_once(
            jobs,
            graph_store,
            policy=AutoCorrelationPolicy(enabled=True),
            now=lambda: NOW,
            service=service,
        )
    finally:
        await service.stop()

    assert decisions == []
    assert graph_store.list_correlation_runs(tenant_id="tenant-a") == []


@pytest.mark.asyncio
async def test_cross_tenant_or_incomplete_batch_is_durably_skipped(tmp_path: Path) -> None:
    jobs = InMemoryJobStore()
    graph_store = SQLiteGraphStore(tmp_path / "graph.db")
    parent = _batch(jobs)
    jobs.put(
        _job(
            parent.child_job_ids[1],
            tenant_id="tenant-b",
            batch_id=parent.batch_id,
            parent_job_id=parent.job_id,
        )
    )
    graph_store.save_graph(_graph(parent.child_job_ids[0]))

    service = GraphCorrelationService(graph_store, now=lambda: NOW)
    await service.start(tenants=["tenant-a"])
    try:
        decisions = await reconcile_auto_correlations_once(
            jobs,
            graph_store,
            policy=AutoCorrelationPolicy(enabled=True),
            now=lambda: NOW,
            service=service,
        )
    finally:
        await service.stop()

    assert len(decisions) == 1
    assert decisions[0]["status"] == "skipped"
    assert decisions[0]["reason"] == "batch_membership_mismatch"
    persisted_parent = jobs.get(parent.job_id, tenant_id="tenant-a")
    assert persisted_parent is not None
    assert persisted_parent.result["auto_correlation"]["status"] == "skipped"
    assert persisted_parent.result["auto_correlation"]["reason"] == "batch_membership_mismatch"
    assert graph_store.list_correlation_runs(tenant_id="tenant-a") == []
    assert graph_store.list_correlation_runs(tenant_id="tenant-b") == []


@pytest.mark.asyncio
async def test_missing_or_empty_snapshot_has_explicit_durable_reason(tmp_path: Path) -> None:
    jobs = InMemoryJobStore()
    graph_store = SQLiteGraphStore(tmp_path / "graph.db")
    parent = _batch(jobs)
    graph_store.save_graph(_graph(parent.child_job_ids[0]))

    service = GraphCorrelationService(graph_store, now=lambda: NOW)
    await service.start(tenants=["tenant-a"])
    try:
        await reconcile_auto_correlations_once(
            jobs,
            graph_store,
            policy=AutoCorrelationPolicy(enabled=True),
            now=lambda: NOW,
            service=service,
        )
    finally:
        await service.stop()

    persisted_parent = jobs.get(parent.job_id, tenant_id="tenant-a")
    assert persisted_parent is not None
    assert persisted_parent.result["auto_correlation"]["status"] == "skipped"
    assert persisted_parent.result["auto_correlation"]["reason"] == "snapshot_set_incomplete"


@pytest.mark.asyncio
async def test_deterministic_idempotency_and_restart_reconciliation(tmp_path: Path) -> None:
    jobs_path = tmp_path / "jobs.db"
    jobs = SQLiteJobStore(jobs_path)
    graph_store = SQLiteGraphStore(tmp_path / "graph.db")
    parent = _batch(jobs)
    for scan_id in parent.child_job_ids:
        graph_store.save_graph(_graph(scan_id))

    dormant = GraphCorrelationService(graph_store, now=lambda: NOW)
    first = await reconcile_auto_correlations_once(
        jobs,
        graph_store,
        policy=AutoCorrelationPolicy(enabled=True),
        now=lambda: NOW,
        service=dormant,
    )
    assert len(first) == 1
    pending = graph_store.get_correlation_run(tenant_id="tenant-a", correlation_id=first[0]["correlation_id"])
    assert pending is not None and pending.status is CorrelationRunStatus.PENDING

    resumed = GraphCorrelationService(graph_store, now=lambda: NOW)
    await resumed.start(tenants=["tenant-a"])
    try:
        replay = await reconcile_auto_correlations_once(
            jobs,
            graph_store,
            policy=AutoCorrelationPolicy(enabled=True, max_age_hours=24),
            now=lambda: NOW,
            service=resumed,
        )
        completed = await resumed.wait("tenant-a", first[0]["correlation_id"], timeout_seconds=5)
        await reconcile_auto_correlations_once(
            jobs,
            graph_store,
            policy=AutoCorrelationPolicy(enabled=True, max_age_hours=24),
            now=lambda: NOW,
            service=resumed,
        )
    finally:
        await resumed.stop()

    assert replay[0]["correlation_id"] == first[0]["correlation_id"]
    assert completed.status is CorrelationRunStatus.COMPLETE
    assert len(graph_store.list_correlation_runs(tenant_id="tenant-a")) == 1
    persisted_parent = SQLiteJobStore(jobs_path).get(parent.job_id, tenant_id="tenant-a")
    assert persisted_parent is not None
    assert persisted_parent.result["auto_correlation"]["status"] == "complete"
    assert persisted_parent.result["auto_correlation"]["output_scan_id"] == first[0]["correlation_id"]
    assert persisted_parent.result["auto_correlation"]["max_age_hours"] == 168


@pytest.mark.asyncio
async def test_active_tenant_quota_defers_without_losing_batch(tmp_path: Path) -> None:
    jobs = InMemoryJobStore()
    graph_store = SQLiteGraphStore(tmp_path / "graph.db")
    first = _batch(jobs, batch_id="batch-first")
    second = _batch(jobs, batch_id="batch-second")
    for scan_id in [*first.child_job_ids, *second.child_job_ids]:
        graph_store.save_graph(_graph(scan_id))

    service = GraphCorrelationService(graph_store, now=lambda: NOW)
    try:
        decisions = await reconcile_auto_correlations_once(
            jobs,
            graph_store,
            policy=AutoCorrelationPolicy(enabled=True, max_batches_per_poll=2, max_active_per_tenant=1),
            now=lambda: NOW,
            service=service,
        )
    finally:
        await service.stop()

    assert len(decisions) == 2
    statuses = {decision["status"] for decision in decisions}
    assert statuses == {"scheduled", "deferred"}
    deferred = next(decision for decision in decisions if decision["status"] == "deferred")
    assert deferred["reason"] == "tenant_active_quota"


@pytest.mark.asyncio
async def test_scheduler_emits_bounded_metrics_and_audit_for_skip_and_schedule(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from agent_bom.api import auto_correlation

    reset_for_tests()
    audit_events: list[tuple[str, dict[str, object]]] = []
    monkeypatch.setattr(
        auto_correlation,
        "log_action",
        lambda action, **details: audit_events.append((action, details)),
    )
    jobs = InMemoryJobStore()
    graph_store = SQLiteGraphStore(tmp_path / "graph.db")
    eligible = _batch(jobs, batch_id="eligible")
    missing = _batch(jobs, batch_id="missing")
    for scan_id in eligible.child_job_ids:
        graph_store.save_graph(_graph(scan_id))
    graph_store.save_graph(_graph(missing.child_job_ids[0]))

    service = GraphCorrelationService(graph_store, now=lambda: NOW)
    try:
        await reconcile_auto_correlations_once(
            jobs,
            graph_store,
            policy=AutoCorrelationPolicy(enabled=True, max_batches_per_poll=2),
            now=lambda: NOW,
            service=service,
        )
    finally:
        await service.stop()

    metrics = "\n".join(render_prometheus_lines())
    assert 'agent_bom_auto_correlations_total{outcome="scheduled",reason="scheduled"} 1' in metrics
    assert 'agent_bom_auto_correlations_total{outcome="skipped",reason="snapshot_set_incomplete"} 1' in metrics
    assert {(action, details["outcome"]) for action, details in audit_events} == {
        ("graph.auto_correlation_decision", "scheduled"),
        ("graph.auto_correlation_decision", "skipped"),
    }
    assert {details["cohort_basis"] for _, details in audit_events} == {"batch_id"}
