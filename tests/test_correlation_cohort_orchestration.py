"""Explicit source-cohort orchestration contracts."""

from __future__ import annotations

import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from agent_bom.api.auto_correlation import AutoCorrelationPolicy, reconcile_auto_correlations_once
from agent_bom.api.graph_store import SQLiteGraphStore
from agent_bom.api.models import ScanRequest
from agent_bom.api.routes import scan as scan_routes
from agent_bom.api.scan_batches import refresh_batch_parent
from agent_bom.api.store import InMemoryJobStore, SQLiteJobStore
from agent_bom.api.stores import set_graph_store, set_job_store
from agent_bom.graph.container import UnifiedGraph
from agent_bom.graph.correlation_service import GraphCorrelationService
from agent_bom.graph.node import UnifiedNode
from agent_bom.graph.types import EntityType

NOW = datetime(2026, 9, 3, 12, 0, tzinfo=timezone.utc)


def _requests() -> list[tuple[str, ScanRequest]]:
    return [
        ("source-repo", ScanRequest(repo_url="https://github.com/example/app")),
        ("source-image", ScanRequest(images=["example/app@sha256:" + "a" * 64])),
    ]


def test_explicit_cohort_is_tenant_bound_and_never_derived_from_mutable_source_labels() -> None:
    alpha = scan_routes.correlation_cohort_id(tenant_id="tenant-a", idempotency_key="run-42")
    beta = scan_routes.correlation_cohort_id(tenant_id="tenant-b", idempotency_key="run-42")

    assert alpha != beta
    assert alpha == scan_routes.correlation_cohort_id(tenant_id="tenant-a", idempotency_key="run-42")


def test_durable_cohort_replay_preserves_exact_membership_and_policy(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    jobs_path = tmp_path / "jobs.db"
    graph_path = tmp_path / "graph.db"
    jobs = SQLiteJobStore(jobs_path)
    set_job_store(jobs)
    set_graph_store(SQLiteGraphStore(graph_path))
    dispatched: list[str] = []
    monkeypatch.setattr(scan_routes, "dispatch_scan_job", lambda job: dispatched.append(job.job_id))
    cohort_id = scan_routes.correlation_cohort_id(tenant_id="tenant-a", idempotency_key="run-42")

    first = scan_routes.enqueue_correlation_cohort(
        tenant_id="tenant-a",
        triggered_by="api-test",
        correlation_cohort_id=cohort_id,
        source_requests=_requests(),
        max_age_hours=24,
    )

    assert first.correlation_cohort_id == cohort_id
    assert first.batch_id == cohort_id
    assert first.result["auto_correlation"]["cohort_basis"] == "correlation_cohort_id"
    assert first.result["auto_correlation"]["max_age_hours"] == 24
    assert len(first.child_job_ids) == 2
    children = [jobs.get(job_id, tenant_id="tenant-a") for job_id in first.child_job_ids]
    assert [child.source_id for child in children if child] == ["source-image", "source-repo"]
    assert all(child.correlation_cohort_id == cohort_id for child in children if child)
    assert dispatched == first.child_job_ids

    set_job_store(SQLiteJobStore(jobs_path))
    set_graph_store(SQLiteGraphStore(graph_path))
    dispatched.clear()
    replay = scan_routes.enqueue_correlation_cohort(
        tenant_id="tenant-a",
        triggered_by="api-test",
        correlation_cohort_id=cohort_id,
        source_requests=list(reversed(_requests())),
        max_age_hours=24,
    )

    assert replay.job_id == first.job_id
    assert replay.child_job_ids == first.child_job_ids
    assert dispatched == []


def test_cohort_creation_publishes_no_durable_or_hot_cache_rows_when_atomic_write_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    class FailAtomicPutStore(SQLiteJobStore):
        def put_many_atomic(self, jobs) -> None:
            raise RuntimeError("database password=do-not-return")

    jobs = FailAtomicPutStore(tmp_path / "jobs.db")
    set_job_store(jobs)
    set_graph_store(SQLiteGraphStore(tmp_path / "graph.db"))
    monkeypatch.setattr(scan_routes, "dispatch_scan_job", lambda job: None)
    cohort_id = scan_routes.correlation_cohort_id(tenant_id="tenant-a", idempotency_key="atomic-run")

    with pytest.raises(RuntimeError, match="database password"):
        scan_routes.enqueue_correlation_cohort(
            tenant_id="tenant-a",
            triggered_by="api-test",
            correlation_cohort_id=cohort_id,
            source_requests=_requests(),
            max_age_hours=24,
        )

    assert jobs.list_all(tenant_id="tenant-a") == []
    from agent_bom.api import stores

    assert not any(job.tenant_id == "tenant-a" for job in stores._jobs.values())


def test_correlation_decision_audit_records_the_exact_cohort_basis(monkeypatch: pytest.MonkeyPatch) -> None:
    from agent_bom.api import auto_correlation
    from agent_bom.api.models import ScanJob, ScanRequest

    records: list[dict] = []
    monkeypatch.setattr(auto_correlation, "log_action", lambda action, **details: records.append({"action": action, **details}))
    parent = ScanJob(
        job_id="parent",
        tenant_id="tenant-a",
        batch_id="cohort",
        correlation_cohort_id="00000000-0000-0000-0000-000000000001",
        created_at=NOW.isoformat(),
        request=ScanRequest(),
    )
    decision = auto_correlation._decision(
        parent=parent,
        policy=AutoCorrelationPolicy(),
        now=NOW,
        status="pending",
        reason="batch_incomplete",
    )

    auto_correlation._record_decision(parent, decision)

    assert records[0]["cohort_basis"] == "correlation_cohort_id"


def test_durable_cohort_replay_repairs_a_missing_child_after_interrupted_legacy_write(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    jobs = SQLiteJobStore(tmp_path / "jobs.db")
    set_job_store(jobs)
    set_graph_store(SQLiteGraphStore(tmp_path / "graph.db"))
    dispatched: list[str] = []
    monkeypatch.setattr(scan_routes, "dispatch_scan_job", lambda job: dispatched.append(job.job_id))
    cohort_id = scan_routes.correlation_cohort_id(tenant_id="tenant-a", idempotency_key="run-42")
    parent = scan_routes.enqueue_correlation_cohort(
        tenant_id="tenant-a",
        triggered_by="api-test",
        correlation_cohort_id=cohort_id,
        source_requests=_requests(),
        max_age_hours=24,
    )
    missing_child_id = parent.child_job_ids[0]
    assert jobs.delete(missing_child_id, tenant_id="tenant-a") is True
    dispatched.clear()

    recovered = scan_routes.enqueue_correlation_cohort(
        tenant_id="tenant-a",
        triggered_by="api-test",
        correlation_cohort_id=cohort_id,
        source_requests=_requests(),
        max_age_hours=24,
    )

    assert recovered.job_id == parent.job_id
    repaired = jobs.get(missing_child_id, tenant_id="tenant-a")
    assert repaired is not None
    assert repaired.parent_job_id == parent.job_id
    assert repaired.source_id == "source-image"
    assert dispatched == [missing_child_id]


def test_two_replicas_dispatch_only_the_winning_cohort_child_repair(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    jobs = SQLiteJobStore(tmp_path / "jobs.db")
    set_job_store(jobs)
    set_graph_store(SQLiteGraphStore(tmp_path / "graph.db"))
    dispatched: list[str] = []
    monkeypatch.setattr(scan_routes, "dispatch_scan_job", lambda job: dispatched.append(job.job_id))
    cohort_id = scan_routes.correlation_cohort_id(tenant_id="tenant-a", idempotency_key="repair-race")
    parent = scan_routes.enqueue_correlation_cohort(
        tenant_id="tenant-a",
        triggered_by="api-test",
        correlation_cohort_id=cohort_id,
        source_requests=_requests(),
        max_age_hours=24,
    )
    missing_id = parent.child_job_ids[0]
    jobs.delete(missing_id, tenant_id="tenant-a")
    dispatched.clear()
    barrier = threading.Barrier(2)
    real_insert = jobs.put_many_if_absent_atomic

    def synchronized_insert(children):
        barrier.wait(timeout=5)
        return real_insert(children)

    monkeypatch.setattr(jobs, "put_many_if_absent_atomic", synchronized_insert)
    kwargs = {
        "tenant_id": "tenant-a",
        "triggered_by": "api-test",
        "correlation_cohort_id": cohort_id,
        "source_requests": _requests(),
        "max_age_hours": 24,
    }
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _index: scan_routes.enqueue_correlation_cohort(**kwargs), range(2)))

    assert [item.job_id for item in results] == [parent.job_id, parent.job_id]
    assert dispatched == [missing_id]


def test_cohort_rejects_duplicates_incomplete_members_and_id_reuse(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    jobs = SQLiteJobStore(tmp_path / "jobs.db")
    set_job_store(jobs)
    set_graph_store(SQLiteGraphStore(tmp_path / "graph.db"))
    monkeypatch.setattr(scan_routes, "dispatch_scan_job", lambda job: None)
    cohort_id = scan_routes.correlation_cohort_id(tenant_id="tenant-a", idempotency_key="run-42")

    with pytest.raises(ValueError, match="distinct source ids"):
        scan_routes.enqueue_correlation_cohort(
            tenant_id="tenant-a",
            triggered_by="api-test",
            correlation_cohort_id=cohort_id,
            source_requests=[("source-repo", _requests()[0][1]), ("source-repo", _requests()[0][1])],
            max_age_hours=24,
        )
    with pytest.raises(ValueError, match="exactly one scan target"):
        scan_routes.enqueue_correlation_cohort(
            tenant_id="tenant-a",
            triggered_by="api-test",
            correlation_cohort_id=cohort_id,
            source_requests=[("source-repo", ScanRequest()), ("source-image", _requests()[1][1])],
            max_age_hours=24,
        )

    scan_routes.enqueue_correlation_cohort(
        tenant_id="tenant-a",
        triggered_by="api-test",
        correlation_cohort_id=cohort_id,
        source_requests=_requests(),
        max_age_hours=24,
    )
    with pytest.raises(ValueError, match="cohort id was reused"):
        scan_routes.enqueue_correlation_cohort(
            tenant_id="tenant-a",
            triggered_by="api-test",
            correlation_cohort_id=cohort_id,
            source_requests=[
                ("source-repo", _requests()[0][1]),
                ("source-other-image", ScanRequest(images=["example/other@sha256:" + "b" * 64])),
            ],
            max_age_hours=24,
        )
    with pytest.raises(ValueError, match="max_age_hours"):
        scan_routes.enqueue_correlation_cohort(
            tenant_id="tenant-a",
            triggered_by="api-test",
            correlation_cohort_id=scan_routes.correlation_cohort_id(tenant_id="tenant-a", idempotency_key="invalid-age"),
            source_requests=_requests(),
            max_age_hours=0,
        )


def test_unsupported_store_records_terminal_cohort_skip(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    jobs = InMemoryJobStore()
    set_job_store(jobs)
    set_graph_store(SQLiteGraphStore(tmp_path / "graph.db"))
    monkeypatch.setattr(scan_routes, "dispatch_scan_job", lambda job: None)
    cohort_id = scan_routes.correlation_cohort_id(tenant_id="tenant-a", idempotency_key="run-42")

    parent = scan_routes.enqueue_correlation_cohort(
        tenant_id="tenant-a",
        triggered_by="api-test",
        correlation_cohort_id=cohort_id,
        source_requests=_requests(),
        max_age_hours=168,
    )

    assert parent.result["auto_correlation"]["status"] == "skipped"
    assert parent.result["auto_correlation"]["reason"] == "durable_job_store_required"


@pytest.mark.asyncio
async def test_cohort_freshness_policy_is_preserved_through_scheduler_reconciliation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    jobs = SQLiteJobStore(tmp_path / "jobs.db")
    graph_store = SQLiteGraphStore(tmp_path / "graph.db")
    set_job_store(jobs)
    set_graph_store(graph_store)
    monkeypatch.setattr(scan_routes, "dispatch_scan_job", lambda job: None)
    cohort_id = scan_routes.correlation_cohort_id(tenant_id="tenant-a", idempotency_key="stale-run")
    parent = scan_routes.enqueue_correlation_cohort(
        tenant_id="tenant-a",
        triggered_by="api-test",
        correlation_cohort_id=cohort_id,
        source_requests=_requests(),
        max_age_hours=24,
        dispatch=False,
    )
    for child_id in parent.child_job_ids:
        child = jobs.get(child_id, tenant_id="tenant-a")
        assert child is not None
        child.status = scan_routes.JobStatus.DONE
        child.completed_at = NOW.isoformat()
        jobs.put(child)
        graph = UnifiedGraph(
            scan_id=child_id,
            tenant_id="tenant-a",
            created_at=(NOW - timedelta(hours=48)).isoformat(),
        )
        graph.add_node(
            UnifiedNode(
                id=f"agent:{child_id}",
                entity_type=EntityType.AGENT,
                label=child_id,
                attributes={"canonical_id": f"runtime:{child_id}"},
                data_sources=["test"],
            )
        )
        graph_store.save_graph(graph)
    refresh_batch_parent(parent.job_id, tenant_id="tenant-a")

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
    finally:
        await service.stop()

    assert decisions[0]["status"] == "skipped"
    assert decisions[0]["reason"] == "stale_input"
    assert decisions[0]["max_age_hours"] == 24
    assert decisions[0]["cohort_basis"] == "correlation_cohort_id"
