"""Asynchronous correlation execution, freshness, and atomic output contracts."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import pytest

from agent_bom.api.graph_store import SQLiteGraphStore
from agent_bom.graph.container import UnifiedGraph
from agent_bom.graph.correlation import CorrelationRunStatus, GraphCorrelationRun, correlation_manifest_digest
from agent_bom.graph.correlation_service import CorrelationRequest, CorrelationServiceError, GraphCorrelationService
from agent_bom.graph.edge import UnifiedEdge
from agent_bom.graph.node import UnifiedNode
from agent_bom.graph.types import EntityType, RelationshipType

NOW = datetime(2026, 8, 30, 12, 0, tzinfo=timezone.utc)


def _graph(scan_id: str, created_at: str, *, purl: str = "pkg:pypi/pillow@9.0.0") -> UnifiedGraph:
    graph = UnifiedGraph(scan_id=scan_id, tenant_id="tenant-a", created_at=created_at)
    graph.add_node(
        UnifiedNode(
            id=f"package:{scan_id}",
            entity_type=EntityType.PACKAGE,
            label="pillow@9.0.0",
            attributes={"purl": purl},
            data_sources=["sbom"],
        )
    )
    graph.add_node(
        UnifiedNode(
            id=f"vuln:{scan_id}",
            entity_type=EntityType.VULNERABILITY,
            label="CVE-2023-4863",
            attributes={"canonical_id": "CVE-2023-4863", "reachability": "confirmed"},
            data_sources=["advisory"],
        )
    )
    graph.add_edge(
        UnifiedEdge(
            source=f"package:{scan_id}",
            target=f"vuln:{scan_id}",
            relationship=RelationshipType.VULNERABLE_TO,
            source_scan_id=scan_id,
            evidence={"advisory": "CVE-2023-4863"},
        )
    )
    return graph


@pytest.mark.asyncio
async def test_service_persists_complete_correlation_and_manifest(tmp_path: Path) -> None:
    store = SQLiteGraphStore(tmp_path / "graph.db")
    store.save_graph(_graph("repo", "2026-08-30T10:00:00+00:00"))
    store.save_graph(_graph("image", "2026-08-30T11:00:00+00:00"))
    service = GraphCorrelationService(store, now=lambda: NOW, queue_capacity=2)
    await service.start(tenants=["tenant-a"])
    try:
        submitted = await service.submit(
            CorrelationRequest(
                correlation_id="corr-1",
                tenant_id="tenant-a",
                idempotency_key="idem-1",
                name="repo plus image",
                scan_ids=("repo", "image"),
                max_age_hours=24,
            )
        )
        assert submitted.status.value == "pending"

        completed = await service.wait("tenant-a", "corr-1", timeout_seconds=5)
    finally:
        await service.stop()

    assert completed.status.value == "complete"
    assert completed.output_scan_id == "corr-1"
    assert completed.manifest_sha256.startswith("sha256:")
    assert completed.result_manifest["correlation_id"] == "corr-1"
    assert completed.result_manifest["analysis_bounds"]["attack_path_fusion"]["status"] == "complete"
    assert {item["freshness"] for item in completed.result_manifest["input_snapshots"]} == {"fresh"}

    output = store.load_graph(tenant_id="tenant-a", scan_id="corr-1")
    assert output.scan_id == "corr-1"
    assert output.nodes
    snapshots = {row["scan_id"]: row for row in store.list_snapshots(tenant_id="tenant-a", limit=10)}
    assert snapshots["corr-1"]["snapshot_kind"] == "correlation"
    assert snapshots["corr-1"]["evidence_manifest_sha256"] == completed.manifest_sha256
    assert output.edges[0].provenance["correlation"]["freshness"] == "fresh"


@pytest.mark.asyncio
async def test_service_rejects_stale_input_before_creating_run(tmp_path: Path) -> None:
    store = SQLiteGraphStore(tmp_path / "graph.db")
    store.save_graph(_graph("old", "2026-08-20T10:00:00+00:00"))
    store.save_graph(_graph("new", "2026-08-30T11:00:00+00:00"))
    service = GraphCorrelationService(store, now=lambda: NOW)

    with pytest.raises(CorrelationServiceError, match="stale_input"):
        await service.submit(
            CorrelationRequest(
                correlation_id="corr-stale",
                tenant_id="tenant-a",
                idempotency_key="idem-stale",
                name="stale rejected",
                scan_ids=("old", "new"),
                max_age_hours=24,
            )
        )

    assert store.get_correlation_run(tenant_id="tenant-a", correlation_id="corr-stale") is None
    assert store.load_graph(tenant_id="tenant-a", scan_id="corr-stale").nodes == {}


@pytest.mark.asyncio
async def test_allowed_stale_input_remains_visibly_stale(tmp_path: Path) -> None:
    store = SQLiteGraphStore(tmp_path / "graph.db")
    store.save_graph(_graph("old", "2026-08-20T10:00:00+00:00"))
    store.save_graph(_graph("new", "2026-08-30T11:00:00+00:00"))
    service = GraphCorrelationService(store, now=lambda: NOW)
    await service.start(tenants=["tenant-a"])
    try:
        await service.submit(
            CorrelationRequest(
                correlation_id="corr-stale-allowed",
                tenant_id="tenant-a",
                idempotency_key="idem-stale-allowed",
                name="stale visible",
                scan_ids=("old", "new"),
                max_age_hours=24,
                allow_stale=True,
            )
        )
        completed = await service.wait("tenant-a", "corr-stale-allowed", timeout_seconds=5)
    finally:
        await service.stop()

    assert {item["freshness"] for item in completed.result_manifest["input_snapshots"]} == {"fresh", "stale_allowed"}
    output = store.load_graph(tenant_id="tenant-a", scan_id="corr-stale-allowed")
    assert output.edges[0].provenance["correlation"]["freshness"] == "stale_allowed"


@pytest.mark.asyncio
async def test_pending_run_is_reconciled_after_restart(tmp_path: Path) -> None:
    store = SQLiteGraphStore(tmp_path / "graph.db")
    store.save_graph(_graph("repo", "2026-08-30T10:00:00+00:00"))
    store.save_graph(_graph("image", "2026-08-30T11:00:00+00:00"))
    dormant = GraphCorrelationService(store, now=lambda: NOW)
    request = CorrelationRequest(
        correlation_id="corr-restart",
        tenant_id="tenant-a",
        idempotency_key="idem-restart",
        name="restart",
        scan_ids=("repo", "image"),
        max_age_hours=24,
    )
    pending = await dormant.submit(request)
    assert pending.status is CorrelationRunStatus.PENDING

    resumed = GraphCorrelationService(store, now=lambda: NOW)
    await resumed.start(tenants=["tenant-a"])
    try:
        completed = await resumed.wait("tenant-a", "corr-restart", timeout_seconds=5)
    finally:
        await resumed.stop()
    assert completed.status is CorrelationRunStatus.COMPLETE


@pytest.mark.asyncio
async def test_restart_reconciliation_backpressures_instead_of_dropping_pending_runs(tmp_path: Path) -> None:
    store = SQLiteGraphStore(tmp_path / "graph.db")
    store.save_graph(_graph("repo", "2026-08-30T10:00:00+00:00"))
    store.save_graph(_graph("image", "2026-08-30T11:00:00+00:00"))
    dormant = GraphCorrelationService(store, now=lambda: NOW, queue_capacity=4)
    for index in range(3):
        await dormant.submit(
            CorrelationRequest(
                f"corr-restart-{index}",
                "tenant-a",
                f"idem-restart-{index}",
                f"restart {index}",
                ("repo", "image"),
                24,
            )
        )

    resumed = GraphCorrelationService(store, now=lambda: NOW, queue_capacity=1)
    await resumed.start(tenants=["tenant-a"])
    try:
        completed = [await resumed.wait("tenant-a", f"corr-restart-{index}", timeout_seconds=5) for index in range(3)]
    finally:
        await resumed.stop()

    assert {run.status for run in completed} == {CorrelationRunStatus.COMPLETE}


@pytest.mark.asyncio
async def test_source_snapshot_change_after_submission_fails_without_output(tmp_path: Path) -> None:
    store = SQLiteGraphStore(tmp_path / "graph.db")
    store.save_graph(_graph("repo", "2026-08-30T10:00:00+00:00"))
    store.save_graph(_graph("image", "2026-08-30T11:00:00+00:00"))
    dormant = GraphCorrelationService(store, now=lambda: NOW)
    await dormant.submit(
        CorrelationRequest(
            "corr-source-changed",
            "tenant-a",
            "idem-source-changed",
            "immutable source",
            ("repo", "image"),
            24,
        )
    )

    store.save_graph(
        _graph(
            "repo",
            "2026-08-30T10:00:00+00:00",
            purl="pkg:pypi/pillow@10.0.0",
        )
    )
    resumed = GraphCorrelationService(store, now=lambda: NOW)
    await resumed.start(tenants=["tenant-a"])
    try:
        failed = await resumed.wait("tenant-a", "corr-source-changed", timeout_seconds=5)
    finally:
        await resumed.stop()

    assert failed.status is CorrelationRunStatus.FAILED
    assert failed.failure_code == "input_snapshot_changed"
    assert store.load_graph(tenant_id="tenant-a", scan_id="corr-source-changed").nodes == {}


@pytest.mark.asyncio
async def test_merge_budget_exceeded_leaves_no_selectable_partial_snapshot(tmp_path: Path) -> None:
    store = SQLiteGraphStore(tmp_path / "graph.db")
    store.save_graph(_graph("repo", "2026-08-30T10:00:00+00:00"))
    store.save_graph(
        _graph(
            "image",
            "2026-08-30T11:00:00+00:00",
            purl="pkg:pypi/pillow@10.0.0",
        )
    )
    service = GraphCorrelationService(store, now=lambda: NOW, max_output_nodes=2, max_output_edges=10)
    await service.start(tenants=["tenant-a"])
    try:
        await service.submit(
            CorrelationRequest(
                "corr-over-budget",
                "tenant-a",
                "idem-over-budget",
                "bounded merge",
                ("repo", "image"),
                24,
            )
        )
        failed = await service.wait("tenant-a", "corr-over-budget", timeout_seconds=5)
    finally:
        await service.stop()

    assert failed.status is CorrelationRunStatus.FAILED
    assert failed.failure_code == "correlation_budget_exceeded"
    assert store.load_graph(tenant_id="tenant-a", scan_id="corr-over-budget").nodes == {}


@pytest.mark.asyncio
async def test_idempotent_replay_does_not_duplicate_run(tmp_path: Path) -> None:
    store = SQLiteGraphStore(tmp_path / "graph.db")
    store.save_graph(_graph("repo", "2026-08-30T10:00:00+00:00"))
    store.save_graph(_graph("image", "2026-08-30T11:00:00+00:00"))
    service = GraphCorrelationService(store, now=lambda: NOW, queue_capacity=2)
    request = CorrelationRequest(
        correlation_id="corr-replay",
        tenant_id="tenant-a",
        idempotency_key="idem-replay",
        name="replay",
        scan_ids=("repo", "image"),
        max_age_hours=24,
    )

    first = await service.submit(request)
    replay = await service.submit(request)

    assert replay.correlation_id == first.correlation_id
    assert len(store.list_correlation_runs(tenant_id="tenant-a")) == 1


@pytest.mark.asyncio
async def test_queue_backpressure_fails_second_run_without_output(tmp_path: Path) -> None:
    store = SQLiteGraphStore(tmp_path / "graph.db")
    store.save_graph(_graph("repo", "2026-08-30T10:00:00+00:00"))
    store.save_graph(_graph("image", "2026-08-30T11:00:00+00:00"))
    service = GraphCorrelationService(store, now=lambda: NOW, queue_capacity=1)
    await service.submit(CorrelationRequest("corr-first", "tenant-a", "idem-first", "first", ("repo", "image"), 24))

    with pytest.raises(CorrelationServiceError, match="queue_capacity_exceeded"):
        await service.submit(CorrelationRequest("corr-second", "tenant-a", "idem-second", "second", ("repo", "image"), 24))

    failed = store.get_correlation_run(tenant_id="tenant-a", correlation_id="corr-second")
    assert failed is not None and failed.status is CorrelationRunStatus.FAILED
    assert failed.failure_code == "queue_capacity_exceeded"
    assert store.load_graph(tenant_id="tenant-a", scan_id="corr-second").nodes == {}


def test_atomic_completion_rolls_back_snapshot_on_manifest_mismatch(tmp_path: Path) -> None:
    store = SQLiteGraphStore(tmp_path / "graph.db")
    run = GraphCorrelationRun(
        correlation_id="corr-atomic",
        tenant_id="tenant-a",
        idempotency_key="idem-atomic",
        name="atomic",
        status=CorrelationRunStatus.PENDING,
        max_age_hours=24,
        allow_stale=False,
        input_manifest=[{"scan_id": "one"}, {"scan_id": "two"}],
        created_at=NOW.isoformat(),
    )
    store.create_correlation_run(run)
    store.update_correlation_run(
        tenant_id="tenant-a",
        correlation_id="corr-atomic",
        status=CorrelationRunStatus.RUNNING,
        started_at=NOW.isoformat(),
    )
    output = _graph("corr-atomic", NOW.isoformat())

    with pytest.raises(ValueError, match="manifest hash"):
        store.complete_correlation_run(
            output,
            result_manifest={"correlation_id": "corr-atomic"},
            manifest_sha256="sha256:" + "0" * 64,
            completed_at=NOW.isoformat(),
        )

    assert store.load_graph(tenant_id="tenant-a", scan_id="corr-atomic").nodes == {}
    running = store.get_correlation_run(tenant_id="tenant-a", correlation_id="corr-atomic")
    assert running is not None and running.status is CorrelationRunStatus.RUNNING


def test_atomic_completion_rejects_a_manifest_bound_to_different_graph_content(tmp_path: Path) -> None:
    store = SQLiteGraphStore(tmp_path / "graph.db")
    run = GraphCorrelationRun(
        correlation_id="corr-content",
        tenant_id="tenant-a",
        idempotency_key="idem-content",
        name="content bound",
        status=CorrelationRunStatus.PENDING,
        max_age_hours=24,
        allow_stale=False,
        input_manifest=[{"scan_id": "one"}, {"scan_id": "two"}],
        created_at=NOW.isoformat(),
    )
    store.create_correlation_run(run)
    store.update_correlation_run(
        tenant_id="tenant-a",
        correlation_id="corr-content",
        status=CorrelationRunStatus.RUNNING,
        started_at=NOW.isoformat(),
    )
    output = _graph("corr-content", NOW.isoformat())
    result_manifest = {
        "correlation_id": "corr-content",
        "output": {
            "scan_id": "corr-content",
            "node_count": len(output.nodes),
            "edge_count": len(output.edges),
            "graph_digest_sha256": "sha256:" + "f" * 64,
        },
    }

    with pytest.raises(ValueError, match="graph digest"):
        store.complete_correlation_run(
            output,
            result_manifest=result_manifest,
            manifest_sha256=correlation_manifest_digest(result_manifest),
            completed_at=NOW.isoformat(),
        )

    assert store.load_graph(tenant_id="tenant-a", scan_id="corr-content").nodes == {}
    running = store.get_correlation_run(tenant_id="tenant-a", correlation_id="corr-content")
    assert running is not None and running.status is CorrelationRunStatus.RUNNING
