"""Bounded asynchronous execution for immutable graph correlations."""

from __future__ import annotations

import asyncio
import logging
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Callable, Sequence

from agent_bom.api.graph_store import GraphStoreProtocol
from agent_bom.graph.analysis import analysis_status_map_to_dict
from agent_bom.graph.attack_path_fusion import apply_attack_path_fusion
from agent_bom.graph.attack_path_mitre import apply_attack_path_technique_mappings
from agent_bom.graph.correlation import (
    CorrelationMergeResult,
    CorrelationRunStatus,
    CorrelationSnapshot,
    GraphCorrelationRun,
    correlation_graph_digest,
    correlation_manifest_digest,
)
from agent_bom.graph.correlation_receipts import (
    CorrelationReceiptError,
    configured_receipt_signing_key,
    sign_correlation_receipt,
    verify_correlation_receipt,
)
from agent_bom.graph.correlation_workspace import CorrelationMergeBudgetError, CorrelationMergeWorkspace

logger = logging.getLogger(__name__)

_MAX_FUTURE_SNAPSHOT_SKEW = timedelta(minutes=5)

_shared_service: GraphCorrelationService | None = None
_shared_service_store: object | None = None
_shared_service_loop: asyncio.AbstractEventLoop | None = None


def _timestamp(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise CorrelationServiceError("invalid_snapshot_timestamp") from exc
    if parsed.tzinfo is None:
        raise CorrelationServiceError("invalid_snapshot_timestamp")
    return parsed.astimezone(timezone.utc)


def _manifest_with_current_freshness(
    manifest: Sequence[dict[str, object]],
    *,
    now: datetime,
    max_age_hours: int,
    allow_stale: bool,
) -> list[dict[str, object]]:
    """Recompute freshness at the decision point without changing receipts."""

    refreshed: list[dict[str, object]] = []
    for item in manifest:
        created_at = _timestamp(str(item.get("created_at") or ""))
        if created_at - now > _MAX_FUTURE_SNAPSHOT_SKEW:
            raise CorrelationServiceError("input_snapshot_in_future")
        age_hours = max(0.0, (now - created_at).total_seconds() / 3600.0)
        freshness = "fresh" if age_hours <= max_age_hours else "stale_allowed"
        if freshness != "fresh" and not allow_stale:
            raise CorrelationServiceError("stale_input")
        receipt = dict(item)
        receipt["freshness"] = freshness
        receipt["age_hours"] = round(age_hours, 6)
        refreshed.append(receipt)
    return refreshed


@dataclass(frozen=True, slots=True)
class CorrelationRequest:
    correlation_id: str
    tenant_id: str
    idempotency_key: str
    name: str
    scan_ids: tuple[str, ...]
    max_age_hours: int
    allow_stale: bool = False


class CorrelationServiceError(RuntimeError):
    """Sanitized machine-readable correlation failure."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class GraphCorrelationService:
    """Single-process bounded worker pool over durable correlation runs."""

    def __init__(
        self,
        store: GraphStoreProtocol,
        *,
        now: Callable[[], datetime] | None = None,
        queue_capacity: int = 16,
        worker_count: int = 1,
        max_output_nodes: int = 100_000,
        max_output_edges: int = 500_000,
        receipt_signing_key: bytes | None = None,
        receipt_signing_key_id: str = "",
        execution_lease_seconds: int = 30,
    ) -> None:
        if queue_capacity < 1:
            raise ValueError("queue_capacity must be positive")
        if not 1 <= worker_count <= 4:
            raise ValueError("worker_count must be between 1 and 4")
        if max_output_nodes < 1 or max_output_edges < 1:
            raise ValueError("correlation output budgets must be positive")
        if execution_lease_seconds < 3:
            raise ValueError("execution_lease_seconds must be at least 3")
        self._store = store
        self._now = now or (lambda: datetime.now(timezone.utc))
        self._queue: asyncio.Queue[tuple[str, str] | None] = asyncio.Queue(maxsize=queue_capacity)
        self._worker_count = worker_count
        self._max_output_nodes = max_output_nodes
        self._max_output_edges = max_output_edges
        self._execution_lease_seconds = execution_lease_seconds
        self._receipt_signing_key = receipt_signing_key
        self._receipt_signing_key_id = receipt_signing_key_id.strip()
        self._workers: list[asyncio.Task[None]] = []
        self._queued: set[tuple[str, str]] = set()
        self._reconciled_tenants: set[str] = set()

    async def start(self, *, tenants: Sequence[str] = ()) -> None:
        if not self._workers:
            self._workers = [asyncio.create_task(self._worker(), name=f"graph-correlation-{index}") for index in range(self._worker_count)]
        for tenant_id in tenants:
            await self.reconcile_tenant(tenant_id)

    async def reconcile_tenant(self, tenant_id: str) -> None:
        """Requeue durable unfinished work once per tenant after a process start."""

        if tenant_id in self._reconciled_tenants:
            return
        runs = await asyncio.to_thread(self._store.list_correlation_runs, tenant_id=tenant_id, limit=1000)
        for run in reversed(runs):
            if run.status in {CorrelationRunStatus.PENDING, CorrelationRunStatus.RUNNING}:
                await self._enqueue(run.tenant_id, run.correlation_id, wait_for_capacity=True)
        self._reconciled_tenants.add(tenant_id)

    async def stop(self) -> None:
        if not self._workers:
            return
        for _worker in self._workers:
            await self._queue.put(None)
        await asyncio.gather(*self._workers)
        self._workers.clear()
        self._queued.clear()
        self._reconciled_tenants.clear()

    async def submit(self, request: CorrelationRequest) -> GraphCorrelationRun:
        replay = await asyncio.to_thread(
            self._store.get_correlation_run_by_idempotency_key,
            tenant_id=request.tenant_id,
            idempotency_key=request.idempotency_key,
        )
        if replay is not None:
            replay_scan_ids = tuple(sorted(str(item.get("scan_id") or "") for item in replay.input_manifest))
            if (
                replay.name != request.name
                or replay.max_age_hours != request.max_age_hours
                or replay.allow_stale is not request.allow_stale
                or replay_scan_ids != tuple(sorted(request.scan_ids))
            ):
                raise ValueError("idempotency key was already used for a different correlation request")
            return replay
        now = self._now().astimezone(timezone.utc).isoformat()
        manifest = await self._validate_inputs(request)
        if self._receipt_signing_key is not None:
            manifest = [
                sign_correlation_receipt(
                    receipt,
                    signing_key=self._receipt_signing_key,
                    key_id=self._receipt_signing_key_id,
                    tenant_id=request.tenant_id,
                    correlation_id=request.correlation_id,
                    correlation_created_at=now,
                    max_age_hours=request.max_age_hours,
                    allow_stale=request.allow_stale,
                )
                for receipt in manifest
            ]
        run = GraphCorrelationRun(
            correlation_id=request.correlation_id,
            tenant_id=request.tenant_id,
            idempotency_key=request.idempotency_key,
            name=request.name,
            status=CorrelationRunStatus.PENDING,
            max_age_hours=request.max_age_hours,
            allow_stale=request.allow_stale,
            input_manifest=manifest,
            created_at=now,
        )
        persisted, created = await asyncio.to_thread(self._store.create_correlation_run, run)
        if created and persisted.status is CorrelationRunStatus.PENDING:
            try:
                await self._enqueue(persisted.tenant_id, persisted.correlation_id)
            except CorrelationServiceError:
                persisted = await asyncio.to_thread(
                    self._store.update_correlation_run,
                    tenant_id=persisted.tenant_id,
                    correlation_id=persisted.correlation_id,
                    status=CorrelationRunStatus.FAILED,
                    failure_code="queue_capacity_exceeded",
                    completed_at=now,
                )
                raise
        return persisted

    async def wait(self, tenant_id: str, correlation_id: str, *, timeout_seconds: float = 30.0) -> GraphCorrelationRun:
        deadline = asyncio.get_running_loop().time() + max(timeout_seconds, 0.01)
        while True:
            run = await asyncio.to_thread(
                self._store.get_correlation_run,
                tenant_id=tenant_id,
                correlation_id=correlation_id,
            )
            if run is None:
                raise CorrelationServiceError("correlation_not_found")
            if run.status in {CorrelationRunStatus.COMPLETE, CorrelationRunStatus.FAILED}:
                return run
            if asyncio.get_running_loop().time() >= deadline:
                raise CorrelationServiceError("correlation_wait_timeout")
            await asyncio.sleep(0.02)

    async def _validate_inputs(self, request: CorrelationRequest) -> list[dict[str, object]]:
        if not 2 <= len(request.scan_ids) <= 32:
            raise CorrelationServiceError("invalid_snapshot_count")
        if len(set(request.scan_ids)) != len(request.scan_ids) or any(not item.strip() for item in request.scan_ids):
            raise CorrelationServiceError("invalid_snapshot_ids")
        if not 1 <= request.max_age_hours <= 8760:
            raise CorrelationServiceError("invalid_freshness_policy")

        rows = await asyncio.to_thread(
            self._store.snapshots_by_ids,
            tenant_id=request.tenant_id,
            scan_ids=set(request.scan_ids),
        )
        metadata = {str(row.get("scan_id") or ""): row for row in rows}
        now = self._now().astimezone(timezone.utc)
        manifest: list[dict[str, object]] = []
        for scan_id in sorted(request.scan_ids):
            row = metadata.get(scan_id)
            if row is None:
                raise CorrelationServiceError("input_snapshot_not_found")
            if row.get("snapshot_kind", "scan") != "scan":
                raise CorrelationServiceError("nested_correlation_unsupported")
            if int(row.get("node_count") or 0) < 1:
                raise CorrelationServiceError("empty_input_snapshot")
            created_at = str(row.get("created_at") or "")
            graph = await asyncio.to_thread(
                self._store.load_graph,
                tenant_id=request.tenant_id,
                scan_id=scan_id,
            )
            snapshot = CorrelationSnapshot.from_graph(graph)
            manifest.append(
                {
                    "scan_id": scan_id,
                    "created_at": created_at,
                    "digest": snapshot.digest,
                    "node_count": len(graph.nodes),
                    "edge_count": len(graph.edges),
                    "source_kinds": sorted({source for node in graph.nodes.values() for source in node.data_sources}),
                }
            )
        return _manifest_with_current_freshness(
            manifest,
            now=now,
            max_age_hours=request.max_age_hours,
            allow_stale=request.allow_stale,
        )

    async def _enqueue(self, tenant_id: str, correlation_id: str, *, wait_for_capacity: bool = False) -> None:
        key = (tenant_id, correlation_id)
        if key in self._queued:
            return
        if wait_for_capacity:
            self._queued.add(key)
            try:
                await self._queue.put(key)
            except BaseException:
                self._queued.discard(key)
                raise
            return
        try:
            self._queue.put_nowait(key)
        except asyncio.QueueFull as exc:
            raise CorrelationServiceError("queue_capacity_exceeded") from exc
        self._queued.add(key)

    async def _worker(self) -> None:
        while True:
            item = await self._queue.get()
            if item is None:
                self._queue.task_done()
                return
            self._queued.discard(item)
            try:
                await self._execute(*item)
            finally:
                self._queue.task_done()

    async def _execute(self, tenant_id: str, correlation_id: str) -> None:
        owner_token = uuid.uuid4().hex
        run = await asyncio.to_thread(
            self._store.claim_correlation_run_execution,
            tenant_id=tenant_id,
            correlation_id=correlation_id,
            owner_token=owner_token,
            lease_seconds=self._execution_lease_seconds,
            now=self._now().astimezone(timezone.utc).isoformat(),
        )
        if run is None:
            return
        lease_lost = asyncio.Event()

        async def heartbeat() -> None:
            while True:
                await asyncio.sleep(max(1.0, self._execution_lease_seconds / 3))
                owned = await asyncio.to_thread(
                    self._store.heartbeat_correlation_run_execution,
                    tenant_id=tenant_id,
                    correlation_id=correlation_id,
                    owner_token=owner_token,
                    lease_seconds=self._execution_lease_seconds,
                    now=self._now().astimezone(timezone.utc).isoformat(),
                )
                if not owned:
                    lease_lost.set()
                    return

        heartbeat_task = asyncio.create_task(heartbeat())
        try:
            for item in run.input_manifest:
                signature = item.get("signature")
                if signature is not None:
                    if self._receipt_signing_key is None:
                        raise CorrelationServiceError("receipt_signing_key_unavailable")
                    if not verify_correlation_receipt(
                        item,
                        signing_key=self._receipt_signing_key,
                        tenant_id=tenant_id,
                        correlation_id=correlation_id,
                        correlation_created_at=run.created_at,
                        max_age_hours=run.max_age_hours,
                        allow_stale=run.allow_stale,
                    ):
                        raise CorrelationServiceError("input_receipt_signature_invalid")
            execution_manifest = _manifest_with_current_freshness(
                run.input_manifest,
                now=self._now().astimezone(timezone.utc),
                max_age_hours=run.max_age_hours,
                allow_stale=run.allow_stale,
            )
            if self._receipt_signing_key is not None:
                execution_manifest = [
                    sign_correlation_receipt(
                        receipt,
                        signing_key=self._receipt_signing_key,
                        key_id=self._receipt_signing_key_id,
                        tenant_id=tenant_id,
                        correlation_id=correlation_id,
                        correlation_created_at=run.created_at,
                        max_age_hours=run.max_age_hours,
                        allow_stale=run.allow_stale,
                    )
                    for receipt in execution_manifest
                ]
            merged = await asyncio.to_thread(
                self._load_and_merge_inputs,
                tenant_id=tenant_id,
                correlation_id=correlation_id,
                created_at=run.created_at,
                input_manifest=execution_manifest,
            )
            freshness_by_scan = {str(item["scan_id"]): str(item["freshness"]) for item in execution_manifest}
            for edge in merged.graph.edges:
                correlation = edge.provenance.get("correlation")
                if not isinstance(correlation, dict):
                    correlation = {}
                    edge.provenance["correlation"] = correlation
                source_ids = [str(item) for item in correlation.get("source_scan_ids") or []]
                correlation["freshness"] = (
                    "stale_allowed" if any(freshness_by_scan.get(scan_id) == "stale_allowed" for scan_id in source_ids) else "fresh"
                )

            await asyncio.to_thread(apply_attack_path_fusion, merged.graph)
            await asyncio.to_thread(apply_attack_path_technique_mappings, merged.graph)
            merge_output = merged.manifest.get("output", {})
            node_conflicts = int(merge_output.get("node_conflict_count") or 0)
            edge_conflicts = int(merge_output.get("edge_conflict_count") or 0)
            result_manifest = {
                "schema_version": "agent-bom.graph-correlation-manifest/v1",
                "correlation_id": correlation_id,
                "tenant_id": tenant_id,
                "created_at": merged.graph.created_at,
                "freshness_policy": {
                    "max_age_hours": run.max_age_hours,
                    "allow_stale": run.allow_stale,
                },
                "input_snapshots": execution_manifest,
                "correlation_merge": {
                    "node_conflict_count": node_conflicts,
                    "edge_conflict_count": edge_conflicts,
                    "conflict_count": node_conflicts + edge_conflicts,
                },
                "analysis_bounds": {
                    "correlation_merge": {
                        "status": "complete",
                        "execution_strategy": "disk_backed_incremental",
                        "max_resident_source_graphs": 1,
                        "node_limit": self._max_output_nodes,
                        "edge_limit": self._max_output_edges,
                        "input_node_observation_count": sum(int(str(item.get("node_count") or 0)) for item in execution_manifest),
                        "input_edge_observation_count": sum(int(str(item.get("edge_count") or 0)) for item in execution_manifest),
                        "node_count": len(merged.graph.nodes),
                        "edge_count": len(merged.graph.edges),
                        "truncated": False,
                    },
                    **analysis_status_map_to_dict(merged.graph.analysis_status),
                },
                "output": {
                    "scan_id": correlation_id,
                    "node_count": len(merged.graph.nodes),
                    "edge_count": len(merged.graph.edges),
                    "attack_path_count": len(merged.graph.attack_paths),
                    "graph_digest_sha256": correlation_graph_digest(merged.graph),
                },
            }
            manifest_sha256 = correlation_manifest_digest(result_manifest)
            if lease_lost.is_set():
                return
            await asyncio.to_thread(
                self._store.complete_correlation_run,
                merged.graph,
                result_manifest=result_manifest,
                manifest_sha256=manifest_sha256,
                completed_at=self._now().astimezone(timezone.utc).isoformat(),
                execution_owner=owner_token,
            )
        except Exception as exc:  # noqa: BLE001 - persisted as a sanitized code only
            code = exc.code if isinstance(exc, CorrelationServiceError) else "correlation_execution_failed"
            logger.warning("graph correlation failed: %s", code)
            if not lease_lost.is_set():
                try:
                    await asyncio.to_thread(
                        self._store.update_correlation_run,
                        tenant_id=tenant_id,
                        correlation_id=correlation_id,
                        status=CorrelationRunStatus.FAILED,
                        failure_code=code,
                        completed_at=self._now().astimezone(timezone.utc).isoformat(),
                        execution_owner=owner_token,
                    )
                except ValueError:
                    # Another replica took over or completed after this worker
                    # lost its lease. The stale worker must not alter that run.
                    return
        finally:
            heartbeat_task.cancel()
            await asyncio.gather(heartbeat_task, return_exceptions=True)

    def _load_and_merge_inputs(
        self,
        *,
        tenant_id: str,
        correlation_id: str,
        created_at: str,
        input_manifest: Sequence[dict[str, object]],
    ) -> CorrelationMergeResult:
        """Load one source at a time into a private disk-backed accumulator."""

        try:
            with CorrelationMergeWorkspace(
                correlation_id=correlation_id,
                tenant_id=tenant_id,
                created_at=created_at,
                max_output_nodes=self._max_output_nodes,
                max_output_edges=self._max_output_edges,
            ) as workspace:
                for item in sorted(
                    input_manifest,
                    key=lambda value: (_timestamp(str(value.get("created_at") or "")), str(value.get("scan_id") or "")),
                ):
                    graph = self._store.load_graph(
                        tenant_id=tenant_id,
                        scan_id=str(item["scan_id"]),
                    )
                    if not graph.nodes:
                        raise CorrelationServiceError("input_snapshot_unavailable")
                    snapshot = CorrelationSnapshot.from_graph(graph)
                    if snapshot.digest != str(item.get("digest") or ""):
                        raise CorrelationServiceError("input_snapshot_changed")
                    workspace.add_snapshot(snapshot)
                    # Do not retain the source graph until the next iteration;
                    # the workspace now owns its serialized observations.
                    del snapshot
                    del graph
                return workspace.finish()
        except CorrelationMergeBudgetError as exc:
            raise CorrelationServiceError("correlation_budget_exceeded") from exc


async def get_graph_correlation_service(store: GraphStoreProtocol, tenant_id: str) -> GraphCorrelationService:
    """Return the process-local worker pool without importing the HTTP surface."""

    global _shared_service, _shared_service_loop, _shared_service_store
    loop = asyncio.get_running_loop()
    if _shared_service is None or _shared_service_store is not store or _shared_service_loop is not loop:
        try:
            receipt_signing_key = configured_receipt_signing_key()
        except CorrelationReceiptError as exc:
            raise CorrelationServiceError(str(exc)) from exc
        from agent_bom import config as agent_config

        _shared_service = GraphCorrelationService(
            store,
            receipt_signing_key=receipt_signing_key,
            receipt_signing_key_id=agent_config.RUNTIME_FACTS_KEY_ID,
        )
        _shared_service_store = store
        _shared_service_loop = loop
    await _shared_service.start(tenants=[tenant_id])
    return _shared_service


__all__ = ["CorrelationRequest", "CorrelationServiceError", "GraphCorrelationService", "get_graph_correlation_service"]
