"""Exact-batch scheduling for immutable graph correlations.

The scheduler deliberately uses only API scan-batch membership as its cohort
contract.  A recurring ``source_id``, a mutable label, or a tenant's latest
snapshots are not sufficient evidence that snapshots describe one scan event.
Supported durable control-plane stores enable this bounded workflow by default;
unsupported stores no-op with a bounded metric reason.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from agent_bom import config
from agent_bom.api.audit_log import log_action
from agent_bom.api.graph_store import GraphStoreProtocol
from agent_bom.api.metrics import record_auto_correlation
from agent_bom.api.models import JobStatus, ScanJob
from agent_bom.api.postgres_common import reset_current_tenant, set_current_tenant
from agent_bom.api.store import InMemoryJobStore, JobStore
from agent_bom.api.stores import _job_lock, _jobs_put
from agent_bom.graph.correlation import CorrelationRunStatus
from agent_bom.graph.correlation_service import (
    CorrelationRequest,
    CorrelationServiceError,
    GraphCorrelationService,
    get_graph_correlation_service,
)
from agent_bom.security import sanitize_text

logger = logging.getLogger(__name__)

_AUTO_CORRELATION_NAMESPACE = uuid.UUID("d4922b75-6f97-56ab-a4d5-05cbb469f4bc")
_MAX_BATCH_TARGETS = 100
_DEFAULT_POLL_SECONDS = 5.0


@dataclass(frozen=True, slots=True)
class AutoCorrelationPolicy:
    """Bounded policy for one scheduler replica.

    ``enabled`` is true by default.  Freshness remains strict: automatic
    runs never set ``allow_stale``.
    """

    enabled: bool = True
    max_age_hours: int = 168
    max_batches_per_poll: int = 8
    max_active_per_tenant: int = 2
    poll_seconds: float = _DEFAULT_POLL_SECONDS

    def __post_init__(self) -> None:
        if not 1 <= self.max_age_hours <= 8760:
            raise ValueError("auto-correlation max_age_hours must be between 1 and 8760")
        if not 1 <= self.max_batches_per_poll <= 64:
            raise ValueError("auto-correlation max_batches_per_poll must be between 1 and 64")
        if not 1 <= self.max_active_per_tenant <= 16:
            raise ValueError("auto-correlation max_active_per_tenant must be between 1 and 16")
        if not 1 <= self.poll_seconds <= 3600:
            raise ValueError("auto-correlation poll_seconds must be between 1 and 3600")


def auto_correlation_policy_from_env() -> AutoCorrelationPolicy:
    """Read the process-start enablement gate and explicit freshness bound."""

    return AutoCorrelationPolicy(
        enabled=config.GRAPH_AUTO_CORRELATE,
        max_age_hours=config.GRAPH_AUTO_CORRELATE_MAX_AGE_HOURS,
    )


def auto_correlation_enabled() -> bool:
    """Return whether exact-batch automatic correlation is enabled."""

    return auto_correlation_policy_from_env().enabled


def auto_correlation_backend_skip_reason(job_store: JobStore, graph_store: GraphStoreProtocol) -> str:
    """Return a bounded reason when automatic correlation cannot run."""

    if isinstance(job_store, InMemoryJobStore):
        return "durable_job_store_required"
    if graph_store.__class__.__name__ == "NeptuneGraphStore":
        return "graph_backend_unsupported"
    return ""


def _deterministic_identity(*, tenant_id: str, batch_id: str) -> tuple[str, str]:
    cohort = f"{tenant_id}\x00{batch_id}"
    digest = hashlib.sha256(cohort.encode("utf-8")).hexdigest()
    correlation_id = str(uuid.uuid5(_AUTO_CORRELATION_NAMESPACE, cohort))
    return correlation_id, f"auto-batch-v1:{digest}"


def _decision(
    *,
    parent: ScanJob,
    policy: AutoCorrelationPolicy,
    now: datetime,
    status: str,
    reason: str,
    correlation_id: str = "",
    scan_ids: tuple[str, ...] = (),
) -> dict[str, Any]:
    prior = (parent.result or {}).get("auto_correlation") if isinstance(parent.result, dict) else None
    cohort_manifest_hash = parent.correlation_cohort_manifest_hash or (
        str(prior.get("cohort_manifest_hash") or "") if isinstance(prior, dict) else ""
    )
    return {
        "schema_version": "agent-bom.auto-correlation/v1",
        "status": status,
        "reason": reason,
        "cohort_basis": "correlation_cohort_id" if parent.correlation_cohort_id else "batch_id",
        "batch_id": parent.batch_id or "",
        "correlation_cohort_id": parent.correlation_cohort_id or "",
        "cohort_manifest_hash": cohort_manifest_hash,
        "correlation_id": correlation_id,
        "output_scan_id": correlation_id if status == "complete" else "",
        "input_scan_ids": list(scan_ids),
        "max_age_hours": policy.max_age_hours,
        "allow_stale": False,
        "updated_at": now.astimezone(timezone.utc).isoformat(),
    }


def initial_auto_correlation_decision(
    parent: ScanJob,
    *,
    policy: AutoCorrelationPolicy,
    now: datetime,
    backend_skip_reason: str = "",
) -> dict[str, Any]:
    """Return the initial pending or unsupported-store handoff for a scan batch."""

    correlation_id, _ = _deterministic_identity(tenant_id=parent.tenant_id, batch_id=parent.batch_id or parent.job_id)
    return _decision(
        parent=parent,
        policy=policy,
        now=now,
        status="skipped" if backend_skip_reason else "pending",
        reason=backend_skip_reason or "batch_incomplete",
        correlation_id=correlation_id,
        scan_ids=tuple(sorted(parent.child_job_ids)),
    )


def _persist_decision(job_store: JobStore, parent: ScanJob, decision: dict[str, Any]) -> None:
    """Merge scheduler state without replacing the completed scan result."""

    with _job_lock(parent.job_id):
        latest = job_store.get(parent.job_id, tenant_id=parent.tenant_id)
        if latest is None:
            return
        result = dict(latest.result) if isinstance(latest.result, dict) else {}
        result["auto_correlation"] = decision
        latest.result = result
        job_store.put(latest)
        _jobs_put(latest.job_id, latest, compact_terminal=True)


def _record_decision(parent: ScanJob, decision: dict[str, Any]) -> None:
    status = str(decision["status"])
    reason = str(decision["reason"])
    record_auto_correlation(outcome=status, reason=reason)
    log_action(
        "graph.auto_correlation_decision",
        actor="system:auto-correlation",
        resource=f"scan-batch/{parent.batch_id or parent.job_id}",
        tenant_id=parent.tenant_id,
        outcome=status,
        reason=reason,
        cohort_basis="batch_id",
        batch_id=parent.batch_id or "",
        correlation_id=str(decision.get("correlation_id") or ""),
        input_count=len(decision.get("input_scan_ids") or []),
        max_age_hours=int(decision["max_age_hours"]),
        allow_stale=False,
    )


def _persist_and_record(job_store: JobStore, parent: ScanJob, decision: dict[str, Any]) -> dict[str, Any]:
    previous = (parent.result or {}).get("auto_correlation") if isinstance(parent.result, dict) else None
    comparable_previous = {key: value for key, value in previous.items() if key != "updated_at"} if isinstance(previous, dict) else None
    comparable_next = {key: value for key, value in decision.items() if key != "updated_at"}
    if comparable_previous != comparable_next:
        _persist_decision(job_store, parent, decision)
        _record_decision(parent, decision)
    return decision


def _parent_rows(job_store: JobStore, policy: AutoCorrelationPolicy) -> list[dict[str, Any]]:
    # A parent is inserted before as many as 100 children.  Bound the query but
    # leave enough room to reach ``max_batches_per_poll`` parents.
    rows = job_store.list_summary(
        all_tenants=True,
        limit=policy.max_batches_per_poll * (_MAX_BATCH_TARGETS + 1),
        status=JobStatus.DONE,
    )
    parents = [row for row in rows if row.get("batch_id") and not row.get("parent_job_id") and len(row.get("child_job_ids") or []) >= 2]
    # Oldest first prevents a continuously active source from starving a prior
    # completed batch.  ``job_id`` makes ties deterministic.
    parents.sort(key=lambda row: (str(row.get("completed_at") or row.get("created_at") or ""), str(row.get("job_id") or "")))
    return parents


def _validated_batch_children(job_store: JobStore, parent: ScanJob) -> tuple[tuple[str, ...], str]:
    child_ids = tuple(parent.child_job_ids)
    if not 2 <= len(child_ids) <= 32 or len(set(child_ids)) != len(child_ids):
        return (), "snapshot_count_out_of_bounds"
    children = [job_store.get(child_id, tenant_id=parent.tenant_id) for child_id in child_ids]
    if any(child is None for child in children):
        return (), "batch_membership_mismatch"
    if any(
        child.tenant_id != parent.tenant_id or child.batch_id != parent.batch_id or child.parent_job_id != parent.job_id
        for child in children
        if child is not None
    ):
        return (), "batch_membership_mismatch"
    if any(child.status is not JobStatus.DONE for child in children if child is not None):
        return (), "batch_incomplete"
    return tuple(sorted(child_ids)), ""


def _snapshot_skip_reason(graph_store: GraphStoreProtocol, *, tenant_id: str, scan_ids: tuple[str, ...]) -> str:
    snapshots = graph_store.snapshots_by_ids(tenant_id=tenant_id, scan_ids=set(scan_ids))
    if len(snapshots) != len(scan_ids):
        return "snapshot_set_incomplete"
    if any(str(row.get("snapshot_kind") or "scan") != "scan" for row in snapshots):
        return "nested_correlation_unsupported"
    if any(int(row.get("node_count") or 0) < 1 for row in snapshots):
        return "empty_input_snapshot"
    return ""


async def _service_for_tenant(
    graph_store: GraphStoreProtocol,
    tenant_id: str,
    service: GraphCorrelationService | None,
) -> GraphCorrelationService:
    if service is not None:
        return service
    return await get_graph_correlation_service(graph_store, tenant_id)


async def _reconcile_parent(
    job_store: JobStore,
    graph_store: GraphStoreProtocol,
    *,
    parent: ScanJob,
    policy: AutoCorrelationPolicy,
    now: datetime,
    service: GraphCorrelationService | None,
) -> dict[str, Any] | None:
    prior = (parent.result or {}).get("auto_correlation") if isinstance(parent.result, dict) else None
    if isinstance(prior, dict) and prior.get("status") in {"complete", "failed", "skipped"}:
        return None

    if parent.correlation_max_age_hours is not None:
        policy = AutoCorrelationPolicy(
            enabled=policy.enabled,
            max_age_hours=parent.correlation_max_age_hours,
            max_batches_per_poll=policy.max_batches_per_poll,
            max_active_per_tenant=policy.max_active_per_tenant,
            poll_seconds=policy.poll_seconds,
        )

    correlation_id, idempotency_key = _deterministic_identity(tenant_id=parent.tenant_id, batch_id=parent.batch_id or parent.job_id)
    scan_ids, skip_reason = _validated_batch_children(job_store, parent)
    if skip_reason:
        return _persist_and_record(
            job_store,
            parent,
            _decision(parent=parent, policy=policy, now=now, status="skipped", reason=skip_reason),
        )
    snapshot_reason = _snapshot_skip_reason(graph_store, tenant_id=parent.tenant_id, scan_ids=scan_ids)
    if snapshot_reason:
        return _persist_and_record(
            job_store,
            parent,
            _decision(parent=parent, policy=policy, now=now, status="skipped", reason=snapshot_reason, scan_ids=scan_ids),
        )

    existing = graph_store.get_correlation_run(tenant_id=parent.tenant_id, correlation_id=correlation_id)
    existing_policy = (
        AutoCorrelationPolicy(
            enabled=True,
            max_age_hours=existing.max_age_hours,
            max_batches_per_poll=policy.max_batches_per_poll,
            max_active_per_tenant=policy.max_active_per_tenant,
            poll_seconds=policy.poll_seconds,
        )
        if existing is not None
        else policy
    )
    if existing is not None:
        existing_scan_ids = tuple(sorted(str(item.get("scan_id") or "") for item in existing.input_manifest))
        if existing.idempotency_key != idempotency_key or existing_scan_ids != scan_ids:
            return _persist_and_record(
                job_store,
                parent,
                _decision(
                    parent=parent,
                    policy=existing_policy,
                    now=now,
                    status="skipped",
                    reason="correlation_identity_conflict",
                    correlation_id=correlation_id,
                    scan_ids=scan_ids,
                ),
            )
    if existing is not None and existing.status in {CorrelationRunStatus.COMPLETE, CorrelationRunStatus.FAILED}:
        status = "complete" if existing.status is CorrelationRunStatus.COMPLETE else "failed"
        reason = "completed" if status == "complete" else existing.failure_code or "correlation_failed"
        return _persist_and_record(
            job_store,
            parent,
            _decision(
                parent=parent,
                policy=existing_policy,
                now=now,
                status=status,
                reason=reason,
                correlation_id=correlation_id,
                scan_ids=scan_ids,
            ),
        )

    if existing is not None:
        await _service_for_tenant(graph_store, parent.tenant_id, service)
        return _persist_and_record(
            job_store,
            parent,
            _decision(
                parent=parent,
                policy=existing_policy,
                now=now,
                status="scheduled",
                reason="scheduled",
                correlation_id=correlation_id,
                scan_ids=scan_ids,
            ),
        )

    active = graph_store.list_correlation_runs(tenant_id=parent.tenant_id, limit=1000)
    active_count = sum(run.status in {CorrelationRunStatus.PENDING, CorrelationRunStatus.RUNNING} for run in active)
    if existing is None and active_count >= policy.max_active_per_tenant:
        return _persist_and_record(
            job_store,
            parent,
            _decision(
                parent=parent,
                policy=policy,
                now=now,
                status="deferred",
                reason="tenant_active_quota",
                correlation_id=correlation_id,
                scan_ids=scan_ids,
            ),
        )

    correlation_service = await _service_for_tenant(graph_store, parent.tenant_id, service)
    try:
        run = await correlation_service.submit(
            CorrelationRequest(
                correlation_id=correlation_id,
                tenant_id=parent.tenant_id,
                idempotency_key=idempotency_key,
                name=f"Automatic correlation for scan batch {parent.batch_id}",
                scan_ids=scan_ids,
                max_age_hours=policy.max_age_hours,
                allow_stale=False,
            )
        )
    except (CorrelationServiceError, ValueError) as exc:
        reason = exc.code if isinstance(exc, CorrelationServiceError) else "idempotency_conflict"
        terminal = reason != "queue_capacity_exceeded"
        status = "skipped" if terminal else "deferred"
        return _persist_and_record(
            job_store,
            parent,
            _decision(
                parent=parent,
                policy=policy,
                now=now,
                status=status,
                reason=reason,
                correlation_id=correlation_id,
                scan_ids=scan_ids,
            ),
        )

    status = "complete" if run.status is CorrelationRunStatus.COMPLETE else "scheduled"
    reason = "completed" if status == "complete" else "scheduled"
    return _persist_and_record(
        job_store,
        parent,
        _decision(
            parent=parent,
            policy=policy,
            now=now,
            status=status,
            reason=reason,
            correlation_id=correlation_id,
            scan_ids=scan_ids,
        ),
    )


async def reconcile_auto_correlations_once(
    job_store: JobStore,
    graph_store: GraphStoreProtocol,
    *,
    policy: AutoCorrelationPolicy,
    now: Callable[[], datetime] | None = None,
    service: GraphCorrelationService | None = None,
) -> list[dict[str, Any]]:
    """Reconcile a bounded set of completed, exact-scope scan batches once."""

    if not policy.enabled:
        return []
    current_time = (now or (lambda: datetime.now(timezone.utc)))().astimezone(timezone.utc)
    decisions: list[dict[str, Any]] = []
    for row in _parent_rows(job_store, policy):
        tenant_id = str(row.get("tenant_id") or "default")
        token = set_current_tenant(tenant_id)
        try:
            parent = job_store.get(str(row["job_id"]), tenant_id=tenant_id)
            if parent is None:
                continue
            decision = await _reconcile_parent(
                job_store,
                graph_store,
                parent=parent,
                policy=policy,
                now=current_time,
                service=service,
            )
            if decision is not None:
                decisions.append(decision)
                if len(decisions) >= policy.max_batches_per_poll:
                    break
        finally:
            reset_current_tenant(token)
    return decisions


async def auto_correlation_loop(
    job_store: JobStore,
    graph_store: GraphStoreProtocol,
    *,
    policy: AutoCorrelationPolicy | None = None,
) -> None:
    """Poll completed batch receipts and submit bounded correlation work."""

    effective_policy = policy or auto_correlation_policy_from_env()
    if not effective_policy.enabled:
        return
    backend_skip_reason = auto_correlation_backend_skip_reason(job_store, graph_store)
    if backend_skip_reason:
        logger.warning("automatic graph correlation skipped: %s", backend_skip_reason.replace("_", " "))
        record_auto_correlation(outcome="skipped", reason=backend_skip_reason)
        return
    while True:
        try:
            await reconcile_auto_correlations_once(job_store, graph_store, policy=effective_policy)
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # noqa: BLE001 - background loop must survive; log is sanitized
            logger.warning("automatic graph-correlation reconciliation failed: %s", sanitize_text(str(exc)))
            record_auto_correlation(outcome="failed", reason="reconciliation_failed")
        await asyncio.sleep(effective_policy.poll_seconds)


__all__ = [
    "AutoCorrelationPolicy",
    "auto_correlation_backend_skip_reason",
    "auto_correlation_enabled",
    "auto_correlation_loop",
    "auto_correlation_policy_from_env",
    "initial_auto_correlation_decision",
    "reconcile_auto_correlations_once",
]
