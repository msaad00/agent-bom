"""Validate and atomically complete push-driven correlation-cohort children."""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING, Any, Callable

from agent_bom.api.correlation_cohort_receipts import (
    CorrelationCohortReceiptError,
    verify_correlation_cohort_child_receipt,
)
from agent_bom.api.models import JobStatus, ScanJob
from agent_bom.api.scan_batches import refresh_batch_parent
from agent_bom.api.stores import _get_graph_store, _get_store, _job_lock, _jobs_put

if TYPE_CHECKING:
    from agent_bom.api.models import CorrelationCohortChildReceipt


class CorrelationCohortIngestError(RuntimeError):
    """Bounded error carrying only a stable reason code."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True, slots=True)
class CorrelationCohortChildContext:
    parent: ScanJob
    child: ScanJob


def validate_correlation_cohort_child(
    *,
    tenant_id: str,
    source_id: str,
    correlation_cohort_id: str,
    receipt: CorrelationCohortChildReceipt,
    allowed_source_kinds: set[str],
) -> CorrelationCohortChildContext:
    """Verify signature plus exact persisted parent/child membership."""

    try:
        verify_correlation_cohort_child_receipt(
            receipt,
            tenant_id=tenant_id,
            correlation_cohort_id=correlation_cohort_id,
            source_id=source_id,
            allowed_source_kinds=allowed_source_kinds,
        )
    except CorrelationCohortReceiptError as exc:
        raise CorrelationCohortIngestError("invalid_receipt") from exc

    job_store = _get_store()
    graph_store = _get_graph_store()
    from agent_bom.api.auto_correlation import auto_correlation_backend_skip_reason

    if auto_correlation_backend_skip_reason(job_store, graph_store):
        raise CorrelationCohortIngestError("durable_store_required")
    parent = job_store.get(receipt.parent_job_id, tenant_id=tenant_id)
    child = job_store.get(receipt.child_job_id, tenant_id=tenant_id)
    expected_target = {"kind": "external_ingest", "source_kind": receipt.source_kind}
    if (
        parent is None
        or child is None
        or parent.correlation_cohort_id != correlation_cohort_id
        or parent.correlation_cohort_manifest_hash != receipt.cohort_manifest_hash
        or parent.correlation_max_age_hours != receipt.max_age_hours
        or receipt.child_job_id not in parent.child_job_ids
        or child.parent_job_id != parent.job_id
        or child.batch_id != correlation_cohort_id
        or child.correlation_cohort_id != correlation_cohort_id
        or child.correlation_cohort_manifest_hash != receipt.cohort_manifest_hash
        or child.correlation_max_age_hours != receipt.max_age_hours
        or child.source_id != source_id
        or child.target != expected_target
    ):
        raise CorrelationCohortIngestError("invalid_receipt")
    return CorrelationCohortChildContext(parent=parent, child=child)


def cohort_evidence_created_at(
    observed_at: list[str],
    *,
    max_age_hours: int,
    now: datetime | None = None,
) -> str:
    """Return the oldest bounded observation time, preserving freshness truth."""

    if not observed_at:
        raise CorrelationCohortIngestError("observation_time_required")
    current = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    parsed: list[datetime] = []
    for value in observed_at:
        try:
            item = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        except (TypeError, ValueError) as exc:
            raise CorrelationCohortIngestError("invalid_observation_time") from exc
        if item.tzinfo is None:
            item = item.replace(tzinfo=timezone.utc)
        parsed.append(item.astimezone(timezone.utc))
    oldest = min(parsed)
    if oldest < current - timedelta(hours=max_age_hours):
        raise CorrelationCohortIngestError("stale_evidence")
    if max(parsed) > current + timedelta(minutes=5):
        raise CorrelationCohortIngestError("invalid_observation_time")
    return oldest.isoformat()


def prior_or_conflict(child: ScanJob, *, request_hash: str) -> ScanJob | None:
    """Return an idempotent completed child or reject a changed duplicate."""

    if child.status is not JobStatus.DONE:
        return None
    result = child.result if isinstance(child.result, dict) else {}
    metadata = result.get("correlation_cohort_ingest")
    stored_hash = str(metadata.get("request_hash") or "") if isinstance(metadata, dict) else ""
    if stored_hash and stored_hash == request_hash:
        return child
    raise CorrelationCohortIngestError("duplicate_result")


def commit_correlation_cohort_child(
    context: CorrelationCohortChildContext,
    *,
    result: dict[str, Any],
    request_hash: str,
    persist_graph: Callable[[ScanJob, dict[str, Any]], None],
    ensure_owned: Callable[[], None] | None = None,
) -> tuple[ScanJob, ScanJob]:
    """Persist graph + child + refreshed parent, compensating every failure."""

    job_store = _get_store()
    graph_store = _get_graph_store()
    child_id = context.child.job_id
    tenant_id = context.child.tenant_id
    with _job_lock(child_id):
        current = job_store.get(child_id, tenant_id=tenant_id)
        if current is None:
            raise CorrelationCohortIngestError("invalid_receipt")
        replay = prior_or_conflict(current, request_hash=request_hash)
        if replay is not None:
            parent = job_store.get(replay.parent_job_id or "", tenant_id=tenant_id)
            if parent is None:
                raise CorrelationCohortIngestError("invalid_receipt")
            return replay, parent
        if current.status is not JobStatus.PENDING:
            raise CorrelationCohortIngestError("child_not_pending")

        original = current.model_copy(deep=True)
        candidate = current.model_copy(deep=True)
        candidate.status = JobStatus.DONE
        candidate.started_at = candidate.started_at or datetime.now(timezone.utc).isoformat()
        candidate.completed_at = datetime.now(timezone.utc).isoformat()
        candidate.result = deepcopy(result)
        candidate.result["scan_id"] = child_id
        candidate.result["correlation_cohort_ingest"] = {
            "schema_version": "agent-bom.correlation-cohort-ingest/v1",
            "correlation_cohort_id": candidate.correlation_cohort_id,
            "cohort_manifest_hash": candidate.correlation_cohort_manifest_hash,
            "source_id": candidate.source_id,
            "source_kind": str((candidate.target or {}).get("source_kind") or ""),
            "request_hash": request_hash,
        }
        child_persisted = False
        try:
            if ensure_owned is not None:
                ensure_owned()
            persist_graph(candidate, candidate.result)
            if ensure_owned is not None:
                ensure_owned()
            job_store.put(candidate)
            child_persisted = True
            if ensure_owned is not None:
                ensure_owned()
            parent = refresh_batch_parent(candidate.parent_job_id or "", tenant_id=tenant_id)
            if parent is None:
                raise CorrelationCohortIngestError("invalid_receipt")
        except Exception:
            if ensure_owned is not None:
                try:
                    ensure_owned()
                except Exception:
                    raise
            # The callback may fail after its backend committed. The child id is
            # reserved exclusively for this cohort, so compensating deletion is
            # safe even when no graph row was written.
            try:
                graph_store.delete_snapshot(tenant_id=tenant_id, scan_id=child_id)
            except Exception as rollback_exc:  # noqa: BLE001
                raise RuntimeError("correlation cohort graph rollback failed") from rollback_exc
            if child_persisted:
                job_store.put(original)
                _jobs_put(original.job_id, original)
            raise
        _jobs_put(candidate.job_id, candidate, compact_terminal=True)
        return candidate, parent


__all__ = [
    "CorrelationCohortChildContext",
    "CorrelationCohortIngestError",
    "cohort_evidence_created_at",
    "commit_correlation_cohort_child",
    "prior_or_conflict",
    "validate_correlation_cohort_child",
]
