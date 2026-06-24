"""Helpers for API scan batch parent/child jobs."""

from __future__ import annotations

from typing import Any

from agent_bom.api.models import JobStatus, ScanJob, ScanRequest
from agent_bom.api.stores import _get_store, _job_lock, _jobs_get, _jobs_is_compacted, _jobs_put

BATCH_LIST_TARGET_FIELDS = (
    "images",
    "tf_dirs",
    "agent_projects",
    "jupyter_dirs",
    "connectors",
    "filesystem_paths",
)
BATCH_SINGLE_TARGET_FIELDS = ("inventory", "gha_path", "sbom")


def scan_request_targets(request: ScanRequest) -> list[dict[str, Any]]:
    """Return explicit top-level scan targets that can be fanned out."""

    targets: list[dict[str, Any]] = []
    for field_name in BATCH_LIST_TARGET_FIELDS:
        values = getattr(request, field_name)
        for index, value in enumerate(values):
            targets.append({"field": field_name, "value": value, "ordinal": index})

    for field_name in BATCH_SINGLE_TARGET_FIELDS:
        value = getattr(request, field_name)
        if value:
            targets.append({"field": field_name, "value": value, "ordinal": 0})

    if request.k8s:
        targets.append(
            {
                "field": "k8s",
                "value": {"namespace": request.k8s_namespace},
                "ordinal": 0,
            }
        )

    return targets


def should_fan_out_scan_request(request: ScanRequest) -> bool:
    """Return True when the API should create a parent batch and child jobs."""

    return len(scan_request_targets(request)) > 1


def child_request_for_target(request: ScanRequest, target: dict[str, Any]) -> ScanRequest:
    """Build a child request containing exactly one explicit scan target."""

    payload = request.model_dump()
    for field_name in BATCH_LIST_TARGET_FIELDS:
        payload[field_name] = []
    for field_name in BATCH_SINGLE_TARGET_FIELDS:
        payload[field_name] = None
    payload["k8s"] = False
    payload["k8s_namespace"] = None

    field_name = str(target["field"])
    value = target.get("value")
    if field_name in BATCH_LIST_TARGET_FIELDS:
        payload[field_name] = [value]
    elif field_name in BATCH_SINGLE_TARGET_FIELDS:
        payload[field_name] = value
    elif field_name == "k8s":
        payload["k8s"] = True
        if isinstance(value, dict):
            payload["k8s_namespace"] = value.get("namespace")

    return ScanRequest.model_validate(payload)


def refresh_batch_parent(parent_job_id: str, *, tenant_id: str | None = None) -> ScanJob | None:
    """Refresh a batch parent from its children and return the parent job."""

    store = _get_store()
    parent = _jobs_get(parent_job_id)
    if parent is None or _jobs_is_compacted(parent):
        parent = store.get(parent_job_id, tenant_id=tenant_id)
    if parent is None:
        return None
    if tenant_id is not None and parent.tenant_id != tenant_id:
        return None
    if not parent.child_job_ids:
        return parent

    children: list[ScanJob] = []
    for child_id in parent.child_job_ids:
        child = store.get(child_id, tenant_id=parent.tenant_id)
        if child is None:
            child = _jobs_get(child_id)
        if child is not None and child.tenant_id == parent.tenant_id:
            children.append(child)

    status_counts = {status.value: 0 for status in JobStatus}
    child_rows: list[dict[str, Any]] = []
    for child in children:
        status_counts[child.status.value] = status_counts.get(child.status.value, 0) + 1
        child_rows.append(
            {
                "job_id": child.job_id,
                "status": child.status.value,
                "target": child.target,
                "target_index": child.target_index,
                "target_count": child.target_count,
                "created_at": child.created_at,
                "started_at": child.started_at,
                "completed_at": child.completed_at,
                "error": child.error,
                "result": child.result,
            }
        )

    total = len(parent.child_job_ids)
    terminal = status_counts[JobStatus.DONE.value] + status_counts[JobStatus.FAILED.value] + status_counts[JobStatus.CANCELLED.value]
    if terminal < total:
        next_status = JobStatus.RUNNING
        completed_at = None
    elif status_counts[JobStatus.DONE.value] > 0:
        next_status = JobStatus.DONE
        completed_at = max((child.completed_at or child.created_at for child in children), default=parent.completed_at)
    elif status_counts[JobStatus.CANCELLED.value] == total:
        next_status = JobStatus.CANCELLED
        completed_at = max((child.completed_at or child.created_at for child in children), default=parent.completed_at)
    else:
        next_status = JobStatus.FAILED
        completed_at = max((child.completed_at or child.created_at for child in children), default=parent.completed_at)

    batch = {
        "batch_id": parent.batch_id or parent.job_id,
        "parent_job_id": parent.job_id,
        "target_count": total,
        "completed_targets": terminal,
        "succeeded_targets": status_counts[JobStatus.DONE.value],
        "failed_targets": status_counts[JobStatus.FAILED.value],
        "cancelled_targets": status_counts[JobStatus.CANCELLED.value],
        "running_targets": status_counts[JobStatus.RUNNING.value],
        "pending_targets": status_counts[JobStatus.PENDING.value],
        "children": sorted(child_rows, key=lambda row: row.get("target_index") or 0),
    }
    result = {"batch": batch, "summary": batch}

    with _job_lock(parent.job_id):
        parent.status = next_status
        parent.result = result
        if completed_at and next_status in (JobStatus.DONE, JobStatus.FAILED, JobStatus.CANCELLED):
            parent.completed_at = completed_at

    store.put(parent)
    _jobs_put(parent.job_id, parent, compact_terminal=next_status in (JobStatus.DONE, JobStatus.FAILED, JobStatus.CANCELLED))
    return parent
