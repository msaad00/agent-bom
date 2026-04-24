"""Tenant quota helpers for noisy-neighbor protection."""

from __future__ import annotations

from collections.abc import Callable

from fastapi import HTTPException

from agent_bom.api.audit_log import log_action
from agent_bom.api.models import JobStatus
from agent_bom.api.stores import _get_fleet_store, _get_schedule_store, _get_store
from agent_bom.config import (
    API_MAX_ACTIVE_SCAN_JOBS_PER_TENANT,
    API_MAX_FLEET_AGENTS_PER_TENANT,
    API_MAX_RETAINED_JOBS_PER_TENANT,
    API_MAX_SCHEDULES_PER_TENANT,
)


def _raise_quota_exceeded(
    *,
    tenant_id: str,
    quota_name: str,
    limit: int,
    current: int,
    attempted: int = 1,
) -> None:
    if quota_name == "active_scan_jobs":
        detail = (
            f"Tenant quota exceeded for concurrent scan jobs: "
            f"limit={limit}, current={current}, attempted={attempted}. "
            "Reduce usage or raise the tenant quota."
        )
    else:
        detail = (
            f"Tenant quota exceeded for {quota_name}: "
            f"limit={limit}, current={current}, attempted={attempted}. "
            "Reduce usage or raise the tenant quota."
        )
    log_action(
        "tenant.quota_exceeded",
        actor=f"tenant:{tenant_id}",
        resource=f"tenant/{tenant_id}",
        tenant_id=tenant_id,
        quota_name=quota_name,
        limit=limit,
        current=current,
        attempted=attempted,
    )
    raise HTTPException(
        status_code=429,
        detail=detail,
    )


def enforce_active_scan_quota(tenant_id: str) -> None:
    """Limit concurrent pending/running scan jobs per tenant."""
    limit = API_MAX_ACTIVE_SCAN_JOBS_PER_TENANT
    if limit <= 0:
        return
    current = sum(1 for job in _get_store().list_all(tenant_id=tenant_id) if job.status in (JobStatus.PENDING, JobStatus.RUNNING))
    if current >= limit:
        _raise_quota_exceeded(
            tenant_id=tenant_id,
            quota_name="active_scan_jobs",
            limit=limit,
            current=current,
        )


def enforce_retained_jobs_quota(tenant_id: str, attempted: int = 1) -> None:
    """Limit total stored scan jobs per tenant."""
    limit = API_MAX_RETAINED_JOBS_PER_TENANT
    if limit <= 0:
        return
    current = len(_get_store().list_all(tenant_id=tenant_id))
    if current + attempted > limit:
        _raise_quota_exceeded(
            tenant_id=tenant_id,
            quota_name="retained_scan_jobs",
            limit=limit,
            current=current,
            attempted=attempted,
        )


def enforce_fleet_agents_quota(tenant_id: str, attempted: int = 1) -> None:
    """Limit retained fleet agents per tenant."""
    limit = API_MAX_FLEET_AGENTS_PER_TENANT
    if limit <= 0 or attempted <= 0:
        return
    current = len(_get_fleet_store().list_by_tenant(tenant_id))
    if current + attempted > limit:
        _raise_quota_exceeded(
            tenant_id=tenant_id,
            quota_name="fleet_agents",
            limit=limit,
            current=current,
            attempted=attempted,
        )


def enforce_schedule_quota(tenant_id: str, attempted: int = 1) -> None:
    """Limit retained schedules per tenant."""
    limit = API_MAX_SCHEDULES_PER_TENANT
    if limit <= 0 or attempted <= 0:
        return
    current = len(_get_schedule_store().list_all(tenant_id=tenant_id))
    if current + attempted > limit:
        _raise_quota_exceeded(
            tenant_id=tenant_id,
            quota_name="schedules",
            limit=limit,
            current=current,
            attempted=attempted,
        )


def get_tenant_quota_runtime(tenant_id: str) -> dict[str, object]:
    """Return operator-facing quota status for a tenant.

    Quotas are process-wide configuration today. This surface makes that
    explicit while still showing the tenant's current usage so the UI can
    explain whether an operator is close to the enforced limits.
    """

    def _entry(limit: int, current: int) -> dict[str, int | bool | None]:
        return {
            "limit": limit,
            "current": current,
            "remaining": None if limit <= 0 else max(limit - current, 0),
            "enforced": limit > 0,
        }

    def _safe_count(fn: Callable[[], int]) -> int:
        try:
            return fn()
        except RuntimeError:
            # Operator status should stay readable during partial startup and tests
            # even if optional stores are not initialized yet.
            return 0

    active_jobs = _safe_count(
        lambda: sum(1 for job in _get_store().list_all(tenant_id=tenant_id) if job.status in (JobStatus.PENDING, JobStatus.RUNNING))
    )
    retained_jobs = _safe_count(lambda: len(_get_store().list_all(tenant_id=tenant_id)))
    fleet_agents = _safe_count(lambda: len(_get_fleet_store().list_by_tenant(tenant_id)))
    schedules = _safe_count(lambda: len(_get_schedule_store().list_all(tenant_id=tenant_id)))

    return {
        "source": "static_process_config",
        "per_tenant_overrides": False,
        "message": (
            "Tenant quotas are enforced from control-plane configuration today. Per-tenant override management is not yet exposed."
        ),
        "usage": {
            "active_scan_jobs": _entry(API_MAX_ACTIVE_SCAN_JOBS_PER_TENANT, active_jobs),
            "retained_scan_jobs": _entry(API_MAX_RETAINED_JOBS_PER_TENANT, retained_jobs),
            "fleet_agents": _entry(API_MAX_FLEET_AGENTS_PER_TENANT, fleet_agents),
            "schedules": _entry(API_MAX_SCHEDULES_PER_TENANT, schedules),
        },
    }
