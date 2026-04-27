"""Tenant quota helpers for noisy-neighbor protection."""

from __future__ import annotations

import contextlib
import hashlib
import logging
import os
import threading
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from typing import Any, Literal

from fastapi import HTTPException

from agent_bom.api.audit_log import log_action
from agent_bom.api.models import JobStatus
from agent_bom.api.stores import _get_fleet_store, _get_schedule_store, _get_store, _get_tenant_quota_store
from agent_bom.config import (
    API_MAX_ACTIVE_SCAN_JOBS_PER_TENANT,
    API_MAX_FLEET_AGENTS_PER_TENANT,
    API_MAX_RETAINED_JOBS_PER_TENANT,
    API_MAX_SCHEDULES_PER_TENANT,
)

_logger = logging.getLogger(__name__)

# ── Per-tenant atomicity for quota enforcement ───────────────────────────────
# Audit-4 P1: each `enforce_*_quota` function reads the current count and
# decides — but the actual insert happens later in the call site, with no
# lock. Two concurrent requests both pass the check and both insert, so a
# tenant exceeds its quota by `num_workers` under load.
#
# Fix: a per-tenant lock that callers hold across the (check + insert)
# pair via the `tenant_quota_guard()` context manager. This eliminates
# the race entirely on a single replica. Multi-replica clusters still
# need a Postgres advisory lock for full safety; that ships as a
# follow-up so the storage layer can carry the lock through.
_TENANT_QUOTA_LOCKS: dict[str, threading.Lock] = {}
_TENANT_QUOTA_LOCKS_LOCK = threading.Lock()


def _tenant_quota_lock(tenant_id: str) -> threading.Lock:
    with _TENANT_QUOTA_LOCKS_LOCK:
        return _TENANT_QUOTA_LOCKS.setdefault(tenant_id, threading.Lock())


def _tenant_advisory_lock_key(tenant_id: str) -> int:
    """Stable signed-64-bit key for ``pg_advisory_lock``.

    Postgres advisory lock keys are bigint (-2^63 .. 2^63 - 1). Hash the
    tenant id with sha256 and fold the leading 8 bytes into a signed
    int. Collisions across tenants would mean false serialisation
    between two unrelated tenants — at sha256 strength that is
    effectively impossible.
    """
    digest = hashlib.sha256(tenant_id.encode("utf-8")).digest()
    return int.from_bytes(digest[:8], "big", signed=True)


@contextlib.contextmanager
def _maybe_postgres_advisory_lock(tenant_id: str) -> Iterator[None]:
    """Hold a Postgres advisory lock keyed on the tenant id when available.

    Cluster-safe extension of the per-process ``threading.Lock`` — under
    multiple replicas the in-process lock only serialises within one
    worker, leaving ``num_replicas`` concurrent (check + insert) windows
    open. ``pg_advisory_lock`` is session-scoped (not transaction-scoped)
    so we hold the same connection from acquire to release. The acquire
    is blocking so concurrent replicas queue rather than spin or fail.

    Falls back to a no-op when Postgres is not configured or the
    psycopg pool can't be reached, so single-replica deployments and
    SQLite-only paths keep working unchanged. The fallback is logged
    once per process so an operator can spot accidental cluster mode
    without storage-layer support.
    """
    if not os.environ.get("AGENT_BOM_POSTGRES_URL"):
        yield
        return
    try:
        from agent_bom.api.postgres_common import _get_pool
    except ImportError:
        yield
        return

    key = _tenant_advisory_lock_key(tenant_id)
    pool = None
    conn: Any = None
    try:
        pool = _get_pool()
        conn = pool.getconn(timeout=5.0)
    except Exception as exc:  # noqa: BLE001
        _logger.warning(
            "tenant_quota_guard could not acquire Postgres advisory lock for tenant=%s: %s. Falling back to per-process serialisation.",
            tenant_id,
            exc,
        )
        if conn is not None and pool is not None:
            try:
                pool.putconn(conn)
            except Exception:  # noqa: BLE001
                pass
        yield
        return
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT pg_advisory_lock(%s)", (key,))
        yield
    finally:
        try:
            with conn.cursor() as cur:
                cur.execute("SELECT pg_advisory_unlock(%s)", (key,))
        except Exception as exc:  # noqa: BLE001
            _logger.warning("pg_advisory_unlock failed for tenant=%s: %s", tenant_id, exc)
        try:
            pool.putconn(conn)
        except Exception:  # noqa: BLE001
            pass


@contextmanager
def tenant_quota_guard(tenant_id: str, *checks: Callable[[], None]) -> Iterator[None]:
    """Run quota checks atomically with whatever the caller does next.

    Two layers of serialisation per tenant:

    1. ``threading.Lock`` — single-process atomicity. Required because
       Postgres advisory locks are session-scoped, not request-scoped,
       and two greenlets in the same worker could otherwise race
       between lock release and the storage commit.
    2. ``pg_advisory_lock`` (when AGENT_BOM_POSTGRES_URL is set) —
       cross-replica atomicity. Without it, N replicas can each pass
       the check concurrently and overshoot the quota by N.

    Use this around (check + insert) pairs in route handlers so the
    second caller sees the first caller's row in its check::

        with tenant_quota_guard(
            tenant_id,
            lambda: enforce_active_scan_quota(tenant_id),
            lambda: enforce_retained_jobs_quota(tenant_id),
        ):
            store.put(job)
    """
    lock = _tenant_quota_lock(tenant_id)
    with lock, _maybe_postgres_advisory_lock(tenant_id):
        for check in checks:
            check()
        yield


QuotaName = Literal["active_scan_jobs", "retained_scan_jobs", "fleet_agents", "schedules"]
QUOTA_NAMES: tuple[QuotaName, ...] = ("active_scan_jobs", "retained_scan_jobs", "fleet_agents", "schedules")


def default_tenant_quotas() -> dict[QuotaName, int]:
    """Return the process-level default tenant quotas."""
    return {
        "active_scan_jobs": API_MAX_ACTIVE_SCAN_JOBS_PER_TENANT,
        "retained_scan_jobs": API_MAX_RETAINED_JOBS_PER_TENANT,
        "fleet_agents": API_MAX_FLEET_AGENTS_PER_TENANT,
        "schedules": API_MAX_SCHEDULES_PER_TENANT,
    }


def get_tenant_quota_overrides(tenant_id: str) -> dict[QuotaName, int]:
    """Return persisted overrides for a tenant."""
    raw = _get_tenant_quota_store().get(tenant_id) or {}
    return {name: int(raw[name]) for name in QUOTA_NAMES if name in raw}


def set_tenant_quota_overrides(tenant_id: str, updates: dict[QuotaName, int | None]) -> dict[QuotaName, int]:
    """Merge quota override updates for a tenant and return the effective override set."""
    current = get_tenant_quota_overrides(tenant_id)
    next_overrides = dict(current)
    for name, value in updates.items():
        if value is None:
            next_overrides.pop(name, None)
        else:
            next_overrides[name] = int(value)

    store = _get_tenant_quota_store()
    if next_overrides:
        payload: dict[str, int] = {name: value for name, value in next_overrides.items()}
        store.put(tenant_id, payload)
    else:
        store.delete(tenant_id)
    return next_overrides


def clear_tenant_quota_overrides(tenant_id: str) -> bool:
    """Remove all tenant-specific quota overrides."""
    return _get_tenant_quota_store().delete(tenant_id)


def effective_tenant_quotas(tenant_id: str) -> dict[QuotaName, int]:
    """Return effective quotas after applying tenant overrides to global defaults."""
    defaults = default_tenant_quotas()
    effective = dict(defaults)
    effective.update(get_tenant_quota_overrides(tenant_id))
    return effective


def _quota_limit(tenant_id: str, quota_name: QuotaName) -> int:
    return effective_tenant_quotas(tenant_id)[quota_name]


def _raise_quota_exceeded(
    *,
    tenant_id: str,
    quota_name: QuotaName,
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
    limit = _quota_limit(tenant_id, "active_scan_jobs")
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
    limit = _quota_limit(tenant_id, "retained_scan_jobs")
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
    limit = _quota_limit(tenant_id, "fleet_agents")
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
    limit = _quota_limit(tenant_id, "schedules")
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

    Effective quotas resolve from global defaults with tenant-specific
    overrides layered on top when configured.
    """

    defaults = default_tenant_quotas()
    overrides = get_tenant_quota_overrides(tenant_id)
    effective = dict(defaults)
    effective.update(overrides)

    def _entry(quota_name: QuotaName, current: int) -> dict[str, int | bool | str | None]:
        limit = effective[quota_name]
        utilization_pct: int | None = None
        status = "unlimited"
        recommended_action = "No enforced limit is configured."
        if limit > 0:
            utilization_pct = min(100, int(round((current / limit) * 100)))
            if current >= limit:
                status = "at_limit"
                recommended_action = "Usage is at the enforced limit. Raise the tenant quota or reduce usage before new work starts."
            elif utilization_pct >= 80:
                status = "near_limit"
                recommended_action = "Usage is approaching the enforced limit. Review rollout size before adding more workload."
            else:
                status = "ok"
                recommended_action = "Usage is within the enforced tenant quota."
        return {
            "limit": limit,
            "default_limit": defaults[quota_name],
            "override_limit": overrides.get(quota_name),
            "current": current,
            "remaining": None if limit <= 0 else max(limit - current, 0),
            "enforced": limit > 0,
            "source": "tenant_override" if quota_name in overrides else "global_default",
            "utilization_pct": utilization_pct,
            "status": status,
            "recommended_action": recommended_action,
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
        "source": "tenant_override" if overrides else "global_default",
        "per_tenant_overrides": True,
        "active_override": bool(overrides),
        "override_endpoint": "/v1/auth/quota",
        "message": (
            "Tenant quotas resolve from tenant-specific overrides with global defaults as fallback."
            if overrides
            else "Tenant quotas resolve from global defaults. Tenant-specific overrides can be configured when needed."
        ),
        "overrides": overrides,
        "usage": {
            "active_scan_jobs": _entry("active_scan_jobs", active_jobs),
            "retained_scan_jobs": _entry("retained_scan_jobs", retained_jobs),
            "fleet_agents": _entry("fleet_agents", fleet_agents),
            "schedules": _entry("schedules", schedules),
        },
    }
