"""Short-lived cache for posture-count blocks shared by the exec surfaces.

``/v1/posture/counts`` and ``/v1/overview`` both read the open issue-group
counts; this cache lets them reuse one grouped walk while the tenant's jobs,
job-store revision and hub evidence revision are unchanged. The TTL bounds
staleness from inputs the fingerprint does not cover. Concurrent readers of one
fingerprint wait for a single computation (in-process only; each worker keeps
its own cache).

Evidence blocks (issue groups, exec severity, compound issues) read only jobs
and hub evidence, so they are kept for ``POSTURE_EVIDENCE_TTL_SECONDS``; that
TTL bounds only the default read window sliding past old rows. A completed
scan or hub write schedules those blocks to be computed for the new
fingerprint in a background worker, so the first read after a write does not
pay the grouped findings walk.
"""

from __future__ import annotations

import hashlib
import logging
import threading
import time
from collections import OrderedDict
from collections.abc import Callable, Iterable
from typing import Any

from starlette.requests import Request

from agent_bom.api.tenant_worker import run_tenant_bound
from agent_bom.config import _bool

_logger = logging.getLogger(__name__)

POSTURE_COUNTS_TTL_SECONDS = 15.0
POSTURE_EVIDENCE_TTL_SECONDS = 300.0
EVIDENCE_BLOCK_KINDS = frozenset({"issues", "exec_severity", "compound_issues"})
POSTURE_PRECOMPUTE_DEBOUNCE_SECONDS = 0.5
POSTURE_COUNTS_CACHE_MAX = 256
POSTURE_COUNTS_CACHE: OrderedDict[tuple[str, str, str], tuple[float, dict[str, Any]]] = OrderedDict()
_LOCK = threading.Lock()
_KEY_LOCKS: dict[tuple[str, str, str], threading.Lock] = {}


def issue_counts_fingerprint(tenant_id: str, tenant_jobs: list[Any]) -> str:
    from agent_bom.api.compliance_hub_store import get_compliance_hub_store

    try:
        hub_revision = str(get_compliance_hub_store().overview_evidence_revision(tenant_id))
    except Exception:  # noqa: BLE001
        hub_revision = "unknown"
    digest = hashlib.sha256(hub_revision.encode())
    digest.update(f"|jobs:{_job_store_revision(tenant_id)}".encode())
    for job in tenant_jobs:
        digest.update(f"|{job.job_id}:{job.status}:{getattr(job, 'completed_at', '')}".encode())
    return digest.hexdigest()


def _job_store_revision(tenant_id: str) -> str:
    """Durable job-store mutation token; covers in-place result refreshes."""
    from agent_bom.api.stores import _get_store

    reader = getattr(_get_store(), "overview_evidence_revision", None)
    if not callable(reader):
        return "none"
    try:
        return str(reader(tenant_id))
    except Exception:  # noqa: BLE001
        return "unknown"


def cached_posture_block(
    request: Request,
    tenant_jobs: list[Any],
    kind: str,
    compute: Callable[[], dict[str, Any]],
) -> dict[str, Any]:
    """Posture-count block reused only while jobs and hub evidence are unchanged."""

    from agent_bom.api.tenancy import require_request_tenant_id

    tenant_id = require_request_tenant_id(request)
    key = (tenant_id, kind, issue_counts_fingerprint(tenant_id, tenant_jobs))
    with _LOCK:
        key_lock = _KEY_LOCKS.setdefault(key, threading.Lock())
    with key_lock:
        try:
            return _cached_locked(key, compute)
        finally:
            with _LOCK:
                if len(_KEY_LOCKS) > POSTURE_COUNTS_CACHE_MAX:
                    _KEY_LOCKS.pop(next(iter(_KEY_LOCKS)), None)


def _ttl_for(kind: str) -> float:
    return POSTURE_EVIDENCE_TTL_SECONDS if kind in EVIDENCE_BLOCK_KINDS else POSTURE_COUNTS_TTL_SECONDS


def _cached_locked(key: tuple[str, str, str], compute: Callable[[], dict[str, Any]]) -> dict[str, Any]:
    with _LOCK:
        hit = POSTURE_COUNTS_CACHE.get(key)
        if hit is not None and hit[0] > time.monotonic():
            POSTURE_COUNTS_CACHE.move_to_end(key)
            return dict(hit[1])
    block = compute()
    with _LOCK:
        # Expiry counts from completion so a slow walk is not cached already expired.
        POSTURE_COUNTS_CACHE[key] = (time.monotonic() + _ttl_for(key[1]), dict(block))
        POSTURE_COUNTS_CACHE.move_to_end(key)
        while len(POSTURE_COUNTS_CACHE) > POSTURE_COUNTS_CACHE_MAX:
            POSTURE_COUNTS_CACHE.popitem(last=False)
    return block


def clear_posture_counts_cache() -> None:
    with _LOCK:
        POSTURE_COUNTS_CACHE.clear()


def posture_precompute_enabled() -> bool:

    return _bool("AGENT_BOM_POSTURE_PRECOMPUTE", True)


_PRECOMPUTE_COND = threading.Condition()
_PRECOMPUTE_PENDING: dict[str, float] = {}
_PRECOMPUTE_RUNNING: set[str] = set()
_PRECOMPUTE_WORKER: threading.Thread | None = None


def schedule_posture_precompute(tenant_id: str | None) -> None:
    """Warm the tenant's evidence blocks after a scan or hub write.

    Never blocks or fails the writer: bursts for one tenant coalesce into one
    computation after ``POSTURE_PRECOMPUTE_DEBOUNCE_SECONDS`` of quiet.
    """
    global _PRECOMPUTE_WORKER
    if not tenant_id or not posture_precompute_enabled():
        return
    with _PRECOMPUTE_COND:
        _PRECOMPUTE_PENDING[tenant_id] = time.monotonic() + POSTURE_PRECOMPUTE_DEBOUNCE_SECONDS
        if _PRECOMPUTE_WORKER is None or not _PRECOMPUTE_WORKER.is_alive():
            _PRECOMPUTE_WORKER = threading.Thread(target=_precompute_loop, name="posture-counts-precompute", daemon=True)
            _PRECOMPUTE_WORKER.start()
        _PRECOMPUTE_COND.notify_all()


def announce_scan_evidence(jobs: Iterable[Any]) -> None:
    """Job-store write hook: schedule a precompute for tenants with a completed scan."""
    for tenant_id in {job.tenant_id for job in jobs if getattr(getattr(job, "status", None), "value", None) == "done"}:
        schedule_posture_precompute(tenant_id)
        from agent_bom.api.campaign_reconciliation import notify_campaign_evidence

        notify_campaign_evidence(tenant_id)


def _next_due_tenant() -> str:
    with _PRECOMPUTE_COND:
        while True:
            now = time.monotonic()
            due = [tenant for tenant, at in _PRECOMPUTE_PENDING.items() if at <= now and tenant not in _PRECOMPUTE_RUNNING]
            if due:
                tenant_id = min(due, key=_PRECOMPUTE_PENDING.__getitem__)
                del _PRECOMPUTE_PENDING[tenant_id]
                _PRECOMPUTE_RUNNING.add(tenant_id)
                return tenant_id
            waiting = [at for tenant, at in _PRECOMPUTE_PENDING.items() if tenant not in _PRECOMPUTE_RUNNING]
            _PRECOMPUTE_COND.wait(max(0.01, min(waiting) - now) if waiting else None)


def _precompute_loop() -> None:

    while True:
        tenant_id = _next_due_tenant()
        try:
            from agent_bom.api.exec_posture import precompute_posture_evidence

            run_tenant_bound(tenant_id, precompute_posture_evidence, tenant_id)
        except Exception:  # noqa: BLE001
            _logger.warning("posture counts precompute failed; reads compute on demand", exc_info=False)
        finally:
            with _PRECOMPUTE_COND:
                _PRECOMPUTE_RUNNING.discard(tenant_id)
                _PRECOMPUTE_COND.notify_all()


def wait_for_posture_precompute(timeout: float) -> bool:
    """Block until scheduled precomputes finish; ``False`` on timeout."""
    deadline = time.monotonic() + timeout
    with _PRECOMPUTE_COND:
        while _PRECOMPUTE_PENDING or _PRECOMPUTE_RUNNING:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return False
            _PRECOMPUTE_COND.wait(remaining)
    return True


__all__ = [
    "EVIDENCE_BLOCK_KINDS",
    "announce_scan_evidence",
    "POSTURE_COUNTS_CACHE",
    "cached_posture_block",
    "clear_posture_counts_cache",
    "issue_counts_fingerprint",
    "posture_precompute_enabled",
    "schedule_posture_precompute",
    "wait_for_posture_precompute",
]
