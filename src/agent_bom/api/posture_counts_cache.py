"""Short-lived cache for posture-count blocks shared by the exec surfaces.

``/v1/posture/counts`` and ``/v1/overview`` both read the open issue-group
counts; this cache lets them reuse one grouped walk while the tenant's jobs and
hub evidence revision are unchanged. The TTL bounds staleness from lifecycle
edits and out-of-band graph writes that do not move either fingerprint input.
Concurrent readers of one fingerprint wait for a single computation
(in-process only; each worker keeps its own cache).
"""

from __future__ import annotations

import hashlib
import threading
import time
from collections import OrderedDict
from collections.abc import Callable
from typing import Any

from fastapi import Request

from agent_bom.api.tenancy import require_request_tenant_id

POSTURE_COUNTS_TTL_SECONDS = 15.0
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
    for job in tenant_jobs:
        digest.update(f"|{job.job_id}:{job.status}:{getattr(job, 'completed_at', '')}".encode())
    return digest.hexdigest()


def cached_posture_block(
    request: Request,
    tenant_jobs: list[Any],
    kind: str,
    compute: Callable[[], dict[str, Any]],
) -> dict[str, Any]:
    """Posture-count block reused only while jobs and hub evidence are unchanged."""
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


def _cached_locked(key: tuple[str, str, str], compute: Callable[[], dict[str, Any]]) -> dict[str, Any]:
    now = time.monotonic()
    with _LOCK:
        hit = POSTURE_COUNTS_CACHE.get(key)
        if hit is not None and hit[0] > now:
            POSTURE_COUNTS_CACHE.move_to_end(key)
            return dict(hit[1])
    block = compute()
    with _LOCK:
        POSTURE_COUNTS_CACHE[key] = (now + POSTURE_COUNTS_TTL_SECONDS, dict(block))
        POSTURE_COUNTS_CACHE.move_to_end(key)
        while len(POSTURE_COUNTS_CACHE) > POSTURE_COUNTS_CACHE_MAX:
            POSTURE_COUNTS_CACHE.popitem(last=False)
    return block


def clear_posture_counts_cache() -> None:
    with _LOCK:
        POSTURE_COUNTS_CACHE.clear()


__all__ = [
    "POSTURE_COUNTS_CACHE",
    "cached_posture_block",
    "clear_posture_counts_cache",
    "issue_counts_fingerprint",
]
