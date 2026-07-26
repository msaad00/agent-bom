"""Short-lived TTL cache for scan-job status counts.

``count_summary_by_status`` is an unbounded ``GROUP BY`` over ``scan_jobs``
— measured at ~342ms across 200k rows — and the dashboard activity feed asks
for it every few seconds for every open browser. The search variant is worse:
its ``LOWER(CONCAT_WS(...)) LIKE`` predicate cannot use an index at all, so the
cost grows with the table no matter how narrow the result is.

Repeated polls are served from memory for a few seconds; a job write drops the
tenant's entries immediately, so a finished job never sits behind a stale count.
Mirrors :mod:`agent_bom.api.findings_count_cache`, which solves the same problem
for finding totals.
"""

from __future__ import annotations

import os
import threading
import time
from dataclasses import dataclass

_DEFAULT_TTL_SECONDS = 5.0


def _ttl_seconds() -> float:
    raw = os.environ.get("AGENT_BOM_JOB_STATUS_COUNT_CACHE_TTL_SECONDS")
    if raw is None:
        return _DEFAULT_TTL_SECONDS
    try:
        return max(0.0, float(raw))
    except (TypeError, ValueError):
        return _DEFAULT_TTL_SECONDS


@dataclass(frozen=True)
class _Entry:
    counts: dict[str, int]
    expires_at: float


_lock = threading.Lock()
_entries: dict[tuple[str, str], _Entry] = {}


def _key(tenant_id: str, query: str | None) -> tuple[str, str]:
    # The search term is part of the key: a filtered count must never be served
    # as the unfiltered one, and vice versa.
    return (tenant_id or "", (query or "").strip().casefold())


def _purge(now: float) -> None:
    for key in [key for key, entry in _entries.items() if entry.expires_at <= now]:
        del _entries[key]


def get_counts(tenant_id: str, query: str | None) -> dict[str, int] | None:
    """Cached status counts, or ``None`` when nothing usable is stored."""
    now = time.monotonic()
    with _lock:
        _purge(now)
        entry = _entries.get(_key(tenant_id, query))
        # Copy so a caller mutating the response cannot corrupt the entry.
        return dict(entry.counts) if entry else None


def set_counts(tenant_id: str, query: str | None, counts: dict[str, int]) -> None:
    ttl = _ttl_seconds()
    if ttl <= 0:  # Explicitly disabled by an operator.
        return
    now = time.monotonic()
    with _lock:
        _purge(now)
        _entries[_key(tenant_id, query)] = _Entry(counts=dict(counts), expires_at=now + ttl)


def invalidate_tenant(tenant_id: str) -> None:
    """Drop every cached count for a tenant after a job write."""
    with _lock:
        for key in [key for key in _entries if key[0] == (tenant_id or "")]:
            del _entries[key]


def reset() -> None:
    """Test helper — never call from production code."""
    with _lock:
        _entries.clear()


def expire_all_for_test() -> None:
    """Test helper that ages every entry out without sleeping."""
    with _lock:
        for key, entry in list(_entries.items()):
            _entries[key] = _Entry(counts=entry.counts, expires_at=0.0)
