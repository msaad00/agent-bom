"""Short-lived per-tenant cache for the hub severity histogram (wave-2 residual #3).

The landing-page overview reads the hub-ingested severity breakdown on EVERY
request — it feeds both the cache fingerprint and the composed payload. The
underlying ``severity_breakdown`` is an indexed ``GROUP BY`` but still scans the
whole tenant ledger, so it grows O(rows): ~130ms at 200k, ~360ms at 1M, ~1s at
2M. That linear cost landed on every ``/v1/overview`` request regardless of the
payload cache.

This memoises the histogram per tenant. The hub ledger is mutated only by the
shared ingest body and the hub-clear route, so both invalidate this cache: a
cached value within TTL is therefore exact (never stale relative to the ledger),
and the histogram — hence the overview headline — reconciles with the findings
API by construction (it is the same ``severity_breakdown`` derivation, memoised).
Between ingests every overview read is O(1); only the first read after an ingest
pays the scan.
"""

from __future__ import annotations

import os
import threading
import time
from dataclasses import dataclass


def _ttl_seconds() -> float:
    raw = os.environ.get("AGENT_BOM_HUB_OVERVIEW_CACHE_TTL_SECONDS", "30")
    try:
        return max(0.0, float(raw))
    except (TypeError, ValueError):
        return 30.0


@dataclass(frozen=True)
class _Entry:
    counts: dict[str, int]
    expires_at: float


@dataclass(frozen=True)
class _KevEntry:
    count: int
    expires_at: float


_lock = threading.Lock()
_entries: dict[str, _Entry] = {}
_kev_entries: dict[str, _KevEntry] = {}


def get_cached_severity(tenant_id: str) -> dict[str, int] | None:
    ttl = _ttl_seconds()
    if ttl <= 0:
        return None
    now = time.monotonic()
    with _lock:
        entry = _entries.get(tenant_id)
        if entry is None or entry.expires_at <= now:
            if entry is not None:
                _entries.pop(tenant_id, None)
            return None
        # Return a copy so callers can mutate their view without corrupting the
        # shared entry.
        return dict(entry.counts)


def set_cached_severity(tenant_id: str, counts: dict[str, int]) -> None:
    ttl = _ttl_seconds()
    if ttl <= 0:
        return
    now = time.monotonic()
    with _lock:
        _entries[tenant_id] = _Entry(counts=dict(counts), expires_at=now + ttl)


def get_cached_kev(tenant_id: str) -> int | None:
    """Return the memoised hub KEV count, or ``None`` on miss/disabled TTL.

    Shares the severity histogram's invalidation contract (every hub mutation
    clears both), so a hit is exact and reconciles with the drill by
    construction — the KEV count derives from the same current-state spine."""
    ttl = _ttl_seconds()
    if ttl <= 0:
        return None
    now = time.monotonic()
    with _lock:
        entry = _kev_entries.get(tenant_id)
        if entry is None or entry.expires_at <= now:
            if entry is not None:
                _kev_entries.pop(tenant_id, None)
            return None
        return entry.count


def set_cached_kev(tenant_id: str, count: int) -> None:
    ttl = _ttl_seconds()
    if ttl <= 0:
        return
    now = time.monotonic()
    with _lock:
        _kev_entries[tenant_id] = _KevEntry(count=int(count), expires_at=now + ttl)


def invalidate_tenant(tenant_id: str) -> None:
    """Drop the cached histogram for a tenant after any hub-ledger mutation."""
    with _lock:
        _entries.pop(tenant_id, None)
        _kev_entries.pop(tenant_id, None)


def reset_hub_overview_cache() -> None:
    """Test helper — never call from production code."""
    with _lock:
        _entries.clear()
        _kev_entries.clear()
