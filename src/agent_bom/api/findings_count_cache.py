"""Short-lived TTL cache for bulk-finding totals (P1-A PR2).

``GET /v1/findings`` with ``?approximate_total=true`` skips ``COUNT(*)`` on
deep pages and reuses the count captured on ``offset=0`` until the entry
expires. Keys are scoped to tenant + filter dimensions that affect cardinality.
"""

from __future__ import annotations

import os
import threading
import time
from dataclasses import dataclass
from typing import Any


def _ttl_seconds() -> float:
    raw = os.environ.get("AGENT_BOM_FINDINGS_COUNT_CACHE_TTL_SECONDS", "60")
    try:
        return max(1.0, float(raw))
    except (TypeError, ValueError):
        return 60.0


@dataclass(frozen=True)
class _CacheEntry:
    total: int
    expires_at: float


_lock = threading.Lock()
_entries: dict[tuple[Any, ...], _CacheEntry] = {}


def _purge_expired(now: float) -> None:
    expired = [key for key, entry in _entries.items() if entry.expires_at <= now]
    for key in expired:
        del _entries[key]


def cache_key(
    *,
    tenant_id: str,
    severity: str | None,
    scan_id: str | None,
    origin: str | None,
) -> tuple[Any, ...]:
    return (
        tenant_id,
        (severity or "").lower(),
        scan_id or "",
        origin or "",
    )


def get_cached_total(key: tuple[Any, ...]) -> int | None:
    now = time.monotonic()
    with _lock:
        _purge_expired(now)
        entry = _entries.get(key)
        if entry is None:
            return None
        return entry.total


def set_cached_total(key: tuple[Any, ...], total: int) -> None:
    now = time.monotonic()
    with _lock:
        _purge_expired(now)
        _entries[key] = _CacheEntry(total=total, expires_at=now + _ttl_seconds())


def invalidate_tenant(tenant_id: str) -> None:
    """Drop cached totals for a tenant after ingest or clear."""
    with _lock:
        doomed = [key for key in _entries if key and key[0] == tenant_id]
        for key in doomed:
            _entries.pop(key, None)


def reset_findings_count_cache() -> None:
    """Test helper — never call from production code."""
    with _lock:
        _entries.clear()


def approximate_total_threshold() -> int | None:
    """Return the tenant-size threshold for auto approximate totals, or ``None`` to disable."""
    raw = os.environ.get("AGENT_BOM_FINDINGS_APPROXIMATE_TOTAL_THRESHOLD", "50000").strip()
    if raw.lower() in {"", "0", "off", "false", "none", "disabled"}:
        return None
    try:
        return max(1, int(raw))
    except (TypeError, ValueError):
        return 50_000


def resolve_effective_approximate_total(
    *,
    requested: bool,
    tenant_id: str,
    severity: str | None,
    scan_id: str | None,
    origin: str | None = "bulk_ingest",
) -> bool:
    """Return whether list-findings should skip ``COUNT(*)`` for the bulk slice."""
    if requested:
        return True
    threshold = approximate_total_threshold()
    if threshold is None:
        return False
    key = cache_key(tenant_id=tenant_id, severity=severity, scan_id=scan_id, origin=origin)
    cached = get_cached_total(key)
    return cached is not None and cached >= threshold
