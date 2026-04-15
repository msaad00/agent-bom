"""Shared scanner runtime state helpers."""

from __future__ import annotations

import asyncio
import threading

from agent_bom.config import SCANNER_MAX_CONCURRENT as MAX_CONCURRENT_REQUESTS

_scan_state_local = threading.local()
_SCAN_PERF_TEMPLATE = {
    "packages_seen": 0,
    "packages_deduplicated": 0,
    "osv_cache_hits": 0,
    "osv_cache_hits_with_vulns": 0,
    "osv_cache_hits_clean": 0,
    "osv_cache_misses": 0,
    "osv_packages_queried": 0,
    "osv_queries_sent": 0,
    "osv_batches": 0,
    "osv_lookup_errors": 0,
    "offline_skips": 0,
    "skipped_unresolvable_versions": 0,
    "skipped_non_osv_ecosystems": 0,
}
_loop_semaphores_lock = threading.Lock()
_MAX_CACHED_LOOPS = 8
_loop_semaphores: dict[int, asyncio.Semaphore] = {}


def _scan_warnings_state() -> list[str]:
    warnings = getattr(_scan_state_local, "warnings", None)
    if warnings is None:
        warnings = []
        _scan_state_local.warnings = warnings
    return warnings


def _scan_performance_state() -> dict[str, int]:
    perf = getattr(_scan_state_local, "performance", None)
    if perf is None:
        perf = dict(_SCAN_PERF_TEMPLATE)
        _scan_state_local.performance = perf
    return perf


def reset_scan_warnings() -> None:
    _scan_state_local.warnings = []


def record_scan_warning(message: str) -> None:
    warnings = _scan_warnings_state()
    if message not in warnings:
        warnings.append(message)


def consume_scan_warnings() -> list[str]:
    warnings_state = _scan_warnings_state()
    warnings = list(warnings_state)
    _scan_state_local.warnings = []
    return warnings


def reset_scan_performance() -> None:
    _scan_state_local.performance = dict(_SCAN_PERF_TEMPLATE)


def _bump_scan_perf(key: str, delta: int = 1) -> None:
    performance = _scan_performance_state()
    performance[key] = int(performance.get(key, 0)) + delta


def consume_scan_performance() -> dict[str, int]:
    snapshot = dict(_scan_performance_state())
    reset_scan_performance()
    total_cache = snapshot["osv_cache_hits"] + snapshot["osv_cache_misses"]
    if total_cache:
        snapshot["osv_cache_hit_rate_pct"] = int(round((snapshot["osv_cache_hits"] / total_cache) * 100))
    return snapshot


def _get_api_semaphore() -> asyncio.Semaphore:
    """Get or create a semaphore bound to the current running event loop."""
    loop = asyncio.get_running_loop()
    loop_id = id(loop)
    with _loop_semaphores_lock:
        if loop_id not in _loop_semaphores:
            if len(_loop_semaphores) >= _MAX_CACHED_LOOPS:
                oldest = next(iter(_loop_semaphores))
                del _loop_semaphores[oldest]
            _loop_semaphores[loop_id] = asyncio.Semaphore(MAX_CONCURRENT_REQUESTS)
        return _loop_semaphores[loop_id]
