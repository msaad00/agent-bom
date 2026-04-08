"""Concurrency regressions for scanner-global state and scan cache access."""

from __future__ import annotations

import threading
import time
from concurrent.futures import ThreadPoolExecutor

from agent_bom.scan_cache import ScanCache


def test_scan_warning_and_perf_state_is_isolated_per_thread():
    from agent_bom.scanners import (
        _bump_scan_perf,
        consume_scan_performance,
        consume_scan_warnings,
        record_scan_warning,
        reset_scan_performance,
        reset_scan_warnings,
    )

    barrier = threading.Barrier(2)

    def worker(name: str, hits: int) -> tuple[list[str], int]:
        reset_scan_warnings()
        reset_scan_performance()
        record_scan_warning(f"warning:{name}")
        _bump_scan_perf("osv_cache_hits", hits)
        barrier.wait(timeout=5)
        warnings = consume_scan_warnings()
        perf = consume_scan_performance()
        return warnings, perf["osv_cache_hits"]

    with ThreadPoolExecutor(max_workers=2) as executor:
        future_a = executor.submit(worker, "a", 1)
        future_b = executor.submit(worker, "b", 3)

    warnings_a, hits_a = future_a.result()
    warnings_b, hits_b = future_b.result()

    assert warnings_a == ["warning:a"]
    assert warnings_b == ["warning:b"]
    assert hits_a == 1
    assert hits_b == 3


def test_get_scan_cache_initialization_is_singleton_under_race(monkeypatch):
    import agent_bom.scanners as scanners

    created: list[object] = []
    create_lock = threading.Lock()

    class FakeCache:
        def __init__(self) -> None:
            time.sleep(0.05)
            with create_lock:
                created.append(self)

    monkeypatch.setattr(scanners, "_scan_cache_instance", None)
    monkeypatch.setattr("agent_bom.scan_cache.ScanCache", FakeCache)

    with ThreadPoolExecutor(max_workers=6) as executor:
        instances = list(executor.map(lambda _i: scanners._get_scan_cache(), range(6)))

    assert len(created) == 1
    assert all(instance is created[0] for instance in instances)


def test_scan_cache_shared_connection_is_serialized(tmp_path):
    cache = ScanCache(db_path=tmp_path / "threaded-cache.db", ttl_seconds=3600, max_entries=0)

    def worker(worker_id: int) -> None:
        for item_id in range(25):
            name = f"pkg-{worker_id}-{item_id}"
            vulns = [{"id": f"CVE-{worker_id}-{item_id}"}]
            cache.put("npm", name, "1.0.0", vulns)
            assert cache.get("npm", name, "1.0.0") == vulns

    with ThreadPoolExecutor(max_workers=8) as executor:
        list(executor.map(worker, range(8)))

    assert cache.size == 200
