"""Scale/read-path hardening: honest counts, bounded scope walks, no stampede.

Each test encodes a property the audit found violated at volume:

* ledger ingest counts must not double-count intra-batch duplicates that the
  ``ON CONFLICT`` upsert collapses into a single row;
* a scope-filtered page that stopped on its scan budget must say so in the
  response envelope instead of looking like an honest empty result;
* concurrent ``/v1/overview`` misses must share one fold (single-flight), not
  stampede the O(estate) composition once per reader;
* the ``findings`` backpressure controller must admit as many concurrent
  readers as there are worker threads, not a hardcoded 8;
* the retention/maintenance tick must not run store work on the event loop.
"""

from __future__ import annotations

import asyncio
import threading
import time
from typing import Any

import pytest

from agent_bom.api.compliance_hub_store import SQLiteComplianceHubStore


def _finding(finding_id: str, **extra: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "id": finding_id,
        "source": "external-agent",
        "origin": "bulk_ingest",
        "severity": "high",
        "cvss_score": 7.5,
    }
    payload.update(extra)
    return payload


# --------------------------------------------------------------------------- #
# Ledger ingest count honesty (intra-batch duplicates)
# --------------------------------------------------------------------------- #


def test_ledger_ingest_count_dedupes_within_the_batch(tmp_path) -> None:
    """Three findings sharing one canonical id land as ONE row; the cached
    tenant total must agree with ``COUNT(*)`` rather than counting all three."""
    store = SQLiteComplianceHubStore(str(tmp_path / "hub.db"))
    tenant = "tenant-dupes"

    reported = store.add(tenant, [_finding("dup-1"), _finding("dup-1"), _finding("dup-1")])

    assert store.count(tenant) == 1
    assert reported == 1


def test_ledger_ingest_count_mixes_new_and_duplicate_rows(tmp_path) -> None:
    store = SQLiteComplianceHubStore(str(tmp_path / "hub.db"))
    tenant = "tenant-mixed"

    store.add(tenant, [_finding("a")])
    # ``a`` already exists (DB dupe); ``b`` appears twice (intra-batch dupe).
    reported = store.add(tenant, [_finding("a"), _finding("b"), _finding("b"), _finding("c")])

    assert store.count(tenant) == 3
    assert reported == 3


# --------------------------------------------------------------------------- #
# Backpressure: read concurrency tracks worker-thread capacity
# --------------------------------------------------------------------------- #


def test_findings_backpressure_defaults_to_worker_thread_capacity(monkeypatch) -> None:
    from agent_bom import backpressure
    from agent_bom.config import WORKER_THREAD_LIMIT

    monkeypatch.delenv("AGENT_BOM_BACKPRESSURE_FINDINGS_CONCURRENCY", raising=False)
    backpressure.reset_backpressure_for_tests()
    try:
        controller = backpressure._controller_for("findings")
        assert controller.max_concurrency == WORKER_THREAD_LIMIT
        assert controller.max_concurrency > 8
    finally:
        backpressure.reset_backpressure_for_tests()


def test_backpressure_concurrency_stays_env_overridable(monkeypatch) -> None:
    from agent_bom import backpressure

    monkeypatch.setenv("AGENT_BOM_BACKPRESSURE_FINDINGS_CONCURRENCY", "3")
    backpressure.reset_backpressure_for_tests()
    try:
        assert backpressure._controller_for("findings").max_concurrency == 3
    finally:
        backpressure.reset_backpressure_for_tests()


def test_backpressure_still_sheds_beyond_the_limit() -> None:
    """The shedding behaviour is unchanged — only the default ceiling moved."""
    from agent_bom.backpressure import BackpressureController, BackpressureRejectedError

    controller = BackpressureController(
        path="findings",
        max_concurrency=2,
        p99_threshold_ms=10_000,
        cooldown_seconds=1,
        min_samples=100,
    )
    controller.try_enter()
    controller.try_enter()
    with pytest.raises(BackpressureRejectedError):
        controller.try_enter()


# --------------------------------------------------------------------------- #
# /v1/overview single-flight (cache stampede)
# --------------------------------------------------------------------------- #


class _FakeJobStore:
    def __init__(self, jobs: list[Any]) -> None:
        self._jobs = jobs

    def list_all(self, tenant_id: str) -> list[Any]:
        return list(self._jobs)


def _await_until(predicate, timeout: float = 10.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.005)
    return False


def test_overview_concurrent_misses_share_one_fold(monkeypatch) -> None:
    """8 concurrent cold readers must fold the estate ONCE.

    The barrier is structural, not a timing assertion: every reader is held
    until all 8 have missed the cache, so a stampeding implementation is
    guaranteed to record 8 folds and a single-flight one exactly 1.
    """
    from agent_bom.api.routes import overview

    overview._reset_overview_cache()
    monkeypatch.setattr(overview, "_tenant_id", lambda request: "acme")
    monkeypatch.delenv("AGENT_BOM_OVERVIEW_CACHE_TTL_SECONDS", raising=False)
    monkeypatch.setattr(overview, "_get_store", lambda: _FakeJobStore([]))
    monkeypatch.setattr(overview, "_hub_severity_snapshot", lambda request: {"critical": 1})

    readers = 8
    arrived = threading.Semaphore(0)
    release = threading.Event()
    folds = {"n": 0}
    folds_lock = threading.Lock()

    real_cache_get = overview._overview_cache_get

    def _counting_cache_get(tenant_id: str, fingerprint: str):
        result = real_cache_get(tenant_id, fingerprint)
        arrived.release()
        return result

    monkeypatch.setattr(overview, "_overview_cache_get", _counting_cache_get)

    def _slow_compose(request, tenant_id, jobs, hub_severity):
        with folds_lock:
            folds["n"] += 1
        assert release.wait(timeout=10)
        return {"schema_version": "overview.v1", "tenant_id": tenant_id}

    monkeypatch.setattr(overview, "_compose_overview", _slow_compose)

    results: list[Any] = [None] * readers
    errors: list[BaseException] = []

    def _reader(index: int) -> None:
        try:
            results[index] = overview._build_overview(object())
        except BaseException as exc:  # noqa: BLE001 — surfaced by the assertion below
            errors.append(exc)

    threads = [threading.Thread(target=_reader, args=(i,)) for i in range(readers)]
    for thread in threads:
        thread.start()
    try:
        for _ in range(readers):
            assert arrived.acquire(timeout=10), "readers did not all reach the cache probe"
    finally:
        release.set()
    for thread in threads:
        thread.join(timeout=15)

    overview._reset_overview_cache()
    assert not errors
    assert all(thread.is_alive() is False for thread in threads)
    assert folds["n"] == 1
    assert all(result == {"schema_version": "overview.v1", "tenant_id": "acme"} for result in results)


def test_overview_singleflight_follower_recomputes_when_leader_fails(monkeypatch) -> None:
    """A failed leader must not poison followers with a missing payload."""
    from agent_bom.api.routes import overview

    overview._reset_overview_cache()
    monkeypatch.setattr(overview, "_tenant_id", lambda request: "acme")
    monkeypatch.setattr(overview, "_get_store", lambda: _FakeJobStore([]))
    monkeypatch.setattr(overview, "_hub_severity_snapshot", lambda request: {"critical": 1})

    calls = {"n": 0}

    def _flaky_compose(request, tenant_id, jobs, hub_severity):
        calls["n"] += 1
        if calls["n"] == 1:
            raise RuntimeError("cold fold exploded")
        return {"schema_version": "overview.v1", "tenant_id": tenant_id}

    monkeypatch.setattr(overview, "_compose_overview", _flaky_compose)

    with pytest.raises(RuntimeError):
        overview._build_overview(object())
    # The in-flight slot must be released so the next reader is not stranded.
    assert overview._build_overview(object()) == {"schema_version": "overview.v1", "tenant_id": "acme"}
    overview._reset_overview_cache()


# --------------------------------------------------------------------------- #
# Retention/maintenance tick runs off the event loop
# --------------------------------------------------------------------------- #


def test_cleanup_tick_runs_store_work_off_the_event_loop(monkeypatch) -> None:
    """Every blocking work item in the maintenance tick must be offloaded.

    The tick records the thread it ran on; none may equal the event-loop
    thread, otherwise a 60s partition-DDL tick freezes the control plane.
    """
    from agent_bom.api import server

    seen: dict[str, int] = {}

    class _RecordingStore:
        def cleanup_expired(self, ttl_seconds: int) -> int:
            seen["cleanup_expired"] = threading.get_ident()
            return 0

        def put(self, job: Any) -> None:  # pragma: no cover - not exercised here
            pass

    monkeypatch.setattr(server, "_get_store", lambda: _RecordingStore())

    class _RecordingReplayStore:
        def cleanup_expired(self) -> int:
            seen["replay_cleanup"] = threading.get_ident()
            return 0

    monkeypatch.setattr(
        "agent_bom.api.proxy_replay_store.get_proxy_replay_store",
        lambda: _RecordingReplayStore(),
    )

    def _hub_retention() -> int:
        seen["hub_observations_retention"] = threading.get_ident()
        return 0

    monkeypatch.setattr(
        "agent_bom.api.hub_observations_partition.run_hub_observations_retention",
        _hub_retention,
    )

    def _partition_retention() -> dict[str, tuple[int, int]]:
        seen["partition_retention"] = threading.get_ident()
        return {}

    monkeypatch.setattr("agent_bom.api.partition_maintenance.run_partition_retention", _partition_retention)

    def _nhi_cleanup(store: Any, *, now: Any, audit_log: Any) -> dict[str, Any]:
        seen["nhi_lifecycle"] = threading.get_ident()
        return {"grants": {}, "dormant": {}, "rotation": {}}

    monkeypatch.setattr("agent_bom.api.agent_identity_store.run_nhi_lifecycle_cleanup", _nhi_cleanup)
    monkeypatch.setattr("agent_bom.api.agent_identity_store.get_agent_identity_store", lambda: object())
    monkeypatch.setattr("agent_bom.api.governance_audit_log.get_governance_audit_log", lambda: object())

    def _fail_stale(store: Any, *, timeout_seconds: int, now: Any) -> int:
        seen["fail_stale_active_scan_jobs"] = threading.get_ident()
        return 0

    def _reconcile(store: Any) -> int:
        seen["reconcile_scan_jobs_active"] = threading.get_ident()
        return 0

    monkeypatch.setattr("agent_bom.api.scan_job_reconciliation.fail_stale_active_scan_jobs", _fail_stale)
    monkeypatch.setattr("agent_bom.api.scan_job_reconciliation.reconcile_scan_jobs_active", _reconcile)
    monkeypatch.setattr("agent_bom.demo_estate.bootstrap.demo_estate_enabled", lambda: False)
    monkeypatch.setattr("agent_bom.api.managed_trial.managed_trial_enabled", lambda: False)

    async def _run() -> int:
        await server._cleanup_tick()
        return threading.get_ident()

    loop_thread_id = asyncio.run(_run())

    expected = {
        "cleanup_expired",
        "replay_cleanup",
        "hub_observations_retention",
        "partition_retention",
        "nhi_lifecycle",
        "fail_stale_active_scan_jobs",
        "reconcile_scan_jobs_active",
    }
    assert expected <= set(seen), f"maintenance work item never ran: {sorted(expected - set(seen))}"
    on_loop = sorted(name for name, ident in seen.items() if ident == loop_thread_id)
    assert on_loop == [], f"maintenance work ran on the event loop: {on_loop}"
