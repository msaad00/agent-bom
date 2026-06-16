"""Distributed scan dispatch — claim/lease queue + per-replica worker.

The PostgresJobStore dispatch methods are exercised against a functional fake
pool with a controllable integer clock so the claim/lease/reclaim *semantics*
(oldest-first claim, no double-claim until lease expiry, dead-node reclaim,
completion removal) are verified without a live Postgres. The worker tests use a
pure-Python dispatch store to verify orchestration (capacity cap, reclaim,
completion). Gating tests cover when distributed mode turns on.
"""

from __future__ import annotations

import pytest

from agent_bom.api.models import ScanJob, ScanRequest
from agent_bom.api.postgres_store import PostgresJobStore
from agent_bom.api.scan_queue import (
    DistributedScanWorker,
    distributed_scans_enabled,
    store_supports_dispatch,
)


def _job(job_id: str, tenant: str = "acme", created_at: str = "2026-06-15T00:00:00Z") -> ScanJob:
    return ScanJob(job_id=job_id, tenant_id=tenant, created_at=created_at, request=ScanRequest())


# ─── Functional fake pool with an integer clock ──────────────────────────────


class _FakeJobConn:
    def __init__(self, state):
        self._s = state

    def execute(self, sql, params=None):
        s = " ".join(sql.lower().split())
        p = params or ()
        rows = self._s["dispatch"]  # job_id -> dict
        jobs = self._s["jobs"]  # job_id -> ScanJob

        if "set_config" in s or s.startswith(("create", "alter", "do ", "select 1")):
            return _Cur()
        if "insert into scan_dispatch_queue" in s:
            jid, tenant, created = p[0], p[1], p[2]
            rows.setdefault(jid, {"tenant_id": tenant, "created_at": created, "status": "pending", "lease": None})
            return _Cur()
        if "from scan_dispatch_queue" in s and "for update skip locked" in s:
            claimable = [
                (jid, r)
                for jid, r in rows.items()
                if r["status"] == "pending" or (r["status"] == "running" and r["lease"] is not None and r["lease"] < self._s["now"])
            ]
            claimable.sort(key=lambda kv: kv[1]["created_at"])
            if not claimable:
                return _Cur([])
            jid, r = claimable[0]
            return _Cur([(jid, r["tenant_id"])])
        if "update scan_dispatch_queue" in s and "set status = 'running'" in s:
            worker_id, lease_seconds, jid = p[0], p[1], p[2]
            rows[jid].update(status="running", claimed_by=worker_id, lease=self._s["now"] + int(lease_seconds))
            return _Cur()
        if "update scan_dispatch_queue" in s and "set lease_expires_at =" in s and "any(" in s:
            lease_seconds, ids = p[0], p[1]
            for jid in ids:
                if jid in rows and rows[jid]["status"] == "running":
                    rows[jid]["lease"] = self._s["now"] + int(lease_seconds)
            return _Cur()
        if "delete from scan_dispatch_queue" in s:
            rows.pop(p[0], None)
            return _Cur()
        if "update scan_dispatch_queue" in s and "set status = 'pending'" in s:
            n = 0
            for r in rows.values():
                if r["status"] == "running" and r["lease"] is not None and r["lease"] < self._s["now"]:
                    r.update(status="pending", claimed_by=None, lease=None)
                    n += 1
            return _Cur(rowcount=n)
        if "count(*) from scan_dispatch_queue" in s:
            return _Cur([(sum(1 for r in rows.values() if r["status"] == "pending"),)])
        if "select data from scan_jobs where job_id" in s:
            job = jobs.get(p[0])
            return _Cur([(job.model_dump_json(),)] if job else [])
        return _Cur([])

    def commit(self):
        pass

    def __enter__(self):
        return self

    def __exit__(self, *a):
        pass


class _Cur:
    def __init__(self, rows=None, rowcount=0):
        self.rows = rows or []
        self.rowcount = rowcount

    def fetchone(self):
        return self.rows[0] if self.rows else None

    def fetchall(self):
        return self.rows


class _FakeJobPool:
    def __init__(self, state):
        self._state = state

    def connection(self):
        return _FakeJobConn(self._state)


def _make_store(state):
    store = object.__new__(PostgresJobStore)  # skip _init_tables (DDL)
    store._pool = _FakeJobPool(state)
    return store


@pytest.fixture()
def state():
    return {"now": 1000, "dispatch": {}, "jobs": {}}


def test_claim_is_oldest_first_and_no_double_claim(state):
    store = _make_store(state)
    for i, jid in enumerate(["j1", "j2", "j3"]):
        job = _job(jid, created_at=f"2026-06-15T00:00:0{i}Z")
        state["jobs"][jid] = job
        store.enqueue_for_dispatch(job)

    first = store.claim_next("worker-a", lease_seconds=600)
    second = store.claim_next("worker-b", lease_seconds=600)
    assert [first.job_id, second.job_id] == ["j1", "j2"]  # oldest first
    # j1/j2 now leased (running, not expired) → only j3 remains claimable
    third = store.claim_next("worker-c", lease_seconds=600)
    assert third.job_id == "j3"
    assert store.claim_next("worker-d", lease_seconds=600) is None
    assert store.pending_dispatch_count() == 0


def test_expired_lease_is_reclaimable(state):
    store = _make_store(state)
    job = _job("j1")
    state["jobs"]["j1"] = job
    store.enqueue_for_dispatch(job)

    claimed = store.claim_next("worker-a", lease_seconds=60)  # lease expires at now+60 = 1060
    assert claimed.job_id == "j1"
    assert store.claim_next("worker-b", lease_seconds=60) is None  # still leased

    state["now"] = 2000  # advance past the lease
    reclaimed = store.claim_next("worker-b", lease_seconds=60)
    assert reclaimed.job_id == "j1"  # dead node's job picked up


def test_requeue_expired_and_complete(state):
    store = _make_store(state)
    job = _job("j1")
    state["jobs"]["j1"] = job
    store.enqueue_for_dispatch(job)
    store.claim_next("worker-a", lease_seconds=60)

    assert store.requeue_expired_leases() == 0  # not expired yet
    state["now"] = 5000
    assert store.requeue_expired_leases() == 1  # now expired → back to pending
    assert store.pending_dispatch_count() == 1

    store.complete_dispatch("j1")
    assert store.pending_dispatch_count() == 0
    assert store.claim_next("w", 60) is None


# ─── Worker orchestration (pure-python dispatch store) ───────────────────────


class _FakeDispatchStore:
    def __init__(self, jobs):
        self._queue = list(jobs)
        self.renewed: list[list[str]] = []
        self.reclaim_calls = 0
        self.completed: list[str] = []

    def claim_next(self, worker_id, lease_seconds):
        return self._queue.pop(0) if self._queue else None

    def renew_leases(self, job_ids, lease_seconds):
        self.renewed.append(list(job_ids))

    def requeue_expired_leases(self):
        self.reclaim_calls += 1
        return 0

    def complete_dispatch(self, job_id):
        self.completed.append(job_id)


def test_worker_respects_capacity_then_drains(monkeypatch):
    import agent_bom.api.pipeline as pipeline_mod

    submitted: list[ScanJob] = []
    completers: list = []

    def fake_submit(job, on_complete):
        submitted.append(job)
        completers.append(lambda: on_complete(job.job_id))

    monkeypatch.setattr(pipeline_mod, "submit_claimed_scan_job", fake_submit)

    store = _FakeDispatchStore([_job("j1"), _job("j2"), _job("j3")])
    worker = DistributedScanWorker(store, worker_id="w", max_concurrent=2)

    worker._tick()
    assert [j.job_id for j in submitted] == ["j1", "j2"]  # capacity cap = 2
    assert worker._inflight == {"j1", "j2"}
    assert store.reclaim_calls == 1

    completers[0]()  # j1 finishes
    assert worker._inflight == {"j2"}
    assert store.completed == ["j1"]

    worker._tick()  # free slot → claim j3, and renew the still-running j2 first
    assert [j.job_id for j in submitted] == ["j1", "j2", "j3"]
    assert any("j2" in batch for batch in store.renewed)  # j2 lease heartbeated


# ─── Gating ──────────────────────────────────────────────────────────────────


def test_store_supports_dispatch_detection(state):
    assert store_supports_dispatch(_make_store(state)) is True
    assert store_supports_dispatch(object()) is False


def test_distributed_disabled_without_postgres(monkeypatch):
    monkeypatch.delenv("AGENT_BOM_POSTGRES_URL", raising=False)
    monkeypatch.delenv("AGENT_BOM_DISTRIBUTED_SCANS", raising=False)
    assert distributed_scans_enabled() is False


def test_distributed_explicit_off_wins(monkeypatch):
    monkeypatch.setenv("AGENT_BOM_POSTGRES_URL", "postgres://x/y")
    monkeypatch.setenv("AGENT_BOM_CONTROL_PLANE_REPLICAS", "5")
    monkeypatch.setenv("AGENT_BOM_DISTRIBUTED_SCANS", "off")
    assert distributed_scans_enabled() is False


def test_distributed_on_when_clustered(monkeypatch):
    monkeypatch.setenv("AGENT_BOM_POSTGRES_URL", "postgres://x/y")
    monkeypatch.setenv("AGENT_BOM_CONTROL_PLANE_REPLICAS", "3")
    monkeypatch.delenv("AGENT_BOM_DISTRIBUTED_SCANS", raising=False)
    assert distributed_scans_enabled() is True


def test_distributed_explicit_on_single_replica(monkeypatch):
    monkeypatch.setenv("AGENT_BOM_POSTGRES_URL", "postgres://x/y")
    monkeypatch.delenv("AGENT_BOM_CONTROL_PLANE_REPLICAS", raising=False)
    monkeypatch.setenv("AGENT_BOM_DISTRIBUTED_SCANS", "1")
    assert distributed_scans_enabled() is True


# ─── Tenant-bound runner ─────────────────────────────────────────────────────


def test_claimed_runner_binds_job_tenant(monkeypatch):
    import agent_bom.api.pipeline as pipeline_mod
    from agent_bom.api.postgres_common import _current_tenant

    seen = {}

    def fake_run(job):
        seen["tenant"] = _current_tenant.get()

    monkeypatch.setattr(pipeline_mod, "_run_scan_sync", fake_run)
    pipeline_mod._run_claimed_scan_sync(_job("j1", tenant="tenant-x"))
    assert seen["tenant"] == "tenant-x"
    assert _current_tenant.get() == "default"  # reset afterwards
