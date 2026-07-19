"""Durable persistence for KSPM cluster-posture runs (issue #4134 stage 3).

Tenant isolation is application-level: ``tenant_id`` leads every WHERE clause and
is part of the primary key, so two tenants can carry a run with the SAME run_id
without one dropping or leaking into the other.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from agent_bom.api.kspm_posture_store import (
    InMemoryKspmPostureStore,
    KspmPostureRun,
    SQLiteKspmPostureStore,
)


def _run(tenant: str, run_id: str, *, outcome: str = "partial") -> KspmPostureRun:
    return KspmPostureRun(
        tenant_id=tenant,
        run_id=run_id,
        cluster_ref="in_cluster:default",
        created_at="2026-07-18T10:00:00Z",
        payload={
            "schema_version": "kspm.cluster.posture.v1",
            "scan_run": {"outcome": outcome},
            "benchmark": {"benchmark_name": "CIS Kubernetes Benchmark"},
        },
    )


@pytest.fixture(params=["memory", "sqlite"])
def store(request, tmp_path: Path):
    if request.param == "memory":
        return InMemoryKspmPostureStore()
    return SQLiteKspmPostureStore(tmp_path / "kspm.db")


def test_put_and_latest_roundtrip(store) -> None:
    store.put(_run("tenant-a", "run-1"))
    latest = store.latest_for_tenant("tenant-a")
    assert latest is not None
    assert latest.run_id == "run-1"
    assert latest.payload["scan_run"]["outcome"] == "partial"


def test_latest_returns_newest(store) -> None:
    store.put(_run("tenant-a", "run-1"))
    newer = _run("tenant-a", "run-2")
    newer.created_at = "2026-07-18T11:00:00Z"
    store.put(newer)
    latest = store.latest_for_tenant("tenant-a")
    assert latest is not None
    assert latest.run_id == "run-2"


def test_latest_absent_is_none(store) -> None:
    assert store.latest_for_tenant("nobody") is None


def test_cross_tenant_isolation_same_run_id(store) -> None:
    # Two tenants with the SAME logical run_id must BOTH persist — neither
    # dropped, neither leaked into the other's view.
    store.put(_run("tenant-a", "shared-run", outcome="partial"))
    store.put(_run("tenant-b", "shared-run", outcome="complete"))

    a = store.latest_for_tenant("tenant-a")
    b = store.latest_for_tenant("tenant-b")
    assert a is not None and b is not None
    assert a.payload["scan_run"]["outcome"] == "partial"
    assert b.payload["scan_run"]["outcome"] == "complete"
    assert len(store.list_for_tenant("tenant-a")) == 1
    assert len(store.list_for_tenant("tenant-b")) == 1
