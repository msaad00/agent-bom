"""Rollback owns one committed generation, across independent store connections."""

from __future__ import annotations

import os
from concurrent.futures import ThreadPoolExecutor, TimeoutError
from contextlib import contextmanager
from threading import Event
from uuid import uuid4

import pytest

from agent_bom.graph import EntityType, RelationshipType, UnifiedEdge, UnifiedNode


@pytest.fixture(params=["sqlite", "postgres"])
def stores(request, tmp_path):
    from agent_bom.api.graph_store import SQLiteGraphStore

    if request.param == "sqlite":
        yield SQLiteGraphStore(tmp_path / "graph.db"), SQLiteGraphStore(tmp_path / "graph.db")
        return
    if not os.environ.get("AGENT_BOM_POSTGRES_URL"):
        pytest.skip("AGENT_BOM_POSTGRES_URL is required for live Postgres ownership checks")
    from agent_bom.api.postgres_common import _new_application_pool
    from agent_bom.api.postgres_graph import PostgresGraphStore

    pools = [_new_application_pool(min_size=1, max_size=2) for _ in range(2)]
    try:
        yield tuple(PostgresGraphStore(pool=pool) for pool in pools)
    finally:
        for pool in pools:
            pool.close()


@contextmanager
def tenant_scope(tenant):
    from agent_bom.api.postgres_common import reset_current_tenant, set_current_tenant

    token = set_current_tenant(tenant)
    try:
        yield
    finally:
        reset_current_tenant(token)


def nodes():
    return [
        UnifiedNode(id="agent:a", entity_type=EntityType.AGENT, label="Agent"),
        UnifiedNode(id="server:b", entity_type=EntityType.SERVER, label="Server"),
    ]


def save(store, tenant, scan, generation, node_iter=None):
    with tenant_scope(tenant):
        store.save_graph_streaming(
            tenant_id=tenant,
            scan_id=scan,
            write_generation=generation,
            nodes=nodes() if node_iter is None else node_iter,
            edges=[UnifiedEdge(source="agent:a", target="server:b", relationship=RelationshipType.USES)],
        )


def test_rollback_requires_matching_generation_and_tenant(stores):
    writer, rollback = stores
    tenant, other, scan = uuid4().hex, uuid4().hex, uuid4().hex
    save(writer, tenant, scan, "owner-a")
    save(writer, other, scan, "owner-b")
    with tenant_scope(tenant):
        assert writer.snapshot_identity(tenant_id=tenant, scan_id=scan) == (scan, "owner-a")
        for wrong in ("", "owner-b", "missing"):
            assert rollback.delete_snapshot(tenant_id=tenant, scan_id=scan, expected_generation=wrong) == 0
        graph = writer.load_graph(tenant_id=tenant, scan_id=scan)
        assert len(graph.nodes) == 2 and len(graph.edges) == 1
        assert rollback.delete_snapshot(tenant_id=tenant, scan_id=scan, expected_generation="owner-a") > 0
        assert writer.snapshot_identity(tenant_id=tenant, scan_id=scan)[1] == ""
        graph = writer.load_graph(tenant_id=tenant, scan_id=scan)
        assert not graph.nodes and not graph.edges
        assert rollback.delete_snapshot(tenant_id=tenant, scan_id=scan, expected_generation="owner-a") == 0
    with tenant_scope(other):
        assert writer.snapshot_identity(tenant_id=other, scan_id=scan)[1] == "owner-b"
        graph = writer.load_graph(tenant_id=other, scan_id=scan)
        assert len(graph.nodes) == 2 and len(graph.edges) == 1


def test_rollback_waits_for_inflight_replacement_and_preserves_new_generation(stores):
    writer, rollback = stores
    tenant, scan = uuid4().hex, uuid4().hex
    save(writer, tenant, scan, "old-owner")
    writing, release, deleting = Event(), Event(), Event()

    def blocked_nodes():
        writing.set()
        assert release.wait(10)
        yield from nodes()

    def remove_old():
        with tenant_scope(tenant):
            deleting.set()
            return rollback.delete_snapshot(tenant_id=tenant, scan_id=scan, expected_generation="old-owner")

    with ThreadPoolExecutor(max_workers=2) as pool:
        write = pool.submit(save, writer, tenant, scan, "new-owner", blocked_nodes())
        assert writing.wait(10)
        remove = pool.submit(remove_old)
        assert deleting.wait(10)
        try:
            with pytest.raises(TimeoutError):
                remove.result(timeout=0.1)
        finally:
            release.set()
        write.result(timeout=10)
        assert remove.result(timeout=10) == 0
    with tenant_scope(tenant):
        assert writer.snapshot_identity(tenant_id=tenant, scan_id=scan)[1] == "new-owner"
        graph = writer.load_graph(tenant_id=tenant, scan_id=scan)
        assert len(graph.nodes) == 2 and len(graph.edges) == 1


@pytest.mark.parametrize("mode", ["direct", "workspace", "store-backed"])
def test_pipeline_preserves_write_generation_in_every_build_path(tmp_path, monkeypatch, mode):
    from agent_bom.api import pipeline
    from agent_bom.api.graph_store import SQLiteGraphStore
    from agent_bom.api.models import ScanJob, ScanRequest

    store = SQLiteGraphStore(tmp_path / "pipeline.db")
    monkeypatch.setattr(pipeline, "_get_graph_store", lambda: store)
    monkeypatch.setenv("AGENT_BOM_GRAPH_BUILD_WORKSPACE", "1" if mode == "workspace" else "0")
    monkeypatch.setenv("AGENT_BOM_GRAPH_STORE_BACKED_BUILD", "1" if mode == "store-backed" else "0")
    job = ScanJob(job_id="pipeline", tenant_id="default", created_at="2026-09-27T00:00:00Z", request=ScanRequest())
    pipeline._persist_graph_snapshot(job, {"scan_id": "pipeline", "agents": []}, write_generation="pipeline-owner")
    assert store.snapshot_identity(tenant_id="default", scan_id="pipeline") == ("pipeline", "pipeline-owner")
