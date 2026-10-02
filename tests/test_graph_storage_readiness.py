"""Readiness validates usable graph storage without loading tenant graphs."""

from __future__ import annotations

import asyncio
import sqlite3
import threading
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from unittest.mock import MagicMock, Mock

import pytest

from agent_bom.api import stores
from agent_bom.api.graph_store import SQLiteGraphStore
from agent_bom.api.readiness import evaluate_control_plane_readiness
from agent_bom.graph import EntityType, RelationshipType, UnifiedEdge, UnifiedGraph, UnifiedNode


@pytest.fixture(autouse=True)
def isolated_storage(monkeypatch, tmp_path):
    monkeypatch.setenv("AGENT_BOM_DB", str(tmp_path / "api.db"))
    monkeypatch.setenv("AGENT_BOM_GRAPH_DB", str(tmp_path / "graph.db"))
    monkeypatch.setenv("AGENT_BOM_STATE_DIR", str(tmp_path))
    monkeypatch.setenv("AGENT_BOM_CONTROL_PLANE_REPLICAS", "1")
    monkeypatch.delenv("AGENT_BOM_POSTGRES_URL", raising=False)
    monkeypatch.delenv("AGENT_BOM_GRAPH_BACKEND", raising=False)
    monkeypatch.setattr("agent_bom.config.GRAPH_BACKEND", "")
    monkeypatch.setattr(stores, "_graph_store", None)
    monkeypatch.setattr("agent_bom.demo_estate.boot_seed.demo_estate_seeding", lambda: False)


def test_corrupt_configured_graph_fails_closed_without_details(tmp_path):
    (tmp_path / "graph.db").write_bytes(b"invalid graph with private path/credential")
    status = evaluate_control_plane_readiness()
    assert status.as_dict() == {"status": "not_ready", "reason": "graph_storage_unavailable"}


def test_fresh_empty_graph_initializes_and_is_queryable():
    assert evaluate_control_plane_readiness().ready
    store = stores._get_graph_store()
    assert store.page_nodes(tenant_id="empty", limit=1)[2] == []
    assert store.search_nodes(tenant_id="empty", query="nothing", limit=1)[0] == []


def test_nonempty_graph_ready_without_loading_graph(monkeypatch, tmp_path):
    store = SQLiteGraphStore(tmp_path / "graph.db")
    graph = UnifiedGraph(tenant_id="tenant", scan_id="scan")
    graph.add_node(UnifiedNode(id="agent", label="agent", entity_type=EntityType.AGENT))
    graph.add_node(UnifiedNode(id="server", label="server", entity_type=EntityType.SERVER))
    graph.add_edge(UnifiedEdge(source="agent", target="server", relationship=RelationshipType.USES))
    store.save_graph(graph)
    monkeypatch.setattr(store, "load_graph", Mock(side_effect=AssertionError("readiness must not load graphs")))
    monkeypatch.setattr(stores, "_graph_store", store)
    assert evaluate_control_plane_readiness().ready
    assert len(store.edges_for_node_ids(tenant_id="tenant", scan_id="scan", node_ids={"agent"})) == 1


def test_warm_probe_does_not_repeat_migrations_or_statistics(monkeypatch):
    assert evaluate_control_plane_readiness().ready
    store = stores._get_graph_store()
    monkeypatch.setattr(store, "_open_rw_conn", Mock(side_effect=AssertionError("no repeated migration")))
    monkeypatch.setattr("agent_bom.db.graph_store.refresh_query_planner_stats", Mock(side_effect=AssertionError("no repeated stats")))
    assert evaluate_control_plane_readiness().ready
    assert evaluate_control_plane_readiness().ready


def test_warm_probe_detects_removed_required_table(tmp_path):
    assert evaluate_control_plane_readiness().ready
    with closing(sqlite3.connect(tmp_path / "graph.db")) as conn:
        conn.execute("DROP TABLE graph_nodes")
        conn.commit()
    assert evaluate_control_plane_readiness().reason == "graph_storage_unavailable"


def test_replaced_graph_is_revalidated_and_recovers(tmp_path):
    assert evaluate_control_plane_readiness().ready
    invalid = tmp_path / "replacement.db"
    invalid.write_bytes(b"invalid replacement")
    invalid.replace(tmp_path / "graph.db")
    assert evaluate_control_plane_readiness().reason == "graph_storage_unavailable"
    healthy = tmp_path / "healthy.db"
    sqlite3.connect(healthy).close()
    healthy.replace(tmp_path / "graph.db")
    assert evaluate_control_plane_readiness().ready


@pytest.mark.parametrize("opt_in", ["0", "1"])
def test_neptune_readiness_is_explicitly_unsupported(monkeypatch, opt_in):
    monkeypatch.setenv("AGENT_BOM_GRAPH_BACKEND", "neptune")
    monkeypatch.setattr("agent_bom.config.GRAPH_BACKEND", "neptune")
    monkeypatch.setenv("AGENT_BOM_EXPERIMENTAL_NEPTUNE_GRAPH", opt_in)
    monkeypatch.setenv("AGENT_BOM_NEPTUNE_ENDPOINT", "wss://private.example/gremlin")
    assert evaluate_control_plane_readiness().as_dict() == {"status": "not_ready", "reason": "graph_readiness_unsupported"}


def test_concurrent_first_probes_initialize_once(monkeypatch):
    original = SQLiteGraphStore._open_rw_conn
    calls = []

    def initialize(self):
        calls.append(1)
        return original(self)

    monkeypatch.setattr(SQLiteGraphStore, "_open_rw_conn", initialize)
    barrier = threading.Barrier(8, timeout=5)

    def probe(_):
        barrier.wait()
        return evaluate_control_plane_readiness().ready

    with ThreadPoolExecutor(max_workers=8) as pool:
        assert all(pool.map(probe, range(8)))
    assert len(calls) == 1


def test_postgres_missing_graph_table_fails_closed(monkeypatch):
    from agent_bom.api.postgres_graph import PostgresGraphStore

    store = PostgresGraphStore.__new__(PostgresGraphStore)
    pool = MagicMock()
    conn = pool.connection.return_value.__enter__.return_value

    def execute(statement):
        if "graph_nodes" in statement:
            raise RuntimeError("private connection details")

    conn.execute.side_effect = execute
    store._pool = pool
    monkeypatch.setattr(stores, "_graph_store", store)
    assert evaluate_control_plane_readiness().as_dict() == {"status": "not_ready", "reason": "graph_storage_unavailable"}
    assert conn.execute.call_args_list[0].args == ("SET LOCAL statement_timeout = '1000ms'",)
    assert pool.connection.return_value.__exit__.called


@pytest.mark.asyncio
async def test_storage_probe_does_not_block_event_loop(monkeypatch):
    from agent_bom.api import server
    from agent_bom.api.readiness import ReadinessStatus

    started, release = threading.Event(), threading.Event()

    def probe():
        started.set()
        release.wait(2)
        return ReadinessStatus(ready=True)

    monkeypatch.setattr(server, "_shutting_down", False)
    monkeypatch.setattr("agent_bom.api.readiness.evaluate_control_plane_readiness", probe)
    task = asyncio.create_task(server.readiness())
    try:
        assert await asyncio.to_thread(started.wait, 1)
        assert not task.done(), "event loop must remain responsive while storage waits"
    finally:
        release.set()
        response = await task
    assert response.status_code == 200


def test_health_remains_live_when_graph_not_ready(tmp_path, monkeypatch):
    from fastapi.testclient import TestClient

    from agent_bom.api import server

    (tmp_path / "graph.db").write_bytes(b"invalid graph")
    monkeypatch.setattr(server, "_shutting_down", False)
    client = TestClient(server.app)
    assert client.get("/health").status_code == 200
    response = client.get("/readyz")
    assert response.status_code == 503
    assert response.json() == {"status": "not_ready", "reason": "graph_storage_unavailable"}


def test_same_inode_corruption_is_not_hidden_by_bootstrap_cache(tmp_path):
    assert evaluate_control_plane_readiness().ready
    path = tmp_path / "graph.db"
    inode = path.stat().st_ino
    with path.open("r+b") as handle:
        handle.write(b"not a SQLite database")
    assert path.stat().st_ino == inode
    assert evaluate_control_plane_readiness().reason == "graph_storage_unavailable"


def test_neptune_adapter_explicitly_rejects_readiness_without_network():
    from agent_bom.api.neptune_graph import NeptuneGraphStore, NeptuneGraphStoreUnsupportedOperationError

    store = NeptuneGraphStore.__new__(NeptuneGraphStore)
    with pytest.raises(NeptuneGraphStoreUnsupportedOperationError, match="check_readiness"):
        store.check_readiness()
