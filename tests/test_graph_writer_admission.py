"""Graph writers queue before opening connections; failed producers roll back."""

from concurrent.futures import ThreadPoolExecutor, TimeoutError
from threading import Event

import pytest

from agent_bom.db import graph_store


def test_competing_graph_opens_wait_before_schema_initialization(monkeypatch, tmp_path):
    path = tmp_path / "graph.db"
    with graph_store.open_graph_db(path):
        pass
    entered, release, contender_started, second_init = Event(), Event(), Event(), Event()
    original = graph_store._init_db

    def initialize(conn, **kwargs):
        second_init.set()
        return original(conn, **kwargs)

    def owner():
        with graph_store.open_graph_db(path):
            entered.set()
            assert release.wait(5)

    def contender():
        contender_started.set()
        with graph_store.open_graph_db(path):
            return True

    with ThreadPoolExecutor(max_workers=2) as pool:
        first = pool.submit(owner)
        assert entered.wait(5)
        monkeypatch.setattr(graph_store, "_init_db", initialize)
        second = pool.submit(contender)
        assert contender_started.wait(5)
        try:
            with pytest.raises(TimeoutError):
                second.result(timeout=0.1)
            assert not second_init.is_set()
        finally:
            release.set()
        first.result(timeout=5)
        assert second.result(timeout=5)
        assert second_init.is_set()


def test_fifo_waiters_precede_owner_reentry():
    from agent_bom.db.graph_write_admission import _WriterQueue

    queue = _WriterQueue()
    order = []

    def enter(number):
        with queue.enter(3):
            order.append(number)

    def await_waiters(count):
        import time

        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            with queue.condition:
                if len(queue.waiters) == count:
                    return
            Event().wait(0.001)
        pytest.fail("Writer did not enter the queue")

    with ThreadPoolExecutor(max_workers=3) as pool:
        with queue.enter(3):
            one = pool.submit(enter, 1)
            await_waiters(1)
            two = pool.submit(enter, 2)
            await_waiters(2)
            three = pool.submit(enter, 3)
            await_waiters(3)
        enter(4)
        for future in (one, two, three):
            future.result(timeout=3)
    assert order == [1, 2, 3, 4]


def test_timeout_removes_waiter_and_preserves_sqlite_diagnostics():
    import sqlite3

    from agent_bom.db.graph_write_admission import _WriterQueue

    queue = _WriterQueue()

    def timed_out():
        with queue.enter(0.01):
            pytest.fail("Writer entered while owned")

    with ThreadPoolExecutor(max_workers=1) as pool:
        with queue.enter(3):
            with pytest.raises(sqlite3.OperationalError) as error:
                pool.submit(timed_out).result(timeout=3)
            assert error.value.sqlite_errorcode == sqlite3.SQLITE_BUSY
            assert error.value.sqlite_errorname == "SQLITE_BUSY"
            assert not queue.waiters
        with queue.enter(0):
            assert queue.depth == 1


def test_failed_nested_owner_releases_admission(tmp_path):
    from agent_bom.db.graph_write_admission import graph_writer_admission

    path = tmp_path / "graph.db"
    with pytest.raises(RuntimeError):
        with graph_writer_admission(path), graph_writer_admission(path):
            raise RuntimeError("producer failed")

    def next_writer():
        with graph_writer_admission(path, timeout=0.1):
            return True

    with ThreadPoolExecutor(max_workers=1) as pool:
        assert pool.submit(next_writer).result(timeout=3)


def test_other_databases_and_initialized_readers_are_not_queued(tmp_path):
    from agent_bom.api.graph_store import SQLiteGraphStore

    path = tmp_path / "graph.db"
    store = SQLiteGraphStore(path)
    with graph_store.open_graph_db(path):
        pass
    # Establish read schema before holding a write transaction.
    assert store.list_presets(tenant_id="a") == []

    def read_and_write_other_file():
        assert store.list_presets(tenant_id="a") == []
        with graph_store.open_graph_db(tmp_path / "other.db"):
            pass
        return True

    with ThreadPoolExecutor(max_workers=1) as pool:
        with graph_store.open_graph_db(path) as conn:
            conn.execute("BEGIN IMMEDIATE")
            assert pool.submit(read_and_write_other_file).result(timeout=3)


def test_api_mutations_wait_before_opening_connections(monkeypatch, tmp_path):
    from agent_bom.api.graph_store import SQLiteGraphStore
    from agent_bom.db.graph_write_admission import graph_writer_admission

    store = SQLiteGraphStore(tmp_path / "graph.db")
    started, opened = Event(), Event()
    original = store._open_rw_conn

    def open_connection():
        opened.set()
        return original()

    monkeypatch.setattr(store, "_open_rw_conn", open_connection)

    def save():
        started.set()
        store.save_preset(tenant_id="a", name="test", description="", filters={}, created_at="2026-10-01")

    with ThreadPoolExecutor(max_workers=1) as pool:
        with graph_writer_admission(store._db_path):
            future = pool.submit(save)
            assert started.wait(3)
            with pytest.raises(TimeoutError):
                future.result(timeout=0.1)
            assert not opened.is_set()
        future.result(timeout=3)
    assert len(store.list_presets(tenant_id="a")) == 1
