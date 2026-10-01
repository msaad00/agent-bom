"""Schema backfill reserves the writer lock before inspecting mutable schema."""

import sqlite3
from concurrent.futures import ThreadPoolExecutor, TimeoutError
from threading import Event

import pytest

from agent_bom.db.graph_store import _init_db, open_graph_db


def test_schema_inspection_and_backfill_are_serialized_with_other_writers(tmp_path):
    db = tmp_path / "graph.db"
    with open_graph_db(db):
        pass
    inspected, release = Event(), Event()

    def initialize():
        with sqlite3.connect(db, timeout=5) as conn:

            def factory(cursor, row):
                if cursor.description[0][0] == "version" and not inspected.is_set():
                    inspected.set()
                    assert release.wait(5)
                return sqlite3.Row(cursor, row)

            conn.row_factory = factory
            _init_db(conn)

    def competing_writer():
        with sqlite3.connect(db, timeout=5) as conn:
            conn.execute("BEGIN IMMEDIATE")
            conn.execute("UPDATE graph_schema_version SET version=version")

    with ThreadPoolExecutor(max_workers=2) as pool:
        migration = pool.submit(initialize)
        assert inspected.wait(5)
        competitor = pool.submit(competing_writer)
        try:
            with pytest.raises(TimeoutError):
                competitor.result(timeout=0.2)
        finally:
            release.set()
        migration.result(timeout=5)
        competitor.result(timeout=5)
