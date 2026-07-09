"""open_graph_db must create missing parent directories on a fresh deploy.

Regression guard: sqlite3.connect does not create missing parent dirs, so a
seeded demo estate on a fresh volume (no ~/.agent-bom/db) crashed to an empty
graph with "unable to open database file".
"""

from __future__ import annotations

from pathlib import Path

from agent_bom.db.graph_store import open_graph_db


def test_open_graph_db_creates_missing_parent_dirs(tmp_path: Path) -> None:
    db_path = tmp_path / "nested" / "deeper" / "graph.db"
    assert not db_path.parent.exists()

    with open_graph_db(db_path) as conn:
        assert conn.execute("SELECT 1").fetchone()[0] == 1

    assert db_path.parent.is_dir()
    assert db_path.exists()


def test_open_graph_db_memory_target_is_unaffected() -> None:
    with open_graph_db(":memory:") as conn:
        assert conn.execute("SELECT 1").fetchone()[0] == 1
