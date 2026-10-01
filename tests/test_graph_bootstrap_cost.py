"""Graph reopen cost stays bounded after legacy edge metadata is normalized."""

import sqlite3

from agent_bom.db.graph_store import _init_db, open_graph_db


def test_reopen_does_not_scan_all_normalized_relationships(tmp_path):
    path = tmp_path / "graph.db"
    with open_graph_db(path) as conn:
        conn.executemany(
            "INSERT INTO graph_edges (source_id, target_id, relationship, scan_id, tenant_id, "
            "first_seen, last_seen, valid_from, source_scan_id) "
            "VALUES ('root', ?, 'uses', 'scan', 'tenant', '2026-09-30', '2026-09-30', '2026-09-30', 'scan')",
            ((f"node:{i}",) for i in range(20000)),
        )
        conn.commit()
    with sqlite3.connect(path) as conn:
        conn.row_factory = sqlite3.Row
        callbacks = 0

        def budget():
            nonlocal callbacks
            callbacks += 1
            return callbacks > 50

        conn.set_progress_handler(budget, 1000)
        _init_db(conn)
        conn.set_progress_handler(None, 0)
        assert conn.execute("SELECT COUNT(*) FROM graph_edges").fetchone()[0] == 20000


def test_late_legacy_edges_are_still_backfilled(tmp_path):
    with open_graph_db(tmp_path / "legacy.db") as conn:
        conn.execute(
            "INSERT INTO graph_edges (source_id, target_id, relationship, scan_id, tenant_id, first_seen, last_seen) "
            "VALUES ('root', 'asset', 'uses', 'scan', 'tenant', '2026-09-30', '2026-09-30')"
        )
        conn.commit()
        _init_db(conn)
        assert tuple(conn.execute("SELECT valid_from, source_scan_id FROM graph_edges").fetchone()) == ("2026-09-30", "scan")


def test_replaced_database_does_not_reuse_path_initialization_cache(tmp_path):
    from agent_bom.api.graph_store import SQLiteGraphStore
    from agent_bom.graph import EntityType, UnifiedGraph, UnifiedNode

    path = tmp_path / "live.db"
    store = SQLiteGraphStore(path)
    graph = UnifiedGraph(tenant_id="tenant", scan_id="old")
    graph.add_node(UnifiedNode(id="old-asset", entity_type=EntityType.AGENT, label="old"))
    store.save_graph(graph)
    assert store.load_graph(tenant_id="tenant", scan_id="old").nodes
    replacement = tmp_path / "replacement.db"
    with sqlite3.connect(replacement) as conn:
        conn.execute("CREATE TABLE restore_receipt (id INTEGER)")
    replacement.replace(path)
    assert not store.load_graph(tenant_id="tenant", scan_id="old").nodes
