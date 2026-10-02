"""Search scope limits work without changing text or tenant/snapshot semantics."""

import sqlite3
from contextlib import closing

import pytest

from agent_bom.api.graph_store import SQLiteGraphStore
from agent_bom.graph import EntityType, UnifiedGraph, UnifiedNode


def save(store, tenant, scan="snapshot", count=1):
    graph = UnifiedGraph(tenant_id=tenant, scan_id=scan)
    for index in range(count):
        graph.add_node(UnifiedNode(id=f"n:{index}", entity_type=EntityType.AGENT, label=f"needle {index}", attributes={"owner": tenant}))
    store.save_graph(graph)


def test_unrelated_tenant_matches_do_not_consume_the_search_budget(tmp_path, monkeypatch):
    store = SQLiteGraphStore(tmp_path / "graph.db")
    save(store, "target", count=100)
    save(store, "unrelated", count=5000)
    original = store._open_ro_conn
    original().close()
    steps = 0

    def connect():
        conn = original()

        def budget():
            nonlocal steps
            steps += 1000
            return steps > 25000

        conn.set_progress_handler(budget, 1000)
        return conn

    monkeypatch.setattr(store, "_open_ro_conn", connect)
    nodes, total, _ = store.search_nodes(tenant_id="target", scan_id="snapshot", query="needle", limit=10)
    assert total == 100 and len(nodes) == 10
    assert {node.attributes["owner"] for node in nodes} == {"target"}


def test_scope_metadata_does_not_become_searchable_content(tmp_path):
    store = SQLiteGraphStore(tmp_path / "graph.db")
    graph = UnifiedGraph(tenant_id="privatecohort", scan_id="privaterevision")
    graph.add_node(UnifiedNode(id="n", entity_type=EntityType.AGENT, label="needle"))
    store.save_graph(graph)
    for query in ("privatecohort", "privaterevision"):
        assert store.search_nodes(tenant_id=graph.tenant_id, scan_id=graph.scan_id, query=query) == ([], 0, None)


@pytest.mark.parametrize("tenant,scan", [("!!!", "..."), ("租户", "快照"), ('t" OR x', 's" OR y'), ("team-a", "scan-a")])
def test_scope_identifiers_remain_exact_and_opaque(tmp_path, tenant, scan):
    store = SQLiteGraphStore(tmp_path / "graph.db")
    for owner in {tenant, tenant.upper(), tenant.replace("-", " "), "unrelated"}:
        for snapshot in {scan, scan.upper(), scan.replace("-", " "), "other"}:
            save(store, owner, snapshot)
    nodes, total, _ = store.search_nodes(tenant_id=tenant, scan_id=scan, query="needle")
    assert total == len(nodes) == 1
    assert nodes[0].attributes["owner"] == tenant


def legacy_index(conn):
    conn.execute("DROP TABLE graph_node_search")
    conn.execute("""CREATE VIRTUAL TABLE graph_node_search USING fts5(
        tenant_id UNINDEXED, scan_id UNINDEXED, node_id UNINDEXED,
        entity_type, severity, compliance_tags, data_sources, search_text)""")
    conn.execute("INSERT INTO graph_node_search VALUES ('target','snapshot','n:0','agent','','','','needle')")
    conn.commit()


def test_legacy_scope_index_upgrade_preserves_rows_and_runs_once(tmp_path):
    store = SQLiteGraphStore(tmp_path / "graph.db")
    save(store, "target")
    with closing(sqlite3.connect(store._db_path)) as conn:
        legacy_index(conn)
    with closing(store._open_rw_conn()) as conn:
        assert conn.execute("SELECT count(*) FROM graph_node_search WHERE graph_node_search MATCH 'tenant_id:target'").fetchone()[0] == 1
    nodes, total, _ = store.search_nodes(tenant_id="target", scan_id="snapshot", query="needle")
    assert total == len(nodes) == 1
    with closing(store._open_rw_conn()) as conn:
        assert conn.execute("SELECT count(*) FROM graph_node_search").fetchone()[0] == 1


def test_failed_scope_index_upgrade_restores_the_original_table(tmp_path):
    from agent_bom.api.storage.sqlite_graph_search import ensure_search_index

    store = SQLiteGraphStore(tmp_path / "graph.db")
    save(store, "target")
    with closing(sqlite3.connect(store._db_path)) as conn:
        legacy_index(conn)
        conn.execute("BEGIN IMMEDIATE")
        conn.set_authorizer(lambda action, *args: sqlite3.SQLITE_DENY if action == sqlite3.SQLITE_ALTER_TABLE else sqlite3.SQLITE_OK)
        with pytest.raises(sqlite3.DatabaseError):
            ensure_search_index(conn)
        conn.set_authorizer(None)
        conn.rollback()
        assert conn.execute("SELECT search_text FROM graph_node_search").fetchall() == [("needle",)]
        assert conn.execute("SELECT name FROM sqlite_master WHERE name='graph_node_search_upgrade'").fetchall() == []


def test_offline_index_rollback_preserves_current_rows_and_old_reader_semantics(tmp_path):
    from agent_bom.api.storage.sqlite_graph_search import rebuild_search_index

    store = SQLiteGraphStore(tmp_path / "graph.db")
    save(store, "target")
    with closing(sqlite3.connect(store._db_path)) as conn:
        before = conn.execute("SELECT rowid, * FROM graph_node_search").fetchall()
        conn.execute("BEGIN IMMEDIATE")
        rebuild_search_index(conn, scoped=False)
        conn.commit()
        assert conn.execute("SELECT rowid, * FROM graph_node_search").fetchall() == before
        assert conn.execute("SELECT count(*) FROM graph_node_search WHERE graph_node_search MATCH 'snapshot'").fetchone()[0] == 0
        assert conn.execute("SELECT count(*) FROM graph_node_search WHERE graph_node_search MATCH 'needle'").fetchone()[0] == 1
        conn.execute("INSERT INTO graph_node_search VALUES ('target','snapshot','old-writer','agent','','','','needle')")
        conn.commit()
        # Older writers use the same eight columns; re-upgrade retains them.
        from agent_bom.api.storage.sqlite_graph_search import ensure_search_index

        conn.execute("BEGIN IMMEDIATE")
        ensure_search_index(conn)
        conn.commit()
        assert conn.execute("SELECT count(*) FROM graph_node_search WHERE graph_node_search MATCH 'tenant_id:target'").fetchone()[0] == 2


@pytest.mark.parametrize("tenant,scan", [("team\x00suffix", "scan"), ("team", "scan\x00suffix")])
def test_nul_scope_cannot_change_prefix_and_semantics_to_substring(tmp_path, tenant, scan):
    store = SQLiteGraphStore(tmp_path / "graph.db")
    save(store, tenant, scan)
    nodes, total, _ = store.search_nodes(tenant_id=tenant, scan_id=scan, query="need age")
    assert total == len(nodes) == 1
