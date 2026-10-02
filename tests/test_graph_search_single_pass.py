"""Search pages count and rank one match set without duplicate estate joins."""

import pytest

from agent_bom.api.graph_store import SQLiteGraphStore
from agent_bom.graph import EntityType, UnifiedGraph, UnifiedNode


@pytest.fixture
def search_store(tmp_path):
    store = SQLiteGraphStore(tmp_path / "search.db")
    for tenant in ("a", "b", "c", "d"):
        graph = UnifiedGraph(tenant_id=tenant, scan_id="snapshot")
        for i in range(1000):
            graph.add_node(
                UnifiedNode(
                    id=f"node:{i:04}",
                    entity_type=EntityType.CLOUD_RESOURCE,
                    label=f"finding {i:04}",
                    risk_score=i % 7,
                    attributes={"tenant": tenant, "detail": "x" * 256},
                )
            )
        store.save_graph(graph)
    return store


def test_search_page_uses_one_match_pass_with_bounded_sql_work(search_store, monkeypatch):
    original = search_store._open_ro_conn
    original().close()
    steps = 0

    def connect():
        conn = original()

        def budget():
            nonlocal steps
            steps += 1000
            return int(steps > 140_000)

        conn.set_progress_handler(budget, 1000)
        return conn

    monkeypatch.setattr(search_store, "_open_ro_conn", connect)
    nodes, total, cursor = search_store.search_nodes(tenant_id="a", scan_id="snapshot", query="finding", limit=7)
    assert total == 1000 and len(nodes) == 7 and cursor
    assert all(n.attributes["tenant"] == "a" for n in nodes)


def test_search_total_survives_empty_offset_and_cursor_pages(search_store):
    args = dict(tenant_id="b", scan_id="snapshot", query="finding")
    nodes, total, cursor = search_store.search_nodes(**args, limit=1000)
    assert total == len(nodes) == 1000 and cursor is None
    assert search_store.search_nodes(**args, offset=1000, limit=10) == ([], 1000, None)
    from agent_bom.api.graph_store import encode_graph_cursor

    assert search_store.search_nodes(**args, cursor=encode_graph_cursor(nodes[-1]), limit=10) == ([], 1000, None)
    assert search_store.search_nodes(**{**args, "query": "absent"}) == ([], 0, None)


@pytest.mark.parametrize("field", ["query", "tenant_id", "scan_id", "entity_types", "data_sources", "compliance_prefixes"])
def test_search_predicates_keep_untrusted_text_in_bound_values(search_store, field):
    payload = "' OR 1=1; DROP TABLE graph_nodes; --"
    args = dict(tenant_id="a", scan_id="snapshot", query="finding")
    args[field] = {payload} if field in {"entity_types", "data_sources", "compliance_prefixes"} else payload
    assert search_store.search_nodes(**args) == ([], 0, None)
    assert search_store.search_nodes(tenant_id="a", scan_id="snapshot", query="finding", limit=1)[1] == 1000
