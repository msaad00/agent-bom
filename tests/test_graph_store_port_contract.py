"""Shared graph port contract, exercised against real SQLite and PostgreSQL."""

import os
from uuid import uuid4

import pytest

from agent_bom.api.graph_store import GraphStoreProtocol, SQLiteGraphStore
from agent_bom.api.postgres_common import reset_current_tenant, set_current_tenant
from agent_bom.graph import EntityType, RelationshipType, UnifiedEdge, UnifiedNode


@pytest.fixture(params=["sqlite", "postgres"])
def store_factory(request, tmp_path):
    if request.param == "sqlite":
        yield lambda: SQLiteGraphStore(tmp_path / "graph.db")
        return
    if not os.environ.get("AGENT_BOM_POSTGRES_URL"):
        pytest.skip("AGENT_BOM_POSTGRES_URL is required for the live graph port contract")
    from agent_bom.api.postgres_common import _new_application_pool
    from agent_bom.api.postgres_graph import PostgresGraphStore

    pool = _new_application_pool(min_size=1, max_size=2)
    try:
        yield lambda: PostgresGraphStore(pool=pool)
    finally:
        pool.close()


def test_streaming_snapshot_port_preserves_paging_scope_and_generation(store_factory):
    store: GraphStoreProtocol = store_factory()
    tenant, other, scan = uuid4().hex, uuid4().hex, uuid4().hex
    context = set_current_tenant(tenant)
    try:
        store.save_graph_streaming(
            scan_id=scan,
            tenant_id=tenant,
            write_generation="one",
            nodes=[
                UnifiedNode(id="agent:a", entity_type=EntityType.AGENT, label="a"),
                UnifiedNode(id="tool:b", entity_type=EntityType.TOOL, label="b"),
            ],
            edges=[UnifiedEdge(source="agent:a", target="tool:b", relationship=RelationshipType.CALLED, evidence={"source": "fixture"})],
        )
        reopened: GraphStoreProtocol = store_factory()
        assert reopened.latest_snapshot_id(tenant_id=tenant) == scan
        assert reopened.snapshot_identity(tenant_id=tenant, scan_id=scan) == (scan, "one")
        _, _, first, total, cursor = reopened.page_nodes(tenant_id=tenant, scan_id=scan, limit=1)
        assert len(first) == 1 and total == 2 and cursor
        _, _, second, total, _ = reopened.page_nodes(tenant_id=tenant, scan_id=scan, limit=1, cursor=cursor)
        assert {first[0].id, second[0].id} == {"agent:a", "tool:b"} and total == 2
        assert reopened.delete_snapshot(tenant_id=tenant, scan_id=scan, expected_generation="wrong") == 0
        graph = reopened.load_graph(tenant_id=tenant, scan_id=scan)
        assert len(graph.edges) == 1 and graph.edges[0].evidence["source"] == "fixture"
        other_context = set_current_tenant(other)
        try:
            assert not reopened.load_graph(tenant_id=other, scan_id=scan).nodes
        finally:
            reset_current_tenant(other_context)
        assert reopened.delete_snapshot(tenant_id=tenant, scan_id=scan, expected_generation="one") > 0
        assert not reopened.load_graph(tenant_id=tenant, scan_id=scan).nodes
    finally:
        reset_current_tenant(context)
