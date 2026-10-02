"""Bounded edge reads on a migration-owned schema with application-role RLS."""

from __future__ import annotations

from tests.test_graph_page_edge_budget import _graph
from tests.test_postgres_migrated_graph_parity import migrated_fresh_database, pytestmark  # noqa: F401


def test_bounded_edges_preserve_postgres_tenant_and_projection_contract(migrated_fresh_database):  # noqa: F811
    from agent_bom.api.postgres_common import reset_current_tenant, set_current_tenant
    from agent_bom.api.postgres_graph import PostgresGraphStore

    store = PostgresGraphStore()
    for tenant, count in (("tenant-a", 1100), ("tenant-b", 5)):
        token = set_current_tenant(tenant)
        try:
            store.save_graph(_graph(tenant, count))
        finally:
            reset_current_tenant(token)
    token = set_current_tenant("tenant-a")
    try:
        edges = store.edges_for_node_ids(tenant_id="tenant-a", scan_id="estate", node_ids={"agent:root", "finding:00001"}, limit=11)
        assert len(edges) == 11
        assert len({edge.id for edge in edges}) == 11
        assert store.edges_for_node_ids(tenant_id="tenant-b", scan_id="estate", node_ids={"agent:root"}, limit=11) == []
        assert store.edges_for_node_ids(tenant_id="tenant-a", scan_id="estate", node_ids={"agent:root"}, direction="in", limit=11) == []
        incoming = store.edges_for_node_ids(
            tenant_id="tenant-a", scan_id="estate", node_ids={"finding:00001"}, direction="in", relationships={"uses"}, limit=11
        )
        assert len(incoming) == 1 and incoming[0].target == "finding:00001"
    finally:
        reset_current_tenant(token)
