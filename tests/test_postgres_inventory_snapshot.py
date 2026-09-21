"""Inventory projections share one tenant-bound PostgreSQL read snapshot."""

import os
from contextlib import contextmanager
from uuid import uuid4

import pytest

from agent_bom.api.postgres_common import _tenant_connection, reset_current_tenant, set_current_tenant
from agent_bom.api.postgres_graph import PostgresGraphStore


class _Cursor:
    def __init__(self, rows=()):
        self.rows = list(rows)

    def fetchone(self):
        return self.rows[0] if self.rows else None

    def fetchall(self):
        return self.rows


class _Connection:
    def __init__(self):
        self.calls = []

    def execute(self, sql, params=None):
        normalized = " ".join(sql.split())
        self.calls.append((normalized, params))
        if normalized.startswith("SELECT scan_id"):
            return _Cursor([("snapshot", "2026-09-21T00:00:00Z")])
        if normalized.startswith("SELECT created_at"):
            return _Cursor([("2026-09-21T00:00:00Z",)])
        if normalized.startswith("SELECT COUNT(*)"):
            return _Cursor([(0,)])
        return _Cursor()


class _Pool:
    def __init__(self):
        self.conn = _Connection()
        self.checkouts = 0

    @contextmanager
    def connection(self):
        self.checkouts += 1
        yield self.conn


@pytest.mark.parametrize("scan_id", ["", "snapshot"])
def test_inventory_establishes_repeatable_snapshot_before_tenant_queries(scan_id):
    pool = _Pool()
    store = object.__new__(PostgresGraphStore)
    store._pool = pool
    token = set_current_tenant("tenant-a")
    try:
        result = store.query_inventory(tenant_id="tenant-a", scan_id=scan_id, asset_entity_types={"agent"})
    finally:
        reset_current_tenant(token)
    assert pool.checkouts == 1
    assert pool.conn.calls[0][0] == "SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY"
    assert pool.conn.calls[1] == ("SELECT set_config('app.tenant_id', %s, true)", ("tenant-a",))
    assert pool.conn.calls[2] == ("SELECT set_config('app.bypass_rls', %s, true)", ("0",))
    assert result["scan_id"] == "snapshot"


def test_default_tenant_connection_does_not_change_transaction_mode():
    pool = _Pool()
    with _tenant_connection(pool):
        pass
    assert pool.conn.calls[0][0].startswith("SELECT set_config('app.tenant_id'")
    assert not any("SET TRANSACTION" in sql for sql, _ in pool.conn.calls)


@pytest.mark.skipif(not os.environ.get("AGENT_BOM_POSTGRES_URL"), reason="requires a migrated live PostgreSQL database")
@pytest.mark.parametrize("explicit_snapshot", [False, True])
def test_inventory_keeps_counts_rows_and_context_consistent_during_replacement(explicit_snapshot):
    from psycopg_pool import ConnectionPool

    from agent_bom.api.postgres_common import resolve_postgres_secret
    from agent_bom.graph import EntityType, RelationshipType, UnifiedEdge, UnifiedGraph, UnifiedNode

    tenant = "inventory-snapshot-" + uuid4().hex
    scan_id = "scan-" + uuid4().hex
    password = resolve_postgres_secret()
    with ConnectionPool(
        os.environ["AGENT_BOM_POSTGRES_URL"], kwargs={"password": password} if password else {}, min_size=1, max_size=2
    ) as pool:
        store = PostgresGraphStore(pool=pool)
        token = set_current_tenant(tenant)
        try:
            graph = UnifiedGraph(scan_id=scan_id, tenant_id=tenant)
            for index in range(3):
                graph.add_node(UnifiedNode(id=f"agent:{index}", entity_type=EntityType.AGENT, label=f"Agent {index}"))
            graph.add_node(
                UnifiedNode(id="finding:old", entity_type=EntityType.VULNERABILITY, label="Old finding", severity="high", severity_id=4)
            )
            graph.add_edge(UnifiedEdge(source="agent:0", target="finding:old", relationship=RelationshipType.VULNERABLE_TO))
            store.save_graph(graph)
            replacement = UnifiedGraph(scan_id=scan_id, tenant_id=tenant)
            replacement.add_node(UnifiedNode(id="agent:new", entity_type=EntityType.AGENT, label="New agent"))
            replaced = False

            class ReplacingConnection:
                def __init__(self, connection):
                    self.connection = connection

                def execute(self, sql, *args):
                    nonlocal replaced
                    if "SELECT id, entity_type, label, category_uid" in sql and not replaced:
                        replaced = True
                        store.save_graph(replacement)
                    return self.connection.execute(sql, *args)

            class ReplacingPool:
                @contextmanager
                def connection(self):
                    with pool.connection() as conn:
                        yield ReplacingConnection(conn)

            reader = object.__new__(PostgresGraphStore)
            reader._pool = ReplacingPool()
            result = reader.query_inventory(tenant_id=tenant, scan_id=scan_id if explicit_snapshot else "", asset_entity_types={"agent"})
            assert replaced
            assert result["scan_id"] == scan_id
            assert result["total"] == 3
            assert {node.id for node in result["nodes"]} == {"agent:0", "agent:1", "agent:2"}
            assert result["facets"]["type"] == [{"value": "agent", "count": 3}]
            assert result["finding_count"] == 1
            assert result["relationship_counts"]["agent:0"] == 1
            assert result["finding_summaries"]["agent:0"]["ids"] == ["finding:old"]
            current = store.query_inventory(tenant_id=tenant, scan_id=scan_id, asset_entity_types={"agent"})
            assert current["total"] == 1
            assert [node.id for node in current["nodes"]] == ["agent:new"]
            assert current["finding_count"] == 0
            other_token = set_current_tenant(tenant + "-other")
            try:
                assert store.query_inventory(tenant_id=tenant, scan_id=scan_id, asset_entity_types={"agent"})["nodes"] == []
            finally:
                reset_current_tenant(other_token)
        finally:
            store.delete_snapshot(tenant_id=tenant, scan_id=scan_id)
            reset_current_tenant(token)
