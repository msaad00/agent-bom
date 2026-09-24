"""Recorded edge paging parity; optional real Postgres uses an isolated test DB."""

from __future__ import annotations

import base64
import json
import os
import uuid

import pytest

from agent_bom.api.graph_store import SQLiteGraphStore
from agent_bom.graph import EntityType, RelationshipType, UnifiedEdge, UnifiedGraph, UnifiedNode


@pytest.fixture(params=["sqlite", "postgres"])
def store(request, tmp_path):
    if request.param == "sqlite":
        yield SQLiteGraphStore(tmp_path / "graph.db")
        return
    dsn = os.environ.get("AGENT_BOM_ADJACENCY_TEST_POSTGRES_URL")
    if not dsn:
        pytest.skip("isolated adjacency Postgres URL not set")
    from psycopg_pool import ConnectionPool

    from agent_bom.api.postgres_graph import PostgresGraphStore

    with ConnectionPool(dsn) as pool:
        yield PostgresGraphStore(pool=pool, maintenance_pool=pool)


def save_fixture(store, tenant, scan="scan", created="2026-09-23T00:00:00Z"):
    graph = UnifiedGraph(tenant_id=tenant, scan_id=scan, created_at=created)
    for id_ in ["hub", "A", "a", "z", "unrelated"]:
        graph.add_node(UnifiedNode(id=id_, entity_type=EntityType.AGENT, label="same label"))
    pairs = [
        ("hub", "A", RelationshipType.USES),
        ("hub", "A", RelationshipType.CONTAINS),
        ("a", "hub", RelationshipType.USES),
        ("hub", "hub", RelationshipType.USES),
        ("hub", "z", RelationshipType.USES),
    ]
    for source, target, relationship in pairs:
        graph.add_edge(UnifiedEdge(source=source, target=target, relationship=relationship, direction="bidirectional"))
    store.save_graph(graph)
    return graph


@pytest.mark.parametrize("direction", ["in", "out", "both"])
def test_pages_preserve_parallel_edges_selfloops_and_recorded_direction(store, direction, monkeypatch):
    tenant = uuid.uuid4().hex
    graph = save_fixture(store, tenant)
    # Neither legacy full-incident reads nor impact are part of the primitive.
    monkeypatch.setattr(store, "node_context", lambda **kwargs: pytest.fail("legacy context read"))
    monkeypatch.setattr(store, "impact_of", lambda **kwargs: pytest.fail("impact read"))
    expected = sorted(
        (e.source, e.target, e.relationship.value)
        for e in graph.edges
        if direction == "both" or (e.source == "hub" if direction == "out" else e.target == "hub")
    )
    seen = []
    cursor = None
    for _ in range(10):
        result = store.incident_edges_page(tenant_id=tenant, scan_id="scan", node_id="hub", direction=direction, limit=2, cursor=cursor)
        assert result is not None
        assert len(result["edges"]) <= 2
        keys = [(e.source, e.target, e.relationship.value) for e in result["edges"]]
        assert {n.id for n in result["nodes"]} == {"hub", *(v for key in keys for v in key[:2])}
        assert result["completeness"]["returned"] == len(keys)
        assert "total" not in result["completeness"]
        seen.extend(keys)
        cursor = result["next_cursor"]
        if not cursor:
            assert result["completeness"]["complete"] is True
            break
        assert result["completeness"]["truncated"] is True
    assert seen == expected
    assert len(set(seen)) == len(seen)


def test_cursor_rejects_scope_changes_and_new_snapshot(store):
    tenant = uuid.uuid4().hex
    save_fixture(store, tenant)
    first = store.incident_edges_page(tenant_id=tenant, node_id="hub", limit=1)
    cursor = first["next_cursor"]
    assert cursor
    for args in ({"node_id": "A"}, {"direction": "in"}):
        with pytest.raises(ValueError, match="scope"):
            store.incident_edges_page(tenant_id=tenant, **{"node_id": "hub", "cursor": cursor, **args})
    other = uuid.uuid4().hex
    save_fixture(store, other)
    with pytest.raises(ValueError, match="scope"):
        store.incident_edges_page(tenant_id=other, node_id="hub", cursor=cursor)
    save_fixture(store, tenant, "new", "2026-09-24T00:00:00Z")
    with pytest.raises(ValueError, match="scope"):
        store.incident_edges_page(tenant_id=tenant, node_id="hub", cursor=cursor)
    assert store.incident_edges_page(tenant_id=tenant, scan_id="scan", node_id="hub", cursor=cursor)
    save_fixture(store, tenant, created="2026-09-25T00:00:00Z")
    with pytest.raises(ValueError, match="scope"):
        store.incident_edges_page(tenant_id=tenant, scan_id="scan", node_id="hub", cursor=cursor)


def test_missing_entities_invalid_cursors_and_limits(store):
    tenant = uuid.uuid4().hex
    save_fixture(store, tenant)
    assert store.incident_edges_page(tenant_id=tenant, node_id="missing") is None
    assert store.incident_edges_page(tenant_id="unknown", scan_id="scan", node_id="hub") is None
    for cursor in ["!bad", "e30=", "x" * 9000, base64.urlsafe_b64encode(("[" * 2000 + "]" * 2000).encode()).decode()]:
        with pytest.raises(ValueError, match="Invalid incident-edge cursor"):
            store.incident_edges_page(tenant_id=tenant, node_id="hub", cursor=cursor)
    for limit in [0, 101, True]:
        with pytest.raises(ValueError, match="limit"):
            store.incident_edges_page(tenant_id=tenant, node_id="hub", limit=limit)
    with pytest.raises(ValueError, match="direction"):
        store.incident_edges_page(tenant_id=tenant, node_id="hub", direction="reverse")
    result = store.incident_edges_page(tenant_id=tenant, node_id="unrelated")
    assert result["edges"] == [] and result["next_cursor"] is None


def test_page_uses_one_snapshot_during_concurrent_replacement(store, monkeypatch):
    tenant = uuid.uuid4().hex
    graph = save_fixture(store, tenant)
    original = store._node_from_row
    replaced = False

    def replace_after_seed(row):
        nonlocal replaced
        node = original(row)
        if not replaced:
            replaced = True
            graph.nodes["A"].label = "replacement"
            graph.created_at = "2026-09-26T00:00:00Z"
            store.save_graph(graph)
        return node

    monkeypatch.setattr(store, "_node_from_row", replace_after_seed)
    page = store.incident_edges_page(tenant_id=tenant, node_id="hub", limit=10)
    assert {n.label for n in page["nodes"]} == {"same label"}
    fresh = store.incident_edges_page(tenant_id=tenant, node_id="hub", limit=10)
    assert "replacement" in {n.label for n in fresh["nodes"]}
    assert fresh["snapshot_generation"] != page["snapshot_generation"]


@pytest.mark.parametrize("direction", ["in", "out"])
def test_sqlite_high_degree_reads_only_bounded_edge_rows(tmp_path, monkeypatch, direction):
    store = SQLiteGraphStore(tmp_path / "high-degree.db")
    graph = UnifiedGraph(tenant_id="acme", scan_id="large")
    graph.add_node(UnifiedNode(id="hub", entity_type=EntityType.SERVER, label="hub"))
    for i in range(5000):
        node_id = f"agent:{i:05d}"
        graph.add_node(UnifiedNode(id=node_id, entity_type=EntityType.AGENT, label="same label"))
        graph.add_edge(
            UnifiedEdge(
                source=node_id if direction == "in" else "hub",
                target="hub" if direction == "in" else node_id,
                relationship=RelationshipType.USES,
            )
        )
    store.save_graph(graph)
    original_open = store._open_ro_conn
    edge_rows = []
    plans = []
    instructions = []

    class Connection:
        def __init__(self, conn):
            self.conn = conn

        def execute(self, sql, params=()):
            if "FROM graph_edges" in sql:
                plans.extend(str(row[3]) for row in self.conn.execute("EXPLAIN QUERY PLAN " + sql, params))
                steps = 0

                def progress():
                    nonlocal steps
                    steps += 1
                    return 0

                self.conn.set_progress_handler(progress, 1)
                rows = self.conn.execute(sql, params).fetchall()
                self.conn.set_progress_handler(None, 0)
                instructions.append(steps)
                edge_rows.append(len(rows))
                return Cursor(rows)
            return self.conn.execute(sql, params)

        def close(self):
            self.conn.close()

    class Cursor:
        def __init__(self, rows):
            self.rows = rows

        def fetchall(self):
            return self.rows

    monkeypatch.setattr(store, "_open_ro_conn", lambda: Connection(original_open()))
    page = store.incident_edges_page(tenant_id="acme", node_id="hub", limit=24, direction=direction)
    assert edge_rows == [25]
    assert len(page["nodes"]) == 25 and len(page["edges"]) == 24
    assert page["next_cursor"]
    assert all("SCAN graph_edges" not in plan and "TEMP B-TREE" not in plan for plan in plans)
    assert any(f"idx_ge_adjacency_{direction}" in plan for plan in plans)
    token = json.loads(base64.urlsafe_b64decode(page["next_cursor"]))
    token["after"] = ["agent:04900", "hub", "uses"] if direction == "in" else ["hub", "agent:04900", "uses"]
    cursor = base64.urlsafe_b64encode(json.dumps(token).encode()).decode()
    deep = store.incident_edges_page(tenant_id="acme", node_id="hub", limit=24, direction=direction, cursor=cursor)
    assert len(deep["edges"]) == 24
    assert edge_rows == [25, 25]
    assert instructions[-1] < instructions[0] * 2 + 500
    assert instructions[-1] < 2500


def test_missing_endpoint_is_not_complete_or_a_dangling_projection(store):
    tenant = uuid.uuid4().hex
    graph = UnifiedGraph(tenant_id=tenant, scan_id="dangling")
    graph.add_node(UnifiedNode(id="hub", entity_type=EntityType.SERVER, label="hub"))
    # Storage accepts raw streamed evidence, including unresolved node references.
    store.save_graph_streaming(
        scan_id=graph.scan_id,
        tenant_id=tenant,
        nodes=graph.nodes.values(),
        edges=[UnifiedEdge(source="hub", target="absent", relationship=RelationshipType.USES)],
    )
    page = store.incident_edges_page(tenant_id=tenant, node_id="hub")
    assert page["edges"] == []
    assert [n.id for n in page["nodes"]] == ["hub"]
    assert page["completeness"]["complete"] is False
    assert page["completeness"]["missing_endpoint_count"] == 1
    assert page["completeness"]["reason"] == "missing_endpoint_nodes"


def test_postgres_rls_independently_rejects_another_tenant(store, monkeypatch):
    if isinstance(store, SQLiteGraphStore):
        pytest.skip("Postgres RLS contract")
    from contextlib import contextmanager

    from agent_bom.api.postgres_common import reset_current_tenant, set_current_tenant

    tenant, other = uuid.uuid4().hex, uuid.uuid4().hex
    save_fixture(store, tenant)
    save_fixture(store, other)
    original_pool = store._pool

    class ReadonlyPool:
        @contextmanager
        def connection(self):
            with original_pool.connection() as conn:
                # Migration-provisioned non-owner role, subject to FORCE RLS.
                conn.execute("SET LOCAL ROLE agent_bom_readonly")
                yield conn

    monkeypatch.setattr(store, "_pool", ReadonlyPool())
    token = set_current_tenant(tenant)
    try:
        page = store.incident_edges_page(tenant_id=tenant, node_id="hub", limit=1)
        assert page and page["next_cursor"]
        assert store.incident_edges_page(tenant_id=other, node_id="hub") is None
        with pytest.raises(ValueError, match="unavailable"):
            store.incident_edges_page(tenant_id=other, node_id="hub", cursor=page["next_cursor"])
    finally:
        reset_current_tenant(token)


@pytest.mark.parametrize("streaming", [False, True])
def test_replacement_with_same_timestamp_and_manifest_invalidates_cursor(store, streaming):
    tenant = uuid.uuid4().hex
    graph = save_fixture(store, tenant)
    page = store.incident_edges_page(tenant_id=tenant, scan_id="scan", node_id="hub", limit=1)
    old_scope = json.loads(base64.urlsafe_b64decode(page["next_cursor"]))["scope"]
    graph.edges.pop()
    if streaming:
        store.save_graph_streaming(
            tenant_id=tenant, scan_id="scan", created_at=graph.created_at, nodes=graph.nodes.values(), edges=graph.edges
        )
    else:
        store.save_graph(graph)
    fresh = store.incident_edges_page(tenant_id=tenant, scan_id="scan", node_id="hub", limit=1)
    new_scope = json.loads(base64.urlsafe_b64decode(fresh["next_cursor"]))["scope"]
    assert old_scope[:4] == new_scope[:4]  # Same tenant, ID, timestamp, manifest.
    assert old_scope[4] != new_scope[4]  # Every successful save advances generation.
    with pytest.raises(ValueError, match="scope"):
        store.incident_edges_page(tenant_id=tenant, scan_id="scan", node_id="hub", cursor=page["next_cursor"])


def test_sqlite_legacy_generation_backfill_is_durable(tmp_path):
    import sqlite3

    from agent_bom.db.graph_store import open_graph_db

    path = tmp_path / "legacy.db"
    store = SQLiteGraphStore(path)
    save_fixture(store, "acme")
    with sqlite3.connect(path) as conn:
        conn.execute("ALTER TABLE graph_snapshots DROP COLUMN snapshot_generation")
    with open_graph_db(path) as conn:
        first = conn.execute("SELECT snapshot_generation FROM graph_snapshots").fetchone()[0]
    with open_graph_db(path) as conn:
        second = conn.execute("SELECT snapshot_generation FROM graph_snapshots").fetchone()[0]
    assert len(first) == 32 and first == second
    assert SQLiteGraphStore(path).incident_edges_page(tenant_id="acme", node_id="hub")


@pytest.mark.parametrize("upgrade_path", ["migration", "runtime"])
def test_generation_backfill_under_non_superuser_migration_owner(monkeypatch, upgrade_path):
    """Existing tenants must survive a separate, non-superuser upgrade transaction."""
    dsn = os.environ.get("AGENT_BOM_ADJACENCY_TEST_POSTGRES_URL")
    if not dsn:
        pytest.skip("isolated adjacency Postgres URL not set")
    from pathlib import Path
    from urllib.parse import urlsplit, urlunsplit

    import psycopg
    from alembic import command
    from alembic.config import Config
    from psycopg import sql

    parts = urlsplit(dsn)
    suffix = uuid.uuid4().hex[:12]
    owner, database = f"adjacency_owner_{suffix}", f"adjacency_upgrade_{suffix}"
    password = "adjacency-fixture-only"
    admin_db = urlunsplit((parts.scheme, parts.netloc, f"/{database}", parts.query, parts.fragment))
    owner_url = urlunsplit((parts.scheme, f"{owner}:{password}@{parts.netloc.rsplit('@', 1)[-1]}", f"/{database}", "", ""))
    root = Path(__file__).resolve().parents[1]
    # Programmatic migrations must not apply CLI logging configuration to pytest.
    cfg = Config()
    cfg.set_main_option("script_location", str(root / "deploy/supabase/postgres/alembic"))
    with psycopg.connect(dsn, autocommit=True) as admin:
        admin.execute(sql.SQL("CREATE ROLE {} LOGIN SUPERUSER PASSWORD {}").format(sql.Identifier(owner), sql.Literal(password)))
        admin.execute(sql.SQL("CREATE DATABASE {} OWNER {}").format(sql.Identifier(database), sql.Identifier(owner)))
        try:
            monkeypatch.setenv("ALEMBIC_DATABASE_URL", owner_url.replace("postgresql://", "postgresql+psycopg://", 1))
            command.upgrade(cfg, "20260923_01")
            with psycopg.connect(owner_url) as conn:
                flags = conn.execute("SELECT rolsuper, rolbypassrls FROM pg_roles WHERE rolname=current_user").fetchone()
                assert flags == (False, False)
            with psycopg.connect(admin_db) as conn:
                conn.execute(
                    "INSERT INTO graph_snapshots(scan_id,tenant_id,created_at) "
                    "VALUES ('legacy','tenant-a','2026-09-23'), ('legacy','tenant-b','2026-09-23')"
                )
            if upgrade_path == "migration":
                command.upgrade(cfg, "head")
            else:
                with psycopg.connect(owner_url) as conn:
                    conn.execute((root / "deploy/supabase/postgres/runtime-schema.sql").read_text())
                    assert conn.execute("SELECT COALESCE(current_setting('app.bypass_rls',true),'0')").fetchone()[0] in {"", "0"}
            with psycopg.connect(admin_db) as conn:
                generations = conn.execute("SELECT snapshot_generation FROM graph_snapshots ORDER BY tenant_id").fetchall()
                assert len(generations) == 2
                assert all(len(row[0]) == 32 for row in generations)
                assert generations[0] != generations[1]
                assert conn.execute("SELECT version FROM control_plane_schema_versions WHERE component='graph'").fetchone()[0] == 5
        finally:
            admin.execute(sql.SQL("DROP DATABASE {} WITH (FORCE)").format(sql.Identifier(database)))
            admin.execute(sql.SQL("DROP ROLE {}").format(sql.Identifier(owner)))


@pytest.mark.parametrize("partial_marker", [None, 3])
def test_queue_only_legacy_upgrade_does_not_require_or_advertise_graph(monkeypatch, partial_marker):
    """Reproduce CI's 0.98.2 queue-only schema stamped at 20260728_02."""
    dsn = os.environ.get("AGENT_BOM_ADJACENCY_TEST_POSTGRES_URL")
    if not dsn:
        pytest.skip("isolated adjacency Postgres URL not set")
    from pathlib import Path
    from urllib.parse import urlsplit, urlunsplit

    import psycopg
    from alembic import command
    from alembic.config import Config
    from psycopg import sql

    parts = urlsplit(dsn)
    database = f"adjacency_legacy_{uuid.uuid4().hex[:12]}"
    url = urlunsplit((parts.scheme, parts.netloc, f"/{database}", parts.query, parts.fragment))
    root = Path(__file__).resolve().parents[1]
    # Programmatic migrations must not apply CLI logging configuration to pytest.
    cfg = Config()
    cfg.set_main_option("script_location", str(root / "deploy/supabase/postgres/alembic"))
    with psycopg.connect(dsn, autocommit=True) as admin:
        admin.execute(sql.SQL("CREATE DATABASE {}").format(sql.Identifier(database)))
        try:
            with psycopg.connect(url) as conn:
                conn.execute("""
                    CREATE TABLE scan_jobs(job_id TEXT PRIMARY KEY);
                    INSERT INTO scan_jobs VALUES ('legacy-queued-job');
                    CREATE TABLE scan_dispatch_queue (
                        job_id TEXT PRIMARY KEY REFERENCES scan_jobs(job_id) ON DELETE CASCADE,
                        tenant_id TEXT NOT NULL, created_at TEXT NOT NULL,
                        status TEXT NOT NULL DEFAULT 'pending', claimed_by TEXT, lease_expires_at TEXT
                    );
                    INSERT INTO scan_dispatch_queue(job_id,tenant_id,created_at)
                        VALUES ('legacy-queued-job','legacy-tenant','2026-07-28T00:00:00Z');
                    CREATE FUNCTION public.abom_current_tenant() RETURNS TEXT LANGUAGE SQL STABLE AS $$
                        SELECT COALESCE(NULLIF(current_setting('app.tenant_id',true),''),'default') $$;
                """)
            monkeypatch.setenv("ALEMBIC_DATABASE_URL", url.replace("postgresql://", "postgresql+psycopg://", 1))
            command.stamp(cfg, "20260728_02")
            command.upgrade(cfg, "head")
            with psycopg.connect(url) as conn:
                assert conn.execute("SELECT job_id FROM scan_dispatch_queue").fetchone()[0] == "legacy-queued-job"
                assert conn.execute("SELECT to_regclass('public.graph_snapshots')").fetchone()[0] is None
                marker = conn.execute("SELECT version FROM control_plane_schema_versions WHERE component='graph'").fetchone()
                assert marker is None or marker[0] < 5
            command.downgrade(cfg, "20260923_01")
            with psycopg.connect(url) as conn:
                assert conn.execute("SELECT to_regclass('public.graph_snapshots')").fetchone()[0] is None
                assert conn.execute("SELECT job_id FROM scan_dispatch_queue").fetchone()[0] == "legacy-queued-job"
            # Two graph-shaped tables alone do not establish a complete graph v4 schema.
            with psycopg.connect(url) as conn:
                conn.execute("CREATE TABLE graph_snapshots(scan_id TEXT)")
                conn.execute("CREATE TABLE graph_edges(tenant_id TEXT,scan_id TEXT,source_id TEXT,target_id TEXT,relationship TEXT)")
                conn.execute("DELETE FROM control_plane_schema_versions WHERE component='graph'")
                if partial_marker is not None:
                    conn.execute("INSERT INTO control_plane_schema_versions(component,version) VALUES ('graph',%s)", (partial_marker,))
            command.upgrade(cfg, "head")
            with psycopg.connect(url) as conn:
                marker = conn.execute("SELECT version FROM control_plane_schema_versions WHERE component='graph'").fetchone()
                assert marker == (None if partial_marker is None else (partial_marker,))
        finally:
            admin.execute(sql.SQL("DROP DATABASE {} WITH (FORCE)").format(sql.Identifier(database)))


def test_cross_node_expansion_pins_generation_without_continuation_cursor(store):
    tenant = uuid.uuid4().hex
    graph = save_fixture(store, tenant)
    first = store.incident_edges_page(tenant_id=tenant, scan_id=graph.scan_id, node_id="hub", limit=100)
    assert first["next_cursor"] is None
    generation = first["snapshot_generation"]
    peer = store.incident_edges_page(tenant_id=tenant, scan_id=graph.scan_id, node_id="A", snapshot_generation=generation)
    assert peer["snapshot_generation"] == generation
    store.save_graph(graph)
    with pytest.raises(ValueError, match="generation"):
        store.incident_edges_page(tenant_id=tenant, scan_id=graph.scan_id, node_id="A", snapshot_generation=generation)
    current = store.incident_edges_page(tenant_id=tenant, scan_id=graph.scan_id, node_id="A")
    assert current["snapshot_generation"] != generation


@pytest.mark.parametrize("field", ["node_id", "scan_id"])
def test_incident_page_rejects_nul_identifiers(store, field):
    with pytest.raises(ValueError, match="NUL"):
        store.incident_edges_page(tenant_id="nul-test", **{"node_id": "hub", "scan_id": "scan", field: "bad\x00id"})


def test_incident_page_rejects_nul_cursor_position(store):
    import base64
    import json

    save_fixture(store, "nul-cursor")
    first = store.incident_edges_page(tenant_id="nul-cursor", scan_id="scan", node_id="hub", limit=1)
    token = json.loads(base64.urlsafe_b64decode(first["next_cursor"]))
    token["after"][0] = "bad\x00id"
    cursor = base64.urlsafe_b64encode(json.dumps(token).encode()).decode()
    with pytest.raises(ValueError, match="cursor"):
        store.incident_edges_page(tenant_id="nul-cursor", scan_id="scan", node_id="hub", cursor=cursor)


def test_snapshot_identity_changes_on_replacement_and_is_tenant_scoped(store):
    save_fixture(store, "identity-a")
    save_fixture(store, "identity-b")
    first = store.snapshot_identity(tenant_id="identity-a", scan_id="scan")
    assert first[0] == "scan" and len(first[1]) == 32
    assert store.snapshot_identity(tenant_id="identity-a") == first
    other = store.snapshot_identity(tenant_id="identity-b", scan_id="scan")
    assert other != first
    save_fixture(store, "identity-a")
    assert store.snapshot_identity(tenant_id="identity-a", scan_id="scan") != first
    assert store.snapshot_identity(tenant_id="identity-b", scan_id="scan") == other
    assert store.snapshot_identity(tenant_id="identity-missing", scan_id="scan") == ("scan", "")
