"""Postgres streamed graph persist: single-pass node + node-search double write.

The Postgres backend fans a single node producer out to BOTH the ``graph_nodes``
row and its ``graph_node_search`` mirror. #4074 left this non-trivial because the
old ``save_graph`` iterated ``graph.nodes.values()`` twice; a lazy producer can
only be consumed once. These tests pin that ``save_graph_streaming`` consumes the
node iterable exactly once, still writes both rows for every node, batches with a
bounded window, and records byte-correct snapshot tallies — all against a fake
connection (no live Postgres required).
"""

from __future__ import annotations

import pytest

from agent_bom.graph.analysis import GraphAnalysisState, GraphAnalysisStatus
from agent_bom.graph.edge import UnifiedEdge
from agent_bom.graph.node import UnifiedNode
from agent_bom.graph.types import EntityType, NodeStatus, RelationshipType


class _FakeCursor:
    def __init__(self, rows=None):
        self.rows = rows or []

    def fetchone(self):
        return self.rows[0] if self.rows else None

    def fetchall(self):
        return self.rows

    def __iter__(self):
        return iter(self.rows)


class _RecordingConn:
    """Fake Postgres connection recording every insert batch by table."""

    def __init__(self):
        self.node_rows: list[tuple] = []
        self.search_rows: list[tuple] = []
        self.edge_rows: list[tuple] = []
        self.snapshot_params: tuple | None = None
        self.executemany_calls: list[str] = []
        self.committed = 0
        self.deleted_tables: list[str] = []
        self.advisory_locks: list[tuple] = []
        self.sql_calls: list[str] = []
        self.sql_params: list[tuple | None] = []
        self.rolled_back = 0

    def __enter__(self):
        return self

    def __exit__(self, *args):
        if args[0] is not None:
            self.rollback()
        return False

    def execute(self, sql, params=None):
        low = " ".join(sql.strip().lower().split())
        self.sql_calls.append(low)
        self.sql_params.append(tuple(params) if params is not None else None)
        if low.startswith("select pg_advisory_xact_lock"):
            self.advisory_locks.append(tuple(params))
        elif low.startswith("delete from"):
            self.deleted_tables.append(low.split()[2])
        if low.startswith("insert into graph_snapshots"):
            self.snapshot_params = tuple(params)
        # latest/previous lookups + set_config + purge scan -> empty history
        return _FakeCursor()

    def executemany(self, sql, seq):
        low = " ".join(sql.strip().lower().split())
        rows = list(seq)
        if low.startswith("insert into graph_nodes"):
            self.executemany_calls.append("graph_nodes")
            self.node_rows.extend(rows)
        elif low.startswith("insert into graph_node_search"):
            self.executemany_calls.append("graph_node_search")
            self.search_rows.extend(rows)
        elif low.startswith("insert into graph_edges"):
            self.edge_rows.extend(rows)
        return _FakeCursor(rows)

    def commit(self):
        self.committed += 1

    def rollback(self):
        self.rolled_back += 1


class _FakePool:
    def __init__(self, conn):
        self._conn = conn
        self.connection_calls = 0

    def connection(self):
        self.connection_calls += 1
        return self._conn


def _make_store(conn, monkeypatch):
    from agent_bom.api import postgres_graph

    monkeypatch.setattr(postgres_graph.PostgresGraphStore, "_init_tables", lambda self: None)
    monkeypatch.setattr(postgres_graph.PostgresGraphStore, "_init_optional_search_indexes", lambda self: None)
    return postgres_graph.PostgresGraphStore(pool=_FakePool(conn))


def _nodes(n):
    for i in range(n):
        yield UnifiedNode(
            id=f"agent:{i}",
            entity_type=EntityType.AGENT if i % 2 == 0 else EntityType.VULNERABILITY,
            label=f"n{i}",
            severity="critical" if i % 2 else "",
            status=NodeStatus.ACTIVE,
            risk_score=float(i),
        )


def test_streaming_consumes_one_shot_producer_and_double_writes(monkeypatch):
    monkeypatch.setenv("AGENT_BOM_GRAPH_WRITE_BATCH_SIZE", "2")
    conn = _RecordingConn()
    store = _make_store(conn, monkeypatch)

    # A generator is single-use: if the impl iterated nodes twice this yields
    # zero rows on the second pass and the search mirror would be empty.
    counts = store.save_graph_streaming(
        scan_id="scan-1",
        tenant_id="t1",
        nodes=_nodes(5),
        edges=iter(()),
    )

    assert counts == {"nodes": 5, "edges": 0}
    # Every node produced BOTH a graph_nodes row and a graph_node_search row.
    assert len(conn.node_rows) == 5
    assert len(conn.search_rows) == 5
    node_ids = [r[0] for r in conn.node_rows]
    search_ids = [r[0] for r in conn.search_rows]
    assert node_ids == [f"agent:{i}" for i in range(5)]
    assert search_ids == node_ids  # same order, one pass
    # Bounded batching: with batch size 2 over 5 nodes the node insert flushed
    # more than once rather than buffering all rows.
    assert conn.executemany_calls.count("graph_nodes") >= 3


def test_streaming_snapshot_tally_matches_nodes(monkeypatch):
    conn = _RecordingConn()
    store = _make_store(conn, monkeypatch)

    store.save_graph_streaming(
        scan_id="scan-2",
        tenant_id="t1",
        nodes=_nodes(4),
        edges=iter(()),
        analysis_status={
            "attack_path_fusion": GraphAnalysisStatus(
                status=GraphAnalysisState.SKIPPED,
                reason_codes=("node_cap_exceeded",),
                limits={"max_nodes": 5000},
                observed={"node_count": 5001},
            )
        },
    )

    # graph_snapshots row: counts plus serialized analysis execution state.
    assert conn.snapshot_params is not None
    scan, tenant, _now, node_count, edge_count, risk_summary, analysis_status = conn.snapshot_params
    assert (scan, tenant, node_count, edge_count) == ("scan-2", "t1", 4, 0)
    import json

    # Two of four nodes carry "critical" severity (odd indices).
    assert json.loads(risk_summary) == {"critical": 2}
    assert json.loads(analysis_status)["attack_path_fusion"] == {
        "status": "skipped",
        "reason_codes": ["node_cap_exceeded"],
        "limits": {"max_nodes": 5000},
        "observed": {"node_count": 5001},
    }
    assert conn.committed == 1


def test_save_graph_delegates_to_streaming(monkeypatch):
    """The materialised save_graph path stays byte-identical (delegates)."""
    from agent_bom.graph.container import UnifiedGraph

    conn = _RecordingConn()
    store = _make_store(conn, monkeypatch)
    g = UnifiedGraph(scan_id="scan-3", tenant_id="t1")
    for node in _nodes(3):
        g.add_node(node)

    store.save_graph(g)

    assert len(conn.node_rows) == 3
    assert len(conn.search_rows) == 3
    assert conn.snapshot_params[0] == "scan-3"


def test_streaming_serializes_and_replaces_same_snapshot(monkeypatch):
    """A retry cannot merge stale rows or race another writer for the scan."""
    conn = _RecordingConn()
    store = _make_store(conn, monkeypatch)

    store.save_graph_streaming(scan_id="scan-retry", tenant_id="t1", nodes=_nodes(1), edges=iter(()))

    assert conn.advisory_locks == [("t1\x1fscan-retry",)]
    assert conn.deleted_tables == [
        "graph_node_search",
        "attack_paths",
        "interaction_risks",
        "graph_edges",
        "graph_nodes",
        "graph_snapshots",
    ]


def test_same_scan_retry_does_not_checkout_nested_connection(monkeypatch):
    """A one-connection pool must not deadlock while resolving prior history."""

    class _RetryConn(_RecordingConn):
        def execute(self, sql, params=None):
            low = " ".join(sql.strip().lower().split())
            if low.startswith("select scan_id") and "order by created_at" in low and "created_at <" not in low:
                return _FakeCursor([("scan-retry", "2026-07-17T00:00:00+00:00")])
            if low.startswith("select created_at"):
                return _FakeCursor([("2026-07-17T00:00:00+00:00",)])
            if low.startswith("select scan_id") and "created_at <" in low:
                return _FakeCursor([])
            return super().execute(sql, params)

    conn = _RetryConn()
    store = _make_store(conn, monkeypatch)

    store.save_graph_streaming(scan_id="scan-retry", tenant_id="t1", nodes=_nodes(1), edges=iter(()))

    assert store._pool.connection_calls == 1


def test_postgres_stream_rolls_back_after_flushed_batch(monkeypatch):
    """A one-shot producer failure cannot commit a partial replacement."""
    monkeypatch.setenv("AGENT_BOM_GRAPH_WRITE_BATCH_SIZE", "1")
    conn = _RecordingConn()
    store = _make_store(conn, monkeypatch)

    def failing_nodes():
        yield next(_nodes(1))
        raise RuntimeError("producer failed after flush")

    import pytest

    with pytest.raises(RuntimeError, match="producer failed after flush"):
        store.save_graph_streaming(scan_id="retry", tenant_id="t1", nodes=failing_nodes(), edges=iter(()))

    assert conn.committed == 0
    assert conn.rolled_back == 1
    assert conn.snapshot_params is None


def test_postgres_writer_lock_precedes_snapshot_reads_and_deletes(monkeypatch):
    conn = _RecordingConn()
    store = _make_store(conn, monkeypatch)

    store.save_graph_streaming(scan_id="scan-1", tenant_id="t1", nodes=_nodes(1), edges=iter(()))

    lock_at = next(i for i, sql in enumerate(conn.sql_calls) if sql.startswith("select pg_advisory_xact_lock"))
    prior_read_at = next(i for i, sql in enumerate(conn.sql_calls) if "from graph_snapshots" in sql and sql.startswith("select"))
    delete_at = next(i for i, sql in enumerate(conn.sql_calls) if sql.startswith("delete from"))
    assert lock_at < prior_read_at < delete_at


def test_prior_edges_reconcile_in_postgres_without_python_materialization(monkeypatch):
    class _PreviousSnapshotConn(_RecordingConn):
        def execute(self, sql, params=None):
            low = " ".join(sql.strip().lower().split())
            if low.startswith("select scan_id, created_at") and "from graph_snapshots" in low:
                self.sql_calls.append(low)
                self.sql_params.append(tuple(params) if params is not None else None)
                return _FakeCursor([("prior-scan", "2026-07-18T00:00:00Z")])
            if low.startswith("select source_id, target_id, relationship"):
                raise AssertionError("prior graph edges must not be fetched into Python")
            return super().execute(sql, params)

    conn = _PreviousSnapshotConn()
    store = _make_store(conn, monkeypatch)
    edge = UnifiedEdge(source="agent:1", target="pkg:1", relationship=RelationshipType.DEPENDS_ON)

    store.save_graph_streaming(
        scan_id="current-scan",
        tenant_id="tenant-a",
        nodes=_nodes(1),
        edges=iter([edge]),
    )

    continuity_at = next(
        i for i, sql in enumerate(conn.sql_calls) if sql.startswith("update graph_edges as current")
    )
    retirement_at = next(
        i for i, sql in enumerate(conn.sql_calls) if sql.startswith("update graph_edges as previous")
    )
    assert conn.sql_params[continuity_at] == ("current-scan", "tenant-a", "prior-scan", "tenant-a")
    assert conn.sql_params[retirement_at][1:] == ("tenant-a", "prior-scan", "current-scan", "tenant-a")


@pytest.mark.parametrize(
    ("risk_summary", "analysis_status"),
    [
        (
            {"critical": 2},
            {
                "attack_path_fusion": {
                    "status": "skipped",
                    "reason_codes": ["node_cap_exceeded"],
                    "limits": {"max_nodes": 5000},
                    "observed": {"node_count": 5001},
                }
            },
        ),
        (
            '{"critical": 2}',
            '{"attack_path_fusion":{"status":"skipped","reason_codes":["node_cap_exceeded"],'
            '"limits":{"max_nodes":5000},"observed":{"node_count":5001}}}',
        ),
    ],
    ids=("native-jsonb", "text-json"),
)
def test_snapshot_history_accepts_psycopg_jsonb_objects_and_text(monkeypatch, risk_summary, analysis_status):
    """Snapshot reads support both canonical TEXT and legacy/native JSONB rows."""

    class _SnapshotConn(_RecordingConn):
        def execute(self, sql, params=None):
            low = " ".join(sql.strip().lower().split())
            if low.startswith("select scan_id, created_at, node_count, edge_count, risk_summary, analysis_status"):
                return _FakeCursor([("scan-json", "2026-07-17T00:00:00Z", 3, 2, risk_summary, analysis_status)])
            return super().execute(sql, params)

    store = _make_store(_SnapshotConn(), monkeypatch)

    snapshots = store.list_snapshots(tenant_id="tenant-a")

    assert snapshots[0]["risk_summary"] == {"critical": 2}
    assert snapshots[0]["analysis_status"]["attack_path_fusion"]["status"] == "skipped"


def test_load_graph_accepts_native_jsonb_analysis_status(monkeypatch):
    """A non-empty psycopg-decoded JSONB status cannot crash the graph read path."""
    status = {
        "attack_path_fusion": {
            "status": "complete",
            "reason_codes": [],
            "limits": {"max_nodes": 5000},
            "observed": {"node_count": 12, "result_count": 1},
        }
    }

    class _GraphReadConn(_RecordingConn):
        def execute(self, sql, params=None):
            low = " ".join(sql.strip().lower().split())
            if low.startswith("select created_at, analysis_status from graph_snapshots"):
                return _FakeCursor([("2026-07-17T00:00:00Z", status)])
            return super().execute(sql, params)

    store = _make_store(_GraphReadConn(), monkeypatch)

    graph = store.load_graph(tenant_id="tenant-a", scan_id="scan-json")

    assert graph.analysis_status["attack_path_fusion"].status is GraphAnalysisState.COMPLETE


@pytest.mark.parametrize(
    "json_values",
    [
        (
            {"owner": "security"},
            ["cis:1.1"],
            ["inventory"],
            {"environment": "production"},
        ),
        (
            '{"owner":"security"}',
            '["cis:1.1"]',
            '["inventory"]',
            '{"environment":"production"}',
        ),
    ],
    ids=("native-jsonb", "legacy-text"),
)
def test_page_nodes_accepts_native_jsonb_and_legacy_text(monkeypatch, json_values):
    """The paginated API read path supports psycopg JSONB and legacy TEXT."""

    native_node_row = (
        "agent:native",
        "agent",
        "Native Agent",
        1,
        1,
        1,
        "active",
        7.5,
        "high",
        4,
        "2026-07-19T00:00:00Z",
        "2026-07-19T00:00:00Z",
        *json_values,
    )

    class _NativeJsonbNodeConn(_RecordingConn):
        def execute(self, sql, params=None):
            low = " ".join(sql.strip().lower().split())
            if low.startswith("select created_at from graph_snapshots"):
                return _FakeCursor([("2026-07-19T00:00:00Z",)])
            if low.startswith("select count(*) from graph_nodes"):
                return _FakeCursor([(1,)])
            if "from graph_nodes" in low and low.startswith("select id, entity_type"):
                return _FakeCursor([native_node_row])
            return super().execute(sql, params)

    store = _make_store(_NativeJsonbNodeConn(), monkeypatch)

    effective_scan_id, _created_at, nodes, total, next_cursor = store.page_nodes(
        tenant_id="tenant-alpha",
        scan_id="scan-jsonb",
        limit=10,
    )

    assert effective_scan_id == "scan-jsonb"
    assert total == 1
    assert next_cursor is None
    assert nodes[0].id == "agent:native"
    assert nodes[0].attributes == {"owner": "security"}
    assert nodes[0].compliance_tags == ["cis:1.1"]
    assert nodes[0].data_sources == ["inventory"]
    assert nodes[0].dimensions.environment == "production"


def test_edge_and_attack_path_reads_accept_native_jsonb_and_preserve_tenant(monkeypatch):
    """Adjacent graph API reads decode JSONB and keep every query tenant-scoped."""
    edge_row = (
        "agent:native",
        "tool:native",
        "uses",
        "forward",
        1.0,
        True,
        "2026-07-19T00:00:00Z",
        "2026-07-19T00:00:00Z",
        "2026-07-19T00:00:00Z",
        None,
        0.9,
        {"collector": "inventory"},
        "scan-jsonb",
        "run-jsonb",
        {"source": "operator_inventory"},
        1,
        "scan-jsonb",
    )
    attack_path_row = (
        "agent:native",
        "tool:native",
        ["agent:native", "tool:native"],
        ["uses"],
        8.5,
        "native JSONB path",
        ["API_KEY"],
        ["run_shell"],
        ["CVE-2026-0001"],
        [],
    )

    class _NativeJsonbRelatedConn(_RecordingConn):
        def __init__(self):
            super().__init__()
            self.read_params = []

        def execute(self, sql, params=None):
            low = " ".join(sql.strip().lower().split())
            if "from graph_edges" in low and low.startswith("select source_id"):
                self.read_params.append(("edges", tuple(params)))
                return _FakeCursor([edge_row])
            if "from attack_paths" in low and "source_node in" in low:
                self.read_params.append(("paths", tuple(params)))
                return _FakeCursor([attack_path_row])
            return super().execute(sql, params)

    conn = _NativeJsonbRelatedConn()
    store = _make_store(conn, monkeypatch)

    edges = store.edges_for_node_ids(
        tenant_id="tenant-alpha",
        scan_id="scan-jsonb",
        node_ids={"agent:native", "tool:native"},
    )
    paths = store.attack_paths_for_sources(
        tenant_id="tenant-alpha",
        scan_id="scan-jsonb",
        source_ids={"agent:native"},
    )

    assert edges[0].provenance == {"collector": "inventory"}
    assert edges[0].evidence == {"source": "operator_inventory"}
    assert paths[0].hops == ["agent:native", "tool:native"]
    assert paths[0].credential_exposure == ["API_KEY"]
    assert paths[0].tool_exposure == ["run_shell"]
    assert ("paths", ("tenant-alpha", "scan-jsonb", "agent:native")) in conn.read_params
    edge_params = next(params for kind, params in conn.read_params if kind == "edges")
    assert edge_params[:2] == ("tenant-alpha", "scan-jsonb")


@pytest.mark.parametrize(
    ("row_index", "malformed", "message"),
    [
        (12, [], "node attributes JSON must be an object"),
        (13, {}, "node compliance tags JSON must be an array"),
        (14, "{not-json", "Expecting property name enclosed in double quotes"),
    ],
)
def test_node_read_rejects_malformed_persisted_json(row_index, malformed, message):
    """Corrupt persisted JSON fails closed with a stable validation error."""
    from agent_bom.api.postgres_graph import PostgresGraphStore

    row = [
        "agent:malformed",
        "agent",
        "Malformed Agent",
        1,
        1,
        1,
        "active",
        0.0,
        "",
        0,
        "2026-07-19T00:00:00Z",
        "2026-07-19T00:00:00Z",
        {},
        [],
        [],
        {},
    ]
    row[row_index] = malformed

    with pytest.raises(ValueError, match=message):
        PostgresGraphStore._node_from_row(row)


def test_retired_edge_update_records_ocsf_close_activity(monkeypatch):
    """Postgres retirement matches SQLite's canonical OCSF Close activity."""

    class _RetirementConn(_RecordingConn):
        def __init__(self):
            super().__init__()
            self.retirement_sql = ""

        def execute(self, sql, params=None):
            low = " ".join(sql.strip().lower().split())
            if low.startswith("select scan_id, created_at from graph_snapshots"):
                return _FakeCursor([("scan-old", "2026-07-16T00:00:00Z")])
            if low.startswith("update graph_edges as previous"):
                self.retirement_sql = low
            return super().execute(sql, params)

    conn = _RetirementConn()
    store = _make_store(conn, monkeypatch)

    store.save_graph_streaming(
        scan_id="scan-new",
        tenant_id="tenant-a",
        nodes=iter(()),
        edges=iter(()),
        created_at="2026-07-17T00:00:00Z",
    )

    assert "set valid_to = coalesce(previous.valid_to, %s)" in conn.retirement_sql
    assert "activity_id = case when previous.activity_id = 1 then 3 else previous.activity_id end" in conn.retirement_sql
