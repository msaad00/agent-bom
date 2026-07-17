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
from agent_bom.graph.node import UnifiedNode
from agent_bom.graph.types import EntityType, NodeStatus


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
            if low.startswith("select source_id, target_id, relationship, first_seen, valid_from, valid_to"):
                return _FakeCursor([("agent:a", "server:b", "uses", "2026-07-16T00:00:00Z", "2026-07-16T00:00:00Z", None)])
            return super().execute(sql, params)

        def executemany(self, sql, seq):
            low = " ".join(sql.strip().lower().split())
            if low.startswith("update graph_edges"):
                self.retirement_sql = low
                list(seq)
                return _FakeCursor()
            return super().executemany(sql, seq)

    conn = _RetirementConn()
    store = _make_store(conn, monkeypatch)

    store.save_graph_streaming(
        scan_id="scan-new",
        tenant_id="tenant-a",
        nodes=iter(()),
        edges=iter(()),
        created_at="2026-07-17T00:00:00Z",
    )

    assert "set valid_to = coalesce(valid_to, %s)" in conn.retirement_sql
    assert "activity_id = case when activity_id = 1 then 3 else activity_id end" in conn.retirement_sql
