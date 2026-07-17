"""Graph-backend correctness: JSONB-column reads and cross-backend retire parity.

Two regressions covered here:

1. ``analysis_status``/``risk_summary`` are declared ``JSONB`` by ``init.sql`` and
   the enterprise migration but ``TEXT`` by the app's own ``_init_tables``. Under
   psycopg3 a ``JSONB`` column returns an already-parsed ``dict``, so the bare
   ``json.loads(...)`` in the graph reads raised ``TypeError`` whenever the status
   was non-empty. The reads must be robust to BOTH a ``str`` (TEXT) and a ``dict``
   (JSONB) return.

2. On retiring an edge dropped from a new snapshot, Postgres stamps the OCSF
   ``activity_id`` Create(1) -> Close(3) but SQLite left it at Create(1) — the same
   scan sequence produced a different change feed per backend. SQLite must match
   Postgres.
"""

from __future__ import annotations

import re
import sqlite3
from pathlib import Path

from agent_bom.graph.analysis import GraphAnalysisState

# ── Fix 1: JSONB dict-return reads ──────────────────────────────────────────


class _FakeCursor:
    def __init__(self, rows=None):
        self.rows = rows or []

    def fetchone(self):
        return self.rows[0] if self.rows else None

    def fetchall(self):
        return self.rows

    def __iter__(self):
        return iter(self.rows)


_NON_EMPTY_STATUS = {
    "attack_path_fusion": {
        "status": "complete",
        "reason_codes": [],
        "limits": {},
        "observed": {"paths": 3},
    }
}
_RISK_SUMMARY = {"critical": 2, "high": 1}


class _JsonbConn:
    """Fake Postgres connection that returns dicts for JSONB columns (psycopg3)."""

    def __init__(self):
        self.committed = 0

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def execute(self, sql, params=None):
        low = " ".join(sql.strip().lower().split())
        if "select created_at, analysis_status from graph_snapshots" in low:
            # load_graph snapshot row: JSONB analysis_status arrives as a dict.
            return _FakeCursor([("2026-07-17T00:00:00Z", dict(_NON_EMPTY_STATUS))])
        if "select scan_id, created_at, node_count, edge_count, risk_summary, analysis_status" in low:
            # list_snapshots: risk_summary AND analysis_status arrive as dicts.
            return _FakeCursor([("scan-1", "2026-07-17T00:00:00Z", 4, 3, dict(_RISK_SUMMARY), dict(_NON_EMPTY_STATUS))])
        if "select analysis_status from graph_snapshots" in low:
            return _FakeCursor([(dict(_NON_EMPTY_STATUS),)])
        return _FakeCursor()

    def commit(self):
        self.committed += 1

    def rollback(self):
        pass


class _FakePool:
    def __init__(self, conn):
        self._conn = conn

    def connection(self):
        return self._conn


def _make_pg_store(conn, monkeypatch):
    from agent_bom.api import postgres_graph

    monkeypatch.setattr(postgres_graph.PostgresGraphStore, "_init_tables", lambda self: None)
    monkeypatch.setattr(postgres_graph.PostgresGraphStore, "_init_optional_search_indexes", lambda self: None)
    return postgres_graph.PostgresGraphStore(pool=_FakePool(conn))


def test_load_graph_reads_jsonb_analysis_status_dict(monkeypatch):
    store = _make_pg_store(_JsonbConn(), monkeypatch)

    graph = store.load_graph(tenant_id="default", scan_id="scan-1")

    status = graph.analysis_status["attack_path_fusion"]
    assert status.status is GraphAnalysisState.COMPLETE
    assert status.observed == {"paths": 3}


def test_list_snapshots_reads_jsonb_columns_dict(monkeypatch):
    store = _make_pg_store(_JsonbConn(), monkeypatch)

    rows = store.list_snapshots(tenant_id="default")

    assert rows[0]["risk_summary"] == _RISK_SUMMARY
    assert rows[0]["analysis_status"]["attack_path_fusion"]["status"] == "complete"


# ── Fix 2: retire-edge activity_id parity (SQLite must match Postgres) ───────


def _init_sqlite_graph_db() -> sqlite3.Connection:
    from agent_bom.db.graph_store import _init_db

    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    _init_db(conn)
    return conn


def _build_two_snapshots():
    from agent_bom.graph import RelationshipType, UnifiedEdge, UnifiedGraph
    from agent_bom.graph.node import UnifiedNode
    from agent_bom.graph.types import EntityType

    def node(node_id: str) -> UnifiedNode:
        return UnifiedNode(id=node_id, entity_type=EntityType.SERVER, label=node_id)

    g1 = UnifiedGraph(scan_id="s1", tenant_id="default", created_at="2026-07-16T00:00:00Z")
    for nid in ("a", "b", "c"):
        g1.add_node(node(nid))
    g1.add_edge(UnifiedEdge(source="a", target="b", relationship=RelationshipType.USES))
    g1.add_edge(UnifiedEdge(source="b", target="c", relationship=RelationshipType.USES))

    # s2 drops the b->c edge (retire).
    g2 = UnifiedGraph(scan_id="s2", tenant_id="default", created_at="2026-07-17T00:00:00Z")
    for nid in ("a", "b", "c"):
        g2.add_node(node(nid))
    g2.add_edge(UnifiedEdge(source="a", target="b", relationship=RelationshipType.USES))
    return g1, g2


def test_sqlite_retire_stamps_activity_id_close_like_postgres():
    from agent_bom.db.graph_store import changed_edges_between_scans, save_graph

    conn = _init_sqlite_graph_db()
    g1, g2 = _build_two_snapshots()
    save_graph(conn, g1)
    save_graph(conn, g2)

    changes = changed_edges_between_scans(conn, "s1", "s2", tenant_id="default")
    removed = changes["edges_removed"]
    assert [(e["source_id"], e["target_id"]) for e in removed] == [("b", "c")]
    # OCSF Close(3): a retired edge is Closed, matching the Postgres backend.
    assert removed[0]["activity_id"] == 3


def test_retire_activity_id_sql_parity_across_backends():
    """Both stores must issue the identical Create(1)->Close(3) stamp on retire."""
    src = Path(__file__).parent.parent / "src" / "agent_bom"
    sqlite_src = (src / "db" / "graph_store.py").read_text()
    pg_src = (src / "api" / "postgres_graph.py").read_text()

    case_expr = r"activity_id\s*=\s*CASE\s+WHEN\s+activity_id\s*=\s*1\s+THEN\s+3\s+ELSE\s+activity_id\s+END"
    assert re.search(case_expr, sqlite_src), "SQLite retire must stamp activity_id 1->3"
    assert re.search(case_expr, pg_src), "Postgres retire must stamp activity_id 1->3"
