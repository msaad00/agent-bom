"""Streamed graph persistence — bounded peak RSS + correctness (#4055).

The public write path builds a whole ``UnifiedGraph`` in RAM before
``save_graph``; at 1M nodes that is ~3.3 GB and OOMs a normal container.
``save_graph_streaming`` persists from node/edge iterables so peak RSS is
decoupled from graph size, and ``iter_graph_nodes``/``iter_graph_edges``
read a snapshot back without re-materialising the whole graph.

These tests assert (a) the streamed path writes exactly what ``save_graph``
would, and (b) a streaming producer keeps peak RSS flat as N grows.
"""

from __future__ import annotations

import os
import subprocess
import sys
import textwrap

from agent_bom.db import graph_store as gs
from agent_bom.graph.container import AttackPath, InteractionRisk, UnifiedGraph
from agent_bom.graph.edge import UnifiedEdge
from agent_bom.graph.node import UnifiedNode
from agent_bom.graph.types import EntityType, RelationshipType


def _sample_graph(scan_id: str) -> UnifiedGraph:
    g = UnifiedGraph(scan_id=scan_id, tenant_id="acme")
    g.add_node(UnifiedNode(id="agent:a", entity_type=EntityType.AGENT, label="agent-a", severity="high", risk_score=9.0))
    g.add_node(UnifiedNode(id="server:s", entity_type=EntityType.SERVER, label="server-s", severity="medium"))
    g.add_node(UnifiedNode(id="pkg:p", entity_type=EntityType.PACKAGE, label="pkg-p"))
    g.add_node(UnifiedNode(id="vuln:v", entity_type=EntityType.VULNERABILITY, label="CVE-1", severity="critical", risk_score=10.0))
    g.add_edge(UnifiedEdge(source="agent:a", target="server:s", relationship=RelationshipType.USES))
    g.add_edge(UnifiedEdge(source="server:s", target="pkg:p", relationship=RelationshipType.DEPENDS_ON))
    g.add_edge(UnifiedEdge(source="pkg:p", target="vuln:v", relationship=RelationshipType.VULNERABLE_TO))
    g.attack_paths.append(
        AttackPath(source="agent:a", target="vuln:v", hops=["agent:a", "server:s", "pkg:p", "vuln:v"], composite_risk=8.5)
    )
    g.interaction_risks.append(InteractionRisk(pattern="shared-cred", agents=["agent:a"], risk_score=7.0, description="x"))
    return g


def _snapshot_rows(conn, scan_id: str, tenant_id: str) -> dict[str, list]:
    def rows(sql: str) -> list:
        return [tuple(r) for r in conn.execute(sql, (tenant_id, scan_id)).fetchall()]

    return {
        "nodes": rows("SELECT * FROM graph_nodes WHERE tenant_id=? AND scan_id=? ORDER BY id"),
        "edges": rows("SELECT * FROM graph_edges WHERE tenant_id=? AND scan_id=? ORDER BY source_id,target_id,relationship"),
        "attack_paths": rows("SELECT * FROM attack_paths WHERE tenant_id=? AND scan_id=? ORDER BY source_node,target_node"),
        "interaction_risks": rows("SELECT * FROM interaction_risks WHERE tenant_id=? AND scan_id=? ORDER BY pattern"),
        "snapshot": rows(
            "SELECT node_count, edge_count, risk_summary, node_type_counts FROM graph_snapshots WHERE tenant_id=? AND scan_id=?"
        ),
    }


def test_streaming_persist_matches_save_graph(tmp_path) -> None:
    """save_graph_streaming writes byte-identical rows to save_graph."""
    baseline = _sample_graph("s1")
    streamed = _sample_graph("s1")

    db_a = tmp_path / "a.db"
    db_b = tmp_path / "b.db"
    with gs.open_graph_db(db_a) as conn:
        gs.save_graph(conn, baseline)
        rows_a = _snapshot_rows(conn, "s1", "acme")

    with gs.open_graph_db(db_b) as conn:
        gs.save_graph_streaming(
            conn,
            scan_id="s1",
            tenant_id="acme",
            created_at=streamed.created_at,
            nodes=iter(streamed.nodes.values()),
            edges=iter(streamed.edges),
            attack_paths=iter(streamed.attack_paths),
            interaction_risks=iter(streamed.interaction_risks),
        )
        rows_b = _snapshot_rows(conn, "s1", "acme")

    assert rows_a == rows_b


def test_streaming_persist_preserves_temporal_reconciliation(tmp_path) -> None:
    """The streamed path reconciles valid_from/valid_to against the prior snapshot."""
    from datetime import datetime, timedelta, timezone

    # Recent timestamps within the retention window so the prior snapshot is not
    # purged before the second save (retention is age-based on created_at).
    t1 = (datetime.now(timezone.utc) - timedelta(days=2)).isoformat()
    t2 = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()

    db = tmp_path / "temporal.db"
    with gs.open_graph_db(db) as conn:
        # prior snapshot has edge a->b and a->c
        g1 = UnifiedGraph(scan_id="v1", tenant_id="acme", created_at=t1)
        for nid in ("a", "b", "c"):
            g1.add_node(UnifiedNode(id=nid, entity_type=EntityType.PACKAGE, label=nid))
        g1.add_edge(UnifiedEdge(source="a", target="b", relationship=RelationshipType.DEPENDS_ON, first_seen=t1))
        g1.add_edge(UnifiedEdge(source="a", target="c", relationship=RelationshipType.DEPENDS_ON, first_seen=t1))
        gs.save_graph(conn, g1)

        # new snapshot keeps a->b (should preserve first_seen/valid_from), drops a->c (valid_to set on prior)
        g2 = UnifiedGraph(scan_id="v2", tenant_id="acme", created_at=t2)
        for nid in ("a", "b"):
            g2.add_node(UnifiedNode(id=nid, entity_type=EntityType.PACKAGE, label=nid))
        g2.add_edge(UnifiedEdge(source="a", target="b", relationship=RelationshipType.DEPENDS_ON, first_seen=t2))
        gs.save_graph_streaming(
            conn,
            scan_id="v2",
            tenant_id="acme",
            created_at=g2.created_at,
            nodes=iter(g2.nodes.values()),
            edges=iter(g2.edges),
        )

        kept = conn.execute(
            "SELECT first_seen, valid_from FROM graph_edges WHERE scan_id='v2' AND source_id='a' AND target_id='b'"
        ).fetchone()
        assert kept["first_seen"] == t1
        assert kept["valid_from"] == t1

        dropped = conn.execute("SELECT valid_to FROM graph_edges WHERE scan_id='v1' AND source_id='a' AND target_id='c'").fetchone()
        assert dropped["valid_to"] == t2


def test_streaming_load_iterators_match_load_graph(tmp_path) -> None:
    """iter_graph_nodes/iter_graph_edges yield the same nodes/edges as load_graph."""
    db = tmp_path / "iter.db"
    g = _sample_graph("s1")
    with gs.open_graph_db(db) as conn:
        gs.save_graph(conn, g)
        full = gs.load_graph(conn, tenant_id="acme", scan_id="s1")
        streamed_nodes = list(gs.iter_graph_nodes(conn, tenant_id="acme", scan_id="s1"))
        streamed_edges = list(gs.iter_graph_edges(conn, tenant_id="acme", scan_id="s1"))

    assert {n.id for n in streamed_nodes} == set(full.nodes)
    assert sorted((n.id, n.severity, n.risk_score) for n in streamed_nodes) == sorted(
        (n.id, n.severity, n.risk_score) for n in full.nodes.values()
    )
    assert sorted((e.source, e.target, e.relationship.value) for e in streamed_edges) == sorted(
        (e.source, e.target, e.relationship.value) for e in full.edges
    )


# ── Memory: a streaming producer must stay flat as N grows ────────────────────

_MEM_SCRIPT = textwrap.dedent(
    """
    import os, sys, tempfile, resource
    from agent_bom.db import graph_store as gs
    from agent_bom.graph.container import UnifiedGraph
    from agent_bom.graph.node import UnifiedNode
    from agent_bom.graph.edge import UnifiedEdge
    from agent_bom.graph.types import EntityType, RelationshipType

    N = int(sys.argv[1]); mode = sys.argv[2]
    db = os.path.join(tempfile.mkdtemp(), "g.db")

    def maxrss_mb():
        r = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        return (r / 1024 / 1024) if sys.platform == "darwin" else (r / 1024)

    def mk_node(i):
        return UnifiedNode(id="n%d" % i, entity_type=EntityType.PACKAGE, label="pkg-%d" % i,
                           severity="high" if i % 5 == 0 else "low", risk_score=float(i % 10))
    def mk_edge(i):
        return UnifiedEdge(source="n%d" % i, target="n%d" % ((i + 1) % N), relationship=RelationshipType.DEPENDS_ON)

    if mode == "full":
        g = UnifiedGraph(scan_id="s", tenant_id="t")
        for i in range(N): g.add_node(mk_node(i))
        for i in range(N): g.add_edge(mk_edge(i))
        with gs.open_graph_db(db) as conn:
            gs.save_graph(conn, g)
    else:  # streaming producer: never materialises the whole graph
        with gs.open_graph_db(db) as conn:
            gs.save_graph_streaming(
                conn, scan_id="s", tenant_id="t",
                nodes=(mk_node(i) for i in range(N)),
                edges=(mk_edge(i) for i in range(N)),
            )
    print(maxrss_mb())
    """
)


def _peak_rss_mb(n: int, mode: str) -> float:
    env = dict(os.environ)
    # Ensure the subprocess imports the same in-tree agent_bom this test does,
    # not a stale site-packages copy.
    env["PYTHONPATH"] = os.pathsep.join(p for p in sys.path if p) + os.pathsep + env.get("PYTHONPATH", "")
    out = subprocess.check_output([sys.executable, "-c", _MEM_SCRIPT, str(n), mode], text=True, env=env)
    return float(out.strip().splitlines()[-1])


def test_streaming_persist_peak_rss_is_bounded() -> None:
    """Streaming persist RSS stays ~flat while the full-graph path scales with N."""
    stream_small = _peak_rss_mb(100_000, "stream")
    stream_large = _peak_rss_mb(300_000, "stream")

    # Streaming growth from 100k -> 300k (3x the data) must stay well under 2x RSS:
    # peak is dominated by a bounded batch, not the graph size.
    assert stream_large < stream_small * 1.5, f"streaming RSS grew with N: {stream_small:.0f} -> {stream_large:.0f} MB"

    # And it must be a large win vs building the whole graph in RAM at the same N.
    full_large = _peak_rss_mb(300_000, "full")
    assert stream_large < full_large * 0.5, f"streaming ({stream_large:.0f}MB) not < half of full ({full_large:.0f}MB)"
