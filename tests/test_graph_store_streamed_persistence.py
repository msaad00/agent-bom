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

import json
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


def test_streaming_snapshot_stats_are_golden_and_match_unified_graph_stats(tmp_path) -> None:
    """The persisted snapshot stat columns hold exact known values.

    ``save_graph`` delegates to ``save_graph_streaming``, so the identity test
    above compares streaming-vs-streaming and would not catch a regression that
    made the *incremental* accumulation diverge from ``UnifiedGraph.stats()``.
    Pin the persisted ``risk_summary`` / ``node_type_counts`` to hard-coded
    golden values for a known small graph AND assert they equal what
    ``UnifiedGraph.stats()`` derives, so any future drift is caught.
    """
    g = _sample_graph("s1")

    db = tmp_path / "golden.db"
    with gs.open_graph_db(db) as conn:
        gs.save_graph_streaming(
            conn,
            scan_id="s1",
            tenant_id="acme",
            created_at=g.created_at,
            nodes=iter(g.nodes.values()),
            edges=iter(g.edges),
            attack_paths=iter(g.attack_paths),
            interaction_risks=iter(g.interaction_risks),
        )
        row = conn.execute(
            "SELECT node_count, edge_count, risk_summary, node_type_counts FROM graph_snapshots WHERE tenant_id=? AND scan_id=?",
            ("acme", "s1"),
        ).fetchone()

    node_count, edge_count = row["node_count"], row["edge_count"]
    risk_summary = json.loads(row["risk_summary"])
    node_type_counts = json.loads(row["node_type_counts"])

    # Golden values — pkg:p has no severity so it is absent from risk_summary
    # (mirrors stats(): severity_counts only counts truthy severities).
    assert node_count == 4
    assert edge_count == 3
    assert risk_summary == {"high": 1, "medium": 1, "critical": 1}
    assert node_type_counts == {"agent": 1, "server": 1, "package": 1, "vulnerability": 1}

    # And they must match UnifiedGraph.stats() exactly, not just each other.
    stats = g.stats()
    assert node_count == stats["total_nodes"]
    assert edge_count == stats["total_edges"]
    assert risk_summary == stats["severity_counts"]
    assert node_type_counts == stats["node_types"]


def test_streaming_stats_count_yields_documented_precondition(tmp_path) -> None:
    """Snapshot stat counters count *yields*; callers must pre-deduplicate.

    ``save_graph_streaming`` accumulates ``node_count`` / ``edge_count`` /
    severity / type breakdowns per yielded item — it does NOT hold a seen-set
    (that would reintroduce the O(n) memory the streaming path exists to avoid).
    Persisted *rows* still dedupe via ``INSERT OR REPLACE`` on the PK, but the
    stat counters would over-count a producer that yields duplicate ids/keys.
    ``UnifiedGraph`` already guarantees this dedup for the ``save_graph`` caller;
    this test pins the contract so a future lazy producer is not silently
    assumed to be safe.
    """
    dup_nodes = [
        UnifiedNode(id="n1", entity_type=EntityType.PACKAGE, label="n1", severity="high"),
        UnifiedNode(id="n1", entity_type=EntityType.PACKAGE, label="n1-dup", severity="high"),
        UnifiedNode(id="n2", entity_type=EntityType.PACKAGE, label="n2"),
    ]
    dup_edges = [
        UnifiedEdge(source="n1", target="n2", relationship=RelationshipType.DEPENDS_ON),
        UnifiedEdge(source="n1", target="n2", relationship=RelationshipType.DEPENDS_ON),
    ]

    db = tmp_path / "precond.db"
    with gs.open_graph_db(db) as conn:
        gs.save_graph_streaming(
            conn,
            scan_id="s1",
            tenant_id="acme",
            nodes=iter(dup_nodes),
            edges=iter(dup_edges),
        )
        persisted_nodes = conn.execute("SELECT COUNT(*) FROM graph_nodes WHERE tenant_id='acme' AND scan_id='s1'").fetchone()[0]
        persisted_edges = conn.execute("SELECT COUNT(*) FROM graph_edges WHERE tenant_id='acme' AND scan_id='s1'").fetchone()[0]
        snap = conn.execute("SELECT node_count, edge_count FROM graph_snapshots WHERE tenant_id='acme' AND scan_id='s1'").fetchone()

    # Rows physically dedupe on the PK …
    assert persisted_nodes == 2
    assert persisted_edges == 1
    # … but the stat counters count yields — the documented precondition is that
    # callers pass already-deduplicated iterables (as UnifiedGraph guarantees).
    assert snap["node_count"] == 3
    assert snap["edge_count"] == 2


def test_streaming_replaces_same_scan_without_stale_rows(tmp_path) -> None:
    """Retrying one scan id replaces, rather than merges, its snapshot."""
    db = tmp_path / "same-scan-retry.db"
    with gs.open_graph_db(db) as conn:
        gs.save_graph_streaming(
            conn,
            scan_id="scan-retry",
            tenant_id="acme",
            nodes=iter(
                [
                    UnifiedNode(id="keep", entity_type=EntityType.PACKAGE, label="keep"),
                    UnifiedNode(id="stale", entity_type=EntityType.PACKAGE, label="stale"),
                ]
            ),
            edges=iter([UnifiedEdge(source="keep", target="stale", relationship=RelationshipType.DEPENDS_ON)]),
        )
        gs.save_graph_streaming(
            conn,
            scan_id="scan-retry",
            tenant_id="acme",
            nodes=iter([UnifiedNode(id="keep", entity_type=EntityType.PACKAGE, label="updated")]),
            edges=iter(()),
        )

        node_ids = {
            row[0]
            for row in conn.execute(
                "SELECT id FROM graph_nodes WHERE tenant_id = ? AND scan_id = ?",
                ("acme", "scan-retry"),
            )
        }
        edge_count = conn.execute(
            "SELECT COUNT(*) FROM graph_edges WHERE tenant_id = ? AND scan_id = ?",
            ("acme", "scan-retry"),
        ).fetchone()[0]
        snapshot = conn.execute(
            "SELECT node_count, edge_count FROM graph_snapshots WHERE tenant_id = ? AND scan_id = ?",
            ("acme", "scan-retry"),
        ).fetchone()

    assert node_ids == {"keep"}
    assert edge_count == 0
    assert tuple(snapshot) == (1, 0)


def test_iter_graph_edges_dangling_edge_matches_documented_contract(tmp_path) -> None:
    """``iter_graph_edges`` vs ``load_graph`` dangling-edge handling is pinned.

    ``load_graph`` reconstructs a consistent graph and always drops an edge whose
    endpoints are not both in the node set. ``iter_graph_edges`` is a raw
    snapshot read: with ``node_ids=None`` it yields every persisted edge; passing
    ``node_ids`` reproduces ``load_graph``'s endpoint filter. Pin both so they
    cannot silently diverge.
    """
    db = tmp_path / "dangling.db"
    with gs.open_graph_db(db) as conn:
        g = UnifiedGraph(scan_id="s1", tenant_id="acme")
        g.add_node(UnifiedNode(id="a", entity_type=EntityType.PACKAGE, label="a"))
        g.add_node(UnifiedNode(id="b", entity_type=EntityType.PACKAGE, label="b"))
        g.add_edge(UnifiedEdge(source="a", target="b", relationship=RelationshipType.DEPENDS_ON))
        gs.save_graph(conn, g)
        # Inject a dangling edge whose target node "ghost" is not persisted.
        now = g.created_at or "2026-01-01T00:00:00+00:00"
        conn.execute(
            """
            INSERT INTO graph_edges
                (source_id, target_id, relationship, first_seen, last_seen, scan_id, tenant_id)
            VALUES ('a', 'ghost', 'depends_on', ?, ?, 's1', 'acme')
            """,
            (now, now),
        )
        conn.commit()

        loaded = gs.load_graph(conn, tenant_id="acme", scan_id="s1")
        all_edges = list(gs.iter_graph_edges(conn, tenant_id="acme", scan_id="s1"))
        filtered = list(gs.iter_graph_edges(conn, tenant_id="acme", scan_id="s1", node_ids=set(loaded.nodes)))

    loaded_keys = {(e.source, e.target) for e in loaded.edges}
    all_keys = {(e.source, e.target) for e in all_edges}
    filtered_keys = {(e.source, e.target) for e in filtered}

    # load_graph drops the dangling edge …
    assert ("a", "ghost") not in loaded_keys
    assert ("a", "b") in loaded_keys
    # … iter_graph_edges (raw, node_ids=None) yields it …
    assert ("a", "ghost") in all_keys
    assert ("a", "b") in all_keys
    # … and passing node_ids reproduces load_graph's endpoint filter exactly.
    assert filtered_keys == loaded_keys


# ── Memory: a streaming producer must stay flat as N grows ────────────────────

# Node/edge counts for the memory-shape assertion. Kept modest so the subprocess
# runs stay fast under the CI test matrix (no `slow` marker), while still large
# enough that the full-graph path's Python heap dwarfs the streaming path's.
_MEM_N_SMALL = 40_000
_MEM_N_LARGE = 120_000

# Measure the PYTHON HEAP peak with ``tracemalloc``, not whole-process RSS.
#
# An earlier version compared ``resource.getrusage().ru_maxrss`` across the two
# modes. That is unreliable: ``ru_maxrss`` is a whole-process high-water mark and
# is dominated by the fixed ~1 GB cost of importing ``agent_bom`` and its deps —
# which is identical in both modes and swamps the graph's own footprint, so the
# streamed and full paths report the *same* peak and the shape signal vanishes
# (it also carries the bytes-vs-KB unit split and musl allocator accounting
# differences across platforms). ``tracemalloc`` is started AFTER imports and
# measures only Python-object allocations during the save — exactly the per-node
# retention the streaming path is designed to bound — so it is deterministic and
# platform-independent (no ru_maxrss units, no glibc/musl allocator variance).
_MEM_SCRIPT = textwrap.dedent(
    """
    import os, sys, tempfile, tracemalloc
    from agent_bom.db import graph_store as gs
    from agent_bom.graph.container import UnifiedGraph
    from agent_bom.graph.node import UnifiedNode
    from agent_bom.graph.edge import UnifiedEdge
    from agent_bom.graph.types import EntityType, RelationshipType

    N = int(sys.argv[1]); mode = sys.argv[2]
    db = os.path.join(tempfile.mkdtemp(), "g.db")

    def mk_node(i):
        return UnifiedNode(id="n%d" % i, entity_type=EntityType.PACKAGE, label="pkg-%d" % i,
                           severity="high" if i % 5 == 0 else "low", risk_score=float(i % 10))
    def mk_edge(i):
        return UnifiedEdge(source="n%d" % i, target="n%d" % ((i + 1) % N), relationship=RelationshipType.DEPENDS_ON)

    # Start tracing only around the work so the import baseline is excluded.
    tracemalloc.start()
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
    _, peak = tracemalloc.get_traced_memory()
    print(peak / 1024 / 1024)
    """
)


def _peak_pymem_mb(n: int, mode: str) -> float:
    env = dict(os.environ)
    # Ensure the subprocess imports the same in-tree agent_bom this test does,
    # not a stale site-packages copy.
    env["PYTHONPATH"] = os.pathsep.join(p for p in sys.path if p) + os.pathsep + env.get("PYTHONPATH", "")
    out = subprocess.check_output([sys.executable, "-c", _MEM_SCRIPT, str(n), mode], text=True, env=env)
    return float(out.strip().splitlines()[-1])


def test_streaming_persist_peak_python_heap_is_bounded() -> None:
    """Streaming persist keeps its Python heap ~flat while the full-graph path scales with N.

    The streaming path flushes nodes/edges to SQLite in bounded batches and never
    materialises the whole graph, so its peak Python-object footprint is decoupled
    from N. The full-graph path holds every node/edge in RAM, so its heap grows
    linearly with N. Assert on that SHAPE (streaming flat, and far below the full
    path) with generous margins rather than a machine-specific absolute MB.
    """
    stream_small = _peak_pymem_mb(_MEM_N_SMALL, "stream")
    stream_large = _peak_pymem_mb(_MEM_N_LARGE, "stream")

    # Streaming growth from N_SMALL -> N_LARGE (3x the data) must stay well under
    # 1.5x: the peak is a bounded write batch, not the graph size.
    assert stream_large < stream_small * 1.5, f"streaming heap grew with N: {stream_small:.1f} -> {stream_large:.1f} MB"

    # And it must be a large win vs building the whole graph in RAM at the same N:
    # the full path retains every node/edge, so its heap is orders of magnitude larger.
    full_large = _peak_pymem_mb(_MEM_N_LARGE, "full")
    assert stream_large < full_large * 0.5, f"streaming ({stream_large:.1f}MB) not < half of full ({full_large:.1f}MB)"
