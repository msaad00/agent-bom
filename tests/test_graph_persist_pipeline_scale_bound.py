"""Production persist path adds no second O(N) copy of a *large new* snapshot (#4055/#4075).

The existing production-path guard
(``test_graph_persist_memory_bound.test_production_persist_path_does_not_materialise_full_prior_graph``)
pins the *prior* side: a large previous snapshot is digested, not re-materialised.
It exercises only a 20-node **new** snapshot, so it cannot catch a regression that
re-materialises the **incoming** snapshot during the streamed save + the SQLite
search-index refresh — exactly the O(N) second materialisation removed in PR-2 of
#4075 (the ``_refresh_snapshot_search_index`` ``fetchall`` rebuild).

This test drives the shipped pipeline entrypoint ``_persist_graph_snapshot`` with a
**scaled** new snapshot and asserts the persist leg's own allocation stays a small
fraction of a full second copy of that snapshot, and that the fraction does not
erode as the new snapshot grows 4x. The prior snapshot is kept small so this
isolates the *incoming-snapshot write path* (streamed save + search-index refresh
+ delta), not the already-covered prior-digest bound.

Scope note (honesty): this bounds the **persist** leg. The graph *producer*
(``build_unified_graph_from_report``) still materialises the whole correlated
graph plus its adjacency / dedup indexes before persist — that residual peak-RSS
wall is the builder re-plumb tracked by #4075 (PR-3/4) and is deliberately
*outside* this test's boundary. The builder is monkeypatched to return an
already-resident graph so the measurement captures the persist leg only.
"""

from __future__ import annotations

import tracemalloc
from pathlib import Path
from types import SimpleNamespace

from agent_bom.api.graph_store import SQLiteGraphStore
from agent_bom.graph import RelationshipType, UnifiedEdge
from agent_bom.graph.container import UnifiedGraph
from agent_bom.graph.node import UnifiedNode
from agent_bom.graph.types import EntityType, NodeStatus

# A 4x span, both well above the write batch window so the ratio reflects the
# true bounded fraction (batch buffer + prior-id digest) rather than batch noise.
_N_SMALL = 3000
_N_LARGE = 12000
# Force a small write batch so the bounded batch window is a small slice of N even
# at _N_SMALL — otherwise the default 1000-row batch is ~N/3 and swamps the signal.
_BATCH = "256"


def _synthetic_graph(scan: str, n: int) -> UnifiedGraph:
    g = UnifiedGraph(scan_id=scan, tenant_id="t1")
    for i in range(n):
        g.add_node(
            UnifiedNode(
                id=f"n:{i}",
                entity_type=EntityType.AGENT if i % 50 == 0 else EntityType.VULNERABILITY,
                label=f"label-{i}",
                severity="high" if i % 3 else "critical",
                risk_score=float(i % 10),
                status=NodeStatus.ACTIVE,
                compliance_tags=["cis-1.1", "soc2"],
                data_sources=["mcp-scan"],
                attributes={"cvss_score": 7.0, "blob": "v" * 64, "purl": f"pkg:pypi/x-{i}@1.0"},
            )
        )
    for i in range(0, n - 1, 2):
        g.add_edge(UnifiedEdge(source=f"n:{i}", target=f"n:{i + 1}", relationship=RelationshipType.DEPENDS_ON))
    return g


def _persist_peak(tmp_path: Path, monkeypatch, n: int) -> int:
    """Peak Python-heap allocated *during* the shipped persist of an N-node snapshot.

    The new graph and the prior snapshot are materialised BEFORE ``tracemalloc.start``
    — so the measured peak reflects only what the persist leg itself allocates, not
    the resident producer graph (that is the residual builder wall, out of scope).
    """
    import agent_bom.api.pipeline as pipeline
    import agent_bom.graph.builder as builder

    store = SQLiteGraphStore(tmp_path / f"pipe-{n}.db")
    # A same-size prior snapshot with the same node ids so this mirrors a real
    # steady-state re-scan: the digest+delta path runs but the delta is bounded (few
    # changed nodes), not the pathological all-new case. What remains O(N)-shaped in
    # the persist is only the streamed write of the incoming snapshot + the bounded
    # prior-id digest — which this test pins as a small fraction of a full copy.
    store.save_graph(_synthetic_graph("scan-prior", n))

    new = _synthetic_graph("scan-new", n)
    monkeypatch.setattr(pipeline, "_get_graph_store", lambda: store)
    monkeypatch.setattr(builder, "build_unified_graph_from_report", lambda report_json, scan_id, tenant_id: new)

    job = SimpleNamespace(job_id="scan-new", tenant_id="t1", progress=[])

    tracemalloc.start()
    pipeline._persist_graph_snapshot(job, {"scan_id": "scan-new"})
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    # Confirm the scaled snapshot actually persisted (the write path really ran).
    # Load it back explicitly rather than via ``latest_snapshot_id`` — the prior and
    # new snapshots share a same-second ``created_at``, so the newest-first ordering
    # would tie-break on ``scan_id`` rather than prove the new snapshot exists.
    persisted = store.load_graph(tenant_id="t1", scan_id="scan-new")
    assert len(persisted.nodes) == n
    return peak


def _full_copy_peak(n: int) -> int:
    """Peak of building one full N-node graph — the cost of a single second copy."""
    tracemalloc.start()
    g = _synthetic_graph("scan-copy", n)
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    assert len(g.nodes) == n
    return peak


def test_persist_of_large_new_snapshot_adds_no_second_full_copy(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("AGENT_BOM_GRAPH_WRITE_BATCH_SIZE", _BATCH)
    # Warm-up: the first ``_persist_graph_snapshot`` call resolves the persist path's
    # lazy imports (builder / delta_digest / webhooks / postgres_store) and first-use
    # SQL caches — one-time allocations that would otherwise be charged to the first
    # measured run. Discard its result.
    _persist_peak(tmp_path, monkeypatch, 400)

    persist_small = _persist_peak(tmp_path, monkeypatch, _N_SMALL)
    persist_large = _persist_peak(tmp_path, monkeypatch, _N_LARGE)
    full_small = _full_copy_peak(_N_SMALL)
    full_large = _full_copy_peak(_N_LARGE)

    ratio_small = persist_small / full_small
    ratio_large = persist_large / full_large

    # The streamed save + search-index refresh + delta stream the incoming snapshot
    # in bounded batches; they never hold a second full copy of it. Measured ~0.12-0.2
    # — guard at 0.5 with margin. A ``fetchall``/full-list regression pushes this
    # toward (or past) 1.0.
    assert ratio_small < 0.5, f"persist peak too close to a full copy at N={_N_SMALL}: {ratio_small:.3f}"
    assert ratio_large < 0.5, f"persist peak too close to a full copy at N={_N_LARGE}: {ratio_large:.3f}"

    # The advantage must not erode as the incoming snapshot grows 4x: if the persist
    # leg secretly scaled with N, the ratio would climb.
    assert ratio_large <= ratio_small * 1.5, (
        f"persist/full-copy ratio eroded with scale: {ratio_small:.3f} -> {ratio_large:.3f}"
    )
