"""Guard C — visual-diff snapshot of the security graph (#2259).

Approach taken: Option 1 (Python-only, payload-level snapshot).

Rationale
---------

The original ticket suggested either a deterministic SVG diff via Cytoscape
+ ``pixelmatch`` or a Playwright screenshot of ``/mesh``, ``/graph``, and
``/lineage-graph``.  Both options are heavier than this guard needs:

- ``--format graph-html`` writes an HTML file that ships a Cytoscape force
  layout.  That layout is *not* deterministic across runs — it relies on a
  random seed inside Cytoscape — so a literal SVG/PNG diff would either be
  flaky or require pinning third-party JS.
- The Playwright path needs the full UI stack (Postgres-backed dashboard,
  Next.js boot, Playwright browsers in CI).  Heavy for catching graph-data
  regressions.

Instead, we snapshot the *graph payload* (nodes + edges + kinds + labels)
that flows into the renderer.  This catches every regression a visual diff
would catch *for graph data* (dropped nodes, dropped edges, renamed kinds,
swapped labels).  Pure layout regressions are explicitly out of scope for
this Python-only guard — those are tracked as a Playwright follow-up
(option 2 in the ticket).

Snapshot location: ``tests/fixtures/graph-snapshots/security-graph.json``
Re-baseline with: ``python scripts/rebaseline_graph_edges.py``
"""

from __future__ import annotations

import json

import pytest

from tests._graph_helpers import (
    GRAPH_SNAPSHOT_FIXTURE,
    build_graph_from_inventory,
    graph_visual_snapshot,
    load_self_scan_fixture,
)

REBASELINE_HINT = "If the snapshot drift is intentional, re-baseline with:\n    python scripts/rebaseline_graph_edges.py"


@pytest.fixture(scope="module")
def baseline_snapshot() -> dict:
    return json.loads(GRAPH_SNAPSHOT_FIXTURE.read_text())


@pytest.fixture(scope="module")
def actual_snapshot() -> dict:
    inv = load_self_scan_fixture()
    graph = build_graph_from_inventory(inv)
    return graph_visual_snapshot(graph)


def test_snapshot_schema_pinned(baseline_snapshot: dict) -> None:
    assert baseline_snapshot["schema"] == "agent-bom.graph-snapshot/v1"


def test_node_count_matches(baseline_snapshot: dict, actual_snapshot: dict) -> None:
    assert actual_snapshot["node_count"] == baseline_snapshot["node_count"], (
        f"Graph node count drifted: baseline {baseline_snapshot['node_count']} → actual {actual_snapshot['node_count']}\n{REBASELINE_HINT}"
    )


def test_edge_count_matches(baseline_snapshot: dict, actual_snapshot: dict) -> None:
    assert actual_snapshot["edge_count"] == baseline_snapshot["edge_count"], (
        f"Graph edge count drifted: baseline {baseline_snapshot['edge_count']} → actual {actual_snapshot['edge_count']}\n{REBASELINE_HINT}"
    )


def test_node_ids_match(baseline_snapshot: dict, actual_snapshot: dict) -> None:
    baseline_ids = {n["id"] for n in baseline_snapshot["nodes"]}
    actual_ids = {n["id"] for n in actual_snapshot["nodes"]}
    missing = baseline_ids - actual_ids
    extra = actual_ids - baseline_ids
    msg_parts = []
    if missing:
        msg_parts.append(f"removed: {sorted(missing)}")
    if extra:
        msg_parts.append(f"added: {sorted(extra)}")
    assert not msg_parts, "Visual snapshot node IDs drifted (" + "; ".join(msg_parts) + f")\n{REBASELINE_HINT}"


def test_edge_triples_match(baseline_snapshot: dict, actual_snapshot: dict) -> None:
    def _triples(snap: dict) -> set[tuple[str, str, str]]:
        return {(e["source"], e["target"], e["kind"]) for e in snap["edges"]}

    baseline = _triples(baseline_snapshot)
    actual = _triples(actual_snapshot)
    missing = baseline - actual
    extra = actual - baseline
    msg_parts = []
    if missing:
        msg_parts.append(f"removed: {sorted(missing)[:5]}")
    if extra:
        msg_parts.append(f"added: {sorted(extra)[:5]}")
    assert not msg_parts, "Visual snapshot edge triples drifted (" + "; ".join(msg_parts) + f")\n{REBASELINE_HINT}"


def test_node_kind_distribution_stable(baseline_snapshot: dict, actual_snapshot: dict) -> None:
    assert actual_snapshot["node_kind_counts"] == baseline_snapshot["node_kind_counts"], (
        f"Node kind distribution drifted: baseline {baseline_snapshot['node_kind_counts']} → "
        f"actual {actual_snapshot['node_kind_counts']}\n{REBASELINE_HINT}"
    )


def test_edge_kind_distribution_stable(baseline_snapshot: dict, actual_snapshot: dict) -> None:
    assert actual_snapshot["edge_kind_counts"] == baseline_snapshot["edge_kind_counts"], (
        f"Edge kind distribution drifted: baseline {baseline_snapshot['edge_kind_counts']} → "
        f"actual {actual_snapshot['edge_kind_counts']}\n{REBASELINE_HINT}"
    )
