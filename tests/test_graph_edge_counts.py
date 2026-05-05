"""Guard B — edge-count regression baseline (#2259).

Builds the context graph from the recorded self-scan fixture and asserts each
edge kind's count is within ±``tolerance_pct`` of the baseline at
``tests/fixtures/graph_edge_counts.json``.

When the upstream graph builder *intentionally* changes edge emission, run::

    python scripts/rebaseline_graph_edges.py

…and check the regenerated baseline into the same PR.

The synthetic fixture is verified with exact (not tolerance-windowed)
expectations because it's deterministically constructed in test code — any
drift there is a real bug, not a corpus drift.
"""

from __future__ import annotations

import json

import pytest

from tests._graph_helpers import (
    EDGE_COUNTS_FIXTURE,
    build_graph_from_inventory,
    edge_counts_by_kind,
    load_self_scan_fixture,
    node_counts_by_kind,
    synthetic_inventory,
)

REBASELINE_HINT = "If this drift is intentional, re-baseline with:\n    python scripts/rebaseline_graph_edges.py"


def _within_tolerance(actual: int, baseline: int, tolerance_pct: float) -> bool:
    """±``tolerance_pct`` around baseline, with a ±1 floor for small counts."""
    if baseline == 0:
        return actual == 0
    delta_allowed = max(1, int(round(baseline * (tolerance_pct / 100.0))))
    return abs(actual - baseline) <= delta_allowed


@pytest.fixture(scope="module")
def baseline() -> dict:
    return json.loads(EDGE_COUNTS_FIXTURE.read_text())


@pytest.fixture(scope="module")
def actual_counts() -> dict:
    inv = load_self_scan_fixture()
    graph = build_graph_from_inventory(inv)
    return {
        "edge_counts": edge_counts_by_kind(graph),
        "node_counts": node_counts_by_kind(graph),
    }


class TestEdgeCountBaseline:
    def test_no_kind_dropped(self, baseline: dict, actual_counts: dict) -> None:
        """Every kind in the baseline must still be emitted."""
        baseline_kinds = set(baseline["edge_counts"].keys())
        actual_kinds = set(actual_counts["edge_counts"].keys())
        missing = baseline_kinds - actual_kinds
        assert not missing, f"Edge kinds disappeared from graph build: {sorted(missing)}\n{REBASELINE_HINT}"

    def test_no_unexpected_kind_appeared(self, baseline: dict, actual_counts: dict) -> None:
        """Surface new edge kinds so they're recorded explicitly, not silently."""
        baseline_kinds = set(baseline["edge_counts"].keys())
        actual_kinds = set(actual_counts["edge_counts"].keys())
        unexpected = actual_kinds - baseline_kinds
        assert not unexpected, f"New edge kinds emitted but not baselined: {sorted(unexpected)}\n{REBASELINE_HINT}"

    def test_edge_counts_within_tolerance(self, baseline: dict, actual_counts: dict) -> None:
        tol = baseline["_meta"]["tolerance_pct"]
        drifted = []
        for kind, expected in baseline["edge_counts"].items():
            got = actual_counts["edge_counts"].get(kind, 0)
            if not _within_tolerance(got, expected, tol):
                drifted.append(f"{kind}: expected {expected} ±{tol}%, got {got}")
        assert not drifted, "Edge-count regression on self-scan fixture:\n  - " + "\n  - ".join(drifted) + f"\n{REBASELINE_HINT}"

    def test_node_counts_within_tolerance(self, baseline: dict, actual_counts: dict) -> None:
        tol = baseline["_meta"]["tolerance_pct"]
        drifted = []
        for kind, expected in baseline["node_counts"].items():
            got = actual_counts["node_counts"].get(kind, 0)
            if not _within_tolerance(got, expected, tol):
                drifted.append(f"{kind}: expected {expected} ±{tol}%, got {got}")
        assert not drifted, "Node-count regression on self-scan fixture:\n  - " + "\n  - ".join(drifted) + f"\n{REBASELINE_HINT}"


class TestSyntheticEdgeCounts:
    """Exact-count assertions on the synthetic fixture (no corpus drift here)."""

    @pytest.fixture(scope="class")
    def graph(self):
        return build_graph_from_inventory(synthetic_inventory())

    def test_synthetic_emits_all_expected_edge_kinds(self, graph) -> None:
        counts = edge_counts_by_kind(graph)
        required = {
            "uses",
            "exposes",
            "provides",
            "vulnerable_to",
            "shares_server",
            "shares_credential",
            "attached_to",
        }
        missing = required - set(counts.keys())
        assert not missing, f"Synthetic fixture failed to exercise edge kinds: {sorted(missing)}"

    def test_synthetic_shares_server_count(self, graph) -> None:
        counts = edge_counts_by_kind(graph)
        # agent-a and agent-b both use ``filesystem`` → exactly one SHARES_SERVER edge.
        assert counts["shares_server"] == 1

    def test_synthetic_shares_credential_count(self, graph) -> None:
        counts = edge_counts_by_kind(graph)
        # GITHUB_TOKEN is exposed by both agent-a and agent-b → exactly one
        # SHARES_CREDENTIAL edge.
        assert counts["shares_credential"] == 1

    def test_synthetic_attached_to_count(self, graph) -> None:
        counts = edge_counts_by_kind(graph)
        # Only agent-a has a cloud_principal.
        assert counts["attached_to"] == 1
