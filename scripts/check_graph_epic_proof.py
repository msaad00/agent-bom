#!/usr/bin/env python3
"""Pure checks for the #2254 graph epic closure proof.

This script intentionally does not require a browser, backend, GitHub token, or
network access. It verifies that the closure document points at checked-in proof
surfaces and that the deterministic graph/effective-reach fixtures still carry
the values claimed by the proof.
"""

from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PROOF = ROOT / "docs" / "graph" / "SECURITY_GRAPH_EPIC_PROOF.md"
EDGE_COUNTS = ROOT / "tests" / "fixtures" / "graph_edge_counts.json"
GRAPH_SNAPSHOT = ROOT / "tests" / "fixtures" / "graph-snapshots" / "security-graph.json"
EFFECTIVE_REACH = ROOT / "tests" / "fixtures" / "effective_reach_snapshots.json"

REQUIRED_FILES = [
    PROOF,
    ROOT / "docs" / "graph" / "CONTRACT.md",
    ROOT / "src" / "agent_bom" / "graph" / "types.py",
    ROOT / "src" / "agent_bom" / "effective_reach.py",
    ROOT / "src" / "agent_bom" / "evidence" / "policy.py",
    ROOT / "ui" / "lib" / "graph-schema.generated.ts",
    ROOT / "ui" / "lib" / "use-graph-layout.ts",
    ROOT / "ui" / "lib" / "filter-algebra.ts",
    ROOT / "ui" / "lib" / "lod-renderer.ts",
    ROOT / "ui" / "components" / "lineage-nodes.tsx",
    ROOT / "tests" / "test_graph_schema_ui_parity.py",
    ROOT / "tests" / "test_graph_edge_counts.py",
    ROOT / "tests" / "test_graph_visual_snapshot.py",
    ROOT / "tests" / "test_evidence_policy.py",
    ROOT / "tests" / "test_effective_reach.py",
    ROOT / "ui" / "tests" / "use-graph-layout.test.tsx",
    ROOT / "ui" / "tests" / "lod-renderer.test.ts",
    ROOT / "ui" / "tests" / "filter-algebra.test.ts",
]


def _load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _assert(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def check_required_files() -> None:
    missing = [str(path.relative_to(ROOT)) for path in REQUIRED_FILES if not path.exists()]
    _assert(not missing, "Missing graph proof surfaces: " + ", ".join(missing))


def check_proof_doc() -> None:
    text = PROOF.read_text(encoding="utf-8")
    for issue in range(2254, 2263):
        _assert(f"#{issue}" in text, f"Proof doc must reference #{issue}")
    for phrase in (
        "Schema codegen",
        "Layouts",
        "LOD, aggregation, and focus",
        "Filter algebra",
        "Accuracy guards",
        "Two-bucket evidence",
        "Effective reach",
        "Layout dispatcher",
        "Honest limits",
        "Closes #2254",
    ):
        _assert(phrase in text, f"Proof doc missing section/phrase: {phrase}")


def check_graph_fixtures() -> None:
    edge_counts = _load_json(EDGE_COUNTS)
    snapshot = _load_json(GRAPH_SNAPSHOT)

    _assert(edge_counts["_meta"]["tolerance_pct"] == 5, "Edge-count tolerance must stay at 5%")
    _assert(snapshot["schema"] == "agent-bom.graph-snapshot/v1", "Unexpected graph snapshot schema")
    _assert(snapshot["node_count"] == 11, "Proof doc expects 11 snapshot nodes")
    _assert(snapshot["edge_count"] == 10, "Proof doc expects 10 snapshot edges")
    _assert(snapshot["node_kind_counts"] == edge_counts["node_counts"], "Node kind counts drifted from edge baseline")
    _assert(snapshot["edge_kind_counts"] == edge_counts["edge_counts"], "Edge kind counts drifted from edge baseline")


def check_effective_reach_fixture() -> None:
    reach = _load_json(EFFECTIVE_REACH)
    low = reach["low_reach"]
    high = reach["high_reach"]

    _assert(low["band"] == "green", "Low-reach fixture must stay green")
    _assert(low["composite"] == 27.4, "Low-reach composite drifted")
    _assert(low["reachable_tools"] == ["search_documents"], "Low-reach tool set drifted")
    _assert(high["band"] == "pulsing-red", "High-reach fixture must stay pulsing-red")
    _assert(high["composite"] == 100.0, "High-reach composite drifted")
    _assert(high["agent_breadth"] == 2, "High-reach breadth drifted")
    _assert("run_shell" in high["reachable_tools"], "High-reach fixture must include run_shell")
    _assert("AWS_ACCESS_KEY_ID" in high["reachable_creds"], "High-reach fixture must include AWS visibility")


def main() -> None:
    check_required_files()
    check_proof_doc()
    check_graph_fixtures()
    check_effective_reach_fixture()
    print("graph epic proof checks passed")


if __name__ == "__main__":
    main()
