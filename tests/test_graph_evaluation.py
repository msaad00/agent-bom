from __future__ import annotations

import json
from pathlib import Path

import pytest

from agent_bom.graph.evaluation import evaluate_graph, graph_score_grade, load_expected_graph_spec


def _actual_graph() -> dict:
    return {
        "nodes": [
            {"id": "provider:local", "kind": "provider", "label": "local"},
            {"id": "agent:claude", "kind": "agent", "label": "Claude Desktop"},
            {"id": "server:claude/filesystem", "kind": "server", "label": "filesystem"},
            {"id": "pkg:npm/next@16.2.6", "kind": "pkg_vuln", "label": "next@16.2.6"},
            {"id": "cve:CVE-2026-21441", "kind": "cve", "label": "CVE-2026-21441"},
        ],
        "edges": [
            {"source": "provider:local", "target": "agent:claude", "kind": "hosts"},
            {"source": "agent:claude", "target": "server:claude/filesystem", "kind": "uses"},
            {
                "source": "server:claude/filesystem",
                "target": "pkg:npm/next@16.2.6",
                "kind": "depends_on",
                "evidence": {"version_source": "lockfile"},
            },
            {"source": "pkg:npm/next@16.2.6", "target": "cve:CVE-2026-21441", "kind": "affects"},
        ],
        "attack_paths": [
            {
                "hops": [
                    "agent:claude",
                    "server:claude/filesystem",
                    "pkg:npm/next@16.2.6",
                    "cve:CVE-2026-21441",
                ]
            }
        ],
    }


def test_evaluate_graph_scores_expected_nodes_edges_and_paths() -> None:
    expected = {
        "name": "demo-blast-radius",
        "expected_nodes": [
            "agent:claude",
            {"id": "server:claude/filesystem", "kind": "server"},
            "pkg:npm/next@16.2.6",
            "cve:CVE-2026-21441",
        ],
        "expected_edges": [
            {"source": "agent:claude", "target": "server:claude/filesystem", "relationship": "uses"},
            ["server:claude/filesystem", "pkg:npm/next@16.2.6", "depends_on"],
            {"source": "pkg:npm/next@16.2.6", "target": "cve:CVE-2026-21441", "kind": "affects"},
        ],
        "expected_paths": [
            {
                "hops": [
                    "agent:claude",
                    "server:claude/filesystem",
                    "pkg:npm/next@16.2.6",
                    "cve:CVE-2026-21441",
                ]
            }
        ],
    }

    result = evaluate_graph(_actual_graph(), expected)
    payload = result.to_dict()

    assert result.overall_score > 0.85
    assert payload["grade"] == "excellent"
    assert payload["scores"]["nodes"]["matched"] == 4
    assert payload["scores"]["edges"]["matched"] == 3
    assert payload["scores"]["paths"]["matched"] == 1
    assert payload["evidence"]["edge_evidence_count"] == 1
    assert payload["readability"]["relationship_type_count"] == 4


def test_evaluate_graph_reports_missing_expected_relationships() -> None:
    expected = {
        "expected_nodes": ["agent:claude", "agent:missing"],
        "expected_edges": [
            {"source": "agent:claude", "target": "server:claude/filesystem", "relationship": "uses"},
            {"source": "agent:missing", "target": "server:claude/filesystem", "relationship": "uses"},
        ],
        "expected_paths": [],
    }

    result = evaluate_graph(_actual_graph(), expected)
    payload = result.to_dict()

    assert result.overall_score < 0.85
    assert "agent:missing" in payload["scores"]["nodes"]["missing"]
    assert ("agent:missing", "server:claude/filesystem", "uses") in result.edges.missing
    assert payload["summary"]["missing_total"] == 2


def test_load_expected_graph_spec_rejects_non_object(tmp_path: Path) -> None:
    spec = tmp_path / "expected.json"
    spec.write_text(json.dumps(["not", "an", "object"]))

    with pytest.raises(ValueError, match="must be a JSON object"):
        load_expected_graph_spec(spec)


def test_graph_score_grade_boundaries() -> None:
    assert graph_score_grade(0.96) == "excellent"
    assert graph_score_grade(0.86) == "strong"
    assert graph_score_grade(0.71) == "usable"
    assert graph_score_grade(0.51) == "weak"
    assert graph_score_grade(0.49) == "failing"
