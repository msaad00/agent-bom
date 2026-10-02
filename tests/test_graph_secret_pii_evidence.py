"""Secret/PII findings retain identity and file evidence in graph consumers."""

from __future__ import annotations

import json

import pytest

from agent_bom.finding import secret_dict_to_finding
from agent_bom.graph.builder import build_unified_graph_from_report
from agent_bom.graph.correlation import correlation_identity
from agent_bom.graph.types import EntityType, RelationshipType
from agent_bom.output.graph_export import build_graph_from_scan_data, to_json


def _row(category="pii", line=3, path="app/config.yaml"):
    return secret_dict_to_finding(
        {
            "category": category,
            "type": "Email Address" if category == "pii" else "API Key",
            "file": path,
            "line": line,
            "severity": "medium",
            "preview": "DO-NOT-PROJECT-RAW-BYTES",
        }
    ).to_dict()


@pytest.mark.parametrize("category", ["pii", "credential", "secret"])
def test_typed_finding_keeps_identity_and_recorded_file_edge(category):
    row = _row(category)
    graph = build_unified_graph_from_report({"findings": [row]}, scan_id="scan-1", tenant_id="tenant-a")
    nodes = [n for n in graph.nodes.values() if n.attributes.get("finding_id") == row["id"]]
    assert len(nodes) == 1
    node = nodes[0]
    assert node.entity_type == EntityType.MISCONFIGURATION
    assert node.attributes["finding_type"] == row["finding_type"]
    assert node.attributes["line"] == 3
    edges = [e for e in graph.edges if e.source == node.id and e.relationship == RelationshipType.AFFECTS]
    assert len(edges) == 1
    assert graph.nodes[edges[0].target].attributes["path"] == "app/config.yaml"
    assert "DO-NOT-PROJECT-RAW-BYTES" not in json.dumps(graph.to_dict())


def test_graph_export_preserves_both_occurrences_and_file_relationships():
    rows = [_row(line=3), _row(line=4)]
    exported = to_json(build_graph_from_scan_data({"findings": rows}))
    findings = [n for n in exported["nodes"] if n.get("attributes", {}).get("finding_id") in {r["id"] for r in rows}]
    assert len(findings) == 2
    node_ids = {n["id"] for n in exported["nodes"]}
    for node in findings:
        edges = [e for e in exported["edges"] if e["source"] == node["id"] and e["kind"] == "affects"]
        assert len(edges) == 1
        assert edges[0]["target"] in node_ids


def test_same_relative_path_does_not_join_findings_across_snapshots():
    row = _row()
    graph = build_unified_graph_from_report({"findings": [row]}, scan_id="scan-1")
    node = next(n for n in graph.nodes.values() if n.attributes.get("finding_id") == row["id"])
    first = correlation_identity(node, scan_id="scan-1")
    second = correlation_identity(node, scan_id="scan-2")
    assert first != second
    assert first[2] == second[2] == "snapshot_scoped_missing_exact_identity"


def test_absent_file_does_not_invent_an_asset_relationship():
    row = _row(path="")
    graph = build_unified_graph_from_report({"findings": [row]}, scan_id="scan-1")
    node = next(n for n in graph.nodes.values() if n.attributes.get("finding_id") == row["id"])
    assert not [e for e in graph.edges if e.source == node.id and e.relationship == RelationshipType.AFFECTS]


def test_duplicate_rows_dedupe_and_untrusted_preview_is_not_projected():
    row = _row()
    row["evidence"]["redacted_preview"] = "DO-NOT-PROJECT-RAW-BYTES"
    row["evidence"]["secret_value"] = "DO-NOT-PROJECT-RAW-BYTES"
    graph = build_unified_graph_from_report({"findings": [row, row]}, scan_id="scan-1")
    assert len([n for n in graph.nodes.values() if n.attributes.get("finding_id") == row["id"]]) == 1
    assert "DO-NOT-PROJECT-RAW-BYTES" not in json.dumps(graph.to_dict())


@pytest.mark.parametrize("rows", [None, {}, [None, {}], [{"id": "untyped", "source": "SECRET_SCAN"}]])
def test_malformed_or_untyped_rows_do_not_create_findings(rows):
    from agent_bom.graph.container import UnifiedGraph
    from agent_bom.graph.finding_projection import project_secret_findings

    graph = UnifiedGraph()
    project_secret_findings(graph, rows)
    assert not graph.nodes
