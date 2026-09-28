"""Graph input excludes unrelated output while retaining each supported evidence lane."""

import ast
from pathlib import Path

import pytest

from agent_bom.graph.build_input import GraphBuildInput, GraphEvidenceSections
from agent_bom.graph.builder import build_unified_graph


@pytest.mark.parametrize(
    "section", sorted(GraphEvidenceSections.__annotations__.keys() - {"agents", "blast_radius", "blast_radii", "scan_sources", "scan_id"})
)
def test_optional_evidence_sections_preserve_presence_and_reference(section):
    # Do not rewrite absence into an empty block: several overlays distinguish it.
    value = {"source_status": "denied", "observation": "retained"}
    inputs = GraphBuildInput.from_report({section: value, "unrelated_output": "private"})
    assert inputs.report_sections()[section] is value
    assert "unrelated_output" not in inputs.report_sections()
    assert section not in GraphBuildInput.from_report({}).report_sections()


def test_runtime_feedback_and_legacy_blast_radius_survive_adaptation():
    blast = [{"vulnerability_id": "CVE-fixture", "severity": "high"}]
    audit = [{"details": {"agentic_identity_graph": {"nodes": [], "edges": []}}}]
    inputs = GraphBuildInput.from_report({"blast_radii": blast, "audit_events": audit, "runtime_incident_feedback_path": "/fixture.json"})
    assert inputs.blast_radius is blast
    assert inputs.evidence["audit_events"] is audit
    assert inputs.evidence["runtime_incident_feedback_path"] == "/fixture.json"


def test_reusing_input_keeps_build_indexes_and_tenant_containers_separate():
    inputs = GraphBuildInput.from_report({"agents": [{"name": "shared", "mcp_servers": [{"name": "tools", "packages": []}]}]})
    first = build_unified_graph(inputs, scan_id="one", tenant_id="tenant-a")
    second = build_unified_graph(inputs, scan_id="two", tenant_id="tenant-b")
    assert first.tenant_id == "tenant-a" and second.tenant_id == "tenant-b"
    assert first.scan_id == "one" and second.scan_id == "two"
    assert len(first.nodes) == len(second.nodes) and len(first.edges) == len(second.edges)
    first.nodes["agent:shared"].attributes["owner"] = "one-only"
    assert second.nodes["agent:shared"].attributes["owner"] == ""


def test_graph_report_consumers_cannot_silently_add_an_unforwarded_section():
    root = Path(__file__).resolve().parents[1] / "src" / "agent_bom"
    consumers = [
        "graph/builder.py",
        "graph/build_analysis.py",
        "graph/benchmark_projection.py",
        "graph/nhi_overlay.py",
        "graph/evidence_overlay.py",
        "graph/runtime_projection.py",
        "graph/repo_structure_overlay.py",
        "graph/repo_trust_overlay.py",
        "graph/ci_graph_overlay.py",
        "graph/endpoint_overlay.py",
        "graph/aspm_overlay.py",
        "a2a_auth_posture.py",
        "mcp_auth_posture.py",
    ]
    read = set()
    for path in consumers:
        for node in ast.walk(ast.parse((root / path).read_text())):
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr == "get"
                and isinstance(node.func.value, ast.Name)
                and node.func.value.id in {"report_json", "report"}
                and node.args
                and isinstance(node.args[0], ast.Constant)
                and isinstance(node.args[0].value, str)
            ):
                read.add(node.args[0].value)
    assert read <= GraphEvidenceSections.__annotations__.keys()
