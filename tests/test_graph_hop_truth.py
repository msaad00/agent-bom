"""Negative runtime evidence and advisory signals keep independent meanings."""

from __future__ import annotations

import pytest

from agent_bom.api.graph_store import SQLiteGraphStore
from agent_bom.evidence.semantics import ExploitabilityDimension
from agent_bom.graph import AttackPath, EntityType, RelationshipType, UnifiedEdge, UnifiedGraph, UnifiedNode
from agent_bom.graph.analysis import GraphAnalysisState, GraphAnalysisStatus
from agent_bom.graph.path_evidence import annotate_attack_path_evidence, exposure_evidence_dimensions


def runtime_path(evidence: dict) -> tuple[UnifiedGraph, AttackPath]:
    graph = UnifiedGraph(scan_id="snapshot-a", tenant_id="tenant-a")
    graph.analysis_status["attack_path_fusion"] = GraphAnalysisStatus(status=GraphAnalysisState.COMPLETE)
    graph.add_node(UnifiedNode(id="agent:a", entity_type=EntityType.AGENT, label="assistant"))
    graph.add_node(UnifiedNode(id="resource:a", entity_type=EntityType.RESOURCE, label="synthetic ledger"))
    graph.add_edge(
        UnifiedEdge(
            source="agent:a",
            target="resource:a",
            relationship=RelationshipType.ACCESSED,
            source_scan_id=graph.scan_id,
            provenance={"source": "synthetic-runtime"},
            evidence={"freshness": "fresh", **evidence},
        )
    )
    path = AttackPath(
        source="agent:a", target="resource:a", hops=["agent:a", "resource:a"], edges=["accessed"], reachability="likely", composite_risk=80
    )
    annotate_attack_path_evidence(path, graph)
    graph.attack_paths = [path]
    return graph, path


@pytest.mark.parametrize("negative", [{"blocked": True}, {"decision": "blocked"}, {"decision": "explicit_deny"}])
def test_blocked_observation_cannot_confirm_successful_reach(negative: dict) -> None:
    graph, path = runtime_path({"runtime_observed_state": "observed", **negative})
    assert path.hop_evidence[0]["runtime_observed_state"] == "blocked"
    assert path.reachability == "unknown"
    assert "blocked_runtime_hop" in path.reachability_basis
    assert exposure_evidence_dimensions(path, graph.nodes[path.target])["reachability"]["verdict"] is None


def test_failed_attempts_are_not_a_success_receipt() -> None:
    _, path = runtime_path({"observation_count": 3, "failure_count": 3})
    assert path.hop_evidence[0]["runtime_outcome"] == "failed"
    assert path.reachability == "unknown"
    assert "failed_runtime_outcome" in path.reachability_basis


def test_observed_call_does_not_invent_downstream_outcome() -> None:
    _, path = runtime_path({"decision": "allowed"})
    assert path.hop_evidence[0]["runtime_observed_state"] == "observed"
    assert path.hop_evidence[0].get("runtime_outcome", "unknown") == "unknown"


def test_blocked_legacy_receipt_is_qualified_after_restart(tmp_path) -> None:
    graph, path = runtime_path({"blocked": True})
    # Historical rows can predate the annotator correction.
    path.reachability = "confirmed"
    path.hop_evidence[0]["complete"] = True
    store = SQLiteGraphStore(tmp_path / "evidence.db")
    store.save_graph(graph)
    restored = SQLiteGraphStore(tmp_path / "evidence.db").load_graph(tenant_id="tenant-a", scan_id=graph.scan_id)
    assert restored.attack_paths[0].hop_evidence == path.hop_evidence
    result = exposure_evidence_dimensions(restored.attack_paths[0], restored.nodes[path.target])
    assert result["reachability"]["verdict"] is None
    assert result["completeness"]["reasonCodes"] == ["blocked_runtime_hop"]
    assert not store.load_graph(tenant_id="tenant-b", scan_id=graph.scan_id).nodes


@pytest.mark.parametrize(
    "attributes",
    [
        {"network_exploitable": True},
        {"is_kev": True, "epss_score": 1, "cvss_score": 10},
        {"exploitability": "exploitable"},
        {"exploitability_assessment": {"status": "complete", "verdict": "exploitable", "evidence_refs": []}},
    ],
)
def test_advisory_or_unreferenced_assertion_is_not_assessed_exploitability(attributes: dict) -> None:
    node = UnifiedNode(id="vuln:a", entity_type=EntityType.VULNERABILITY, label="synthetic advisory", attributes=attributes)
    result = exposure_evidence_dimensions(AttackPath(source="agent:a", target=node.id), node)
    assert result["exploitability"]["verdict"] is None
    assert result["exploitability"]["status"] == "unavailable"


def test_referenced_exploitability_assessment_retains_qualifications() -> None:
    assessment = ExploitabilityDimension(
        status="partial", verdict="unknown", evidence_refs=("assessment:1",), reason_codes=("preconditions_not_collected",)
    )
    node = UnifiedNode(
        id="vuln:a",
        entity_type=EntityType.VULNERABILITY,
        label="advisory",
        attributes={"exploitability_assessment": assessment.model_dump(mode="json")},
    )
    result = exposure_evidence_dimensions(AttackPath(source="agent:a", target=node.id), node)["exploitability"]
    assert result["status"] == "partial"
    assert result["verdict"] == "unknown"
    assert result["evidenceRefs"] == ["assessment:1"]
    assert result["reasonCodes"] == ["preconditions_not_collected"]
