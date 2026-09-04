"""Mechanical correlation contracts: path coexistence and evidence truth."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from agent_bom.api.graph_store import SQLiteGraphStore
from agent_bom.api.routes.graph import _derived_attack_paths
from agent_bom.graph.analysis import GraphAnalysisState, GraphAnalysisStatus
from agent_bom.graph.attack_path_fusion import apply_attack_path_fusion, compute_fused_attack_paths
from agent_bom.graph.container import AttackPath, UnifiedGraph
from agent_bom.graph.edge import UnifiedEdge
from agent_bom.graph.node import UnifiedNode
from agent_bom.graph.path_evidence import annotate_attack_path_evidence, exposure_evidence_dimensions
from agent_bom.graph.types import EntityType, RelationshipType


def _ordinary_vulnerability_graph() -> UnifiedGraph:
    graph = UnifiedGraph(scan_id="scan-a", tenant_id="tenant-a")
    graph.analysis_status["attack_path_fusion"] = GraphAnalysisStatus(
        status=GraphAnalysisState.COMPLETE,
    )
    graph.add_node(UnifiedNode(id="agent:a", entity_type=EntityType.AGENT, label="agent-a"))
    graph.add_node(UnifiedNode(id="server:a", entity_type=EntityType.SERVER, label="server-a"))
    graph.add_node(
        UnifiedNode(
            id="vuln:CVE-2026-1",
            entity_type=EntityType.VULNERABILITY,
            label="CVE-2026-1",
            severity="critical",
            risk_score=9.8,
            attributes={"reachability": "confirmed", "reachability_basis": ["import_path"]},
        )
    )
    graph.add_edge(
        UnifiedEdge(
            source="agent:a",
            target="server:a",
            relationship=RelationshipType.USES,
            source_scan_id="scan-a",
            provenance={"source": "repository"},
            evidence={"freshness": "fresh"},
        )
    )
    graph.add_edge(
        UnifiedEdge(
            source="server:a",
            target="vuln:CVE-2026-1",
            relationship=RelationshipType.VULNERABLE_TO,
            source_scan_id="scan-a",
            evidence={"advisory": "CVE-2026-1", "freshness": "fresh"},
        )
    )
    return graph


def test_materialized_and_ordinary_vulnerability_paths_coexist() -> None:
    graph = _ordinary_vulnerability_graph()
    graph.add_node(
        UnifiedNode(
            id="data_store:crown",
            entity_type=EntityType.DATA_STORE,
            label="crown-jewel",
            attributes={"data_sensitivity": "restricted"},
        )
    )
    graph.add_edge(
        UnifiedEdge(
            source="server:a",
            target="data_store:crown",
            relationship=RelationshipType.STORES,
            source_scan_id="scan-a",
            evidence={"source": "modeled_data_lineage"},
        )
    )
    graph.attack_paths.append(
        AttackPath(
            source="server:a",
            target="data_store:crown",
            hops=["server:a", "data_store:crown"],
            edges=[RelationshipType.STORES.value],
            composite_risk=90.0,
            summary="materialized crown-jewel path",
        )
    )

    paths = _derived_attack_paths(graph)

    assert any(path.summary == "materialized crown-jewel path" for path in paths)
    assert any(path.target == "vuln:CVE-2026-1" and path.source == "agent:a" for path in paths)


def test_fused_path_rejects_non_traversable_hop() -> None:
    graph = UnifiedGraph(scan_id="scan-a", tenant_id="tenant-a")
    graph.add_node(
        UnifiedNode(
            id="workload:public",
            entity_type=EntityType.CLOUD_RESOURCE,
            label="public workload",
            attributes={"internet_exposed": True},
        )
    )
    graph.add_node(
        UnifiedNode(
            id="data_store:crown",
            entity_type=EntityType.DATA_STORE,
            label="crown-jewel",
            attributes={"data_sensitivity": "restricted"},
        )
    )
    graph.add_edge(
        UnifiedEdge(
            source="workload:public",
            target="data_store:crown",
            relationship=RelationshipType.CAN_ACCESS,
            traversable=False,
            source_scan_id="scan-a",
            evidence={"source": "modeled_policy"},
        )
    )

    assert compute_fused_attack_paths(graph) == []


def test_materialized_fused_path_carries_hop_evidence() -> None:
    graph = UnifiedGraph(scan_id="scan-a", tenant_id="tenant-a")
    graph.add_node(
        UnifiedNode(
            id="workload:public",
            entity_type=EntityType.CLOUD_RESOURCE,
            label="public workload",
            attributes={"internet_exposed": True},
        )
    )
    graph.add_node(
        UnifiedNode(
            id="data_store:crown",
            entity_type=EntityType.DATA_STORE,
            label="crown-jewel",
            attributes={"data_sensitivity": "restricted"},
        )
    )
    graph.add_edge(
        UnifiedEdge(
            source="workload:public",
            target="data_store:crown",
            relationship=RelationshipType.CAN_ACCESS,
            source_scan_id="scan-a",
            evidence={"source": "modeled_policy"},
        )
    )

    apply_attack_path_fusion(graph)

    assert graph.attack_paths[0].hop_evidence[0]["evidence_tier"] == "modeled_infrastructure"
    assert graph.attack_paths[0].hop_evidence[0]["source_snapshot_ids"] == ["scan-a"]
    assert graph.attack_paths[0].analysis["status"] == "complete"


def test_evidence_annotation_preserves_fused_path_identity_when_provenance_is_incomplete() -> None:
    graph = UnifiedGraph(scan_id="", tenant_id="tenant-a")
    graph.add_node(
        UnifiedNode(
            id="workload:public",
            entity_type=EntityType.CLOUD_RESOURCE,
            label="public workload",
            attributes={"internet_exposed": True},
        )
    )
    graph.add_node(
        UnifiedNode(
            id="data_store:crown",
            entity_type=EntityType.DATA_STORE,
            label="crown-jewel",
            attributes={"data_sensitivity": "restricted"},
        )
    )
    graph.add_edge(
        UnifiedEdge(
            source="workload:public",
            target="data_store:crown",
            relationship=RelationshipType.CAN_ACCESS,
        )
    )

    apply_attack_path_fusion(graph)

    path = graph.attack_paths[0]
    assert path.summary.startswith("Internet-exposed ")
    assert path.reachability == "unknown"
    assert path.composite_risk <= 39.0
    assert path.hop_evidence[0]["complete"] is False


def test_zero_hop_structural_candidate_cannot_be_confirmed() -> None:
    graph = UnifiedGraph(scan_id="scan-a", tenant_id="tenant-a")
    graph.add_node(UnifiedNode(id="finding:only", entity_type=EntityType.MISCONFIGURATION, label="finding"))
    path = AttackPath(
        source="finding:only",
        target="finding:only",
        hops=["finding:only"],
        composite_risk=91.0,
        reachability="likely",
    )

    annotate_attack_path_evidence(path, graph)

    assert path.hop_evidence == []
    assert path.reachability == "unknown"
    assert path.composite_risk <= 39.0
    assert "incomplete_hop_evidence" in path.reachability_basis


def test_bidirectional_hop_remains_structural_not_confirmed() -> None:
    graph = UnifiedGraph(scan_id="scan-a", tenant_id="tenant-a")
    graph.add_node(UnifiedNode(id="workload:public", entity_type=EntityType.CLOUD_RESOURCE, label="public workload"))
    graph.add_node(UnifiedNode(id="data_store:crown", entity_type=EntityType.DATA_STORE, label="crown jewel"))
    graph.add_edge(
        UnifiedEdge(
            source="workload:public",
            target="data_store:crown",
            relationship=RelationshipType.CAN_ACCESS,
            direction="bidirectional",
            traversable=True,
            source_scan_id="scan-a",
            provenance={"source": "modeled_policy"},
        )
    )
    path = AttackPath(
        source="workload:public",
        target="data_store:crown",
        hops=["workload:public", "data_store:crown"],
        edges=[RelationshipType.CAN_ACCESS.value],
        composite_risk=90.0,
        reachability="likely",
    )

    annotate_attack_path_evidence(path, graph)

    assert path.hop_evidence[0]["direction"] == "bidirectional"
    assert path.hop_evidence[0]["complete"] is False
    assert path.reachability == "unknown"
    assert path.composite_risk <= 39.0


def test_stale_allowed_hop_cannot_be_promoted_to_confirmed() -> None:
    graph = UnifiedGraph(scan_id="corr-stale", tenant_id="tenant-a")
    graph.analysis_status["attack_path_fusion"] = GraphAnalysisStatus(status=GraphAnalysisState.COMPLETE)
    graph.add_node(UnifiedNode(id="workload:public", entity_type=EntityType.CLOUD_RESOURCE, label="public workload"))
    graph.add_node(UnifiedNode(id="data_store:crown", entity_type=EntityType.DATA_STORE, label="crown jewel"))
    graph.add_edge(
        UnifiedEdge(
            source="workload:public",
            target="data_store:crown",
            relationship=RelationshipType.CAN_ACCESS,
            source_scan_id="corr-stale",
            provenance={
                "correlation": {
                    "source_scan_ids": ["scan-a"],
                    "freshness": "stale_allowed",
                    "observations": [
                        {
                            "scan_id": "scan-a",
                            "source_edge_id": "can_access:workload:public:data_store:crown",
                            "evidence_digest": "sha256:receipt",
                        }
                    ],
                }
            },
        )
    )
    path = AttackPath(
        source="workload:public",
        target="data_store:crown",
        hops=["workload:public", "data_store:crown"],
        edges=[RelationshipType.CAN_ACCESS.value],
        composite_risk=80.0,
        reachability="likely",
    )

    annotate_attack_path_evidence(path, graph)

    assert path.hop_evidence[0]["complete"] is True
    assert path.reachability == "likely"
    assert "stale_evidence_allowed" in path.reachability_basis
    assert "directed_provenance_backed_hops" not in path.reachability_basis


def test_bounded_analysis_cannot_promote_a_path_to_confirmed() -> None:
    graph = UnifiedGraph(scan_id="corr-limited", tenant_id="tenant-a")
    graph.analysis_status["attack_path_fusion"] = GraphAnalysisStatus(
        status=GraphAnalysisState.LIMITED,
        reason_codes=("path_limit_reached",),
        limits={"path_limit": 1},
        observed={"path_count": 1},
    )
    graph.add_node(UnifiedNode(id="workload:public", entity_type=EntityType.CLOUD_RESOURCE, label="public workload"))
    graph.add_node(UnifiedNode(id="data_store:crown", entity_type=EntityType.DATA_STORE, label="crown jewel"))
    graph.add_edge(
        UnifiedEdge(
            source="workload:public",
            target="data_store:crown",
            relationship=RelationshipType.CAN_ACCESS,
            source_scan_id="corr-limited",
            provenance={"source": "modeled_policy"},
        )
    )
    path = AttackPath(
        source="workload:public",
        target="data_store:crown",
        hops=["workload:public", "data_store:crown"],
        edges=[RelationshipType.CAN_ACCESS.value],
        composite_risk=80.0,
        reachability="likely",
    )

    annotate_attack_path_evidence(path, graph)

    assert path.hop_evidence[0]["truncated"] is True
    assert path.reachability == "unknown"
    assert path.composite_risk <= 39.0
    assert "incomplete_hop_evidence" in path.reachability_basis


def test_confirmed_path_carries_complete_per_hop_evidence() -> None:
    path = next(path for path in _derived_attack_paths(_ordinary_vulnerability_graph()) if path.target == "vuln:CVE-2026-1")

    assert path.reachability == "confirmed"
    assert len(path.hop_evidence) == 2
    assert path.hop_evidence[0] == {
        "source_node_id": "agent:a",
        "target_node_id": "server:a",
        "relationship": "uses",
        "source_snapshot_ids": ["scan-a"],
        "evidence_tier": "static_evidence",
        "confidence": 1.0,
        "freshness": "fresh",
        "runtime_observed_state": "not_observed",
        "direction": "directed",
        "traversable": True,
        "complete": True,
        "truncated": False,
    }
    assert path.hop_evidence[1]["relationship"] == "vulnerable_to"
    assert path.hop_evidence[1]["source_snapshot_ids"] == ["scan-a"]
    assert path.analysis == {"status": "complete", "reason_codes": [], "limits": {}, "observed": {"hop_count": 2}}

    restored = AttackPath.from_dict(path.to_dict())
    assert restored.hop_evidence == path.hop_evidence
    assert restored.analysis == path.analysis


def test_attack_path_evidence_survives_sqlite_round_trip(tmp_path: Path) -> None:
    graph = _ordinary_vulnerability_graph()
    path = next(path for path in _derived_attack_paths(graph) if path.target == "vuln:CVE-2026-1")
    graph.attack_paths = [path]
    store = SQLiteGraphStore(tmp_path / "graph.db")

    store.save_graph(graph)
    restored = store.load_graph(tenant_id="tenant-a", scan_id="scan-a").attack_paths[0]

    assert restored.hop_evidence == path.hop_evidence
    assert restored.analysis == path.analysis
    assert restored.reachability == "confirmed"
    assert exposure_evidence_dimensions(restored, graph.nodes[restored.target])["reachability"] == {
        "status": "complete",
        "verdict": "confirmed",
        "basis": ["import_path"],
    }


def test_missing_analyzer_status_cannot_confirm_fresh_hops() -> None:
    graph = UnifiedGraph(scan_id="scan-a", tenant_id="tenant-a")
    graph.add_node(UnifiedNode(id="workload:public", entity_type=EntityType.CLOUD_RESOURCE, label="public workload"))
    graph.add_node(UnifiedNode(id="data_store:crown", entity_type=EntityType.DATA_STORE, label="crown jewel"))
    graph.add_edge(
        UnifiedEdge(
            source="workload:public",
            target="data_store:crown",
            relationship=RelationshipType.CAN_ACCESS,
            source_scan_id="scan-a",
            evidence={"source": "policy_evaluator", "freshness": "fresh"},
        )
    )
    path = AttackPath(
        source="workload:public",
        target="data_store:crown",
        hops=["workload:public", "data_store:crown"],
        edges=[RelationshipType.CAN_ACCESS.value],
        composite_risk=80.0,
        reachability="likely",
    )

    annotate_attack_path_evidence(path, graph)

    assert path.analysis["status"] == "not_recorded"
    assert path.hop_evidence[0]["truncated"] is True
    assert path.reachability == "unknown"
    dimensions = exposure_evidence_dimensions(path, graph.nodes[path.target])
    assert dimensions["reachability"]["status"] == "unavailable"
    assert dimensions["completeness"]["status"] == "unavailable"


def test_unknown_freshness_cannot_complete_or_confirm_hop_evidence(tmp_path: Path) -> None:
    graph = UnifiedGraph(scan_id="scan-a", tenant_id="tenant-a")
    graph.analysis_status["attack_path_fusion"] = GraphAnalysisStatus(status=GraphAnalysisState.COMPLETE)
    graph.add_node(UnifiedNode(id="workload:public", entity_type=EntityType.CLOUD_RESOURCE, label="public workload"))
    graph.add_node(UnifiedNode(id="data_store:crown", entity_type=EntityType.DATA_STORE, label="crown jewel"))
    graph.add_edge(
        UnifiedEdge(
            source="workload:public",
            target="data_store:crown",
            relationship=RelationshipType.CAN_ACCESS,
            source_scan_id="scan-a",
            evidence={"source": "policy_evaluator"},
        )
    )
    path = AttackPath(
        source="workload:public",
        target="data_store:crown",
        hops=["workload:public", "data_store:crown"],
        edges=[RelationshipType.CAN_ACCESS.value],
        composite_risk=80.0,
        reachability="likely",
    )

    annotate_attack_path_evidence(path, graph)

    assert path.hop_evidence[0]["freshness"] == "unknown"
    assert path.hop_evidence[0]["complete"] is False
    assert path.reachability == "unknown"
    dimensions = exposure_evidence_dimensions(path, graph.nodes[path.target])
    assert dimensions["reachability"]["status"] == "unavailable"
    assert dimensions["completeness"] == {
        "status": "partial",
        "expectedHops": 1,
        "evidencedHops": 1,
        "analysisStatus": "complete",
        "reasonCodes": ["unknown_evidence_freshness"],
    }

    graph.attack_paths = [path]
    store = SQLiteGraphStore(tmp_path / "graph.db")
    store.save_graph(graph)
    restored = store.load_graph(tenant_id="tenant-a", scan_id="scan-a").attack_paths[0]
    restored_dimensions = exposure_evidence_dimensions(restored, graph.nodes[restored.target])
    assert restored.reachability == "unknown"
    assert restored_dimensions["reachability"]["status"] == "unavailable"
    assert restored_dimensions["completeness"]["reasonCodes"] == ["unknown_evidence_freshness"]


def test_snapshot_membership_and_irrelevant_provenance_are_not_relationship_receipts() -> None:
    graph = UnifiedGraph(scan_id="corr-a", tenant_id="tenant-a")
    graph.analysis_status["attack_path_fusion"] = GraphAnalysisStatus(status=GraphAnalysisState.COMPLETE)
    graph.add_node(UnifiedNode(id="workload:public", entity_type=EntityType.CLOUD_RESOURCE, label="public workload"))
    graph.add_node(UnifiedNode(id="data_store:crown", entity_type=EntityType.DATA_STORE, label="crown jewel"))
    graph.add_edge(
        UnifiedEdge(
            source="workload:public",
            target="data_store:crown",
            relationship=RelationshipType.CAN_ACCESS,
            source_scan_id="corr-a",
            provenance={
                "note": "not a relationship receipt",
                "correlation": {"source_scan_ids": ["scan-a"], "freshness": "fresh"},
            },
        )
    )
    path = AttackPath(
        source="workload:public",
        target="data_store:crown",
        hops=["workload:public", "data_store:crown"],
        edges=[RelationshipType.CAN_ACCESS.value],
        composite_risk=80.0,
        reachability="likely",
    )

    annotate_attack_path_evidence(path, graph)

    assert path.hop_evidence[0]["complete"] is False
    assert path.reachability == "unknown"
    assert exposure_evidence_dimensions(path, graph.nodes[path.target])["completeness"]["status"] == "partial"


def test_final_fusion_runs_after_runtime_code_ci_and_endpoint_overlays(monkeypatch: Any) -> None:
    import agent_bom.graph.attack_path_fusion as fusion_module
    import agent_bom.graph.builder as builder
    import agent_bom.graph.endpoint_overlay as endpoint_module

    events: list[str] = []

    def marker(name: str):
        def apply(_graph: UnifiedGraph, _report: Any = None) -> None:
            events.append(name)

        return apply

    monkeypatch.setattr(builder, "_apply_runtime_evidence_overlay", marker("runtime"))
    monkeypatch.setattr(builder, "_apply_repo_structure_overlay", marker("repository"))
    monkeypatch.setattr(builder, "_apply_ast_tool_overlay", marker("ast"))
    monkeypatch.setattr(builder, "_apply_code_graph_overlay", marker("code"))
    monkeypatch.setattr(builder, "_apply_ci_graph_overlay", marker("ci"))
    monkeypatch.setattr(endpoint_module, "apply_endpoint_inventory_overlay", marker("endpoint"))

    def capture_fusion(_graph: UnifiedGraph) -> dict[str, int]:
        events.append("fusion")
        return {"fused_attack_paths": 0}

    monkeypatch.setattr(fusion_module, "apply_attack_path_fusion", capture_fusion)

    builder.build_unified_graph_from_report({"scan_id": "ordered", "agents": []}, tenant_id="tenant-a")

    assert events.index("fusion") > max(events.index(name) for name in ("runtime", "repository", "ast", "code", "ci", "endpoint"))
