"""Mechanical correlation contracts: path coexistence and evidence truth."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from agent_bom.api.graph_store import SQLiteGraphStore
from agent_bom.api.routes.graph import _derived_attack_paths
from agent_bom.graph.attack_path_fusion import apply_attack_path_fusion, compute_fused_attack_paths
from agent_bom.graph.container import AttackPath, UnifiedGraph
from agent_bom.graph.edge import UnifiedEdge
from agent_bom.graph.node import UnifiedNode
from agent_bom.graph.types import EntityType, RelationshipType


def _ordinary_vulnerability_graph() -> UnifiedGraph:
    graph = UnifiedGraph(scan_id="scan-a", tenant_id="tenant-a")
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
        )
    )
    graph.add_edge(
        UnifiedEdge(
            source="server:a",
            target="vuln:CVE-2026-1",
            relationship=RelationshipType.VULNERABLE_TO,
            source_scan_id="scan-a",
            evidence={"advisory": "CVE-2026-1"},
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
        "freshness": "unknown",
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
