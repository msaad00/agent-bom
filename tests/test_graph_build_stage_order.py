"""Characterize graph topology and analysis order before decomposing the builder."""

import importlib

import pytest

from agent_bom.graph.builder import build_unified_graph_from_report
from agent_bom.graph.container import UnifiedGraph
from agent_bom.graph.node import UnifiedNode
from agent_bom.graph.types import EntityType

STAGES = (
    ("agent_bom.graph.nhi_overlay", "apply_nhi_overlay_from_report"),
    ("agent_bom.graph.cnapp_overlay", "apply_cnapp_overlay"),
    ("agent_bom.graph.effective_permissions", "apply_effective_permissions"),
    ("agent_bom.graph.nhi_governance", "apply_nhi_governance_with_findings"),
    ("agent_bom.a2a_auth_posture", "annotate_graph_a2a_auth_from_report"),
    ("agent_bom.mcp_auth_posture", "annotate_graph_mcp_auth_from_report"),
    ("agent_bom.graph.builder", "_apply_runtime_evidence_overlay"),
    ("agent_bom.graph.builder", "_apply_repo_structure_overlay"),
    ("agent_bom.graph.builder", "_apply_ast_tool_overlay"),
    ("agent_bom.graph.builder", "_apply_code_graph_overlay"),
    ("agent_bom.graph.builder", "_apply_repo_trust_overlay"),
    ("agent_bom.graph.builder", "_apply_ci_graph_overlay"),
    ("agent_bom.graph.endpoint_overlay", "apply_endpoint_inventory_overlay"),
    ("agent_bom.graph.attack_path_fusion", "apply_attack_path_fusion"),
    ("agent_bom.graph.attack_path_mitre", "apply_attack_path_technique_mappings"),
    ("agent_bom.graph.builder", "_apply_agent_reach_risk"),
    ("agent_bom.graph.builder", "_apply_aspm_overlay"),
    ("agent_bom.graph.builder", "_apply_cost_overlay"),
)


def _stage(name, calls, fail):
    def run(graph, *args):
        assert graph.get_node("provider:local") is not None
        calls.append(name)
        if name == fail:
            raise RuntimeError("fixture stage failure")
        graph.add_node(UnifiedNode(id=name, entity_type=EntityType.RESOURCE, label=name))
        return {}, []

    return run


@pytest.mark.parametrize("fail", [None, *(name for _, name in STAGES)])
def test_all_topology_precedes_fusion_and_stage_failure_preserves_later_evidence(monkeypatch, fail):
    calls = []
    for module, name in STAGES:
        monkeypatch.setattr(importlib.import_module(module), name, _stage(name, calls, fail))
    graph = UnifiedGraph(scan_id="retained", tenant_id="tenant-a")
    report = {"scan_id": "report", "agents": [{"name": "agent", "type": "custom", "mcp_servers": []}]}
    result = build_unified_graph_from_report(report, scan_id="explicit", tenant_id="tenant-a", container=graph)
    assert result is graph
    assert result.scan_id == "retained"
    assert result.tenant_id == "tenant-a"
    assert calls == [name for _, name in STAGES]
    assert {name for _, name in STAGES if name != fail} <= graph.nodes.keys()
    if fail == "apply_attack_path_fusion":
        assert graph.analysis_status["attack_path_fusion"].status.value == "failed"
        assert graph.analysis_status["attack_path_fusion"].reason_codes == ("analysis_error",)
