"""Attack-path scoring fuses governance / CNAPP / runtime evidence."""

from __future__ import annotations

from agent_bom.api.routes.graph import _derived_attack_paths, _fusion_signals_for_path, _risk_reasons_for_path
from agent_bom.graph.container import UnifiedGraph
from agent_bom.graph.edge import UnifiedEdge
from agent_bom.graph.node import UnifiedNode
from agent_bom.graph.types import EntityType, RelationshipType


def _chain_graph(*, expose: bool, drift: bool) -> UnifiedGraph:
    g = UnifiedGraph(scan_id="s", tenant_id="t")
    g.add_node(UnifiedNode(id="agent:a", entity_type=EntityType.AGENT, label="agent-a"))
    g.add_node(
        UnifiedNode(id="server:fs", entity_type=EntityType.SERVER, label="fs", attributes={"internet_exposed": True} if expose else {})
    )
    g.add_node(UnifiedNode(id="vuln:CVE-1", entity_type=EntityType.VULNERABILITY, label="CVE-1", severity="critical", risk_score=9.0))
    g.add_edge(UnifiedEdge(source="agent:a", target="server:fs", relationship=RelationshipType.USES))
    g.add_edge(UnifiedEdge(source="server:fs", target="vuln:CVE-1", relationship=RelationshipType.VULNERABLE_TO, weight=8.0))
    if drift:
        g.add_node(UnifiedNode(id="drift:1", entity_type=EntityType.DRIFT_INCIDENT, label="drift: agent-a"))
        g.add_edge(UnifiedEdge(source="agent:a", target="drift:1", relationship=RelationshipType.EXHIBITS_DRIFT, direction="bidirectional"))
    return g


def test_exposure_and_drift_raise_path_risk_above_baseline():
    baseline = _derived_attack_paths(_chain_graph(expose=False, drift=False))
    fused = _derived_attack_paths(_chain_graph(expose=True, drift=True))
    assert baseline and fused
    assert fused[0].composite_risk > baseline[0].composite_risk


def test_fusion_reasons_surface_governance_signals():
    g = _chain_graph(expose=True, drift=True)
    path = _derived_attack_paths(g)[0]
    kinds = {k for k, _l, _d, _b in _fusion_signals_for_path(g, path.hops)}
    assert "internet_exposed" in kinds
    assert "behavioral_drift" in kinds
    reason_kinds = {r["kind"] for r in _risk_reasons_for_path(g, path)}
    assert "internet_exposed" in reason_kinds or "behavioral_drift" in reason_kinds


def test_no_signals_yields_no_boost():
    g = _chain_graph(expose=False, drift=False)
    path = _derived_attack_paths(g)[0]
    assert _fusion_signals_for_path(g, path.hops) == []
