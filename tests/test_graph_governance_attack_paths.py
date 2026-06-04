"""Governance / CNAPP / effective-permission chains surface as attack paths."""

from __future__ import annotations

from agent_bom.api.routes.graph import _derived_attack_paths, _derived_governance_attack_paths
from agent_bom.graph.container import UnifiedGraph
from agent_bom.graph.edge import UnifiedEdge
from agent_bom.graph.node import UnifiedNode
from agent_bom.graph.types import EntityType, RelationshipType


def _summaries(paths):
    return " || ".join(p.summary for p in paths)


def test_privilege_escalation_and_data_exposure_paths():
    g = UnifiedGraph(scan_id="s", tenant_id="t")
    g.add_node(UnifiedNode(id="user:dev", entity_type=EntityType.USER, label="dev"))
    g.add_node(
        UnifiedNode(id="cloud:bucket", entity_type=EntityType.CLOUD_RESOURCE, label="prod bucket", attributes={"internet_exposed": True})
    )
    g.add_node(
        UnifiedNode(id="ds:bucket", entity_type=EntityType.DATA_STORE, label="data: prod bucket", attributes={"internet_exposed": True})
    )
    # privilege escalation (assume_chain) + data-exposure
    g.add_edge(
        UnifiedEdge(
            source="user:dev", target="cloud:bucket", relationship=RelationshipType.HAS_PERMISSION, evidence={"access": "assume_chain"}
        )
    )
    g.add_edge(UnifiedEdge(source="cloud:bucket", target="ds:bucket", relationship=RelationshipType.EXPOSED_TO))

    paths = _derived_governance_attack_paths(g)
    kinds = {(p.source, p.target) for p in paths}
    assert ("user:dev", "cloud:bucket") in kinds  # privilege escalation
    assert ("cloud:bucket", "ds:bucket") in kinds  # data exposure
    esc = next(p for p in paths if p.source == "user:dev")
    # escalation to internet-exposed resource scores high (base 65 + fusion boosts)
    assert esc.composite_risk >= 80


def test_over_scoped_tool_and_drift_paths():
    g = UnifiedGraph(scan_id="s", tenant_id="t")
    g.add_node(UnifiedNode(id="agent:a", entity_type=EntityType.AGENT, label="agent-a"))
    g.add_node(UnifiedNode(id="id:1", entity_type=EntityType.MANAGED_IDENTITY, label="agent-a", attributes={"scope_bound": False}))
    g.add_node(UnifiedNode(id="tool:shell", entity_type=EntityType.TOOL, label="run_shell"))
    g.add_node(UnifiedNode(id="tool:list", entity_type=EntityType.TOOL, label="list_files"))
    g.add_node(UnifiedNode(id="drift:1", entity_type=EntityType.DRIFT_INCIDENT, label="drift: agent-a"))
    g.add_edge(UnifiedEdge(source="agent:a", target="id:1", relationship=RelationshipType.AUTHENTICATES_AS))
    g.add_edge(UnifiedEdge(source="id:1", target="tool:shell", relationship=RelationshipType.SCOPED_TO))
    g.add_edge(UnifiedEdge(source="id:1", target="tool:list", relationship=RelationshipType.SCOPED_TO))
    g.add_edge(UnifiedEdge(source="agent:a", target="drift:1", relationship=RelationshipType.EXHIBITS_DRIFT, direction="bidirectional"))
    g.add_edge(UnifiedEdge(source="drift:1", target="tool:shell", relationship=RelationshipType.SCOPED_TO))

    paths = _derived_governance_attack_paths(g)
    targets = {(p.source, p.target) for p in paths}
    # dangerous tool (run_shell) surfaced via identity; benign list_files NOT.
    assert ("agent:a", "tool:shell") in targets
    over_scoped = [p for p in paths if p.hops == ["agent:a", "id:1", "tool:shell"]]
    assert over_scoped and "run_shell" in over_scoped[0].summary
    assert not any(p.target == "tool:list" for p in paths)
    # drift → tool path present
    drift = [p for p in paths if p.hops == ["agent:a", "drift:1", "tool:shell"]]
    assert drift


def test_governance_paths_merge_into_derived_attack_paths():
    g = UnifiedGraph(scan_id="s", tenant_id="t")
    g.add_node(UnifiedNode(id="user:dev", entity_type=EntityType.USER, label="dev"))
    g.add_node(UnifiedNode(id="cloud:r", entity_type=EntityType.CLOUD_RESOURCE, label="r"))
    g.add_edge(
        UnifiedEdge(source="user:dev", target="cloud:r", relationship=RelationshipType.HAS_PERMISSION, evidence={"access": "assume_chain"})
    )
    # No vuln-anchored paths, but the governance path should still surface.
    all_paths = _derived_attack_paths(g)
    assert any(p.source == "user:dev" and p.target == "cloud:r" for p in all_paths)
