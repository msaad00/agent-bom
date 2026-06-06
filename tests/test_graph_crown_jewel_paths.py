"""Cloud-security crown-jewel paths: stacked toxic factors surface as top paths.

Validates the fused multi-factor combination (exposure + exploitable vuln +
reach-to-sensitive-data + admin-reachable) the same way both surfaces consume it
— the headless ``/v1/graph/attack-paths`` derivation that agents query and the
graph cockpit humans use.
"""

from __future__ import annotations

from agent_bom.api.routes.graph import _derived_attack_paths, _derived_toxic_combination_paths
from agent_bom.graph.container import UnifiedGraph
from agent_bom.graph.edge import UnifiedEdge
from agent_bom.graph.node import UnifiedNode
from agent_bom.graph.types import EntityType, RelationshipType


def _crown_jewel_graph() -> UnifiedGraph:
    g = UnifiedGraph(scan_id="cj", tenant_id="t")
    # An internet-exposed, vulnerable VM that reaches a PCI data store.
    g.add_node(
        UnifiedNode(
            id="cloud:vm",
            entity_type=EntityType.CLOUD_RESOURCE,
            label="prod-api (EC2)",
            attributes={"internet_exposed": True, "toxic_exposed_vulnerable": True},
        )
    )
    g.add_node(UnifiedNode(id="vuln:rce", entity_type=EntityType.VULNERABILITY, label="CVE-RCE", severity="critical"))
    g.add_node(
        UnifiedNode(
            id="ds:pay",
            entity_type=EntityType.DATA_STORE,
            label="payments-db",
            attributes={"data_sensitivity": "sensitive", "data_regulatory_frameworks": ["PCI-DSS"]},
        )
    )
    g.add_edge(UnifiedEdge(source="cloud:vm", target="vuln:rce", relationship=RelationshipType.VULNERABLE_TO))
    g.add_edge(UnifiedEdge(source="cloud:vm", target="ds:pay", relationship=RelationshipType.EXPOSED_TO))
    return g


def test_three_factor_resource_is_a_crown_jewel():
    g = _crown_jewel_graph()
    paths = _derived_toxic_combination_paths(g)
    assert paths, "a 3-factor resource must surface a toxic-combination path"
    cj = paths[0]
    assert "Crown jewel" in cj.summary
    assert "internet-exposed" in cj.summary
    assert "exploitable vulnerability" in cj.summary
    assert "PCI-DSS" in cj.summary  # regulation named
    assert cj.composite_risk >= 95


def test_crown_jewel_ranks_at_top_of_derived_paths():
    g = _crown_jewel_graph()
    all_paths = _derived_attack_paths(g)
    assert all_paths
    top = max(all_paths, key=lambda p: p.composite_risk)
    assert "Crown jewel" in top.summary and top.composite_risk >= 95


def test_single_factor_is_not_a_toxic_combination():
    g = UnifiedGraph(scan_id="s", tenant_id="t")
    # exposed but nothing else stacked
    g.add_node(
        UnifiedNode(
            id="cloud:lb",
            entity_type=EntityType.CLOUD_RESOURCE,
            label="public-lb",
            attributes={"internet_exposed": True},
        )
    )
    assert _derived_toxic_combination_paths(g) == []


def test_two_factor_is_a_toxic_combination_not_crown_jewel():
    g = UnifiedGraph(scan_id="s", tenant_id="t")
    g.add_node(
        UnifiedNode(
            id="cloud:vm",
            entity_type=EntityType.CLOUD_RESOURCE,
            label="vm",
            attributes={"internet_exposed": True},
        )
    )
    g.add_node(UnifiedNode(id="vuln:x", entity_type=EntityType.VULNERABILITY, label="CVE-X", severity="high"))
    g.add_edge(UnifiedEdge(source="cloud:vm", target="vuln:x", relationship=RelationshipType.VULNERABLE_TO))
    paths = _derived_toxic_combination_paths(g)
    assert len(paths) == 1
    assert "Toxic combination" in paths[0].summary
    assert 80 <= paths[0].composite_risk < 95
