"""Effective permissions + privilege-escalation detection over identity edges."""

from __future__ import annotations

from agent_bom.graph.container import UnifiedGraph
from agent_bom.graph.edge import UnifiedEdge
from agent_bom.graph.effective_permissions import apply_effective_permissions
from agent_bom.graph.node import UnifiedNode
from agent_bom.graph.types import EntityType, RelationshipType


def _perm(graph, src):
    return {
        e.target: e.evidence.get("access") for e in graph.edges if e.relationship == RelationshipType.HAS_PERMISSION and e.source == src
    }


def test_assume_chain_yields_effective_permission_and_escalation():
    g = UnifiedGraph(scan_id="s", tenant_id="t")
    g.add_node(UnifiedNode(id="user:dev", entity_type=EntityType.USER, label="dev"))
    g.add_node(UnifiedNode(id="role:admin", entity_type=EntityType.ROLE, label="admin-role"))
    g.add_node(
        UnifiedNode(id="cloud:bucket", entity_type=EntityType.CLOUD_RESOURCE, label="prod bucket", attributes={"internet_exposed": True})
    )
    g.add_node(UnifiedNode(id="cloud:logs", entity_type=EntityType.CLOUD_RESOURCE, label="logs"))
    # dev can directly access logs, and can assume admin-role which can access the bucket.
    g.add_edge(UnifiedEdge(source="user:dev", target="cloud:logs", relationship=RelationshipType.CAN_ACCESS))
    g.add_edge(UnifiedEdge(source="user:dev", target="role:admin", relationship=RelationshipType.TRUSTS))
    g.add_edge(UnifiedEdge(source="role:admin", target="cloud:bucket", relationship=RelationshipType.CAN_ACCESS))

    stats = apply_effective_permissions(g)
    assert stats["has_permission_edges"] >= 2
    assert stats["privilege_escalations"] == 1

    dev_perms = _perm(g, "user:dev")
    assert dev_perms.get("cloud:logs") == "direct"
    assert dev_perms.get("cloud:bucket") == "assume_chain"  # reachable only via assume

    dev = g.nodes["user:dev"]
    assert dev.attributes.get("can_escalate_privilege") is True
    # escalation to an internet-exposed resource raises the risk to the top band
    esc = [r for r in g.interaction_risks if r.pattern == "privilege_escalation"]
    assert esc and esc[0].risk_score == 9.5


def test_no_assume_chain_is_direct_only_no_escalation():
    g = UnifiedGraph(scan_id="s", tenant_id="t")
    g.add_node(UnifiedNode(id="user:a", entity_type=EntityType.USER, label="a"))
    g.add_node(UnifiedNode(id="cloud:r", entity_type=EntityType.CLOUD_RESOURCE, label="r"))
    g.add_edge(UnifiedEdge(source="user:a", target="cloud:r", relationship=RelationshipType.CAN_ACCESS))

    stats = apply_effective_permissions(g)
    assert stats["privilege_escalations"] == 0
    assert _perm(g, "user:a") == {"cloud:r": "direct"}
    assert g.nodes["user:a"].attributes.get("can_escalate_privilege") is None


def test_assume_cycle_is_bounded():
    g = UnifiedGraph(scan_id="s", tenant_id="t")
    g.add_node(UnifiedNode(id="role:a", entity_type=EntityType.ROLE, label="a"))
    g.add_node(UnifiedNode(id="role:b", entity_type=EntityType.ROLE, label="b"))
    g.add_node(UnifiedNode(id="cloud:x", entity_type=EntityType.CLOUD_RESOURCE, label="x"))
    g.add_edge(UnifiedEdge(source="role:a", target="role:b", relationship=RelationshipType.ASSUMES))
    g.add_edge(UnifiedEdge(source="role:b", target="role:a", relationship=RelationshipType.ASSUMES))
    g.add_edge(UnifiedEdge(source="role:b", target="cloud:x", relationship=RelationshipType.CAN_ACCESS))

    apply_effective_permissions(g)  # must terminate
    assert _perm(g, "role:a").get("cloud:x") == "assume_chain"
