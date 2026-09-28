"""Cloud role evidence must retain provider-native resource boundaries."""

from agent_bom.graph.builder import build_unified_graph_from_report
from agent_bom.graph.types import EntityType, RelationshipType


def _inventory(subscription, scope, *, role="Reader", principal="operator"):
    return {
        "status": "ok",
        "provider": "azure",
        "account_id": subscription,
        "role_assignments": [{"principal_id": principal, "principal_type": "user", "role_name": role, "scope": scope}],
    }


def test_same_named_resource_groups_in_different_subscriptions_are_distinct():
    scopes = [f"/subscriptions/{subscription}/resourceGroups/production" for subscription in ("sub-a", "sub-b")]
    graph = build_unified_graph_from_report({"cloud_inventory": [_inventory(sub, scope) for sub, scope in zip(("sub-a", "sub-b"), scopes)]})
    edges = [edge for edge in graph.edges if edge.relationship is RelationshipType.HAS_PERMISSION]
    assert len({edge.target for edge in edges}) == 2
    assert {graph.nodes[edge.target].attributes["resource_id"] for edge in edges} == set(scopes)


def test_arm_scope_case_and_trailing_slash_do_not_duplicate_resource_groups():
    original = "/subscriptions/sub-a/resourceGroups/Production"
    inventory = _inventory("sub-a", original)
    inventory["role_assignments"] += _inventory("sub-a", original.upper() + "/", role="Contributor")["role_assignments"]
    graph = build_unified_graph_from_report({"cloud_inventory": inventory})
    groups = [
        node
        for node in graph.nodes.values()
        if node.entity_type is EntityType.CLOUD_RESOURCE and node.attributes.get("resource_type") == "resource_group"
    ]
    assert len(groups) == 1
    edges = [edge for edge in graph.edges if edge.relationship is RelationshipType.HAS_PERMISSION]
    assert len(edges) == 1
    assert set(edges[0].evidence["roles"]) == {"Reader", "Contributor"}


def test_authoritative_partial_evidence_does_not_get_legacy_permission_edges():
    inventory = _inventory("sub-a", "/subscriptions/sub-a")
    inventory["authorization_evidence"] = {"provider": "azure"}
    inventory["authorization_sources"] = [{"name": "role_assignments", "state": "partial"}]
    graph = build_unified_graph_from_report({"cloud_inventory": inventory})
    assert not [edge for edge in graph.edges if edge.evidence.get("source") == "cloud-rbac"]


def test_group_grant_preserves_member_evidence_without_inventing_other_members():
    from agent_bom.graph.cloud_rbac import add_cloud_role_assignments
    from agent_bom.graph.container import UnifiedGraph
    from agent_bom.graph.edge import UnifiedEdge
    from agent_bom.graph.node import UnifiedNode

    graph = UnifiedGraph()
    for node_id, entity in [
        ("group:azure:operators", EntityType.GROUP),
        ("user:azure:alice", EntityType.USER),
        ("user:azure:bob", EntityType.USER),
    ]:
        graph.add_node(
            UnifiedNode(
                id=node_id,
                entity_type=entity,
                label=node_id,
                attributes={"cloud_provider": "azure", "principal_id": node_id.rsplit(":", 1)[-1]},
            )
        )
    graph.add_edge(UnifiedEdge(source="user:azure:alice", target="group:azure:operators", relationship=RelationshipType.MEMBER_OF))
    inventory = _inventory("sub-a", "/subscriptions/sub-a", principal="operators")
    inventory["role_assignments"][0]["principal_type"] = "group"
    add_cloud_role_assignments(graph, inventory, "fixture")
    edges = [edge for edge in graph.edges if edge.relationship is RelationshipType.HAS_PERMISSION]
    assert {edge.source for edge in edges} == {"group:azure:operators", "user:azure:alice"}
    member = next(edge for edge in edges if edge.source == "user:azure:alice")
    assert member.evidence["via_group"] == "operators"
    assert member.evidence["roles"] == ["Reader"]


def test_managed_identity_role_assignment_joins_directory_id_without_duplicate():
    inventory = _inventory("sub-a", "/subscriptions/sub-a", principal="NATIVE-ID")
    inventory["role_assignments"][0]["principal_type"] = "ServicePrincipal"
    inventory["managed_identities"] = [
        {
            "name": "scanner",
            "arn": "/subscriptions/sub-a/resourceGroups/rg/providers/Microsoft.ManagedIdentity/userAssignedIdentities/scanner",
            "principal_id": "native-id",
            "principal_type": "managed-identity",
            "privilege_level": "unknown",
        }
    ]
    graph = build_unified_graph_from_report({"cloud_inventory": inventory})
    managed = next(n for n in graph.nodes.values() if n.entity_type == EntityType.MANAGED_IDENTITY)
    edges = [e for e in graph.edges if e.evidence.get("source") == "cloud-rbac"]
    assert len(edges) == 1
    assert edges[0].source == managed.id
    assert not [n for n in graph.nodes.values() if n.entity_type == EntityType.SERVICE_PRINCIPAL]
    assert managed.label == "scanner"
    assert managed.attributes["nhi_is_dormant"] is False
    assert managed.attributes["nhi_is_orphaned"] is False


def test_collected_group_native_id_preserves_role_and_member_join():
    inventory = _inventory("sub-a", "/subscriptions/sub-a", principal="operators-id")
    inventory["role_assignments"][0]["principal_type"] = "group"
    inventory["entra_groups"] = [
        {
            "name": "operators",
            "arn": "operators-id",
            "principal_id": "operators-id",
            "members": [{"id": "alice-id", "type": "user", "name": "Alice"}],
        }
    ]
    graph = build_unified_graph_from_report({"cloud_inventory": inventory})
    edges = [e for e in graph.edges if e.evidence.get("source") == "cloud-rbac"]
    assert {e.source for e in edges} == {"group:azure:operators-id", "user:azure:alice-id"}
    assert graph.nodes["group:azure:operators-id"].label == "operators"
