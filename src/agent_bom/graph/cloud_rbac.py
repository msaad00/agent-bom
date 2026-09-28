"""Project legacy cloud role assignments without collapsing resource scopes.

Authoritative authorization evidence takes precedence. This adapter records
configured role grants; it does not prove observed or successful resource access.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any

from agent_bom.graph.authorization_evidence import has_authoritative_authorization_evidence
from agent_bom.graph.container import UnifiedGraph
from agent_bom.graph.edge import UnifiedEdge
from agent_bom.graph.identity_nodes import find_native_principal, identity_node_id, unresolved_principal_node_id
from agent_bom.graph.node import NodeDimensions, UnifiedNode
from agent_bom.graph.types import EntityType, RelationshipType
from agent_bom.graph.util import clean_graph_part

_RBAC_PRINCIPAL_ENTITY = {
    "serviceprincipal": EntityType.SERVICE_PRINCIPAL,
    "service_principal": EntityType.SERVICE_PRINCIPAL,
    "user": EntityType.USER,
    "group": EntityType.GROUP,
    "managedidentity": EntityType.MANAGED_IDENTITY,
    "managed_identity": EntityType.MANAGED_IDENTITY,
}


# Configured role names flag broad grants; they do not prove effective access.
_RBAC_PRIVILEGED_ROLES = {
    "owner",
    "contributor",
    "user access administrator",
    "role based access control administrator",
    "key vault administrator",
    "storage blob data owner",
}


def _group_assignments(assignments: list[Any]) -> dict[tuple[str, str], dict[str, Any]]:
    grouped: dict[tuple[str, str], dict[str, Any]] = {}
    for assignment in assignments:
        if not isinstance(assignment, dict):
            continue
        principal = clean_graph_part(assignment.get("principal_id"))
        scope = clean_graph_part(assignment.get("scope")).rstrip("/")
        if not principal or not scope:
            continue
        principal_type = str(assignment.get("principal_type") or "").lower().replace("-", "").replace("_", "")
        # Azure ARM identifiers are case-insensitive; retain the first display
        # spelling while grouping all roles for the same native scope.
        entry = grouped.setdefault((principal, scope.lower()), {"principal_type": principal_type, "scope": scope, "roles": []})
        role = clean_graph_part(assignment.get("role_name"))
        if role and role not in entry["roles"]:
            entry["roles"].append(role)
    return grouped


@dataclass
class _Projection:
    graph: UnifiedGraph
    provider: str
    account_id: str
    data_sources: list[str]
    resource_by_arm: dict[str, str] = field(default_factory=dict)
    group_members: dict[str, list[str]] = field(default_factory=lambda: defaultdict(list))

    def index(self) -> None:
        for node in self.graph.nodes.values():
            if node.entity_type == EntityType.CLOUD_RESOURCE:
                arm = clean_graph_part(node.attributes.get("resource_id"))
                if arm:
                    self.resource_by_arm[arm.rstrip("/").lower()] = node.id
        for edge in self.graph.edges:
            if edge.relationship == RelationshipType.MEMBER_OF:
                target = self.graph.nodes.get(edge.target)
                if target is not None and target.entity_type == EntityType.GROUP:
                    self.group_members[edge.target].append(edge.source)

    def scope_target(self, scope: str) -> str:
        normalized = scope.rstrip("/").lower()
        if normalized in self.resource_by_arm:
            return self.resource_by_arm[normalized]
        if self.account_id and normalized == f"/subscriptions/{self.account_id}".lower():
            return identity_node_id(EntityType.ACCOUNT, self.provider, self.account_id)
        is_group = "/resourcegroups/" in normalized and "/providers/" not in normalized
        kind = "resource_group" if is_group else "scope"
        # Full provider-native scope is identity; display names are not unique
        # across subscriptions. Case/trailing slash cannot create another node.
        node_id = f"cloud_resource:{self.provider}:{kind}:{normalized}"
        if node_id not in self.graph.nodes:
            name = scope.rsplit("/", 1)[-1] or scope
            attributes = {"resource_id": scope, "cloud_provider": self.provider}
            if is_group:
                attributes.update(resource_name=name, resource_type="resource_group")
            self.graph.add_node(
                UnifiedNode(
                    id=node_id,
                    entity_type=EntityType.CLOUD_RESOURCE,
                    label=f"resource group: {name}" if is_group else name,
                    attributes=attributes,
                    data_sources=self.data_sources,
                    dimensions=NodeDimensions(cloud_provider=self.provider),
                )
            )
        return node_id

    def add_assignment(self, principal: str, entry: dict[str, Any]) -> None:
        principal_type = entry["principal_type"]
        entity = _RBAC_PRINCIPAL_ENTITY.get(principal_type, EntityType.SERVICE_PRINCIPAL)
        principal_node = find_native_principal(self.graph, self.provider, entity, principal)
        if principal_node is None:
            principal_node = unresolved_principal_node_id(self.graph, self.provider, entity, principal)
            self.graph.add_node(
                UnifiedNode(
                    id=principal_node,
                    entity_type=entity,
                    label=f"{principal_type or 'principal'}: {principal[:8]}",
                    attributes={"principal_id": principal, "principal_type": principal_type, "cloud_provider": self.provider},
                    data_sources=self.data_sources,
                    dimensions=NodeDimensions(cloud_provider=self.provider, surface="identity"),
                )
            )
        target = self.scope_target(entry["scope"])
        roles = entry["roles"]
        evidence = {
            "source": "cloud-rbac",
            "roles": roles,
            "role": roles[0] if roles else "",
            "privileged": any(role.lower() in _RBAC_PRIVILEGED_ROLES for role in roles),
            "scope": entry["scope"],
        }
        self.graph.add_edge(
            UnifiedEdge(source=principal_node, target=target, relationship=RelationshipType.HAS_PERMISSION, evidence=evidence)
        )
        if entity == EntityType.GROUP:
            for member in self.group_members.get(principal_node, []):
                self.graph.add_edge(
                    UnifiedEdge(
                        source=member,
                        target=target,
                        relationship=RelationshipType.HAS_PERMISSION,
                        evidence={**evidence, "via_group": principal},
                    )
                )


def add_cloud_role_assignments(graph: UnifiedGraph, inventory: Any, data_source: str) -> None:
    """Project configured grants, deferring to authoritative evidence when present."""
    if not isinstance(inventory, dict) or has_authoritative_authorization_evidence(inventory):
        return
    assignments = inventory.get("role_assignments") or []
    if not assignments:
        return
    projection = _Projection(
        graph=graph,
        provider=clean_graph_part(inventory.get("provider")) or "azure",
        account_id=clean_graph_part(inventory.get("account_id") or inventory.get("subscription_id")),
        data_sources=sorted({data_source, "cloud-rbac"} - {""}),
    )
    projection.index()
    for (principal, _scope), entry in _group_assignments(assignments).items():
        projection.add_assignment(principal, entry)
