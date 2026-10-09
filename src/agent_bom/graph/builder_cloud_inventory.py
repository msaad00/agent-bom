"""Cloud inventory projection: resources, hierarchy and instance-profile wiring."""

from __future__ import annotations

from typing import Any

from agent_bom.graph.builder_network_exposure import _instance_internet_reachable
from agent_bom.graph.container import UnifiedGraph
from agent_bom.graph.edge import UnifiedEdge
from agent_bom.graph.identity_nodes import identity_node_id as _identity_node_id
from agent_bom.graph.node import NodeDimensions, UnifiedNode
from agent_bom.graph.types import EntityType, RelationshipType
from agent_bom.graph.util import clean_graph_part as _clean_graph_part


def _wire_instance_profile_roles(
    graph: UnifiedGraph,
    inventory: dict[str, Any],
    *,
    provider: str,
    instance_node_by_id: dict[str, str],
) -> None:
    """Link EC2 instance profiles to IAM roles and mark lateral roles exposed."""
    role_by_name = {
        _clean_graph_part(role.get("name")): role
        for role in inventory.get("roles", []) or []
        if isinstance(role, dict) and _clean_graph_part(role.get("name"))
    }
    for instance in inventory.get("instances", []) or []:
        if not isinstance(instance, dict):
            continue
        inst_id = _clean_graph_part(instance.get("instance_id"))
        inst_node = instance_node_by_id.get(inst_id)
        if not inst_node:
            continue
        profile = _clean_graph_part(instance.get("iam_instance_profile"))
        if not profile:
            continue
        role_name = ""
        if ":role/" in profile:
            role_name = profile.rsplit(":role/", 1)[-1].split("/")[0]
        elif profile in role_by_name:
            role_name = profile
        role = role_by_name.get(role_name)
        if role is None:
            continue
        role_arn = _clean_graph_part(role.get("arn")) or role_name
        role_node_id = _identity_node_id(EntityType.ROLE, provider, role_arn)
        if role_node_id not in graph.nodes:
            continue
        graph.add_edge(
            UnifiedEdge(
                source=inst_node,
                target=role_node_id,
                relationship=RelationshipType.ASSUMES,
                evidence={"source": "cloud-inventory", "reason": "ec2_instance_profile"},
            )
        )
        if _instance_internet_reachable(graph, inst_node, instance):
            graph.nodes[role_node_id].attributes["internet_exposed"] = True


def _add_management_group_hierarchy(graph: UnifiedGraph, inventory: dict[str, Any], *, provider: str, data_sources: list[str]) -> None:
    """Build the management-group → subscription hierarchy as ORG nodes + CONTAINS edges.

    Management groups are the tenant tier above subscriptions. Each becomes an
    ``ORG`` node; its children (nested management groups and subscriptions) are
    linked with ``CONTAINS``, so the graph carries the multi-subscription
    hierarchy and blast-radius can reason across the whole tenant. Subscription
    account nodes are created here if a per-subscription scan hasn't already.
    """
    for mg in inventory.get("management_groups", []) or []:
        if not isinstance(mg, dict):
            continue
        name = _clean_graph_part(mg.get("name"))
        if not name:
            continue
        org_node_id = _identity_node_id(EntityType.ORG, provider, name)
        graph.add_node(
            UnifiedNode(
                id=org_node_id,
                entity_type=EntityType.ORG,
                label=_clean_graph_part(mg.get("display_name")) or name,
                attributes={
                    "management_group_id": _clean_graph_part(mg.get("id")),
                    "cloud_provider": provider,
                    "source": "cloud-inventory",
                },
                data_sources=data_sources,
                dimensions=NodeDimensions(cloud_provider=provider, surface="identity"),
            )
        )
        for child in mg.get("children", []) or []:
            if not isinstance(child, dict):
                continue
            child_name = _clean_graph_part(child.get("name"))
            if not child_name:
                continue
            child_type = str(child.get("type") or "").lower()
            if "managementgroups" in child_type:
                # The child ORG node is created when its own entry is processed.
                child_node_id = _identity_node_id(EntityType.ORG, provider, child_name)
            elif "subscriptions" in child_type:
                child_node_id = _identity_node_id(EntityType.ACCOUNT, provider, child_name)
                graph.add_node(
                    UnifiedNode(
                        id=child_node_id,
                        entity_type=EntityType.ACCOUNT,
                        label=_clean_graph_part(child.get("display_name")) or child_name,
                        attributes={"account_id": child_name, "cloud_provider": provider, "source": "cloud-inventory"},
                        data_sources=data_sources,
                        dimensions=NodeDimensions(cloud_provider=provider, surface="identity"),
                    )
                )
            else:
                continue
            graph.add_edge(
                UnifiedEdge(
                    source=org_node_id,
                    target=child_node_id,
                    relationship=RelationshipType.CONTAINS,
                    evidence={"source": "cloud-inventory"},
                )
            )
