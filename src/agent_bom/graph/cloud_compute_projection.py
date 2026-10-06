"""Project compute resources and their recorded security-group relationships."""

from __future__ import annotations

from typing import Any

from agent_bom.cloud.normalization import coerce_truthy
from agent_bom.graph.cloud_context import _recorded_exposure_attributes, _resource_environment
from agent_bom.graph.container import UnifiedGraph
from agent_bom.graph.edge import UnifiedEdge
from agent_bom.graph.identity_nodes import identity_node_id as _identity_node_id
from agent_bom.graph.node import NodeDimensions, UnifiedNode
from agent_bom.graph.types import EntityType, RelationshipType
from agent_bom.graph.util import clean_graph_part as _clean_graph_part


def project_security_groups(
    graph: UnifiedGraph,
    inventory: dict[str, Any],
    *,
    provider: str,
    account_id: str,
    region: str,
    data_sources: list[str],
    resource_ids: list[str],
) -> dict[str, str]:
    """Return the recorded security-group index for subsequent instance wiring."""
    # ── EC2 security groups → CLOUD_RESOURCE (carry structured exposure) ──
    sg_node_by_id: dict[str, str] = {}
    for group in inventory.get("security_groups", []) or []:
        if not isinstance(group, dict):
            continue
        group_id = _clean_graph_part(group.get("group_id"))
        if not group_id:
            continue
        sg_service = _clean_graph_part(group.get("_service")) or "ec2"
        sg_kind = _clean_graph_part(group.get("_kind")) or "ec2-security-group"
        sg_resource_type = _clean_graph_part(group.get("_resource_type")) or "security-group"
        sg_env = _resource_environment(group)
        node_id = f"cloud_resource:{provider}:{sg_service}:{sg_resource_type}:{group_id}"
        sg_node_by_id[group_id] = node_id
        graph.add_node(
            UnifiedNode(
                id=node_id,
                entity_type=EntityType.CLOUD_RESOURCE,
                label=f"{sg_resource_type}: {group.get('name') or group_id}",
                attributes={
                    "resource_id": group_id,
                    "resource_name": _clean_graph_part(group.get("name")) or group_id,
                    "resource_type": sg_resource_type,
                    "resource_kind": sg_kind,
                    "cloud_provider": provider,
                    "cloud_service": sg_service,
                    "location": region,
                    "vpc_id": _clean_graph_part(group.get("vpc_id")),
                    **_recorded_exposure_attributes(group, "internet_exposed"),
                    "network_exposure": list(group.get("network_exposure", []) or []),
                    # GCP firewall scoping (empty on AWS); the instance-matching
                    # pass below reads these to know which instances a rule covers.
                    "fw_network": _clean_graph_part(group.get("network")),
                    "fw_target_tags": list(group.get("target_tags", []) or []),
                    "fw_target_service_accounts": list(group.get("target_service_accounts", []) or []),
                    "fw_source_ranges": list(group.get("source_ranges", []) or []),
                    "account_id": account_id,
                    "environment": sg_env,
                },
                data_sources=data_sources,
                dimensions=NodeDimensions(cloud_provider=provider, surface="ec2", environment=sg_env),
            )
        )
        resource_ids.append(node_id)
    return sg_node_by_id


def project_instances(
    graph: UnifiedGraph,
    inventory: dict[str, Any],
    *,
    provider: str,
    account_id: str,
    region: str,
    data_sources: list[str],
    resource_ids: list[str],
    sg_node_by_id: dict[str, str],
) -> list[tuple[str, dict[str, Any]]]:
    """Return instances with their source records for later exposure matching."""
    # ── EC2 instances → CLOUD_RESOURCE (linked to their security groups) ──
    # Track (node_id, raw-instance) so the GCP firewall-matching pass can mark
    # exposure by network + target tags/SA (GCP has no per-instance SG-id list).
    instance_nodes: list[tuple[str, dict[str, Any]]] = []
    for instance in inventory.get("instances", []) or []:
        if not isinstance(instance, dict):
            continue
        instance_id = _clean_graph_part(instance.get("instance_id"))
        if not instance_id:
            continue
        inst_service = _clean_graph_part(instance.get("_service")) or "ec2"
        inst_kind = _clean_graph_part(instance.get("_kind")) or "ec2-instance"
        inst_label = _clean_graph_part(instance.get("_label")) or "ec2"
        node_id = f"cloud_resource:{provider}:{inst_service}:instance:{instance_id}"
        public_ip = _clean_graph_part(instance.get("public_ip"))
        instance_env = _resource_environment(instance)
        graph.add_node(
            UnifiedNode(
                id=node_id,
                entity_type=EntityType.CLOUD_RESOURCE,
                label=f"{inst_label}: {instance.get('name') or instance_id}",
                attributes={
                    "resource_id": instance_id,
                    "resource_name": _clean_graph_part(instance.get("name")) or instance_id,
                    "resource_type": "instance",
                    "resource_kind": inst_kind,
                    "cloud_provider": provider,
                    "cloud_service": inst_service,
                    "location": _clean_graph_part(instance.get("region")) or region,
                    "instance_type": _clean_graph_part(instance.get("instance_type")),
                    "image_id": _clean_graph_part(instance.get("image_id")),
                    "state": _clean_graph_part(instance.get("state")),
                    "vpc_id": _clean_graph_part(instance.get("vpc_id")),
                    "public_ip": public_ip,
                    "private_ip": _clean_graph_part(instance.get("private_ip")),
                    "iam_instance_profile": _clean_graph_part(instance.get("iam_instance_profile")),
                    "security_group_ids": list(instance.get("security_group_ids", []) or []),
                    # GCP instance scoping (empty on AWS); the GCP firewall-matching
                    # pass below reads these to decide which permissive rules apply.
                    "network": _clean_graph_part(instance.get("network")),
                    "network_tags": list(instance.get("network_tags", []) or []),
                    "service_accounts": list(instance.get("service_accounts", []) or []),
                    "account_id": account_id,
                    "environment": instance_env,
                },
                data_sources=data_sources,
                dimensions=NodeDimensions(cloud_provider=provider, surface="ec2", environment=instance_env),
            )
        )
        resource_ids.append(node_id)
        instance_nodes.append((node_id, instance))
        _link_instance_security_groups(graph, node_id, instance, sg_node_by_id)
        _link_instance_managed_identities(graph, node_id, instance, provider)
    return instance_nodes


def _link_instance_security_groups(graph: UnifiedGraph, node_id: str, instance: dict[str, Any], sg_node_by_id: dict[str, str]) -> None:
    """Link only recorded groups and preserve their qualified exposure flags."""
    for sg_id in instance.get("security_group_ids", []) or []:
        sg_node_id = sg_node_by_id.get(_clean_graph_part(sg_id))
        if not sg_node_id:
            continue
        graph.add_edge(
            UnifiedEdge(source=node_id, target=sg_node_id, relationship=RelationshipType.PART_OF, evidence={"source": "cloud-inventory"})
        )
        # An internet-facing security group exposes the instances in it.
        sg_node = graph.nodes.get(sg_node_id)
        if sg_node is not None and coerce_truthy(sg_node.attributes.get("internet_exposed")):
            graph.add_edge(
                UnifiedEdge(
                    source=sg_node_id,
                    target=node_id,
                    relationship=RelationshipType.EXPOSED_TO,
                    weight=6.0,
                    evidence={"source": "cloud-inventory", "reason": "internet_facing_security_group"},
                )
            )


def _link_instance_managed_identities(graph: UnifiedGraph, node_id: str, instance: dict[str, Any], provider: str) -> None:
    """Record identity assumptions before the identity projection creates principals."""
    # A user-assigned managed identity is assumed by the VM: the identity's
    # permissions become the VM's blast radius. ASSUMES from the VM node to
    # each managed-identity node (those nodes are added by the principal pass
    # below; edges may reference them ahead of creation).
    for mi_arm_id in instance.get("user_assigned_identity_ids", []) or []:
        mi_clean = _clean_graph_part(mi_arm_id)
        if not mi_clean:
            continue
        mi_node_id = _identity_node_id(EntityType.MANAGED_IDENTITY, provider, mi_clean)
        graph.add_edge(
            UnifiedEdge(
                source=node_id,
                target=mi_node_id,
                relationship=RelationshipType.ASSUMES,
                weight=5.0,
                evidence={"source": "cloud-inventory", "reason": "vm_user_assigned_identity"},
            )
        )
