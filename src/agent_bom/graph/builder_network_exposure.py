"""Internet exposure wiring for cloud network inventory (firewalls, load balancers, entry points)."""

from __future__ import annotations

from typing import Any

from agent_bom.cloud.normalization import coerce_truthy
from agent_bom.graph.container import UnifiedGraph
from agent_bom.graph.edge import UnifiedEdge
from agent_bom.graph.types import RelationshipType
from agent_bom.graph.util import clean_graph_part as _clean_graph_part


def _gcp_firewall_applies(firewall_attrs: dict[str, Any], instance: dict[str, Any]) -> bool:
    """Return whether a permissive GCP firewall rule reaches *instance*.

    A rule applies when it is on the instance's network AND its target scope
    covers the instance. The target scope is: target tags (instance must carry
    one) OR target service accounts (instance must run as one). An EMPTY target
    set means the rule applies to ALL instances on its network — the GCP default.
    A blank firewall network also matches (the rule scope is the whole project).
    """
    fw_network = _clean_graph_part(firewall_attrs.get("fw_network"))
    inst_network = _clean_graph_part(instance.get("network"))
    if fw_network and inst_network and fw_network != inst_network:
        return False

    target_tags = {str(t).strip() for t in (firewall_attrs.get("fw_target_tags") or []) if str(t).strip()}
    target_sas = {str(s).strip() for s in (firewall_attrs.get("fw_target_service_accounts") or []) if str(s).strip()}
    if not target_tags and not target_sas:
        # No targets → the rule applies to every instance on the network.
        return True
    instance_tags = {str(t).strip() for t in (instance.get("network_tags") or []) if str(t).strip()}
    if target_tags and instance_tags & target_tags:
        return True
    instance_sas = {str(s).strip() for s in (instance.get("service_accounts") or []) if str(s).strip()}
    if target_sas and instance_sas & target_sas:
        return True
    return False


def _apply_gcp_firewall_exposure(
    graph: UnifiedGraph,
    sg_node_by_id: dict[str, str],
    instance_nodes: list[tuple[str, dict[str, Any]]],
) -> None:
    """Mark GCP instances internet-exposed when a permissive firewall reaches them.

    For each instance with an external IP, find every internet-facing
    (``internet_exposed``) firewall node that applies to it (network + target
    tags/SA match). Set ``internet_exposed=True`` on the instance node — which the
    CNAPP overlay preserves — and add an ``EXPOSED_TO`` edge from the firewall to
    the instance, mirroring how an AWS security group exposes an EC2 instance.
    """
    firewall_nodes = [(graph.nodes.get(node_id), node_id) for node_id in sg_node_by_id.values()]
    permissive = [
        (node, node_id) for node, node_id in firewall_nodes if node is not None and coerce_truthy(node.attributes.get("internet_exposed"))
    ]
    if not permissive:
        return
    for inst_node_id, instance in instance_nodes:
        inst_node = graph.nodes.get(inst_node_id)
        if inst_node is None:
            continue
        # Only an instance with an external/public IP can be reached from the
        # internet; a permissive rule on a no-public-IP instance is not exposure.
        if not _clean_graph_part(instance.get("public_ip")):
            continue
        for fw_node, fw_node_id in permissive:
            if not _gcp_firewall_applies(fw_node.attributes, instance):
                continue
            inst_node.attributes["internet_exposed"] = True
            graph.add_edge(
                UnifiedEdge(
                    source=fw_node_id,
                    target=inst_node_id,
                    relationship=RelationshipType.EXPOSED_TO,
                    weight=6.0,
                    evidence={"source": "cloud-inventory", "reason": "permissive_firewall_external_ip"},
                )
            )


def _add_exposure_path_edge(
    graph: UnifiedGraph,
    *,
    source: str,
    target: str,
    reason: str,
    weight: float = 6.0,
) -> None:
    """Emit a provenance-tagged EXPOSED_TO edge when both endpoints exist."""
    if source not in graph.nodes or target not in graph.nodes or source == target:
        return
    for edge in graph.edges:
        if edge.source == source and edge.target == target and edge.relationship == RelationshipType.EXPOSED_TO:
            return
    graph.add_edge(
        UnifiedEdge(
            source=source,
            target=target,
            relationship=RelationshipType.EXPOSED_TO,
            weight=weight,
            evidence={"source": "cloud-inventory", "reason": reason},
        )
    )


def _instance_internet_reachable(graph: UnifiedGraph, inst_node_id: str, instance: dict[str, Any]) -> bool:
    node = graph.nodes.get(inst_node_id)
    if node is None:
        return False
    if coerce_truthy(node.attributes.get("internet_exposed")) or _clean_graph_part(instance.get("public_ip")):
        return True
    return any(e.relationship == RelationshipType.EXPOSED_TO and e.target == inst_node_id for e in graph.edges)


def _link_internet_facing_load_balancers(
    graph: UnifiedGraph,
    load_balancers: list[tuple[str, str]],
    instance_nodes: list[tuple[str, dict[str, Any]]],
) -> None:
    """Link internet-facing LBs to reachable instances in the same VPC."""
    for lb_node_id, lb_vpc_id in load_balancers:
        lb_node = graph.nodes.get(lb_node_id)
        if lb_node is None or not coerce_truthy(lb_node.attributes.get("internet_exposed")):
            continue
        for inst_node_id, instance in instance_nodes:
            inst_vpc = _clean_graph_part(instance.get("vpc_id"))
            if lb_vpc_id and inst_vpc and inst_vpc != lb_vpc_id:
                continue
            if _instance_internet_reachable(graph, inst_node_id, instance):
                _add_exposure_path_edge(
                    graph,
                    source=lb_node_id,
                    target=inst_node_id,
                    reason="internet_facing_load_balancer",
                )
