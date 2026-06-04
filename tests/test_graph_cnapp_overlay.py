"""Cloud-CNAPP overlay: internet exposure, data stores, toxic chains."""

from __future__ import annotations

from agent_bom.graph.cnapp_overlay import apply_cnapp_overlay
from agent_bom.graph.container import UnifiedGraph
from agent_bom.graph.edge import UnifiedEdge
from agent_bom.graph.node import UnifiedNode
from agent_bom.graph.types import EntityType, NodeStatus, RelationshipType


def _rels(graph, rel):
    return [(e.source, e.target) for e in graph.edges if e.relationship == rel]


def test_overlay_marks_exposure_classifies_data_store_and_flags_toxic():
    graph = UnifiedGraph(scan_id="s", tenant_id="t")
    graph.add_node(
        UnifiedNode(
            id="cloud:s3-prod",
            entity_type=EntityType.CLOUD_RESOURCE,
            label="prod-data S3 bucket",
            attributes={"resource_type": "s3"},
        )
    )
    graph.add_node(
        UnifiedNode(
            id="mc:public",
            entity_type=EntityType.MISCONFIGURATION,
            label="S3 bucket is publicly accessible",
        )
    )
    graph.add_node(UnifiedNode(id="vuln:CVE-1", entity_type=EntityType.VULNERABILITY, label="CVE-1", severity="critical"))
    # misconfig AFFECTS the bucket; bucket VULNERABLE_TO a CVE.
    graph.add_edge(UnifiedEdge(source="mc:public", target="cloud:s3-prod", relationship=RelationshipType.AFFECTS))
    graph.add_edge(UnifiedEdge(source="cloud:s3-prod", target="vuln:CVE-1", relationship=RelationshipType.VULNERABLE_TO))

    stats = apply_cnapp_overlay(graph)

    bucket = graph.nodes["cloud:s3-prod"]
    assert bucket.attributes.get("internet_exposed") is True
    assert bucket.attributes.get("toxic_exposed_vulnerable") is True
    assert bucket.status == NodeStatus.VULNERABLE
    assert bucket.risk_score >= 9.0

    # data store companion + STORES edge + EXPOSED_TO edge
    ds_nodes = [n for n in graph.nodes.values() if n.entity_type == EntityType.DATA_STORE]
    assert len(ds_nodes) == 1
    ds_id = ds_nodes[0].id
    assert ("cloud:s3-prod", ds_id) in _rels(graph, RelationshipType.STORES)
    assert ("cloud:s3-prod", ds_id) in _rels(graph, RelationshipType.EXPOSED_TO)

    assert stats["exposed_nodes"] == 1
    assert stats["data_stores_added"] == 1
    assert stats["toxic_combinations"] == 1
    assert any(r.pattern == "internet_exposed_vulnerable" for r in graph.interaction_risks)


def test_overlay_no_exposure_is_noop_for_private_resources():
    graph = UnifiedGraph(scan_id="s", tenant_id="t")
    graph.add_node(UnifiedNode(id="cloud:rds", entity_type=EntityType.CLOUD_RESOURCE, label="internal RDS database"))
    graph.add_node(UnifiedNode(id="mc:enc", entity_type=EntityType.MISCONFIGURATION, label="RDS encryption disabled"))
    graph.add_edge(UnifiedEdge(source="mc:enc", target="cloud:rds", relationship=RelationshipType.AFFECTS))

    stats = apply_cnapp_overlay(graph)
    # RDS is a data store, but not internet-exposed → DATA_STORE added, no toxic/exposed.
    assert stats["data_stores_added"] == 1
    assert stats["exposed_nodes"] == 0
    assert stats["toxic_combinations"] == 0
    assert graph.nodes["cloud:rds"].attributes.get("internet_exposed") is None


def test_structured_network_exposure_is_port_aware():
    from agent_bom.api.routes.graph import _fusion_signals_for_path

    g = UnifiedGraph(scan_id="s", tenant_id="t")
    g.add_node(UnifiedNode(id="cloud:vm", entity_type=EntityType.CLOUD_RESOURCE, label="bastion vm"))
    g.add_node(
        UnifiedNode(
            id="mc:sg",
            entity_type=EntityType.MISCONFIGURATION,
            label="security group allows admin access",
            attributes={
                "network_exposure": [{"resource": "sg-bad", "from_port": 22, "to_port": 22, "protocol": "tcp", "scope": "internet"}]
            },
        )
    )
    g.add_edge(UnifiedEdge(source="mc:sg", target="cloud:vm", relationship=RelationshipType.AFFECTS))

    apply_cnapp_overlay(g)
    vm = g.nodes["cloud:vm"]
    # Structured exposure (no exposure keyword in the label) still marks it exposed,
    # and attaches the specific open port.
    assert vm.attributes.get("internet_exposed") is True
    assert vm.attributes.get("exposed_ports") == [{"from_port": 22, "to_port": 22, "protocol": "tcp"}]
    # The attack-path reason names the port.
    detail = next(d for k, _l, d, _b in _fusion_signals_for_path(g, ["cloud:vm"]) if k == "internet_exposed")
    assert "port(s) 22" in detail
