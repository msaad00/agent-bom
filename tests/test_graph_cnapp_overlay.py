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


def test_resource_tags_drive_data_sensitivity_cross_cloud():
    """AWS/Azure tags (and GCP labels) carrying a classification feed the shared
    sensitivity classifier — an internet-exposed tagged bucket becomes a toxic,
    GDPR-classified crown jewel, exactly as a Snowflake-tagged object would."""
    graph = UnifiedGraph(scan_id="s", tenant_id="t")
    graph.add_node(
        UnifiedNode(
            id="cloud:s3-pii",
            entity_type=EntityType.CLOUD_RESOURCE,
            label="customer S3 bucket",  # label alone carries no sensitivity keyword
            attributes={
                "resource_type": "bucket",
                "internet_exposed": True,
                "tags": {"classification": "pii", "env": "prod"},
            },
        )
    )

    apply_cnapp_overlay(graph)

    companion = graph.nodes.get("data_store:cloud:s3-pii")
    assert companion is not None, "CNAPP must attach a DATA_STORE companion to the bucket"
    assert companion.attributes.get("data_sensitivity") == "sensitive"
    # internet-exposed + sensitive ⇒ toxic, and the pii tag classifies it GDPR.
    assert companion.attributes.get("toxic_exposed_sensitive") is True
    assert "GDPR" in (companion.attributes.get("data_regulatory_frameworks") or [])
    assert companion.attributes.get("data_classification_tier") == "restricted"


def test_non_sensitive_tags_do_not_falsely_classify():
    graph = UnifiedGraph(scan_id="s", tenant_id="t")
    graph.add_node(
        UnifiedNode(
            id="cloud:s3-plain",
            entity_type=EntityType.CLOUD_RESOURCE,
            label="logs S3 bucket",
            attributes={"resource_type": "bucket", "internet_exposed": True, "tags": {"env": "prod", "team": "ops"}},
        )
    )
    apply_cnapp_overlay(graph)
    companion = graph.nodes.get("data_store:cloud:s3-plain")
    assert companion is not None
    assert not companion.attributes.get("data_sensitivity")
    assert not companion.attributes.get("toxic_exposed_sensitive")


def test_content_classification_drives_sensitive_data_store_risk():
    graph = UnifiedGraph(scan_id="s", tenant_id="t")
    graph.add_node(
        UnifiedNode(
            id="cloud:s3-classified",
            entity_type=EntityType.CLOUD_RESOURCE,
            label="customer exports bucket",
            attributes={
                "resource_type": "bucket",
                "internet_exposed": True,
                "content_classification": {
                    "schema_version": "agent-bom.dspm.s3_classification.v1",
                    "status": "ok",
                    "objects_sampled": 2,
                    "total_findings": 4,
                    "findings_by_type": {"credit_card": 1, "email": 3},
                    "sensitivity_score": 90,
                    "data_sensitivity": "sensitive",
                    "redaction": "raw object bytes and matched values are not stored",
                },
            },
        )
    )

    stats = apply_cnapp_overlay(graph)

    companion = graph.nodes.get("data_store:cloud:s3-classified")
    assert companion is not None, "classified object-store evidence must flow into the graph"
    assert companion.attributes.get("data_sensitivity") == "sensitive"
    assert companion.attributes.get("toxic_exposed_sensitive") is True
    assert companion.attributes.get("data_classification_tier") == "restricted"
    assert "PCI-DSS" in (companion.attributes.get("data_regulatory_frameworks") or [])
    assert companion.attributes.get("data_classification_source") == "content_sampling"
    assert companion.attributes.get("content_classification_counts") == {"credit_card": 1, "email": 3}
    assert companion.attributes.get("content_classification_findings") == 4
    assert companion.attributes.get("content_objects_sampled") == 2
    assert stats["sensitive_data_nodes"] == 1
    assert stats["exposed_sensitive_data"] == 1


def test_review_content_classification_does_not_escalate_to_sensitive():
    graph = UnifiedGraph(scan_id="s", tenant_id="t")
    graph.add_node(
        UnifiedNode(
            id="cloud:gcs-review",
            entity_type=EntityType.CLOUD_RESOURCE,
            label="analytics bucket",
            attributes={
                "resource_type": "bucket",
                "internet_exposed": True,
                "content_classification": {
                    "schema_version": "agent-bom.dspm.gcs_classification.v1",
                    "status": "ok",
                    "objects_sampled": 1,
                    "total_findings": 1,
                    "findings_by_type": {"phone": 1},
                    "sensitivity_score": 30,
                    "data_sensitivity": "review",
                },
            },
        )
    )

    stats = apply_cnapp_overlay(graph)

    companion = graph.nodes.get("data_store:cloud:gcs-review")
    assert companion is not None
    assert companion.attributes.get("content_data_sensitivity") == "review"
    assert companion.attributes.get("data_classification_source") == "content_sampling"
    assert companion.attributes.get("data_sensitivity") is None
    assert companion.attributes.get("toxic_exposed_sensitive") is None
    assert stats["sensitive_data_nodes"] == 0
    assert stats["exposed_sensitive_data"] == 0
