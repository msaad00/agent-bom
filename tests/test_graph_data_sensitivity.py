"""Data-sensitivity classification and path-to-sensitive-data attack paths."""

from __future__ import annotations

from agent_bom.api.routes.graph import _derived_governance_attack_paths, _fusion_signals_for_path
from agent_bom.graph.cnapp_overlay import _is_sensitive, apply_cnapp_overlay
from agent_bom.graph.container import UnifiedGraph
from agent_bom.graph.edge import UnifiedEdge
from agent_bom.graph.node import UnifiedNode
from agent_bom.graph.types import EntityType, RelationshipType


def test_is_sensitive_reads_flags_tags_and_label():
    pii_dataset = UnifiedNode(
        id="dataset:d1",
        entity_type=EntityType.DATASET,
        label="customers",
        attributes={"security_flags": [{"type": "pii_detected", "description": "emails and SSNs found"}]},
    )
    assert _is_sensitive(pii_dataset)
    gdpr_dataset = UnifiedNode(id="dataset:d2", entity_type=EntityType.DATASET, label="eu-users", compliance_tags=["GDPR-Art5"])
    assert _is_sensitive(gdpr_dataset)
    benign = UnifiedNode(id="dataset:d3", entity_type=EntityType.DATASET, label="public weather data")
    assert not _is_sensitive(benign)


def test_exposed_sensitive_data_store_is_toxic_and_scored():
    g = UnifiedGraph(scan_id="s", tenant_id="t")
    g.add_node(
        UnifiedNode(
            id="cloud:bucket",
            entity_type=EntityType.CLOUD_RESOURCE,
            label="customer-pii prod S3 bucket",
            attributes={"resource_type": "s3"},
        )
    )
    g.add_node(UnifiedNode(id="mc:public", entity_type=EntityType.MISCONFIGURATION, label="S3 bucket is publicly accessible"))
    g.add_edge(UnifiedEdge(source="mc:public", target="cloud:bucket", relationship=RelationshipType.AFFECTS))

    stats = apply_cnapp_overlay(g)
    assert stats["sensitive_data_nodes"] >= 1
    assert stats["exposed_sensitive_data"] == 1

    ds = next(n for n in g.nodes.values() if n.entity_type == EntityType.DATA_STORE)
    assert ds.attributes.get("data_sensitivity") == "sensitive"
    assert ds.attributes.get("internet_exposed") is True
    assert ds.attributes.get("toxic_exposed_sensitive") is True
    assert ds.risk_score >= 9.5
    assert any(r.pattern == "internet_exposed_sensitive_data" for r in g.interaction_risks)

    # fusion signal surfaces on a path through the sensitive-exposed data store
    kinds = {k for k, _l, _d, _b in _fusion_signals_for_path(g, [ds.id])}
    assert "exposed_sensitive_data" in kinds

    # the data-exposure attack path to the sensitive store is top-banded
    paths = _derived_governance_attack_paths(g)
    data_paths = [p for p in paths if p.target == ds.id]
    assert data_paths and "sensitive" in data_paths[0].summary
    assert data_paths[0].composite_risk >= 85


def test_non_sensitive_store_not_flagged():
    g = UnifiedGraph(scan_id="s", tenant_id="t")
    g.add_node(
        UnifiedNode(id="cloud:logs", entity_type=EntityType.CLOUD_RESOURCE, label="app logs bucket", attributes={"resource_type": "s3"})
    )
    stats = apply_cnapp_overlay(g)
    assert stats["data_stores_added"] == 1
    assert stats["sensitive_data_nodes"] == 0
    ds = next(n for n in g.nodes.values() if n.entity_type == EntityType.DATA_STORE)
    assert ds.attributes.get("data_sensitivity") is None
