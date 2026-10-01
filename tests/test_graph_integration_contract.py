"""Public graph compatibility and evidence boundaries for external consumers."""

import pytest

from agent_bom.graph import EntityType, RelationshipType, UnifiedEdge, UnifiedGraph, UnifiedNode
from agent_bom.graph.attack_path_fusion import _edge_boost


def test_graph_envelope_version_and_legacy_roundtrip():
    graph = UnifiedGraph(scan_id="snapshot", tenant_id="tenant")
    graph.add_node(UnifiedNode(id="tool:one", entity_type=EntityType.TOOL, label="Tool", attributes={"canonical_id": "external:one"}))
    payload = graph.to_dict()
    assert payload["schema_version"] == "agent-bom.graph/v1"
    payload["future_optional_field"] = {"safe": True}
    restored = UnifiedGraph.from_dict(payload)
    assert restored.nodes["tool:one"].canonical_id == "external:one"
    payload.pop("schema_version")
    assert UnifiedGraph.from_dict(payload).tenant_id == "tenant"


@pytest.mark.parametrize("version", ["agent-bom.graph/v2", "other/v1", "", None, 1])
def test_unknown_explicit_version_fails_closed(version):
    with pytest.raises(ValueError, match="Unsupported graph schema version"):
        UnifiedGraph.from_dict({"schema_version": version, "nodes": [], "edges": []})


def test_provenance_preserves_sources_without_inventing_observed_execution():
    node = UnifiedNode(
        id="tool:one",
        entity_type=EntityType.TOOL,
        label="Tool",
        data_sources=["gateway_runtime", "mcp_config"],
        attributes={"evidence_tier": "modeled_infrastructure"},
    )
    evidence = node.to_dict()["evidence_provenance"]
    assert evidence["tier"] == "modeled_infrastructure"
    assert evidence["sources"] == ["gateway_runtime", "mcp_config"]
    assert evidence["execution"] == "not_established"
    assert UnifiedNode.from_dict(node.to_dict()).to_dict()["evidence_provenance"] == evidence


def test_source_name_alone_never_promotes_runtime_observation():
    node = UnifiedNode(id="tool:one", entity_type=EntityType.TOOL, label="Tool", data_sources=["gateway_runtime"])
    assert node.to_dict()["evidence_provenance"]["tier"] == "unspecified"
    assert node.to_dict()["evidence_provenance"]["sources"] == ["gateway_runtime"]


@pytest.mark.parametrize("relationship", [RelationshipType.VULNERABLE_TO, RelationshipType.HAS_PERMISSION, RelationshipType.CAN_ACCESS])
def test_structural_path_narration_does_not_assert_execution(relationship):
    node = UnifiedNode(id="target", entity_type=EntityType.VULNERABILITY, label="Target")
    _, narrative = _edge_boost(UnifiedEdge(source="a", target="target", relationship=relationship), node)
    assert not any(claim in narrative for claim in ("exploits ", "uses effective permission", "accesses "))


def test_unknown_entity_kind_is_rejected_instead_of_silently_disappearing():
    with pytest.raises(ValueError):
        UnifiedGraph.from_dict({"schema_version": "agent-bom.graph/v1", "nodes": [{"id": "x", "entity_type": "future_kind", "label": "X"}]})


def test_rest_mcp_exposure_share_versioned_provenance():
    from agent_bom.graph import AttackPath
    from agent_bom.graph.exposure import _exposure_path_for_attack_path
    from agent_bom.mcp_tools.graph import _exposure_path_payload

    node = UnifiedNode(id="tool", entity_type=EntityType.TOOL, label="Tool", data_sources=["mcp_config"])
    path = AttackPath(source="tool", target="tool", hops=["tool"])
    rest = _exposure_path_for_attack_path(path, nodes_by_id={"tool": node}, scan_id="s")
    mcp = _exposure_path_payload(path, nodes_by_id={"tool": node}, edges=[], rank=1, scan_id="s")
    assert rest["schemaVersion"] == mcp["schemaVersion"] == "agent-bom.graph-evidence/v1"
    assert rest["source"]["evidenceProvenance"] == mcp["source"]["evidenceProvenance"]


def test_relationship_kind_compatibility_and_context_roundtrip():
    from agent_bom.graph import NodeDimensions

    graph = UnifiedGraph(scan_id="context", tenant_id="tenant")
    for kind in (EntityType.ORG, EntityType.ACCOUNT, EntityType.ENVIRONMENT, EntityType.CLOUD_RESOURCE, EntityType.SERVICE_ACCOUNT):
        graph.add_node(
            UnifiedNode(
                id=kind.value,
                entity_type=kind,
                label=kind.value,
                dimensions=NodeDimensions(cloud_provider="aws", environment="production"),
                attributes={"canonical_id": "canonical:" + kind.value},
                data_sources=["inventory"],
            )
        )
    graph.add_edge(UnifiedEdge(source="account", target="cloud_resource", relationship=RelationshipType.CONTAINS))
    payload = graph.to_dict()
    restored = UnifiedGraph.from_dict(payload)
    # Deserialization normalizes risk-assessment attributes and recomputes
    # derived statistics; the versioned identity/context contract is stable.
    restored_payload = restored.to_dict()
    assert restored_payload["schema_version"] == payload["schema_version"]
    assert restored_payload["edges"] == payload["edges"]
    for before, after in zip(payload["nodes"], restored_payload["nodes"], strict=True):
        for key in ("id", "canonical_id", "entity_type", "dimensions", "evidence_provenance", "data_sources"):
            assert after[key] == before[key]
    assert restored.nodes["cloud_resource"].dimensions.environment == "production"
    assert restored.nodes["service_account"].canonical_id == "canonical:service_account"
    payload["edges"][0]["relationship"] = "unknown_future_relationship"
    with pytest.raises(ValueError):
        UnifiedGraph.from_dict(payload)
