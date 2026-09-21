"""Provider flags must survive graph construction without inventing exposure."""

from copy import deepcopy

import pytest

from agent_bom.api.graph_store import SQLiteGraphStore
from agent_bom.graph.aspm_overlay import _node_is_exposed
from agent_bom.graph.attack_path_fusion import apply_attack_path_fusion
from agent_bom.graph.builder import build_unified_graph_from_report
from agent_bom.graph.cnapp_overlay import apply_cnapp_overlay
from agent_bom.graph.container import UnifiedGraph
from agent_bom.graph.cost_overlay import _is_high_risk
from agent_bom.graph.edge import UnifiedEdge
from agent_bom.graph.nhi_governance import _exposed_targets
from agent_bom.graph.node import UnifiedNode
from agent_bom.graph.path_derivation import _fusion_signals_for_path
from agent_bom.graph.rollup import RollupFilters, rollup_view
from agent_bom.graph.toxic_findings import build_toxic_combination_findings
from agent_bom.graph.types import EntityType, RelationshipType


@pytest.mark.parametrize("provider,collection", [("aws", "buckets"), ("azure", "storage_accounts"), ("gcp", "buckets")])
@pytest.mark.parametrize(
    "value,expected", [(False, False), ("false", False), ("0", False), ("unknown", None), (None, None), (True, True), ("true", True)]
)
@pytest.mark.parametrize("name", ["private-data", "not-public-data"])
def test_provider_exposure_flags_remain_qualified_through_build_sqlite_and_rollup(tmp_path, provider, collection, value, expected, name):
    report = {
        "scan_id": "flags",
        "cloud_inventory": {
            "provider": provider,
            "status": "ok",
            "account_id": "account-a",
            collection: [{"name": name, "publicly_accessible": value}],
        },
    }
    before = deepcopy(report)
    graph = build_unified_graph_from_report(report, tenant_id="default")
    store = SQLiteGraphStore(tmp_path / "flags.db")
    store.save_graph(graph)
    restored = SQLiteGraphStore(tmp_path / "flags.db").load_graph(scan_id="flags", tenant_id="default")
    resource = next(node for node in restored.nodes.values() if node.entity_type == EntityType.CLOUD_RESOURCE)
    assert resource.attributes["internet_exposed"] is expected
    assert resource.attributes["internet_exposure_evidence"]["inputs"]["publicly_accessible"] == value
    companion = restored.nodes[f"data_store:{resource.id}"]
    assert companion.attributes["internet_exposed"] is expected
    assert report == before
    exposed_edges = [edge for edge in restored.edges if edge.relationship == RelationshipType.EXPOSED_TO]
    assert bool(exposed_edges) is (expected is True)
    payload = rollup_view(restored, filters=RollupFilters(exposed_only=True))
    count = sum(item["aggregate"]["exposed_count"] for item in payload["top_level"])
    assert bool(count) is (expected is True)
    if expected is not True:
        assert not restored.attack_paths


@pytest.mark.parametrize("name", ["private-data", "public-data", "not-public-data"])
def test_resource_names_and_absent_flags_do_not_establish_exposure(name):
    graph = build_unified_graph_from_report(
        {
            "cloud_inventory": {
                "provider": "aws",
                "status": "ok",
                "account_id": "account-a",
                "buckets": [{"name": name}],
            }
        }
    )
    resource = next(node for node in graph.nodes.values() if node.entity_type == EntityType.CLOUD_RESOURCE)
    assert resource.attributes["internet_exposed"] is None
    assert resource.attributes["internet_exposure_evidence"]["inputs"] == {}
    assert not any(edge.relationship == RelationshipType.EXPOSED_TO for edge in graph.edges)


@pytest.mark.parametrize("label", ["public access allowed", "public access disabled", "not publicly accessible", "no internet route"])
def test_unstructured_finding_text_is_context_not_observed_exposure(label):
    graph = UnifiedGraph(scan_id="text", tenant_id="default")
    graph.add_node(UnifiedNode(id="resource", entity_type=EntityType.CLOUD_RESOURCE, label="private bucket"))
    graph.add_node(UnifiedNode(id="finding", entity_type=EntityType.MISCONFIGURATION, label=label))
    graph.add_edge(UnifiedEdge(source="finding", target="resource", relationship=RelationshipType.AFFECTS))
    apply_cnapp_overlay(graph)
    assert graph.nodes["finding"].label == label
    assert graph.nodes["resource"].attributes.get("internet_exposed") is not True
    assert not any(edge.relationship == RelationshipType.EXPOSED_TO for edge in graph.edges)


def test_structured_public_rule_still_establishes_recorded_exposure():
    graph = UnifiedGraph(scan_id="rule", tenant_id="default")
    graph.add_node(UnifiedNode(id="resource", entity_type=EntityType.CLOUD_RESOURCE, label="private bucket"))
    graph.add_node(
        UnifiedNode(
            id="finding",
            entity_type=EntityType.MISCONFIGURATION,
            label="network rule",
            attributes={
                "network_exposure": [{"scope": "internet", "from_port": 443, "to_port": 443, "protocol": "tcp"}],
            },
        )
    )
    graph.add_edge(UnifiedEdge(source="finding", target="resource", relationship=RelationshipType.AFFECTS))
    apply_cnapp_overlay(graph)
    assert graph.nodes["resource"].attributes["internet_exposed"] is True
    assert graph.nodes["resource"].attributes["exposed_ports"] == [{"from_port": 443, "to_port": 443, "protocol": "tcp"}]
    assert any(edge.relationship == RelationshipType.EXPOSED_TO for edge in graph.edges)


@pytest.mark.parametrize("value", ["false", "unknown", "0", False])
def test_imported_legacy_flag_values_remain_unchanged_but_cannot_drive_rollup_or_fusion(tmp_path, value):
    graph = UnifiedGraph(scan_id="legacy-flags", tenant_id="default")
    graph.add_node(
        UnifiedNode.from_dict(
            {
                "id": "resource",
                "entity_type": "cloud_resource",
                "label": "Resource",
                "attributes": {
                    "internet_exposed": value,
                    "toxic_exposed_vulnerable": value,
                    "toxic_exposed_sensitive": value,
                },
            }
        )
    )
    graph.add_node(
        UnifiedNode(id="data", entity_type=EntityType.DATA_STORE, label="Sensitive data", attributes={"data_sensitivity": "sensitive"})
    )
    graph.add_edge(UnifiedEdge(source="resource", target="data", relationship=RelationshipType.CAN_ACCESS))
    store = SQLiteGraphStore(tmp_path / "legacy.db")
    store.save_graph(graph)
    restored = SQLiteGraphStore(tmp_path / "legacy.db").load_graph(scan_id=graph.scan_id, tenant_id="default")
    before = deepcopy(restored.to_dict())
    assert not rollup_view(restored, filters=RollupFilters(exposed_only=True))["top_level"]
    assert not rollup_view(restored, filters=RollupFilters(toxic_only=True))["top_level"]
    assert not _fusion_signals_for_path(restored, ["resource"])
    assert not build_toxic_combination_findings(restored)
    assert not _node_is_exposed(restored.nodes["resource"])
    assert not _is_high_risk(restored.nodes["resource"])
    assert not _exposed_targets(restored, {"resource"})
    apply_attack_path_fusion(restored)
    assert not restored.attack_paths
    assert restored.nodes["resource"].attributes["internet_exposed"] == value
    persisted_again = SQLiteGraphStore(tmp_path / "legacy.db").load_graph(scan_id=graph.scan_id, tenant_id="default")
    assert persisted_again.to_dict() == before


@pytest.mark.parametrize("provider,collection", [("aws", "buckets"), ("azure", "storage_accounts"), ("gcp", "buckets")])
@pytest.mark.parametrize("value,expected", [("false", False), ("unknown", None), ("true", True)])
def test_recorded_exposure_and_receipts_survive_graph_and_rollup_api(tmp_path, provider, collection, value, expected):
    from starlette.testclient import TestClient

    from agent_bom.api import stores
    from agent_bom.api.server import app

    graph = build_unified_graph_from_report(
        {
            "scan_id": "api-flags",
            "cloud_inventory": {
                "provider": provider,
                "status": "ok",
                "account_id": "account-a",
                collection: [{"name": "not-public-data", "publicly_accessible": value}],
            },
        },
        tenant_id="default",
    )
    store = SQLiteGraphStore(tmp_path / "api.db")
    store.save_graph(graph)
    before = store.load_graph(scan_id=graph.scan_id, tenant_id="default").to_dict()
    original = stores._graph_store
    try:
        stores.set_graph_store(store)
        client = TestClient(app)
        response = client.get("/v1/graph", params={"scan_id": graph.scan_id})
        assert response.status_code == 200
        resource = next(node for node in response.json()["nodes"] if node["entity_type"] == "cloud_resource")
        assert resource["attributes"]["internet_exposed"] is expected
        assert resource["attributes"]["internet_exposure_evidence"]["inputs"] == {"publicly_accessible": value}
        rollup = client.get("/v1/graph/rollup", params={"scan_id": graph.scan_id, "exposed_only": True})
        assert rollup.status_code == 200
        count = sum(item["aggregate"]["exposed_count"] for item in rollup.json()["top_level"])
        assert bool(count) is (expected is True)
        assert store.load_graph(scan_id=graph.scan_id, tenant_id="default").to_dict() == before
    finally:
        stores.set_graph_store(original)


@pytest.mark.parametrize(
    "provider,section,collection",
    [("aws", "cis_benchmark", "buckets"), ("azure", "azure_cis_benchmark", "storage_accounts"), ("gcp", "gcp_cis_benchmark", "buckets")],
)
def test_structured_public_rule_preserves_its_source_and_original_negative_flag(tmp_path, provider, section, collection):
    rule = {"scope": "internet", "protocol": "tcp", "from_port": 443, "to_port": 443}
    graph = build_unified_graph_from_report(
        {
            "scan_id": "structured-rule",
            "cloud_inventory": {
                "provider": provider,
                "status": "ok",
                "account_id": "account-a",
                collection: [{"name": "private-data", "publicly_accessible": "false"}],
            },
            section: {
                "provider": provider,
                "checks": [
                    {
                        "check_id": "public-rule",
                        "status": "FAIL",
                        "title": "Recorded rule",
                        "resource_ids": ["private-data"],
                        "network_exposure": [rule],
                    }
                ],
            },
        },
        tenant_id="default",
    )
    store = SQLiteGraphStore(tmp_path / "rule.db")
    store.save_graph(graph)
    restored = store.load_graph(scan_id=graph.scan_id, tenant_id="default")
    resource = next(node for node in restored.nodes.values() if node.entity_type == EntityType.CLOUD_RESOURCE)
    assert resource.attributes["internet_exposed"] is True
    receipt = resource.attributes["internet_exposure_evidence"]
    assert receipt["inputs"] == {"publicly_accessible": "false"}
    assert receipt["network_rules"] == [{"finding_id": f"misconfig:{section}:public-rule", "sources": [section], "rules": [rule]}]
    assert any(edge.relationship == RelationshipType.EXPOSED_TO for edge in restored.edges)


@pytest.mark.parametrize("value,expected", [("false", False), ("unknown", None), ("true", True)])
def test_subnet_text_flags_cannot_create_public_network_path(value, expected):
    graph = build_unified_graph_from_report(
        {
            "cloud_inventory": {
                "provider": "aws",
                "status": "ok",
                "account_id": "account-a",
                "subnets": [{"id": "subnet-a", "name": "public-subnet", "vpc_id": "vpc-a", "is_public": value}],
                "internet_gateways": [{"id": "gateway-a", "vpc_id": "vpc-a"}],
            }
        }
    )
    subnet = graph.nodes["cloud_resource:aws:network:subnet:subnet-a"]
    assert subnet.attributes["internet_exposed"] is expected
    assert any(edge.relationship == RelationshipType.EXPOSED_TO and edge.target == subnet.id for edge in graph.edges) is (expected is True)


@pytest.mark.parametrize(
    "flags,expected",
    [
        ({"publicly_accessible": "false", "internet_exposed": "false"}, False),
        ({"publicly_accessible": "false", "internet_exposed": "unknown"}, None),
        ({"publicly_accessible": "false", "endpoint_public": "true"}, True),
    ],
)
def test_multiple_provider_flags_require_an_explicit_positive(flags, expected):
    graph = build_unified_graph_from_report(
        {"cloud_inventory": {"provider": "aws", "status": "ok", "rds_instances": [{"name": "db", **flags}]}}
    )
    resource = graph.nodes["cloud_resource:aws:rds:database:db"]
    assert resource.attributes["internet_exposed"] is expected
    assert resource.attributes["internet_exposure_evidence"]["inputs"] == flags


def test_generic_ip_address_on_database_is_not_a_public_ip_receipt():
    graph = build_unified_graph_from_report(
        {
            "cloud_inventory": {
                "provider": "azure",
                "status": "ok",
                "databases": [{"name": "private-db", "id": "db-a", "ip_address": "10.0.0.2"}],
            }
        }
    )
    resource = next(node for node in graph.nodes.values() if node.entity_type == EntityType.CLOUD_RESOURCE)
    assert resource.attributes["internet_exposed"] is None
    assert not any(edge.relationship == RelationshipType.EXPOSED_TO for edge in graph.edges)
