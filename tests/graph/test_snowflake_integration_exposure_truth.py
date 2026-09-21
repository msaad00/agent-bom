"""Configured Snowflake egress is not observed inbound reachability or exfiltration."""

from copy import deepcopy

import pytest

from agent_bom.api.graph_store import SQLiteGraphStore
from agent_bom.graph.builder import build_unified_graph_from_report
from agent_bom.graph.path_derivation import _fusion_signals_for_path
from agent_bom.graph.rollup import RollupFilters, rollup_view
from agent_bom.graph.types import RelationshipType


def _report(category="STORAGE", enabled=True):
    return {
        "scan_id": "integration",
        "snowflake_integrations": {
            "status": "ok",
            "account": "ACCT",
            "integrations": [{"name": "PII_S3_STORE", "category": category, "type": "EXTERNAL_STAGE", "enabled": enabled}],
        },
    }


@pytest.mark.parametrize("category", ["STORAGE", "API", "EXTERNAL_ACCESS", "NOTIFICATION", "CATALOG"])
@pytest.mark.parametrize("raw,enabled", [(True, True), (False, False), ("false", False), ("unknown", None), (None, None)])
def test_enabled_integration_records_outbound_configuration_without_inbound_exposure(tmp_path, category, raw, enabled):
    report = _report(category, raw)
    original = deepcopy(report)
    graph = build_unified_graph_from_report(report, tenant_id="default")
    store = SQLiteGraphStore(tmp_path / "egress.db")
    store.save_graph(graph)
    restored = SQLiteGraphStore(tmp_path / "egress.db").load_graph(scan_id=graph.scan_id, tenant_id="default")
    node = restored.nodes["cloud_resource:snowflake:integration:PII_S3_STORE"]
    assert node.attributes["internet_exposed"] is None
    assert node.attributes["enabled"] is enabled
    assert node.attributes["outbound_access_configured"] is enabled
    assert node.attributes["integration_evidence"] == {
        "source": "snowflake-integrations",
        "basis": "recorded_configuration",
        "network_direction": "outbound",
        "access_outcome": "not_observed",
        "inputs": {"category": category, "type": "EXTERNAL_STAGE", "enabled": raw},
    }
    assert "snowflake-integrations" in node.data_sources
    assert node.attributes["account_id"] == "ACCT"
    assert not any(edge.relationship == RelationshipType.EXPOSED_TO for edge in restored.edges)
    assert not restored.attack_paths
    assert not _fusion_signals_for_path(restored, [node.id])
    assert not rollup_view(restored, filters=RollupFilters(exposed_only=True))["top_level"]
    assert report == original


def test_absent_enabled_and_unknown_category_stay_unknown():
    report = _report("UNKNOWN")
    del report["snowflake_integrations"]["integrations"][0]["enabled"]
    graph = build_unified_graph_from_report(report)
    attrs = graph.nodes["cloud_resource:snowflake:integration:PII_S3_STORE"].attributes
    assert attrs["enabled"] is None
    assert attrs["outbound_access_configured"] is None
    assert attrs["internet_exposed"] is None
    assert attrs["integration_evidence"]["network_direction"] == "not_assessed"
    assert "enabled" not in attrs["integration_evidence"]["inputs"]


def test_federation_is_preserved_without_claiming_outbound_or_inbound_access():
    graph = build_unified_graph_from_report(_report("SECURITY"))
    attrs = graph.nodes["cloud_resource:snowflake:integration:PII_S3_STORE"].attributes
    assert attrs["identity_federation"] is True
    assert attrs["outbound_access_configured"] is None
    assert attrs["internet_exposed"] is None


def test_external_access_category_normalizes_without_changing_source_receipt():
    graph = build_unified_graph_from_report(_report(" external access ", "true"))
    attrs = graph.nodes["cloud_resource:snowflake:integration:PII_S3_STORE"].attributes
    assert attrs["integration_category"] == "EXTERNAL_ACCESS"
    assert attrs["external_access"] is True
    assert attrs["outbound_access_configured"] is True
    assert attrs["integration_evidence"]["inputs"]["category"] == "external access"


def test_configuration_qualifiers_survive_api_without_rewriting_snapshot(tmp_path):
    from starlette.testclient import TestClient

    from agent_bom.api import stores
    from agent_bom.api.server import app

    graph = build_unified_graph_from_report(_report(), tenant_id="default")
    store = SQLiteGraphStore(tmp_path / "api.db")
    store.save_graph(graph)
    original = stores._graph_store
    before = store.load_graph(scan_id=graph.scan_id, tenant_id="default").to_dict()
    try:
        stores.set_graph_store(store)
        client = TestClient(app)
        response = client.get("/v1/graph", params={"scan_id": graph.scan_id})
        assert response.status_code == 200
        node = next(node for node in response.json()["nodes"] if node["id"] == "cloud_resource:snowflake:integration:PII_S3_STORE")
        assert node["attributes"]["internet_exposed"] is None
        assert node["attributes"]["outbound_access_configured"] is True
        assert node["attributes"]["integration_evidence"]["access_outcome"] == "not_observed"
        rollup = client.get("/v1/graph/rollup", params={"scan_id": graph.scan_id, "exposed": True})
        assert rollup.status_code == 200
        assert not rollup.json()["top_level"]
        assert store.load_graph(scan_id=graph.scan_id, tenant_id="default").to_dict() == before
    finally:
        stores.set_graph_store(original)


def test_outbound_destinations_and_native_grants_remain_and_independent_public_cloud_proof_survives(tmp_path):
    report = _report()
    report["snowflake_exfil_graph"] = {
        "status": "ok",
        "account": "ACCT",
        "external_stages": [{"stage_name": "EXPORT_STAGE", "cloud_provider": "aws", "bucket": "exports", "url": "s3://exports/path/"}],
    }
    report["snowflake_object_graph"] = {
        "status": "ok",
        "account": "ACCT",
        "grants": [{"role": "ANALYST", "privilege": "SELECT", "object_fqn": "DB.PUBLIC.CUSTOMERS", "object_type": "table"}],
    }
    report["cloud_inventory"] = {
        "status": "ok",
        "provider": "aws",
        "account_id": "AWS",
        "buckets": [{"name": "exports", "publicly_accessible": True}],
    }
    graph = build_unified_graph_from_report(report, tenant_id="default")
    store = SQLiteGraphStore(tmp_path / "relations.db")
    store.save_graph(graph)
    restored = store.load_graph(scan_id=graph.scan_id, tenant_id="default")
    stage = restored.nodes["cloud_resource:snowflake:stage:EXPORT_STAGE"]
    assert stage.attributes["destination_bucket"] == "exports"
    assert stage.attributes["url"] == "s3://exports/path/"
    assert any(edge.source == stage.id and edge.target == "cloud_resource:aws:s3:bucket:exports" for edge in restored.edges)
    grant = next(
        edge for edge in restored.edges if edge.relationship == RelationshipType.HAS_PERMISSION and edge.source == "role:snowflake:ANALYST"
    )
    assert grant.evidence["grant_receipts"] == [
        {
            "source": "snowflake-objects",
            "account": "ACCT",
            "role": "ANALYST",
            "privilege": "SELECT",
            "object_fqn": "DB.PUBLIC.CUSTOMERS",
            "object_type": "table",
        }
    ]
    assert restored.nodes["cloud_resource:aws:s3:bucket:exports"].attributes["internet_exposed"] is True
    assert restored.nodes["cloud_resource:snowflake:integration:PII_S3_STORE"].attributes["internet_exposed"] is None


def test_same_name_integrations_remain_account_scoped_with_bounded_staging():
    from agent_bom.graph.store_backed import open_store_backed_unified_graph

    first = _report("EXTERNAL_ACCESS", True)["snowflake_integrations"]
    second = _report("EXTERNAL_ACCESS", "unknown")["snowflake_integrations"]
    second["account"] = "OTHER"
    with open_store_backed_unified_graph(backend="sqlite", capacity=2, page_size=2) as container:
        build_unified_graph_from_report({"snowflake_integrations": first}, container=container)
        graph = build_unified_graph_from_report({"snowflake_integrations": second}, container=container)
        integrations = {
            node.attributes["account_id"]: node for node in graph.nodes.values() if node.attributes.get("resource_type") == "integration"
        }
        assert set(integrations) == {"ACCT", "OTHER"}
        assert integrations["ACCT"].id != integrations["OTHER"].id
        assert integrations["ACCT"].attributes["outbound_access_configured"] is True
        assert integrations["OTHER"].attributes["outbound_access_configured"] is None
        assert integrations["OTHER"].attributes["integration_evidence"]["inputs"]["enabled"] == "unknown"
        assert all(node.attributes["internet_exposed"] is None for node in integrations.values())
        assert not graph.attack_paths
