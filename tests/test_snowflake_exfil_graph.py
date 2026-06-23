"""Snowflake egress surfaces become exfil graph nodes/edges.

Outbound shares → EXPOSED_TO consumer accounts; external stages → EXPOSED_TO the
destination bucket (cross-cloud stitch); sensitivity-tagged objects → DATA_STORE.
"""

from __future__ import annotations

from agent_bom.graph.builder import build_unified_graph_from_report


def _report() -> dict:
    return {
        "snowflake_exfil_graph": {
            "status": "ok",
            "account": "acct1",
            "outbound_shares": [
                {"share_name": "PARTNER_SHARE", "database_name": "DB", "consumers": ["ORG2.ACCT9"], "is_marketplace": False},
                {"share_name": "PUBLIC_LISTING", "database_name": "DB", "consumers": [], "is_marketplace": True},
            ],
            "external_stages": [
                {
                    "stage_name": "EXPORT_STAGE",
                    "database_name": "DB",
                    "schema_name": "PUBLIC",
                    "url": "s3://acme-exports/dump/",
                    "cloud_provider": "aws",
                    "bucket": "acme-exports",
                },
                {
                    "stage_name": "AZ_STAGE",
                    "database_name": "DB",
                    "schema_name": "PUBLIC",
                    "url": "azure://acct.blob.core.windows.net/container",
                    "cloud_provider": "azure",
                    "bucket": "acct.blob.core.windows.net",
                },
            ],
            "sensitive_objects": [
                {"fqn": "DB.PUBLIC.CUSTOMERS", "tagged_columns": 3, "tag_count": 2, "is_protected": False, "sensitivity": "sensitive"},
                {"fqn": "DB.PUBLIC.PAYMENTS", "tagged_columns": 1, "tag_count": 1, "is_protected": True, "sensitivity": "sensitive"},
            ],
        }
    }


def _build(report: dict | None = None):
    g = build_unified_graph_from_report(report if report is not None else _report())
    edges = list(g.edges.values()) if isinstance(g.edges, dict) else list(g.edges)
    return g, edges


def test_outbound_share_exposed_to_consumer_account() -> None:
    g, edges = _build()
    assert "data_store:snowflake:share:PARTNER_SHARE" in g.nodes
    exposed = {(e.source, e.target) for e in edges if e.relationship.value == "exposed_to"}
    assert ("data_store:snowflake:share:PARTNER_SHARE", "account:snowflake:ORG2.ACCT9") in exposed


def test_marketplace_share_reaches_public_consumer() -> None:
    g, edges = _build()
    pub = g.nodes.get("account:snowflake:public-marketplace")
    assert pub is not None
    assert pub.attributes["internet_exposed"] is True
    exposed = {(e.source, e.target) for e in edges if e.relationship.value == "exposed_to"}
    assert ("data_store:snowflake:share:PUBLIC_LISTING", "account:snowflake:public-marketplace") in exposed


def test_external_stage_exposed_to_bucket_node() -> None:
    g, edges = _build()
    assert "cloud_resource:snowflake:stage:EXPORT_STAGE" in g.nodes
    exposed = {(e.source, e.target) for e in edges if e.relationship.value == "exposed_to"}
    assert ("cloud_resource:snowflake:stage:EXPORT_STAGE", "cloud_resource:aws:s3:bucket:acme-exports") in exposed


def test_stage_bucket_id_matches_aws_scan_scheme_for_cross_cloud_stitch() -> None:
    # The stage's destination bucket node id must be identical to the id an AWS S3
    # inventory scan emits, so the two graphs merge onto one node rather than two.
    g, _ = _build()
    bucket = g.nodes.get("cloud_resource:aws:s3:bucket:acme-exports")
    assert bucket is not None
    # Azure stage stitches to the azure/blob scheme.
    assert "cloud_resource:azure:blob:bucket:acct.blob.core.windows.net" in g.nodes


def test_stitch_does_not_overwrite_existing_cloud_scan_bucket_node() -> None:
    # When a cloud scan already created the rich bucket node, the exfil pass must
    # reuse it (thin node only created when absent).
    report = _report()
    report["cloud_inventory"] = {
        "status": "ok",
        "provider": "aws",
        "account_id": "111122223333",
        "buckets": [{"name": "acme-exports", "publicly_accessible": True}],
    }
    g, edges = _build(report)
    bucket = g.nodes.get("cloud_resource:aws:s3:bucket:acme-exports")
    assert bucket is not None
    # The rich attribute from the cloud scan survives (thin node would lack it).
    assert bucket.attributes.get("internet_exposed") is True
    exposed = {(e.source, e.target) for e in edges if e.relationship.value == "exposed_to"}
    assert ("cloud_resource:snowflake:stage:EXPORT_STAGE", "cloud_resource:aws:s3:bucket:acme-exports") in exposed


def test_sensitive_objects_become_data_store_with_sensitivity() -> None:
    g, _ = _build()
    cust = g.nodes.get("data_store:snowflake:DB.PUBLIC.CUSTOMERS")
    assert cust is not None
    assert cust.attributes["sensitivity"] == "sensitive"
    assert cust.attributes["is_protected"] is False
    assert g.nodes["data_store:snowflake:DB.PUBLIC.PAYMENTS"].attributes["is_protected"] is True


def test_non_ok_payload_is_noop() -> None:
    g = build_unified_graph_from_report({"snowflake_exfil_graph": {"status": "no_account"}})
    assert not [k for k in g.nodes if "snowflake" in k]
