"""Snowflake tasks/streams/pipes become graph nodes with their dependency edges."""

from __future__ import annotations

from agent_bom.graph.builder import build_unified_graph_from_report


def _report() -> dict:
    return {
        "snowflake_pipeline": {
            "status": "ok",
            "account": "acct1",
            "tasks": [
                {
                    "name": "T_ETL",
                    "fqn": "DB.PUBLIC.T_ETL",
                    "warehouse": "WH_ETL",
                    "schedule": "5 MINUTE",
                    "state": "STARTED",
                    "owner": "ETL_ROLE",
                }
            ],
            "streams": [{"name": "S_ORD", "fqn": "DB.PUBLIC.S_ORD", "source_fqn": "DB.PUBLIC.ORDERS", "stale": True, "type": "DELTA"}],
            "pipes": [
                {"name": "P_LOAD", "fqn": "DB.PUBLIC.P_LOAD", "stage": "DB.PUBLIC.INGEST_STG", "auto_ingest": True, "integration": "NOTIF"}
            ],
        }
    }


def _edges(report=None):
    g = build_unified_graph_from_report(report if report is not None else _report())
    return g, {(e.source, e.target, e.relationship.value) for e in g.edges}


def test_task_depends_on_warehouse_and_assumes_owner_role() -> None:
    g, edgeset = _edges()
    assert "cloud_resource:snowflake:task:DB.PUBLIC.T_ETL" in g.nodes
    assert ("cloud_resource:snowflake:task:DB.PUBLIC.T_ETL", "cloud_resource:snowflake:warehouse:WH_ETL", "depends_on") in edgeset
    assert ("cloud_resource:snowflake:task:DB.PUBLIC.T_ETL", "role:snowflake:ETL_ROLE", "assumes") in edgeset


def test_stream_depends_on_source_table() -> None:
    g, edgeset = _edges()
    assert g.nodes["data_store:snowflake:stream:DB.PUBLIC.S_ORD"].attributes["stale"] is True
    assert ("data_store:snowflake:stream:DB.PUBLIC.S_ORD", "data_store:snowflake:DB.PUBLIC.ORDERS", "depends_on") in edgeset


def test_pipe_depends_on_stage_by_name() -> None:
    g, edgeset = _edges()
    # stage fqn DB.PUBLIC.INGEST_STG resolves to the stage node keyed by name.
    assert ("cloud_resource:snowflake:pipe:DB.PUBLIC.P_LOAD", "cloud_resource:snowflake:stage:INGEST_STG", "depends_on") in edgeset


def test_pipe_to_stage_to_bucket_ingress_chain_stitches_with_exfil() -> None:
    # When the exfil layer also ran, the pipe's stage is the SAME node exfil
    # exposes to the cloud bucket → the ingress path is traversable end to end.
    report = _report()
    report["snowflake_exfil_graph"] = {
        "status": "ok",
        "account": "acct1",
        "outbound_shares": [],
        "external_stages": [{"stage_name": "INGEST_STG", "url": "s3://acme-raw/in/", "cloud_provider": "aws", "bucket": "acme-raw"}],
        "sensitive_objects": [],
    }
    g, edgeset = _edges(report)
    assert ("cloud_resource:snowflake:pipe:DB.PUBLIC.P_LOAD", "cloud_resource:snowflake:stage:INGEST_STG", "depends_on") in edgeset
    assert ("cloud_resource:snowflake:stage:INGEST_STG", "cloud_resource:aws:s3:bucket:acme-raw", "exposed_to") in edgeset


def test_non_ok_payload_is_noop() -> None:
    g = build_unified_graph_from_report({"snowflake_pipeline": {"status": "no_account"}})
    assert not [k for k in g.nodes if "snowflake" in k]
