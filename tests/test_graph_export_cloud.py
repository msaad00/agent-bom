"""The CLI graph export (DepGraph) includes cloud/identity nodes, not just local."""

from __future__ import annotations

from agent_bom.output.graph_export import build_graph_from_scan_data, to_json


def _scan() -> dict:
    return {
        "document_type": "AI-BOM",
        "agents": [{"name": "claude", "source": "local", "mcp_servers": []}],
        "cloud_inventory": {
            "status": "ok",
            "provider": "aws",
            "account_id": "111122223333",
            "rds_instances": [
                {"name": "prod-db", "engine": "postgres", "publicly_accessible": True, "arn": "arn:rds", "location": "us-east-1"}
            ],
            "role_assignments": [],
        },
        "snowflake_object_graph": {
            "status": "ok",
            "account": "acct1",
            "objects": [{"fqn": "DB.PUBLIC.ORDERS", "object_type": "table"}],
            "dependencies": [],
            "grants": [],
            "role_memberships": [],
        },
    }


def test_cli_graph_export_includes_cloud_nodes() -> None:
    g = build_graph_from_scan_data(_scan())
    ids = {n["id"] for n in to_json(g)["nodes"]}
    assert "cloud_resource:aws:rds:database:prod-db" in ids  # AWS resource
    assert "account:aws:111122223333" in ids  # cloud account
    assert "data_store:snowflake:DB.PUBLIC.ORDERS" in ids  # Snowflake object
    # local nodes still present
    assert "agent:claude" in ids


def test_local_only_scan_unaffected() -> None:
    g = build_graph_from_scan_data({"document_type": "AI-BOM", "agents": [{"name": "a", "source": "local", "mcp_servers": []}]})
    kinds = {n["kind"] for n in to_json(g)["nodes"]}
    assert "agent" in kinds
    assert not (kinds & {"cloud_resource", "data_store", "account"})  # no cloud noise
