"""ACCESS_HISTORY observation receipts stay distinct through graph persistence/API."""

from __future__ import annotations

import asyncio
import json
from copy import deepcopy
from unittest.mock import MagicMock

from starlette.testclient import TestClient

from agent_bom.api import stores as api_stores
from agent_bom.api.graph_store import SQLiteGraphStore
from agent_bom.api.server import app
from agent_bom.api.stores import set_graph_store
from agent_bom.cloud.snowflake import _mine_access_history
from agent_bom.governance import GovernanceReport
from agent_bom.graph.builder import build_unified_graph_from_report
from agent_bom.graph.edge import merge_edge_evidence
from agent_bom.mcp_tools.inventory import inventory_asset_impl


def _collect():
    # A self-update reads a source column and writes a distinct target column.
    # directSources is column lineage, not a SQL operation-type field.
    read = {"objectName": "DB.PUBLIC.ORDERS", "objectDomain": "Table", "columns": [{"columnName": "OLD_STATUS"}]}
    write = {
        "objectName": "DB.PUBLIC.ORDERS",
        "objectDomain": "Table",
        "columns": [{"columnName": "STATUS", "directSources": [{"objectName": "DB.PUBLIC.ORDERS", "columnName": "OLD_STATUS"}]}],
    }
    cursor = MagicMock()
    cursor.description = [
        (key,)
        for key in (
            "query_id",
            "user_name",
            "role_name",
            "query_start_time",
            "direct_objects_accessed",
            "base_objects_accessed",
            "objects_modified",
        )
    ]
    cursor.fetchall.return_value = [
        ("q-update", "BOT", "ETL_ROLE", "2026-09-20T10:00:00Z", json.dumps([read]), json.dumps([read]), json.dumps([write])),
        ("q-read", "BOT", None, "2026-09-20T11:00:00Z", json.dumps([read]), json.dumps([read]), "[]"),
    ]
    conn = MagicMock()
    conn.cursor.return_value = cursor
    records, warnings = _mine_access_history(conn, 30)
    assert warnings == []
    return records


def _payload():
    report = GovernanceReport(account="ACCT1")
    report.access_records = _collect()
    return {"status": "ok", **report.to_dict()}


def _access_edge(graph):
    return next(edge for edge in graph.edges if edge.relationship.value == "accessed")


def test_collector_retains_separate_read_and_write_observations():
    records = _collect()
    assert [(record.query_id, record.operation, record.is_write) for record in records] == [
        ("q-update", "READ", False),
        ("q-update", "WRITE", True),
        ("q-read", "READ", False),
    ]
    assert records[0].columns == ["OLD_STATUS"]
    assert records[1].columns == ["STATUS"]
    assert records[2].role_name == ""
    assert records[0].source_field == "direct_objects_accessed"
    assert records[1].source_field == "objects_modified"


def test_collector_to_graph_restart_and_api_preserves_whole_receipts(tmp_path):
    payload = _payload()
    graph = build_unified_graph_from_report({"snowflake_governance": payload}, scan_id="access-receipts", tenant_id="default")
    edge = _access_edge(graph)
    evidence = edge.evidence
    receipts = evidence["access_receipts"]
    assert len(receipts) == 3
    assert {(r["query_id"], r["role_name"], r["operation"], tuple(r["columns"])) for r in receipts} == {
        ("q-update", "ETL_ROLE", "READ", ("OLD_STATUS",)),
        ("q-update", "ETL_ROLE", "WRITE", ("STATUS",)),
        ("q-read", "", "READ", ("OLD_STATUS",)),
    }
    assert all(r["account"] == "ACCT1" and r["query_start"] for r in receipts)
    assert all(r["base_objects"] == ["DB.PUBLIC.ORDERS"] for r in receipts)
    assert not {"operation", "is_write", "role_name", "query_id", "query_start"} & evidence.keys()
    assert evidence["evidence_kind"] == "historical_access"
    assert evidence["authorization_state"] == "not_evaluated"
    assert evidence["data_impact_state"] == "unknown"
    assert not any(e.relationship.value == "has_permission" for e in graph.edges)
    db = tmp_path / "access.db"
    SQLiteGraphStore(db).save_graph(graph)
    store = SQLiteGraphStore(db)
    restored = store.load_graph(scan_id=graph.scan_id, tenant_id="default")
    assert _access_edge(restored).evidence == evidence
    original = api_stores._graph_store
    try:
        set_graph_store(store)
        response = TestClient(app).get("/v1/graph", params={"scan": graph.scan_id, "limit": 200})
    finally:
        set_graph_store(original)
    assert response.status_code == 200
    transported = next(e for e in response.json()["edges"] if e["relationship"] == "accessed")
    assert transported["evidence"] == evidence
    mcp = json.loads(
        asyncio.run(
            inventory_asset_impl(
                asset_id="user:snowflake:BOT",
                scan_id=graph.scan_id,
                _get_graph_store=lambda: store,
                _truncate_response=lambda value: value,
            )
        )
    )
    mcp_edge = next(e for e in mcp["edges_out"] if e["relationship"] == "accessed")
    assert mcp_edge["evidence"] == evidence


def test_access_receipts_are_order_independent_and_deduplicated():
    payload = _payload()
    expected = None
    records = payload["access_records"]
    for ordered in (records, list(reversed(records)), records * 3):
        graph = build_unified_graph_from_report({"snowflake_governance": {**payload, "access_records": ordered}})
        evidence = _access_edge(graph).evidence
        assert len(evidence["access_receipts"]) == 3
        if expected is not None:
            assert evidence == expected
        expected = deepcopy(evidence)


def test_legacy_access_merge_does_not_fill_missing_query_or_role():
    old = {"source": "snowflake-governance", "operation": "SELECT", "is_write": False}
    incoming = {
        "source": "snowflake-governance",
        "access_receipts": [
            {
                "source": "snowflake-governance",
                "operation": "WRITE",
                "is_write": True,
                "query_id": "q-new",
                "role_name": "ETL_ROLE",
                "query_start": "2026-09-20T12:00:00Z",
            }
        ],
    }
    assert merge_edge_evidence(old, incoming)
    assert len(old["access_receipts"]) == 2
    legacy = next(r for r in old["access_receipts"] if r["operation"] == "SELECT")
    assert legacy == {"source": "snowflake-governance", "operation": "SELECT", "is_write": False}
    assert not {"operation", "is_write", "role_name", "query_id", "query_start"} & old.keys()
    assert not merge_edge_evidence(old, incoming)


def test_collector_sized_history_keeps_receipts_without_per_query_edges():
    payload = _payload()
    read, write = payload["access_records"][:2]
    payload["access_records"] = [{**record, "query_id": f"q-{query}"} for query in range(1000) for record in (read, write)]
    graph = build_unified_graph_from_report({"snowflake_governance": payload})
    edges = [edge for edge in graph.edges if edge.relationship.value == "accessed"]
    assert len(edges) == 1
    assert len(edges[0].evidence["access_receipts"]) == 2000
    assert len({record["query_id"] for record in edges[0].evidence["access_receipts"]}) == 1000


def test_unscoped_scalar_cannot_fill_a_receipt_missing_its_role():
    old = {"source": "snowflake-governance", "access_receipts": [{"operation": "READ", "is_write": False}]}
    assert merge_edge_evidence(old, {"role_name": "UNRELATED_ROLE"})
    assert "role_name" not in old
    assert old["access_receipts"] == [{"operation": "READ", "is_write": False}]
