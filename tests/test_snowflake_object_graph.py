"""Snowflake tables/views + OBJECT_DEPENDENCIES become DATA_STORE nodes + DEPENDS_ON edges."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from agent_bom.graph.builder import build_unified_graph_from_report


def _report() -> dict:
    return {
        "snowflake_object_graph": {
            "status": "ok",
            "account": "acct1",
            "objects": [
                {
                    "fqn": "DB.PUBLIC.ORDERS",
                    "database": "DB",
                    "schema": "PUBLIC",
                    "name": "ORDERS",
                    "object_type": "table",
                    "row_count": 100,
                    "bytes": 4096,
                },
                {"fqn": "DB.PUBLIC.ORDERS_V", "database": "DB", "schema": "PUBLIC", "name": "ORDERS_V", "object_type": "view"},
            ],
            "dependencies": [
                # the view depends on the base table
                {
                    "referencing_fqn": "DB.PUBLIC.ORDERS_V",
                    "referencing_domain": "VIEW",
                    "referenced_fqn": "DB.PUBLIC.ORDERS",
                    "referenced_domain": "TABLE",
                    "dependency_type": "BY_NAME",
                },
                # a dependency on an object not in the objects list → thin node created
                {
                    "referencing_fqn": "DB.PUBLIC.ORDERS_V",
                    "referencing_domain": "VIEW",
                    "referenced_fqn": "SNOWFLAKE.SYS.X",
                    "referenced_domain": "TABLE",
                    "dependency_type": "BY_NAME",
                },
            ],
        }
    }


def _build():
    g = build_unified_graph_from_report(_report())
    edges = list(g.edges.values()) if isinstance(g.edges, dict) else list(g.edges)
    return g, edges


def test_objects_become_owned_data_store_nodes() -> None:
    g, edges = _build()
    orders = g.nodes.get("data_store:snowflake:DB.PUBLIC.ORDERS")
    assert orders is not None
    assert str(orders.entity_type).split(".")[-1].lower() == "data_store"
    assert orders.attributes["is_data_store"] is True
    assert orders.attributes["row_count"] == 100
    owns = {(e.source, e.target) for e in edges if e.relationship.value == "owns"}
    contains = {(e.source, e.target) for e in edges if e.relationship.value == "contains"}
    account_orders = ("account:snowflake:acct1", "data_store:snowflake:DB.PUBLIC.ORDERS")
    assert account_orders in owns
    assert account_orders in contains


def test_dependencies_become_depends_on_lineage_edges() -> None:
    g, edges = _build()
    deps = {(e.source, e.target) for e in edges if e.relationship.value == "depends_on"}
    assert ("data_store:snowflake:DB.PUBLIC.ORDERS_V", "data_store:snowflake:DB.PUBLIC.ORDERS") in deps


def test_thin_node_created_for_external_dependency_endpoint() -> None:
    g, _ = _build()
    # SNOWFLAKE.SYS.X isn't in objects but is a dependency target → thin node exists
    assert "data_store:snowflake:SNOWFLAKE.SYS.X" in g.nodes


def test_non_ok_payload_is_noop() -> None:
    g = build_unified_graph_from_report({"snowflake_object_graph": {"status": "no_account"}})
    assert not [k for k in g.nodes if "snowflake" in k]


def _report_with_grants() -> dict:
    return {
        "snowflake_object_graph": {
            "status": "ok",
            "account": "acct1",
            "objects": [{"fqn": "DB.PUBLIC.ORDERS", "name": "ORDERS", "object_type": "table"}],
            "dependencies": [],
            "grants": [
                {"role": "ANALYST", "privilege": "SELECT", "object_fqn": "DB.PUBLIC.ORDERS", "object_type": "table"},
            ],
            "role_memberships": [{"user": "ALICE", "role": "ANALYST"}],
        }
    }


def test_grants_become_role_has_permission_edges() -> None:
    g = build_unified_graph_from_report(_report_with_grants())
    edges = list(g.edges.values()) if isinstance(g.edges, dict) else list(g.edges)
    assert "role:snowflake:ANALYST" in g.nodes
    has_perm = {(e.source, e.target) for e in edges if e.relationship.value == "has_permission"}
    assert ("role:snowflake:ANALYST", "data_store:snowflake:DB.PUBLIC.ORDERS") in has_perm


def test_user_role_membership_becomes_assumes_edge() -> None:
    g = build_unified_graph_from_report(_report_with_grants())
    edges = list(g.edges.values()) if isinstance(g.edges, dict) else list(g.edges)
    assert "user:snowflake:ALICE" in g.nodes
    assumes = {(e.source, e.target) for e in edges if e.relationship.value == "assumes"}
    assert ("user:snowflake:ALICE", "role:snowflake:ANALYST") in assumes


def test_multiple_privileges_retain_whole_grants_independently_of_order(tmp_path) -> None:
    from agent_bom.api.graph_store import SQLiteGraphStore

    report = _report_with_grants()
    grants = report["snowflake_object_graph"]["grants"]
    grants.append({**grants[0], "privilege": "INSERT"})
    expected = None
    for index, ordered in enumerate((grants, list(reversed(grants)), grants * 3)):
        report["snowflake_object_graph"]["grants"] = ordered
        graph = build_unified_graph_from_report(report, scan_id=f"grant-snapshot-{index}")
        edge = next(e for e in graph.edges if e.source == "role:snowflake:ANALYST" and e.relationship.value == "has_permission")
        assert edge.evidence.get("privilege") is None
        assert edge.evidence["privileges"] == ["INSERT", "SELECT"]
        records = edge.evidence["grant_receipts"]
        assert len(records) == 2
        assert {(record["account"], record["role"], record["privilege"], record["object_fqn"]) for record in records} == {
            ("acct1", "ANALYST", "SELECT", "DB.PUBLIC.ORDERS"),
            ("acct1", "ANALYST", "INSERT", "DB.PUBLIC.ORDERS"),
        }
        assert all("decision" not in record and "observed_at" not in record for record in records)
        if expected is not None:
            assert records == expected
        expected = records
        db = tmp_path / f"grants-{index}.db"
        SQLiteGraphStore(db).save_graph(graph)
        restored = SQLiteGraphStore(db).load_graph(scan_id=graph.scan_id)
        stored = next(e for e in restored.edges if e.id == edge.id)
        assert stored.evidence == edge.evidence


def test_legacy_grant_merge_keeps_missing_source_fields_unknown() -> None:
    from agent_bom.graph.edge import merge_edge_evidence

    old = {"source": "snowflake-objects", "privilege": "SELECT"}
    incoming = {
        "source": "snowflake-objects",
        "privilege": "INSERT",
        "grant_receipts": [
            {"source": "snowflake-objects", "account": "acct1", "role": "ANALYST", "privilege": "INSERT", "object_fqn": "DB.PUBLIC.ORDERS"},
        ],
    }
    assert merge_edge_evidence(old, incoming)
    legacy = next(record for record in old["grant_receipts"] if record["privilege"] == "SELECT")
    assert legacy == {"source": "snowflake-objects", "privilege": "SELECT"}
    assert old.get("privilege") is None
    assert not merge_edge_evidence(old, incoming)


@pytest.mark.parametrize(
    "name,database,schema,expected",
    [
        ("ORDERS", "DB", "PUBLIC", "DB.PUBLIC.ORDERS"),
        ("DB.PUBLIC.ORDERS", "DB", "PUBLIC", "DB.PUBLIC.ORDERS"),
        ("PUBLIC.ORDERS", "DB", "PUBLIC", "DB.PUBLIC.ORDERS"),
        ('"DB"."PUBLIC"."Order.Items"', "DB", "PUBLIC", '"DB"."PUBLIC"."Order.Items"'),
        ('"Order.Items"', "DB", "PUBLIC", 'DB.PUBLIC."Order.Items"'),
        ('"Order"".Items"', "DB", "PUBLIC", 'DB.PUBLIC."Order"".Items"'),
        ("DB.PUBLIC.ORDERS", None, None, "DB.PUBLIC.ORDERS"),
    ],
)
def test_collected_grants_keep_one_qualified_object_target(tmp_path, name, database, schema, expected):
    from agent_bom.api.graph_store import SQLiteGraphStore
    from agent_bom.cloud.snowflake import _discover_sf_grants

    grant_cursor = MagicMock()
    grant_cursor.description = [(key,) for key in ("grantee_name", "privilege", "granted_on", "name", "table_catalog", "table_schema")]
    grant_cursor.fetchall.return_value = [("ANALYST", action, "TABLE", name, database, schema) for action in ("SELECT", "INSERT")]
    membership_cursor = MagicMock()
    membership_cursor.description = [("grantee_name",), ("role",)]
    membership_cursor.fetchall.return_value = [("ALICE", "ANALYST")]
    conn = MagicMock()
    conn.cursor.side_effect = [grant_cursor, membership_cursor]
    warnings = []
    grants, memberships = _discover_sf_grants(conn, warnings)
    assert not warnings
    assert {grant["object_fqn"] for grant in grants} == {expected}

    graph = build_unified_graph_from_report(
        {
            "snowflake_object_graph": {
                "status": "ok",
                "account": "acct1",
                "objects": [{"fqn": expected, "object_type": "table", "row_count": 100}],
                "grants": grants,
                "role_memberships": memberships,
            }
        },
        scan_id="grant-name",
        tenant_id="tenant-a",
    )
    object_ids = {node.id for node in graph.nodes.values() if node.entity_type.value == "data_store"}
    assert object_ids == {f"data_store:snowflake:{expected}"}
    permission = next(edge for edge in graph.edges if edge.relationship.value == "has_permission")
    assert permission.target == f"data_store:snowflake:{expected}"
    assert {receipt["privilege"] for receipt in permission.evidence["grant_receipts"]} == {"SELECT", "INSERT"}
    assert {receipt["object_fqn"] for receipt in permission.evidence["grant_receipts"]} == {expected}
    store = SQLiteGraphStore(tmp_path / "grant-name.db")
    store.save_graph(graph)
    restored = SQLiteGraphStore(tmp_path / "grant-name.db").load_graph(scan_id=graph.scan_id, tenant_id=graph.tenant_id)
    restored_permission = next(edge for edge in restored.edges if edge.relationship.value == "has_permission")
    assert restored_permission.evidence["grant_receipts"] == permission.evidence["grant_receipts"]
