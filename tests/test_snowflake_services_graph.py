"""Snowflake warehouses + database/schema containment become graph nodes/edges."""

from __future__ import annotations

from agent_bom.graph.builder import build_unified_graph_from_report


def _report() -> dict:
    return {
        "snowflake_object_graph": {
            "status": "ok",
            "account": "acct1",
            "objects": [
                {"fqn": "DB.PUBLIC.ORDERS", "object_type": "table"},
                {"fqn": "DB.PUBLIC.ORDERS_V", "object_type": "view"},
                {"fqn": "DB.SALES.LEADS", "object_type": "table"},
            ],
            "dependencies": [],
            "grants": [],
            "role_memberships": [],
        },
        "snowflake_services": {
            "status": "ok",
            "account": "acct1",
            "warehouses": [{"name": "WH_ETL", "size": "X-SMALL", "state": "STARTED", "auto_suspend": None}],
            "databases": [{"name": "DB", "owner": "SYSADMIN", "retention_time": 1}],
            "schemas": [
                {"name": "PUBLIC", "database_name": "DB", "fqn": "DB.PUBLIC", "owner": "SYSADMIN"},
                {"name": "SALES", "database_name": "DB", "fqn": "DB.SALES", "owner": "SYSADMIN"},
            ],
        },
    }


def _build(report=None):
    g = build_unified_graph_from_report(report if report is not None else _report())
    edges = list(g.edges.values()) if isinstance(g.edges, dict) else list(g.edges)
    return g, edges


def test_warehouse_is_compute_cloud_resource_owned_by_account() -> None:
    g, edges = _build()
    wh = g.nodes.get("cloud_resource:snowflake:warehouse:WH_ETL")
    assert wh is not None
    assert wh.attributes["resource_kind"] == "snowflake-warehouse"
    owns = {(e.source, e.target) for e in edges if e.relationship.value == "owns"}
    assert ("account:snowflake:acct1", "cloud_resource:snowflake:warehouse:WH_ETL") in owns


def test_database_contains_schema() -> None:
    g, edges = _build()
    assert "data_store:snowflake:db:DB" in g.nodes
    contains = {(e.source, e.target) for e in edges if e.relationship.value == "contains"}
    assert ("data_store:snowflake:db:DB", "data_store:snowflake:schema:DB.PUBLIC") in contains
    assert ("data_store:snowflake:db:DB", "data_store:snowflake:schema:DB.SALES") in contains


def test_schema_contains_its_tables_and_views() -> None:
    g, edges = _build()
    contains = {(e.source, e.target) for e in edges if e.relationship.value == "contains"}
    assert ("data_store:snowflake:schema:DB.PUBLIC", "data_store:snowflake:DB.PUBLIC.ORDERS") in contains
    assert ("data_store:snowflake:schema:DB.PUBLIC", "data_store:snowflake:DB.PUBLIC.ORDERS_V") in contains
    # objects route to the correct schema, not all under one
    assert ("data_store:snowflake:schema:DB.SALES", "data_store:snowflake:DB.SALES.LEADS") in contains
    assert ("data_store:snowflake:schema:DB.PUBLIC", "data_store:snowflake:DB.SALES.LEADS") not in contains


def test_containers_not_self_linked_as_tables() -> None:
    # The schema/db container nodes must not be treated as 3-part objects to link.
    g, edges = _build()
    contains = {(e.source, e.target) for e in edges if e.relationship.value == "contains"}
    assert ("data_store:snowflake:schema:DB.PUBLIC", "data_store:snowflake:schema:DB.SALES") not in contains


def test_services_work_without_object_graph() -> None:
    # Schemas present but no table nodes → containers still created, no crash.
    g, edges = _build({"snowflake_services": _report()["snowflake_services"]})
    assert "data_store:snowflake:db:DB" in g.nodes
    assert "data_store:snowflake:schema:DB.PUBLIC" in g.nodes


def test_non_ok_payload_is_noop() -> None:
    g = build_unified_graph_from_report({"snowflake_services": {"status": "no_account"}})
    assert not [k for k in g.nodes if "snowflake" in k]
