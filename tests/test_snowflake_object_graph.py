"""Snowflake tables/views + OBJECT_DEPENDENCIES become DATA_STORE nodes + DEPENDS_ON edges."""

from __future__ import annotations

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
    assert ("account:snowflake:acct1", "data_store:snowflake:DB.PUBLIC.ORDERS") in owns


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
