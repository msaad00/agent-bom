"""Account drill-down and DSPM companions must carry the same estate coordinates.

Two proven asymmetries are guarded here:

1. **Snowflake resources had no ``account_id``.** Every AWS/Azure/GCP resource
   node carries ``account_id``, which is the key
   :func:`agent_bom.graph.scope.select_observed_scope` matches for
   ``kind="account"``. Snowflake tables, warehouses, databases, and schemas set
   only ``fqn``/``cloud_provider``, so the account drill-down returned the bare
   ACCOUNT node and dropped the entire Snowflake estate under it.

2. **CNAPP ``DATA_STORE`` companions had no dimensions at all.** The overlay
   mirrors an inventoried resource as a crown-jewel data store but built the
   companion with no provider, account, or environment — so one asset appeared
   in a scoped projection under its ``CLOUD_RESOURCE`` face and vanished under
   its ``DATA_STORE`` face.
"""

from __future__ import annotations

from typing import Any

import pytest

from agent_bom.graph.builder import build_unified_graph_from_report
from agent_bom.graph.scope import select_observed_scope

SNOWFLAKE_ACCOUNT = "ACME-PROD"

SNOWFLAKE_REPORT: dict[str, Any] = {
    "snowflake_object_graph": {
        "status": "ok",
        "account": SNOWFLAKE_ACCOUNT,
        "objects": [
            {
                "fqn": "DB.PUBLIC.ORDERS",
                "database": "DB",
                "schema": "PUBLIC",
                "name": "ORDERS",
                "object_type": "table",
                "row_count": 100,
            },
            {
                "fqn": "DB.PUBLIC.CUSTOMERS",
                "database": "DB",
                "schema": "PUBLIC",
                "name": "CUSTOMERS",
                "object_type": "table",
            },
        ],
        "dependencies": [],
    },
    "snowflake_services": {
        "status": "ok",
        "account": SNOWFLAKE_ACCOUNT,
        "warehouses": [{"name": "WH1", "size": "X-SMALL"}],
        "databases": [{"name": "DB"}],
    },
}

AWS_REPORT: dict[str, Any] = {
    "cloud_inventory": [
        {
            "provider": "aws",
            "status": "ok",
            "account_id": "123456789012",
            "buckets": [{"name": "b1"}, {"name": "b2"}],
            "rds_instances": [{"name": "db1"}],
        }
    ]
}


def _scope(graph, scope_id: str):
    return select_observed_scope(
        graph,
        kind="account",
        scope_id=scope_id,
        max_depth=4,
        max_nodes=500,
        max_edges=500,
    )


def test_snowflake_resources_carry_the_account_scope_key() -> None:
    """Every account-owned Snowflake node is tagged with its account."""
    graph = build_unified_graph_from_report(SNOWFLAKE_REPORT)
    unscoped = sorted(
        node.id
        for node in graph.nodes.values()
        if node.entity_type.value in {"data_store", "cloud_resource"} and str(node.attributes.get("account_id") or "") != SNOWFLAKE_ACCOUNT
    )
    assert not unscoped, f"Snowflake nodes missing account_id: {unscoped}"


def test_snowflake_account_drilldown_returns_the_estate() -> None:
    """The account scope must not collapse to the bare ACCOUNT node."""
    graph = build_unified_graph_from_report(SNOWFLAKE_REPORT)
    scoped = _scope(graph, SNOWFLAKE_ACCOUNT)
    assert scoped.observed
    assert len(scoped.graph.nodes) == len(graph.nodes), (
        f"account scope returned {sorted(scoped.graph.nodes)} but the graph holds {sorted(graph.nodes)}"
    )


def test_cloud_account_drilldown_is_still_complete() -> None:
    """Regression guard for the cloud lane the Snowflake fix generalizes."""
    graph = build_unified_graph_from_report(AWS_REPORT)
    scoped = _scope(graph, "123456789012")
    # The PROVIDER node is estate-level, not account-scoped; everything else is.
    expected = {node_id for node_id in graph.nodes if not node_id.startswith("provider:")}
    assert set(scoped.graph.nodes) == expected


@pytest.mark.parametrize(
    ("provider", "inventory"),
    [
        (
            "aws",
            {
                "provider": "aws",
                "status": "ok",
                "account_id": "123456789012",
                "region": "us-east-1",
                "buckets": [{"name": "b1", "tags": {"environment": "prod"}}],
            },
        ),
        (
            "azure",
            {
                "provider": "azure",
                "status": "ok",
                "account_id": "sub-1",
                "subscription_id": "sub-1",
                "region": "eastus",
                "storage_accounts": [{"name": "sa1", "id": "/subscriptions/sub-1/sa1", "tags": {"environment": "prod"}}],
            },
        ),
        (
            "gcp",
            {
                "provider": "gcp",
                "status": "ok",
                "account_id": "proj-1",
                "project_id": "proj-1",
                "buckets": [{"name": "gb1", "tags": {"environment": "prod"}}],
            },
        ),
    ],
)
def test_data_store_companion_inherits_estate_coordinates(provider: str, inventory: dict) -> None:
    """A DSPM companion is scoped exactly like the resource it mirrors."""
    graph = build_unified_graph_from_report({"cloud_inventory": [inventory]})
    companions = [node for node in graph.nodes.values() if node.id.startswith("data_store:cloud_resource:")]
    assert companions, f"{provider}: CNAPP built no data-store companion"
    for companion in companions:
        backing = graph.nodes[companion.attributes["backed_by"]]
        assert companion.dimensions.cloud_provider == backing.dimensions.cloud_provider
        assert companion.dimensions.environment == backing.dimensions.environment
        assert companion.attributes.get("account_id") == backing.attributes.get("account_id")


def test_data_store_companion_stays_in_the_account_and_environment_scope() -> None:
    """Both faces of one asset appear together in a scoped projection."""
    graph = build_unified_graph_from_report(
        {
            "cloud_inventory": [
                {
                    "provider": "aws",
                    "status": "ok",
                    "account_id": "123456789012",
                    "buckets": [{"name": "b1", "tags": {"environment": "prod"}}],
                }
            ]
        }
    )
    companion = next(node for node in graph.nodes.values() if node.id.startswith("data_store:cloud_resource:"))
    for kind, scope_id in (("account", "123456789012"), ("environment", "prod")):
        scoped = select_observed_scope(graph, kind=kind, scope_id=scope_id, max_depth=4, max_nodes=500, max_edges=500)
        assert companion.id in scoped.graph.nodes, f"{kind} scope dropped the data-store companion"
