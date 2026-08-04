"""``/v1/graph/schema`` must not call an edge/node kind dead that the builder emits.

The schema publishes an ``emission_status`` of ``emitted`` or ``reserved`` for
every graph vocabulary term, and it is the contract the UI codegen and any
downstream consumer reads to decide what can appear on a canvas. A term marked
``reserved`` is a promise that nothing produces it.

``owns`` was marked reserved ("Reserved for ownership imports from enterprise
identity and cloud inventory sources") while ``_add_account_resource_hierarchy``
emits it as the primary account → resource hierarchy edge on every cloud scan —
so the schema declared the backbone of the estate hierarchy to be dead
vocabulary.

This guard runs the real builder over a representative multi-provider estate and
asserts that nothing it actually emits is declared reserved.
"""

from __future__ import annotations

from typing import Any

import pytest

from agent_bom.api.routes.graph import (
    _RESERVED_GRAPH_EDGE_KINDS,
    _RESERVED_GRAPH_NODE_KINDS,
)
from agent_bom.graph.builder import build_unified_graph_from_report

REPORT: dict[str, Any] = {
    "scan_sources": ["cloud"],
    "cloud_inventory": [
        {
            "provider": "aws",
            "status": "ok",
            "account_id": "123456789012",
            "region": "us-east-1",
            "buckets": [{"name": "b1", "tags": {"environment": "prod"}}],
            "instances": [{"instance_id": "i-1", "name": "vm", "public_ip": "1.2.3.4", "security_group_ids": ["sg-1"]}],
            "security_groups": [{"group_id": "sg-1", "name": "open", "internet_exposed": True}],
            "rds_instances": [{"name": "db1"}],
            "api_gateways": [{"id": "api-1", "name": "gw"}],
            "roles": [
                {
                    "name": "r1",
                    "arn": "arn:aws:iam::123456789012:role/r1",
                    "principal_type": "iam-role",
                    "policies": [{"policy_id": "p1", "policy_name": "p1", "privilege_level": "admin"}],
                    "trust_principals": [
                        {"principal_id": "arn:aws:iam::999:root", "principal_type": "account", "relationship": "cross_account_trust"}
                    ],
                }
            ],
            "users": [{"name": "u1", "arn": "arn:aws:iam::123456789012:user/u1", "principal_type": "user"}],
            "groups": [{"name": "g1", "principal_type": "group", "members": [{"id": "u1", "name": "u1", "type": "user"}]}],
        },
        {
            "provider": "azure",
            "status": "ok",
            "account_id": "sub-1",
            "subscription_id": "sub-1",
            "storage_accounts": [{"name": "sa1", "id": "/subscriptions/sub-1/sa1", "tags": {"environment": "prod"}}],
            "role_assignments": [
                {"principal_id": "pid-1", "principal_type": "serviceprincipal", "scope": "/subscriptions/sub-1", "role_name": "Owner"}
            ],
        },
        {
            "provider": "gcp",
            "status": "ok",
            "account_id": "proj-1",
            "project_id": "proj-1",
            "buckets": [{"name": "gb1", "tags": {"environment": "prod"}}],
            "cloud_sql_instances": [{"name": "sql1", "labels": {"environment": "prod"}}],
        },
    ],
    "snowflake_object_graph": {
        "status": "ok",
        "account": "ACME",
        "objects": [{"fqn": "DB.PUBLIC.T", "database": "DB", "schema": "PUBLIC", "name": "T", "object_type": "table"}],
        "dependencies": [],
    },
    "snowflake_services": {"status": "ok", "account": "ACME", "warehouses": [{"name": "WH"}]},
    "cis_benchmark": {
        "status": "ok",
        "provider": "aws",
        "account_id": "123456789012",
        "checks": [{"check_id": "1.1", "title": "check", "status": "FAIL", "severity": "high", "resource_ids": ["b1"]}],
    },
}


@pytest.fixture(scope="module")
def built():
    graph = build_unified_graph_from_report(REPORT)
    edges = list(graph.edges.values()) if isinstance(graph.edges, dict) else list(graph.edges)
    node_kinds = {node.entity_type.value for node in graph.nodes.values()}
    edge_kinds = {edge.relationship.value for edge in edges}
    return node_kinds, edge_kinds


def test_emitted_edge_kinds_are_not_declared_reserved(built) -> None:
    _, edge_kinds = built
    assert edge_kinds, "the probe estate produced no edges"
    misdeclared = sorted(edge_kinds & set(_RESERVED_GRAPH_EDGE_KINDS))
    assert not misdeclared, f"graph schema declares these edge kinds reserved but the builder emits them: {misdeclared}"


def test_emitted_node_kinds_are_not_declared_reserved(built) -> None:
    node_kinds, _ = built
    assert node_kinds, "the probe estate produced no nodes"
    misdeclared = sorted(node_kinds & set(_RESERVED_GRAPH_NODE_KINDS))
    assert not misdeclared, f"graph schema declares these node kinds reserved but the builder emits them: {misdeclared}"


def test_probe_estate_actually_exercises_the_cloud_hierarchy(built) -> None:
    """Guard the guard: a shrinking probe must not silently stop proving anything."""
    node_kinds, edge_kinds = built
    assert {"provider", "account", "cloud_resource", "data_store", "api_gateway"} <= node_kinds
    assert {"owns", "contains", "affects", "member_of"} <= edge_kinds
