"""Management-group hierarchy → ORG nodes + CONTAINS edges (multi-subscription tree)."""

from __future__ import annotations

from agent_bom.graph.builder import build_unified_graph_from_report


def _report() -> dict:
    return {
        "cloud_inventory": [
            {
                "provider": "azure",
                "status": "ok",
                "subscription_id": "sub-1",
                "account_id": "sub-1",
                "management_groups": [
                    {
                        "id": "/providers/.../mg-root",
                        "name": "mg-root",
                        "display_name": "Tenant Root",
                        "children": [
                            {"id": "/m/mg-eng", "name": "mg-eng", "type": "Microsoft.Management/managementGroups", "display_name": "Eng"},
                            {"id": "/subscriptions/sub-1", "name": "sub-1", "type": "/subscriptions", "display_name": "Prod"},
                        ],
                    },
                    {
                        "id": "/providers/.../mg-eng",
                        "name": "mg-eng",
                        "display_name": "Eng",
                        "children": [{"id": "/subscriptions/sub-2", "name": "sub-2", "type": "/subscriptions", "display_name": "Dev"}],
                    },
                ],
            }
        ]
    }


def _build():
    g = build_unified_graph_from_report(_report())
    edges = list(g.edges.values()) if isinstance(g.edges, dict) else list(g.edges)
    return g, edges


def test_management_groups_become_org_nodes() -> None:
    g, _ = _build()
    orgs = {k for k, n in g.nodes.items() if str(getattr(n, "entity_type", "")).split(".")[-1].lower() == "org"}
    assert {"org:azure:mg-root", "org:azure:mg-eng"} <= orgs


def test_contains_edges_span_nested_groups_and_subscriptions() -> None:
    g, edges = _build()
    contains = {(e.source, e.target) for e in edges if e.relationship.value == "contains"}
    assert ("org:azure:mg-root", "org:azure:mg-eng") in contains  # MG → nested MG
    assert ("org:azure:mg-root", "account:azure:sub-1") in contains  # MG → subscription
    assert ("org:azure:mg-eng", "account:azure:sub-2") in contains
    # subscription nodes exist even though only sub-1 was the scanned subscription
    accounts = {k for k, n in g.nodes.items() if str(getattr(n, "entity_type", "")).split(".")[-1].lower() == "account"}
    assert {"account:azure:sub-1", "account:azure:sub-2"} <= accounts
