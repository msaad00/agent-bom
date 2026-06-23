"""Subscription-scoped cloud CIS misconfigurations must not orphan in the graph.

A live Azure scan showed that CIS controls with no specific ``resource_ids``
(Defender plans, Activity Log alerts, Network Watcher, security contacts) were
added as misconfiguration nodes but linked to nothing — so blast-radius and
attack-path analysis never reached them and they never surfaced to the user.
They are now anchored to the cloud account node.
"""

from __future__ import annotations

from agent_bom.graph.builder import build_unified_graph_from_report


def _report(checks: list[dict]) -> dict:
    return {
        "azure_cis_benchmark": {
            "subscription_id": "sub-123",
            "checks": checks,
        }
    }


def _build(checks: list[dict]):
    g = build_unified_graph_from_report(_report(checks))
    edges = list(g.edges.values()) if isinstance(g.edges, dict) else list(g.edges)
    connected = set()
    for e in edges:
        connected.add(e.source)
        connected.add(e.target)
    return g, edges, connected


def test_subscription_scoped_misconfig_anchored_to_account() -> None:
    g, edges, connected = _build(
        [
            {
                "check_id": "2.12",
                "title": "Security contact email configured",
                "status": "FAIL",
                "severity": "medium",
                "resource_ids": [],  # subscription-scoped — no specific resource
            }
        ]
    )
    misconfig_id = "misconfig:azure_cis_benchmark:2.12"
    account_id = "account:azure:sub-123"
    assert misconfig_id in g.nodes
    assert account_id in g.nodes, "account node not created for subscription-scoped control"
    assert misconfig_id in connected, "subscription-scoped misconfig left orphaned"
    assert any(e.source == misconfig_id and e.target == account_id for e in edges), "misconfig not linked to its cloud account"


def test_resource_scoped_misconfig_still_links_to_resource_not_account() -> None:
    g, edges, connected = _build(
        [
            {
                "check_id": "3.2",
                "title": "Storage default network access denied",
                "status": "FAIL",
                "severity": "high",
                "resource_ids": ["mystorageacct"],
            }
        ]
    )
    misconfig_id = "misconfig:azure_cis_benchmark:3.2"
    assert misconfig_id in connected
    # resource-scoped checks keep their resource edge; the account anchor is
    # only the fallback for checks with no resource.
    assert any(e.source == misconfig_id and "cloud_resource" in e.target for e in edges), "resource-scoped misconfig lost its resource link"
