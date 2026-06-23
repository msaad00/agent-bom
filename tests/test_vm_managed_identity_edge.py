"""A VM assumes its user-assigned managed identity (CIEM privilege edge)."""

from __future__ import annotations

from agent_bom.graph.builder import build_unified_graph_from_report

_MI_ARM = "/subscriptions/sub-1/resourceGroups/rg/providers/Microsoft.ManagedIdentity/userAssignedIdentities/mi1"


def _build():
    report = {
        "cloud_inventory": [
            {
                "provider": "azure",
                "status": "ok",
                "subscription_id": "sub-1",
                "account_id": "sub-1",
                "instances": [
                    {
                        "instance_id": "/subscriptions/sub-1/.../virtualMachines/vm1",
                        "name": "vm1",
                        "user_assigned_identity_ids": [_MI_ARM],
                    }
                ],
                "managed_identities": [{"name": "mi1", "arn": _MI_ARM, "principal_id": "pid", "principal_type": "managed-identity"}],
            }
        ]
    }
    g = build_unified_graph_from_report(report)
    edges = list(g.edges.values()) if isinstance(g.edges, dict) else list(g.edges)
    return g, edges


def test_vm_assumes_user_assigned_identity() -> None:
    g, edges = _build()
    assumes = [e for e in edges if e.relationship.value == "assumes"]
    assert len(assumes) == 1
    edge = assumes[0]
    src = g.nodes[edge.source]
    tgt = g.nodes[edge.target]
    assert str(src.entity_type).split(".")[-1].lower() == "cloud_resource"
    assert str(tgt.entity_type).split(".")[-1].lower() == "managed_identity"
    assert edge.target in g.nodes  # links to the real MI node, not a dangling id


def test_vm_without_user_assigned_identity_has_no_assumes_edge() -> None:
    report = {
        "cloud_inventory": [
            {
                "provider": "azure",
                "status": "ok",
                "subscription_id": "sub-1",
                "account_id": "sub-1",
                "instances": [{"instance_id": "/.../vm1", "name": "vm1"}],
            }
        ]
    }
    g = build_unified_graph_from_report(report)
    edges = list(g.edges.values()) if isinstance(g.edges, dict) else list(g.edges)
    assert not [e for e in edges if e.relationship.value == "assumes"]
