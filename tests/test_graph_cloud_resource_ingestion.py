"""Normalized cloud resources (data/secret/registry/network) become graph nodes.

Before this, the graph builder only turned storage + security groups into nodes,
so Key Vaults, registries, databases, and network topology surfaced in the
inventory but never in the graph — absent from visualization, blast-radius, and
attack-path analysis.
"""

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
                "key_vaults": [{"name": "kv", "id": "/.../kv", "location": "eastus"}],
                "container_registries": [{"name": "acr", "id": "/.../acr"}],
                "databases": [{"name": "cos", "id": "/.../cos", "native_type": "Microsoft.DocumentDB/databaseAccounts"}],
                "virtual_networks": [{"name": "vnet", "id": "/.../vnet"}],
                "public_ips": [{"name": "pip", "id": "/.../pip", "ip_address": "20.1.2.3"}],
                "load_balancers": [{"name": "lb", "id": "/.../lb", "internet_facing": True}],
            }
        ]
    }


def _build():
    g = build_unified_graph_from_report(_report())
    edges = list(g.edges.values()) if isinstance(g.edges, dict) else list(g.edges)
    return g, edges


def test_new_resource_types_become_cloud_resource_nodes() -> None:
    g, _ = _build()
    by_type = {
        n.attributes.get("resource_type")
        for n in g.nodes.values()
        if str(getattr(n, "entity_type", "")).split(".")[-1].lower() == "cloud_resource"
    }
    assert {"secret_store", "container_registry", "database", "virtual_network", "public_ip", "load_balancer"} <= by_type


def test_resources_owned_by_account_and_not_orphaned() -> None:
    g, edges = _build()
    cr = [n for n in g.nodes.values() if str(getattr(n, "entity_type", "")).split(".")[-1].lower() == "cloud_resource"]
    accounts = {k for k in g.nodes if k.startswith("account:")}
    owns = {e.target for e in edges if e.source in accounts and e.relationship.value == "owns"}
    assert all(n.id in owns for n in cr), "some cloud resources are not owned by the account"
    connected = {e.source for e in edges} | {e.target for e in edges}
    assert all(n.id in connected for n in cr), "orphaned cloud resource node"


def test_exposure_and_datastore_flags() -> None:
    g, _ = _build()
    by_name = {n.attributes.get("resource_name"): n for n in g.nodes.values() if n.attributes.get("resource_type")}
    assert by_name["pip"].attributes["internet_exposed"] is True
    assert by_name["lb"].attributes["internet_exposed"] is True
    assert by_name["kv"].attributes["is_data_store"] is True
    assert by_name["cos"].attributes["is_data_store"] is True
