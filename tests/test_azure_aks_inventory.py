"""AKS clusters inventory → normalized CONTAINER_CLUSTER → graph node."""

from __future__ import annotations

from agent_bom.cloud.resource_model import CloudResourceType, normalize_cloud_inventory
from agent_bom.graph.builder import build_unified_graph_from_report

_NATIVE = "Microsoft.ContainerService/managedClusters"


def _inv(clusters: list[dict]) -> dict:
    return {"provider": "azure", "status": "ok", "subscription_id": "s", "account_id": "s", "container_clusters": clusters}


def test_aks_normalizes_to_container_cluster() -> None:
    inv = _inv([{"name": "aks1", "id": "/s/aks1", "native_type": _NATIVE}])
    res = normalize_cloud_inventory(inv)
    assert [(r.resource_type, r.native_type) for r in res] == [(CloudResourceType.CONTAINER_CLUSTER, _NATIVE)]


def test_public_api_server_cluster_is_internet_exposed_node() -> None:
    inv = _inv([{"name": "aks1", "id": "/s/aks1", "native_type": _NATIVE, "api_server_fqdn": "aks1.azmk8s.io", "internet_facing": True}])
    g = build_unified_graph_from_report({"cloud_inventory": [inv]})
    nodes = [n for n in g.nodes.values() if n.attributes.get("resource_type") == "container_cluster"]
    assert len(nodes) == 1
    assert nodes[0].attributes["internet_exposed"] is True


def test_private_cluster_not_internet_exposed() -> None:
    inv = _inv([{"name": "aks2", "id": "/s/aks2", "native_type": _NATIVE, "internet_facing": False}])
    g = build_unified_graph_from_report({"cloud_inventory": [inv]})
    nodes = [n for n in g.nodes.values() if n.attributes.get("resource_type") == "container_cluster"]
    assert nodes and nodes[0].attributes["internet_exposed"] is False
