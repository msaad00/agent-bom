"""Cloud resource identity must retain native scope instead of display-name joins."""

import copy

import pytest

from agent_bom.graph.builder import _add_cloud_inventory
from agent_bom.graph.container import UnifiedGraph
from agent_bom.graph.resource_aliases import _resolve_cloud_resource_node_id


def inventory(provider, scope, name="shared", *, native=True):
    if provider == "aws":
        collection, field = "lambda_functions", "arn"
        identifier = f"arn:aws:lambda:us-east-1:{scope}:function:stable-id"
    elif provider == "azure":
        collection, field = "key_vaults", "id"
        identifier = f"/subscriptions/{scope}/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/stable-id"
    else:
        collection, field = "cloud_sql_instances", "id"
        identifier = f"projects/{scope}/instances/stable-id"
    resource = {"name": name, "location": "region-one"}
    if native:
        resource[field] = identifier
    return {
        "provider": provider,
        "status": "ok",
        "account_id": scope,
        "subscription_id": scope,
        "project_id": scope,
        "region": "region-one",
        collection: [resource],
    }


@pytest.mark.parametrize("provider", ["aws", "azure", "gcp"])
@pytest.mark.parametrize("native", [True, False])
def test_same_names_in_distinct_accounts_keep_separate_nodes_and_owners(provider, native):
    graph = UnifiedGraph()
    for scope in ("account-a", "account-b"):
        _add_cloud_inventory(graph, inventory(provider, scope, native=native), "fixture")
    resources = [node for node in graph.nodes.values() if node.attributes.get("resource_name") == "shared"]
    assert len(resources) == 2
    for node in resources:
        owners = {edge.source for edge in graph.edges.values() if edge.target == node.id and edge.relationship.value == "owns"}
        assert owners == {f"account:{provider}:{node.attributes['account_id']}"}
    assert _resolve_cloud_resource_node_id(graph, provider, "shared") is None


@pytest.mark.parametrize("provider", ["aws", "azure", "gcp"])
def test_native_identity_survives_display_name_change(provider):
    graph = UnifiedGraph()
    payload = inventory(provider, "account-a")
    _add_cloud_inventory(graph, payload, "fixture")
    old = next(node for node in graph.nodes.values() if node.attributes.get("resource_name") == "shared")
    renamed = copy.deepcopy(payload)
    collection = {"aws": "lambda_functions", "azure": "key_vaults", "gcp": "cloud_sql_instances"}[provider]
    renamed[collection][0]["name"] = "renamed"
    _add_cloud_inventory(graph, renamed, "fixture")
    resources = [node for node in graph.nodes.values() if node.attributes.get("resource_name") in {"shared", "renamed"}]
    assert len(resources) == 1
    assert resources[0].id == old.id
    assert resources[0].attributes["resource_name"] == "renamed"
