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
        owners = {edge.source for edge in graph.edges if edge.target == node.id and edge.relationship.value == "owns"}
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


@pytest.mark.parametrize("provider", ["aws", "azure", "gcp"])
def test_foreign_native_resource_never_falls_back_to_local_name(provider):
    from agent_bom.graph.node import UnifiedNode
    from agent_bom.graph.types import EntityType

    graph = UnifiedGraph()
    native = {
        "aws": "arn:aws:lambda:us-east-1:account-a:function:shared",
        "azure": "/subscriptions/account-a/providers/Microsoft.KeyVault/vaults/shared",
        "gcp": "projects/account-a/instances/shared",
    }[provider]
    graph.add_node(
        UnifiedNode(
            id="local",
            entity_type=EntityType.CLOUD_RESOURCE,
            label="shared",
            attributes={
                "resource_id": native,
                "resource_name": "shared",
                "cloud_provider": provider,
            },
        )
    )
    assert _resolve_cloud_resource_node_id(graph, provider, native.replace("account-a", "account-b")) is None
    assert _resolve_cloud_resource_node_id(graph, provider, native) == "local"


def test_native_database_reference_resolves_to_existing_data_store():
    graph = UnifiedGraph()
    payload = inventory("gcp", "account-a")
    _add_cloud_inventory(graph, payload, "fixture")
    native = payload["cloud_sql_instances"][0]["id"]
    node = next(n for n in graph.nodes.values() if n.attributes.get("resource_id") == native)
    assert _resolve_cloud_resource_node_id(graph, "gcp", native) == node.id


def test_scoped_benchmark_selects_only_its_account_and_retains_database_type():
    from agent_bom.graph.benchmark_projection import BenchmarkInput, project_benchmarks
    from agent_bom.graph.types import EntityType

    graph = UnifiedGraph()
    for account in ("account-a", "account-b"):
        _add_cloud_inventory(graph, inventory("gcp", account), "fixture")
    project_benchmarks(
        graph,
        [
            BenchmarkInput(
                "gcp_cis_benchmark",
                {
                    "project_id": "account-a",
                    "checks": [{"check_id": "scope", "status": "FAIL", "resource_ids": ["shared"]}],
                },
                "gcp",
            )
        ],
    )
    affected = [graph.nodes[e.target] for e in graph.edges if e.relationship.value == "affects"]
    assert len(affected) == 1
    assert affected[0].attributes["account_id"] == "account-a"
    assert affected[0].entity_type is EntityType.DATA_STORE
    assert len([n for n in graph.nodes.values() if n.attributes.get("resource_name") == "shared"]) == 2


@pytest.mark.parametrize("provider", ["aws", "azure", "gcp"])
def test_local_native_identifiers_are_scoped_and_distinct_from_names(provider):
    from agent_bom.core.cloud_identity import cloud_resource_node_id

    def key(row, account="a", region="east"):
        return cloud_resource_node_id(provider, "kind", row, account, region)

    native = {"id": "local-id", "name": "display"}
    assert key(native) != key(native, account="b")
    assert key(native) != key(native, region="west")
    assert key(native) != key({"name": "local-id"})
    assert key(native) == key({**native, "name": "renamed"})
    assert key({**native, "resource_group": "group-a"}) != key({**native, "resource_group": "group-b"})
    assert key({**native, "location": "a/b"}) != key({**native, "location": "a", "resource_group": "b"})


@pytest.mark.parametrize("provider", ["aws", "azure", "gcp"])
def test_native_identifier_case_rules_and_original_evidence(provider):
    graph = UnifiedGraph()
    payload = inventory(provider, "account-a")
    _add_cloud_inventory(graph, payload, "fixture")
    node = next(n for n in graph.nodes.values() if n.attributes.get("resource_name") == "shared")
    original = node.attributes["resource_id"]
    if provider == "azure":
        assert _resolve_cloud_resource_node_id(graph, provider, original.upper()) == node.id
    else:
        assert _resolve_cloud_resource_node_id(graph, provider, original.replace("stable-id", "STABLE-ID")) is None
    assert node.attributes["resource_id"] == original
