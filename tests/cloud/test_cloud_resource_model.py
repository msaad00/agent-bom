"""Normalized cross-cloud resource model."""

from __future__ import annotations

import pytest

from agent_bom.cloud.resource_model import (
    CloudResource,
    CloudResourceType,
    normalize_azure_inventory,
    normalize_cloud_inventory,
)


def _azure_inv() -> dict:
    return {
        "provider": "azure",
        "subscription_id": "sub-1",
        "storage_accounts": [
            {"name": "stg1", "id": "/subscriptions/sub-1/.../stg1", "location": "eastus", "resource_group": "rg1", "tags": {"env": "prod"}},
        ],
        "instances": [
            {"name": "vm1", "id": "/subscriptions/sub-1/.../vm1", "location": "westus", "resource_group": "rg2"},
        ],
        "security_groups": [{"name": "nsg1", "id": "/subscriptions/sub-1/.../nsg1"}],
        "managed_identities": [{"name": "mi1", "id": "/subscriptions/sub-1/.../mi1"}],
        "service_principals": [],
    }


def test_azure_inventory_maps_to_normalized_types() -> None:
    resources = normalize_azure_inventory(_azure_inv())
    by_type = {r.resource_type for r in resources}
    assert by_type == {
        CloudResourceType.OBJECT_STORE,
        CloudResourceType.COMPUTE_INSTANCE,
        CloudResourceType.NETWORK_SECURITY_GROUP,
        CloudResourceType.MANAGED_IDENTITY,
    }
    stg = next(r for r in resources if r.resource_type is CloudResourceType.OBJECT_STORE)
    assert stg.provider == "azure"
    assert stg.native_type == "Microsoft.Storage/storageAccounts"
    assert stg.account == "sub-1"
    assert stg.region == "eastus"
    assert stg.resource_group == "rg1"
    assert stg.tags == {"env": "prod"}


def test_blank_items_skipped() -> None:
    inv = {"provider": "azure", "subscription_id": "s", "storage_accounts": [{}, {"name": "ok", "id": "x"}]}
    assert len(normalize_azure_inventory(inv)) == 1


def test_dispatch_unknown_provider_returns_empty() -> None:
    assert normalize_cloud_inventory({"provider": "aws"}) == []
    assert normalize_cloud_inventory({"provider": "azure", "subscription_id": "s"}) == []


def test_to_dict_roundtrip_shape() -> None:
    r = CloudResource(
        provider="azure",
        resource_type=CloudResourceType.SECRET_STORE,
        native_type="Microsoft.KeyVault/vaults",
        resource_id="id",
        name="kv",
        account="s",
    )
    d = r.to_dict()
    assert d["resource_type"] == "secret_store"
    assert d["native_type"] == "Microsoft.KeyVault/vaults"
    assert "raw" not in d  # raw is provenance-only, not serialized


def test_data_services_normalize_to_shared_types() -> None:
    inv = {
        "provider": "azure",
        "subscription_id": "s",
        "key_vaults": [{"name": "kv", "id": "/.../kv"}],
        "container_registries": [{"name": "acr", "id": "/.../acr"}],
        "databases": [{"name": "cos", "id": "/.../cos", "native_type": "Microsoft.DocumentDB/databaseAccounts"}],
    }
    by_type = {r.resource_type: r for r in normalize_azure_inventory(inv)}
    assert by_type[CloudResourceType.SECRET_STORE].native_type == "Microsoft.KeyVault/vaults"
    assert by_type[CloudResourceType.CONTAINER_REGISTRY].native_type == "Microsoft.ContainerRegistry/registries"
    # item-level native_type wins for the shared databases collection
    assert by_type[CloudResourceType.DATABASE].native_type == "Microsoft.DocumentDB/databaseAccounts"


def test_network_topology_normalizes_to_shared_types() -> None:
    inv = {
        "provider": "azure",
        "subscription_id": "s",
        "virtual_networks": [{"name": "vnet", "id": "/.../vnet"}],
        "public_ips": [{"name": "pip", "id": "/.../pip", "ip_address": "1.2.3.4"}],
        "load_balancers": [{"name": "lb", "id": "/.../lb"}],
    }
    by_type = {r.resource_type: r for r in normalize_azure_inventory(inv)}
    assert by_type[CloudResourceType.VIRTUAL_NETWORK].native_type == "Microsoft.Network/virtualNetworks"
    assert by_type[CloudResourceType.PUBLIC_IP].raw["ip_address"] == "1.2.3.4"
    assert by_type[CloudResourceType.LOAD_BALANCER].native_type == "Microsoft.Network/loadBalancers"


_PROVIDER_INVENTORIES = {
    "aws": {
        "provider": "aws",
        "account_id": "123456789012",
        "region": "us-east-1",
        "buckets": [{"name": "evidence", "arn": "arn:aws:s3:::evidence", "tags": {"environment": "prod"}}],
        "rds_instances": [
            {
                "name": "orders",
                "db_instance_arn": "arn:aws:rds:us-east-1:123456789012:db:orders",
                "tags": {"owner": "data"},
            }
        ],
        "redshift_clusters": [{"name": "analytics", "cluster_identifier": "analytics"}],
        "roles": [{"name": "scanner", "arn": "arn:aws:iam::123456789012:role/scanner"}],
    },
    "gcp": {
        "provider": "gcp",
        "project_id": "project-1",
        "account_id": "project-1",
        "region": "us-central1",
        "buckets": [{"name": "evidence", "id": "project-1/evidence", "labels": {"environment": "prod"}}],
        "cloud_sql_instances": [
            {
                "name": "orders",
                "id": "projects/project-1/instances/orders",
                "location": "us-central1",
                "labels": {"owner": "data"},
            }
        ],
        "service_accounts": [{"name": "scanner", "email": "scanner@project-1.iam.gserviceaccount.com"}],
    },
    "snowflake": {
        "provider": "snowflake",
        "account": "ACME_PROD",
        "warehouses": [{"name": "ANALYTICS", "owner": "SYSADMIN"}],
        "databases": [{"name": "ORDERS", "owner": "DATA_ADMIN"}],
        "schemas": [{"name": "PUBLIC", "database_name": "ORDERS", "fqn": "ORDERS.PUBLIC"}],
        "objects": [
            {
                "name": "CUSTOMERS",
                "database": "ORDERS",
                "schema": "PUBLIC",
                "fqn": "ORDERS.PUBLIC.CUSTOMERS",
                "object_type": "TABLE",
            }
        ],
    },
}


@pytest.mark.parametrize("provider", sorted(_PROVIDER_INVENTORIES))
def test_dispatch_normalizes_each_shipped_cloud_provider(provider: str) -> None:
    resources = normalize_cloud_inventory(_PROVIDER_INVENTORIES[provider])

    assert resources, f"{provider} returned no normalized resources"
    assert {resource.provider for resource in resources} == {provider}
    assert {resource.account for resource in resources} == {
        "123456789012" if provider == "aws" else "project-1" if provider == "gcp" else "ACME_PROD"
    }
    assert all(resource.resource_id or resource.name for resource in resources)
    assert all(resource.native_type for resource in resources)


def test_database_and_analytics_warehouse_types_are_provider_neutral() -> None:
    resources = {provider: normalize_cloud_inventory(inventory) for provider, inventory in _PROVIDER_INVENTORIES.items()}

    for provider in ("aws", "gcp", "snowflake"):
        assert any(resource.resource_type is CloudResourceType.DATABASE for resource in resources[provider])
    assert any(resource.resource_type is CloudResourceType.DATA_WAREHOUSE for resource in resources["aws"])
    assert any(resource.resource_type is CloudResourceType.DATA_WAREHOUSE for resource in resources["snowflake"])


def test_provider_specific_identity_and_metadata_map_to_one_contract() -> None:
    aws = normalize_cloud_inventory(_PROVIDER_INVENTORIES["aws"])
    gcp = normalize_cloud_inventory(_PROVIDER_INVENTORIES["gcp"])
    snowflake = normalize_cloud_inventory(_PROVIDER_INVENTORIES["snowflake"])

    aws_role = next(resource for resource in aws if resource.name == "scanner")
    gcp_service_account = next(resource for resource in gcp if resource.name == "scanner")
    assert aws_role.resource_type is CloudResourceType.MANAGED_IDENTITY
    assert gcp_service_account.resource_type is CloudResourceType.MANAGED_IDENTITY
    assert gcp_service_account.resource_id == "scanner@project-1.iam.gserviceaccount.com"

    aws_bucket = next(resource for resource in aws if resource.name == "evidence")
    gcp_bucket = next(resource for resource in gcp if resource.name == "evidence")
    assert aws_bucket.resource_type is gcp_bucket.resource_type is CloudResourceType.OBJECT_STORE
    assert aws_bucket.tags == gcp_bucket.tags == {"environment": "prod"}

    sf_schema = next(resource for resource in snowflake if resource.name == "PUBLIC")
    sf_table = next(resource for resource in snowflake if resource.name == "CUSTOMERS")
    assert sf_schema.resource_id == "ORDERS.PUBLIC"
    assert sf_table.resource_id == "ORDERS.PUBLIC.CUSTOMERS"
    assert sf_table.native_type == "SNOWFLAKE::TABLE"


@pytest.mark.parametrize(
    ("provider", "collection", "expected_type"),
    [
        ("aws", "buckets", CloudResourceType.OBJECT_STORE),
        ("aws", "instances", CloudResourceType.COMPUTE_INSTANCE),
        ("aws", "security_groups", CloudResourceType.NETWORK_SECURITY_GROUP),
        ("aws", "roles", CloudResourceType.MANAGED_IDENTITY),
        ("aws", "rds_instances", CloudResourceType.DATABASE),
        ("aws", "lambda_functions", CloudResourceType.SERVERLESS_FUNCTION),
        ("aws", "dynamodb_tables", CloudResourceType.DATABASE),
        ("aws", "eks_clusters", CloudResourceType.CONTAINER_CLUSTER),
        ("aws", "elb_load_balancers", CloudResourceType.LOAD_BALANCER),
        ("aws", "vpcs", CloudResourceType.VIRTUAL_NETWORK),
        ("aws", "secrets", CloudResourceType.SECRET_STORE),
        ("aws", "ecr_repositories", CloudResourceType.CONTAINER_REGISTRY),
        ("aws", "redshift_clusters", CloudResourceType.DATA_WAREHOUSE),
        ("aws", "messaging", CloudResourceType.MESSAGING),
        ("aws", "api_gateways", CloudResourceType.LOAD_BALANCER),
        ("aws", "ip_addresses", CloudResourceType.PUBLIC_IP),
        ("gcp", "buckets", CloudResourceType.OBJECT_STORE),
        ("gcp", "instances", CloudResourceType.COMPUTE_INSTANCE),
        ("gcp", "firewalls", CloudResourceType.NETWORK_SECURITY_GROUP),
        ("gcp", "service_accounts", CloudResourceType.MANAGED_IDENTITY),
        ("gcp", "gke_clusters", CloudResourceType.CONTAINER_CLUSTER),
        ("gcp", "cloud_run_services", CloudResourceType.CONTAINER_APP),
        ("gcp", "cloud_functions", CloudResourceType.SERVERLESS_FUNCTION),
        ("gcp", "cloud_sql_instances", CloudResourceType.DATABASE),
        ("gcp", "vpc_networks", CloudResourceType.VIRTUAL_NETWORK),
        ("gcp", "load_balancers", CloudResourceType.LOAD_BALANCER),
        ("gcp", "api_gateways", CloudResourceType.LOAD_BALANCER),
        ("gcp", "ip_addresses", CloudResourceType.PUBLIC_IP),
        ("gcp", "disks", CloudResourceType.BLOCK_STORAGE),
        ("gcp", "pubsub_topics", CloudResourceType.MESSAGING),
        ("snowflake", "warehouses", CloudResourceType.DATA_WAREHOUSE),
        ("snowflake", "databases", CloudResourceType.DATABASE),
        ("snowflake", "schemas", CloudResourceType.DATABASE),
        ("snowflake", "objects", CloudResourceType.DATABASE),
    ],
)
def test_every_mapped_collection_has_an_explicit_provider_neutral_type(
    provider: str,
    collection: str,
    expected_type: CloudResourceType,
) -> None:
    inventory = {
        "provider": provider,
        "account_id": "account-1",
        collection: [{"name": "resource-1"}],
    }

    resources = normalize_cloud_inventory(inventory)

    assert len(resources) == 1
    assert resources[0].resource_type is expected_type
