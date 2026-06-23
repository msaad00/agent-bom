"""Normalized cross-cloud resource model."""

from __future__ import annotations

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
