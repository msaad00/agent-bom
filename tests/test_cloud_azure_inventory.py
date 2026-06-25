"""Tests for agent_bom.cloud.azure_inventory — estate-wide Azure asset inventory.

The Azure SDKs are not hard dependencies, so these tests inject fake
``azure.identity`` and ``azure.mgmt.*`` modules (no live calls) and exercise:
enumeration → payload, the flag-off no-op path, the sdk-missing path, the
no-subscription / no-credentials paths, and the graph-builder integration that
turns the payload into nodes the CNAPP / effective-permissions overlays consume.

Authentication is token/credential only — the tests inject a fake credential
object, never a password.
"""

from __future__ import annotations

import sys
import types
from typing import Any
from unittest.mock import patch

import pytest

from agent_bom.cloud import azure_inventory

# ---------------------------------------------------------------------------
# Fake azure-mgmt SDK objects
# ---------------------------------------------------------------------------


class _Obj:
    """Tiny attribute bag mirroring azure-mgmt model objects."""

    def __init__(self, **kwargs: Any) -> None:
        for key, value in kwargs.items():
            setattr(self, key, value)


class _FakeStorageOps:
    def list(self) -> list[Any]:
        return [
            _Obj(
                name="publiclake",
                id="/subscriptions/sub-1/resourceGroups/rg-data/providers/Microsoft.Storage/storageAccounts/publiclake",
                location="eastus",
                kind="StorageV2",
                allow_blob_public_access=True,
                network_rule_set=_Obj(default_action="Allow"),
                tags={"classification": "pii"},
            ),
            _Obj(
                name="privatelogs",
                id="/subscriptions/sub-1/resourceGroups/rg-ops/providers/Microsoft.Storage/storageAccounts/privatelogs",
                location="westus",
                kind="StorageV2",
                allow_blob_public_access=False,
                network_rule_set=_Obj(default_action="Deny"),
                tags={},
            ),
        ]


class _FakeStorageClient:
    def __init__(self, _credential: Any, _subscription_id: str) -> None:
        self.storage_accounts = _FakeStorageOps()


class _FakeVMOps:
    def list_all(self) -> list[Any]:
        return [
            _Obj(
                name="web-1",
                id="/subscriptions/sub-1/resourceGroups/rg-web/providers/Microsoft.Compute/virtualMachines/web-1",
                location="eastus",
                hardware_profile=_Obj(vm_size="Standard_D2s_v3"),
                identity=_Obj(principal_id="mi-principal-1", type="UserAssigned"),
                tags={"app": "web"},
            )
        ]


class _FakeComputeClient:
    def __init__(self, _credential: Any, _subscription_id: str) -> None:
        self.virtual_machines = _FakeVMOps()


class _FakeNSGOps:
    def list_all(self) -> list[Any]:
        return [
            _Obj(
                name="web-nsg",
                id="/subscriptions/sub-1/resourceGroups/rg-web/providers/Microsoft.Network/networkSecurityGroups/web-nsg",
                location="eastus",
                security_rules=[
                    _Obj(
                        direction="Inbound",
                        access="Allow",
                        protocol="Tcp",
                        source_address_prefix="*",
                        destination_port_range="22",
                    )
                ],
            ),
            _Obj(
                name="internal-nsg",
                id="/subscriptions/sub-1/resourceGroups/rg-web/providers/Microsoft.Network/networkSecurityGroups/internal-nsg",
                location="eastus",
                security_rules=[
                    _Obj(
                        direction="Inbound",
                        access="Allow",
                        protocol="Tcp",
                        source_address_prefix="10.0.0.0/8",
                        destination_port_range="443",
                    )
                ],
            ),
        ]


class _FakeNetworkClient:
    def __init__(self, _credential: Any, _subscription_id: str) -> None:
        self.network_security_groups = _FakeNSGOps()


class _FakeMSIOps:
    def list_by_subscription(self) -> list[Any]:
        return [
            _Obj(
                name="web-identity",
                id="/subscriptions/sub-1/resourceGroups/rg-web/providers/Microsoft.ManagedIdentity/userAssignedIdentities/web-identity",
                principal_id="mi-principal-1",
                client_id="mi-client-1",
                location="eastus",
            )
        ]


class _FakeMSIClient:
    def __init__(self, _credential: Any, _subscription_id: str) -> None:
        self.user_assigned_identities = _FakeMSIOps()


class _FakeCredential:
    """Stand-in for a token credential (never a password)."""


def _install_fake_azure() -> Any:
    """Return a patch.dict context installing fake azure-identity + azure-mgmt."""
    identity_mod = types.ModuleType("azure.identity")
    identity_mod.DefaultAzureCredential = _FakeCredential  # type: ignore[attr-defined]

    storage_mod = types.ModuleType("azure.mgmt.storage")
    storage_mod.StorageManagementClient = _FakeStorageClient  # type: ignore[attr-defined]
    compute_mod = types.ModuleType("azure.mgmt.compute")
    compute_mod.ComputeManagementClient = _FakeComputeClient  # type: ignore[attr-defined]
    network_mod = types.ModuleType("azure.mgmt.network")
    network_mod.NetworkManagementClient = _FakeNetworkClient  # type: ignore[attr-defined]
    msi_mod = types.ModuleType("azure.mgmt.msi")
    msi_mod.ManagedServiceIdentityClient = _FakeMSIClient  # type: ignore[attr-defined]

    azure_mod = types.ModuleType("azure")
    mgmt_mod = types.ModuleType("azure.mgmt")
    return patch.dict(
        sys.modules,
        {
            "azure": azure_mod,
            "azure.identity": identity_mod,
            "azure.mgmt": mgmt_mod,
            "azure.mgmt.storage": storage_mod,
            "azure.mgmt.compute": compute_mod,
            "azure.mgmt.network": network_mod,
            "azure.mgmt.msi": msi_mod,
        },
    )


# ---------------------------------------------------------------------------
# Flag gating
# ---------------------------------------------------------------------------


def test_inventory_disabled_by_default(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(azure_inventory.INVENTORY_ENV_FLAG, raising=False)
    monkeypatch.setenv("AZURE_SUBSCRIPTION_ID", "sub-1")
    assert azure_inventory.inventory_enabled() is False
    payload = azure_inventory.discover_inventory()
    assert payload["status"] == "disabled"
    assert payload["storage_accounts"] == []
    assert payload["managed_identities"] == []


def test_inventory_flag_enables(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(azure_inventory.INVENTORY_ENV_FLAG, "true")
    assert azure_inventory.inventory_enabled() is True


def test_inventory_flag_off_short_circuits_before_sdk(monkeypatch: pytest.MonkeyPatch) -> None:
    """With the flag off we must not even attempt to import the SDK."""
    monkeypatch.delenv(azure_inventory.INVENTORY_ENV_FLAG, raising=False)
    with patch.dict(sys.modules, {"azure.identity": None}):
        payload = azure_inventory.discover_inventory()
    assert payload["status"] == "disabled"


# ---------------------------------------------------------------------------
# Degraded paths
# ---------------------------------------------------------------------------


def test_inventory_sdk_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(azure_inventory.INVENTORY_ENV_FLAG, "1")
    monkeypatch.setenv("AZURE_SUBSCRIPTION_ID", "sub-1")
    import builtins

    original = builtins.__import__

    def _no_azure(name: str, *args: Any, **kwargs: Any) -> Any:
        if name == "azure.identity" or name.startswith("azure.identity"):
            raise ImportError("mocked")
        return original(name, *args, **kwargs)

    with patch("builtins.__import__", side_effect=_no_azure):
        payload = azure_inventory.discover_inventory()
    assert payload["status"] == "sdk_missing"
    assert payload["storage_accounts"] == []
    assert payload["warnings"]


def test_inventory_no_subscription(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(azure_inventory.INVENTORY_ENV_FLAG, "1")
    monkeypatch.delenv("AZURE_SUBSCRIPTION_ID", raising=False)
    with _install_fake_azure():
        payload = azure_inventory.discover_inventory()
    assert payload["status"] == "no_subscription"
    assert payload["warnings"]


def test_inventory_no_credentials(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(azure_inventory.INVENTORY_ENV_FLAG, "1")
    monkeypatch.setenv("AZURE_SUBSCRIPTION_ID", "sub-1")

    class _BoomCredential(_FakeCredential):
        def __init__(self) -> None:
            raise RuntimeError("could not acquire token")

    identity_mod = types.ModuleType("azure.identity")
    identity_mod.DefaultAzureCredential = _BoomCredential  # type: ignore[attr-defined]
    with patch.dict(sys.modules, {"azure.identity": identity_mod}):
        payload = azure_inventory.discover_inventory()
    assert payload["status"] == "no_credentials"
    assert payload["warnings"]


# ---------------------------------------------------------------------------
# Enumeration
# ---------------------------------------------------------------------------


def test_inventory_enumerates_all_three_classes(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(azure_inventory.INVENTORY_ENV_FLAG, "1")
    with _install_fake_azure():
        payload = azure_inventory.discover_inventory(subscription_id="sub-1", credential=_FakeCredential())

    assert payload["status"] == "ok"
    assert payload["subscription_id"] == "sub-1"

    # Storage accounts: estate-wide, public posture + tags from posture APIs only.
    accounts = {a["name"]: a for a in payload["storage_accounts"]}
    assert set(accounts) == {"publiclake", "privatelogs"}
    assert accounts["publiclake"]["publicly_accessible"] is True
    assert accounts["publiclake"]["resource_group"] == "rg-data"
    assert accounts["publiclake"]["tags"] == {"classification": "pii"}
    # Deny default action means not public even with blob public access False.
    assert accounts["privatelogs"]["publicly_accessible"] is False

    # VMs (NOT tag-filtered).
    assert len(payload["instances"]) == 1
    vm = payload["instances"][0]
    assert vm["name"] == "web-1"
    assert vm["instance_type"] == "Standard_D2s_v3"

    # NSGs with structured exposure.
    nsgs = {g["name"]: g for g in payload["security_groups"]}
    assert nsgs["web-nsg"]["internet_exposed"] is True
    assert nsgs["web-nsg"]["network_exposure"][0]["scope"] == "internet"
    assert nsgs["web-nsg"]["network_exposure"][0]["from_port"] == 22
    assert nsgs["internal-nsg"]["internet_exposed"] is False

    # Managed identities as principals.
    identities = {i["name"]: i for i in payload["managed_identities"]}
    assert identities["web-identity"]["principal_type"] == "managed-identity"
    assert identities["web-identity"]["principal_id"] == "mi-principal-1"
    assert identities["web-identity"]["privilege_level"] == "unknown"

    # Per-run trust contract.
    env = payload["discovery_envelope"]
    assert env["scan_mode"] == "cloud_read_only"
    assert "Microsoft.Storage/storageAccounts/read" in env["permissions_used"]
    assert "azure:subscription/sub-1" in env["discovery_scope"]


def test_inventory_force_bypasses_flag(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(azure_inventory.INVENTORY_ENV_FLAG, raising=False)
    with _install_fake_azure():
        payload = azure_inventory.discover_inventory(subscription_id="sub-1", credential=_FakeCredential(), force=True)
    assert payload["status"] == "ok"
    assert payload["storage_accounts"]


def test_inventory_selective_classes(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(azure_inventory.INVENTORY_ENV_FLAG, "1")
    with _install_fake_azure():
        payload = azure_inventory.discover_inventory(
            subscription_id="sub-1", credential=_FakeCredential(), include_compute=False, include_identity=False
        )
    assert payload["storage_accounts"]
    assert payload["instances"] == []
    assert payload["managed_identities"] == []
    env = payload["discovery_envelope"]
    assert "Microsoft.Compute/virtualMachines/read" not in env["permissions_used"]
    assert "Microsoft.ManagedIdentity/userAssignedIdentities/read" not in env["permissions_used"]


# ---------------------------------------------------------------------------
# Graph-builder integration
# ---------------------------------------------------------------------------


def _build_graph_from_inventory(payload: dict[str, Any]) -> Any:
    from agent_bom.graph.builder import build_unified_graph_from_report

    return build_unified_graph_from_report({"agents": [], "cloud_inventory": payload})


def test_graph_emits_inventory_nodes_and_overlays(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(azure_inventory.INVENTORY_ENV_FLAG, "1")
    with _install_fake_azure():
        payload = azure_inventory.discover_inventory(subscription_id="sub-1", credential=_FakeCredential())

    graph = _build_graph_from_inventory(payload)
    from agent_bom.graph.types import EntityType

    nodes = graph.nodes
    # Storage account → CLOUD_RESOURCE, with a DATA_STORE companion from CNAPP.
    account_id = "cloud_resource:azure:storage:bucket:publiclake"
    assert account_id in nodes
    assert nodes[account_id].attributes["internet_exposed"] is True
    assert f"data_store:{account_id}" in nodes
    assert nodes[f"data_store:{account_id}"].entity_type == EntityType.DATA_STORE

    # VM + NSG present. The VM node id keys off the full ARM resource id.
    vm_arn = "/subscriptions/sub-1/resourceGroups/rg-web/providers/Microsoft.Compute/virtualMachines/web-1"
    vm_id = f"cloud_resource:azure:compute:instance:{vm_arn}"
    nsg_arn = "/subscriptions/sub-1/resourceGroups/rg-web/providers/Microsoft.Network/networkSecurityGroups/web-nsg"
    nsg_id = f"cloud_resource:azure:network:network-security-group:{nsg_arn}"
    assert vm_id in nodes
    assert nsg_id in nodes
    assert nodes[nsg_id].attributes["internet_exposed"] is True

    # Managed identity as a MANAGED_IDENTITY principal node.
    identity_arn = "/subscriptions/sub-1/resourceGroups/rg-web/providers/Microsoft.ManagedIdentity/userAssignedIdentities/web-identity"
    identity_id = f"managed_identity:azure:{identity_arn}"
    assert identity_id in nodes
    assert nodes[identity_id].entity_type == EntityType.MANAGED_IDENTITY


def test_graph_inventory_noop_when_not_ok() -> None:
    graph = _build_graph_from_inventory(
        {"provider": "azure", "status": "disabled", "storage_accounts": [], "instances": [], "security_groups": []}
    )
    assert not any(nid.startswith("cloud_resource:azure:") for nid in graph.nodes)


# ---------------------------------------------------------------------------
# Partial-permission tolerance: a single failing discoverer must degrade to a
# warning (and, for access errors, an actionable missing_permissions entry)
# without aborting the rest of the scan.
# ---------------------------------------------------------------------------


class _AzureAuthError(Exception):
    """Stand-in for azure.core HttpResponseError on a 403 (AuthorizationFailed)."""

    def __init__(self) -> None:
        super().__init__("(AuthorizationFailed) The client does not have authorization to perform action.")
        self.status_code = 403


def test_azure_discoverer_exception_does_not_abort_scan(monkeypatch: pytest.MonkeyPatch) -> None:
    # Patch the SDK call INSIDE the VM discoverer so the real discoverer's own
    # try/except runs — this proves the genuine degrade path, not a stub.
    monkeypatch.setenv(azure_inventory.INVENTORY_ENV_FLAG, "1")

    def _boom(self: Any) -> list[Any]:
        raise RuntimeError("transient ARM 500 from the VM list endpoint")

    monkeypatch.setattr(_FakeVMOps, "list_all", _boom)
    with _install_fake_azure():
        payload = azure_inventory.discover_inventory(subscription_id="sub-1", credential=_FakeCredential())

    # The overall call still returns ok and the OTHER resource types are present.
    assert payload["status"] == "ok"
    assert {a["name"] for a in payload["storage_accounts"]} == {"publiclake", "privatelogs"}
    # The failed resource type still produced a clear warning (never a silent drop).
    assert any("transient ARM 500" in w for w in payload["warnings"])
    # A generic (non-access) failure produces NO missing_permissions entry.
    assert payload["missing_permissions"] == []


def test_azure_permission_denied_degrades_with_guidance(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(azure_inventory.INVENTORY_ENV_FLAG, "1")

    def _denied(self: Any) -> list[Any]:
        raise _AzureAuthError()

    monkeypatch.setattr(_FakeVMOps, "list_all", _denied)
    with _install_fake_azure():
        payload = azure_inventory.discover_inventory(subscription_id="sub-1", credential=_FakeCredential())

    assert payload["status"] == "ok"
    # Other resource types still discovered — no silent total failure.
    assert {a["name"] for a in payload["storage_accounts"]} == {"publiclake", "privatelogs"}
    # The access error yields an ACTIONABLE warning naming the missing permission.
    actionable = [w for w in payload["warnings"] if "role lacks" in w and "Azure virtual machines" in w]
    assert actionable, payload["warnings"]
    assert "Microsoft.Compute/virtualMachines/read" in actionable[0]
    assert "add it to the read-only policy" in actionable[0]
    # And a structured missing_permissions entry the product can render.
    entries = [e for e in payload["missing_permissions"] if e["resource_type"] == "Azure virtual machines"]
    assert entries == [
        {"cloud": "azure", "permission": "Microsoft.Compute/virtualMachines/read", "resource_type": "Azure virtual machines"}
    ]


def test_azure_missing_permissions_are_sorted_and_deduped(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(azure_inventory.INVENTORY_ENV_FLAG, "1")

    def _denied(self: Any) -> list[Any]:
        raise _AzureAuthError()

    # Two discoverers denied (compute VMs + storage accounts): the result list
    # must be deterministic + deduped regardless of thread completion order.
    monkeypatch.setattr(_FakeVMOps, "list_all", _denied)
    monkeypatch.setattr(_FakeStorageOps, "list", _denied)
    with _install_fake_azure():
        payload = azure_inventory.discover_inventory(subscription_id="sub-1", credential=_FakeCredential())

    perms = payload["missing_permissions"]
    # Sorted by (cloud, resource_type, permission) → Storage before virtual machines.
    assert [e["resource_type"] for e in perms] == ["Azure Storage Accounts", "Azure virtual machines"]
    # Idempotent: re-deduping the same list is a no-op.
    assert azure_inventory.dedupe_missing_permissions(perms + perms) == perms
