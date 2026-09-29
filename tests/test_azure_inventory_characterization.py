"""Golden characterization of Azure estate inventory discovery.

Drives the public entrypoints (``discover_inventory``,
``discover_all_subscription_inventories``, ``enumerate_subscription_ids``)
against fake Azure SDK modules installed in ``sys.modules`` and pins the COMPLETE
returned payloads plus every emitted ``agent_bom`` log record, across the happy
path, empty tenant, access-denied, throttled, mid-pagination failure, SDK-missing
and every pre-discovery gate. Regenerate with ``UPDATE_CLOUD_GOLDEN=1``.

All credentials and tokens here are inert fakes.
"""

from __future__ import annotations

import json
import logging
import os
import sys
import types
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from agent_bom.cloud import azure_authorization_collector, azure_blob_data_classifier  # noqa: F401 — import before sys.modules faking
from agent_bom import discovery_envelope
from agent_bom.cloud import azure_inventory as azinv
from agent_bom.identity import entra_nhi

GOLDEN = Path(__file__).parent / "fixtures" / "cloud_characterization" / "azure_inventory.json"

SUB = "00000000-0000-0000-0000-00000000aaaa"
RG = f"/subscriptions/{SUB}/resourceGroups"


class _Obj:
    def __init__(self, **kwargs: Any) -> None:
        for key, value in kwargs.items():
            setattr(self, key, value)


class _AccessDenied(Exception):
    status_code = 403


class _Throttled(Exception):
    status_code = 429


def _denied() -> Exception:
    return _AccessDenied("(AuthorizationFailed) The client does not have authorization to perform action")


def _throttled() -> Exception:
    return _Throttled("(TooManyRequests) Rate limit exceeded, retry after 30s")


class _Pager:
    """ItemPaged stand-in: yields item pages lazily, optionally failing mid-stream."""

    def __init__(self, pages: list[list[Any]], error: Exception | None = None) -> None:
        self._pages = pages
        self._error = error

    def __iter__(self) -> Any:
        for page in self._pages:
            yield from page
        if self._error is not None:
            raise self._error


# ---------------------------------------------------------------------------
# Fixture data (full estate)
# ---------------------------------------------------------------------------


def _vnet_id(name: str) -> str:
    return f"{RG}/rg-net/providers/Microsoft.Network/virtualNetworks/{name}"


def _data() -> dict[str, list[Any]]:
    web_subnet = f"{_vnet_id('vnet-1')}/subnets/web"
    db_subnet = f"{_vnet_id('vnet-1')}/subnets/db"
    return {
        "storage": [
            _Obj(
                name="publiclake",
                id=f"{RG}/rg-data/providers/Microsoft.Storage/storageAccounts/publiclake",
                location="eastus",
                kind="StorageV2",
                allow_blob_public_access=True,
                network_rule_set=_Obj(default_action="Allow"),
                tags={"classification": "pii", None: "dropped"},
            ),
            _Obj(
                name="privatelogs",
                id=f"{RG}/rg-ops/providers/Microsoft.Storage/storageAccounts/privatelogs",
                location="westus",
                kind="BlobStorage",
                allow_blob_public_access=False,
                network_rule_set=_Obj(default_action="Deny"),
                tags=None,
            ),
            _Obj(name="firewalled", id="", allow_blob_public_access=True, network_rule_set=_Obj(default_action="Deny")),
            _Obj(name="norules", id="bare-id", allow_blob_public_access=True, network_rule_set=None, tags=["not", "dict"]),
            _Obj(name="  ", id="skip-me"),
        ],
        "vms": [
            _Obj(
                name="web-1",
                id=f"{RG}/rg-web/providers/Microsoft.Compute/virtualMachines/web-1",
                location="eastus",
                hardware_profile=_Obj(vm_size="Standard_D2s_v3"),
                identity=_Obj(principal_id="mi-principal-1", type="SystemAssigned,UserAssigned", user_assigned_identities={"/uai/a": {}, "": {}}),
                tags={"app": "web"},
            ),
            _Obj(name="typed-only", id="", hardware_profile=None, identity=_Obj(principal_id="", type="UserAssigned", user_assigned_identities=None)),
            _Obj(name="no-identity", id="vm-bare", identity=None),
            _Obj(name="", id="skip"),
        ],
        "aks": [
            _Obj(
                name="public-aks",
                id=f"{RG}/rg-k8s/providers/Microsoft.ContainerService/managedClusters/public-aks",
                location="eastus",
                kubernetes_version="1.29.2",
                fqdn="public-aks.hcp.eastus.azmk8s.io",
                api_server_access_profile=_Obj(enable_private_cluster=False),
                enable_rbac=True,
                tags={"env": "prod"},
            ),
            _Obj(name="private-aks", id="aks-2", fqdn="private.azmk8s.io", api_server_access_profile=_Obj(enable_private_cluster=True)),
            _Obj(name="noprofile", id="aks-3", fqdn="", api_server_access_profile=None),
            _Obj(name=None),
        ],
        "nsgs": [
            _Obj(
                name="web-nsg",
                id=f"{RG}/rg-web/providers/Microsoft.Network/networkSecurityGroups/web-nsg",
                location="eastus",
                security_rules=[
                    _Obj(direction="Inbound", access="Allow", protocol="Tcp", source_address_prefix="*", destination_port_range="22"),
                    _Obj(
                        direction="Inbound",
                        access="Allow",
                        protocol="Udp",
                        source_address_prefix=None,
                        source_address_prefixes=["10.0.0.0/8", "", "Internet"],
                        destination_port_range=None,
                        destination_port_ranges=["8000-8080", "9000"],
                    ),
                    _Obj(direction="Inbound", access="Allow", protocol=None, source_address_prefix="0.0.0.0/0", destination_port_range="*"),
                    _Obj(direction="Inbound", access="Allow", protocol="*", source_address_prefix="Any", destination_port_range="abc"),
                    _Obj(direction="Inbound", access="Allow", protocol="Tcp", source_address_prefix="::/0", destination_port_range=None),
                    _Obj(direction="Outbound", access="Allow", protocol="Tcp", source_address_prefix="*", destination_port_range="443"),
                    _Obj(direction="Inbound", access="Deny", protocol="Tcp", source_address_prefix="*", destination_port_range="3389"),
                    _Obj(direction="Inbound", access="Allow", protocol="Tcp", source_address_prefix="10.1.0.0/16", destination_port_range="80"),
                ],
            ),
            _Obj(name="empty-nsg", id="", security_rules=None),
            _Obj(name=" ", id="skip"),
        ],
        "msi": [
            _Obj(
                name="web-identity",
                id=f"{RG}/rg-web/providers/Microsoft.ManagedIdentity/userAssignedIdentities/web-identity",
                principal_id="mi-principal-1",
                client_id="mi-client-1",
                location="eastus",
            ),
            _Obj(name="", id="skip"),
        ],
        "role_assignments": [
            _Obj(
                id=f"/subscriptions/{SUB}/providers/Microsoft.Authorization/roleAssignments/ra-1",
                name="ra-1",
                principal_id="mi-principal-1",
                principal_type="ServicePrincipal",
                role_definition_id=f"/subscriptions/{SUB}/providers/Microsoft.Authorization/roleDefinitions/contrib",
                scope=f"/subscriptions/{SUB}",
            ),
            _Obj(id="ra-2", principal_id="", principal_type="User", role_definition_id="rd", scope="s"),
        ],
        "role_definitions": [
            _Obj(
                id=f"/subscriptions/{SUB}/providers/Microsoft.Authorization/roleDefinitions/contrib",
                role_name="Contributor",
                role_type="BuiltInRole",
                assignable_scopes=["/"],
                permissions=[_Obj(actions=["*"], not_actions=["Microsoft.Authorization/*/Write"], data_actions=[], not_data_actions=[])],
            )
        ],
        "deny_assignments": [],
        "vaults": [
            _Obj(
                name="kv-prod",
                id=f"{RG}/rg-sec/providers/Microsoft.KeyVault/vaults/kv-prod",
                location="eastus",
                properties=_Obj(vault_uri="https://kv-prod.vault.azure.net/", enable_rbac_authorization=True, public_network_access="Disabled"),
            ),
            _Obj(name="kv-noprops", id="kv-2", properties=None),
            _Obj(name="", id="skip"),
        ],
        "registries": [
            _Obj(
                name="acrprod",
                id=f"{RG}/rg-ci/providers/Microsoft.ContainerRegistry/registries/acrprod",
                location="eastus",
                login_server="acrprod.azurecr.io",
                sku=_Obj(name="Premium"),
                admin_user_enabled=True,
                public_network_access="Enabled",
            ),
            _Obj(name="acr-nosku", id="acr-2", sku=None),
            _Obj(name="", id="skip"),
        ],
        "cosmos": [
            _Obj(
                name="cosmos-1",
                id=f"{RG}/rg-data/providers/Microsoft.DocumentDB/databaseAccounts/cosmos-1",
                location="eastus",
                public_network_access="Enabled",
                is_virtual_network_filter_enabled=True,
            ),
            _Obj(name="", id="skip"),
        ],
        "sql": [
            _Obj(name="sql-1", id=f"{RG}/rg-data/providers/Microsoft.Sql/servers/sql-1", location="eastus", public_network_access="Enabled"),
            _Obj(name="", id="skip"),
        ],
        "postgres": [
            _Obj(name="pg-1", id=f"{RG}/rg-data/providers/Microsoft.DBforPostgreSQL/flexibleServers/pg-1", network=_Obj(public_network_access="Disabled")),
            _Obj(name="pg-2", id="pg-2", public_network_access="", network=None),
        ],
        "mysql": [_Obj(name="mysql-1", id="mysql-1", location="westus", tags={"t": 1})],
        "eventhubs": [
            _Obj(name="eh-1", id=f"{RG}/rg-msg/providers/Microsoft.EventHub/namespaces/eh-1", sku=_Obj(name="Standard"), public_network_access="Enabled"),
            _Obj(name="eh-2", id="eh-2", sku=None),
            _Obj(name="", id="skip"),
        ],
        "servicebus": [
            _Obj(name="sb-1", id=f"{RG}/rg-msg/providers/Microsoft.ServiceBus/namespaces/sb-1", sku=_Obj(name="Premium"), public_network_access="Disabled"),
            _Obj(name="sb-2", id="sb-2", sku=None),
            _Obj(name="", id="skip"),
        ],
        "redis": [
            _Obj(
                name="redis-1",
                id=f"{RG}/rg-cache/providers/Microsoft.Cache/Redis/redis-1",
                sku=_Obj(name="Basic"),
                enable_non_ssl_port=True,
                public_network_access="Enabled",
            ),
            _Obj(name="redis-2", id="redis-2", sku=None),
            _Obj(name="", id="skip"),
        ],
        "vnets": [
            _Obj(
                name="vnet-1",
                id=_vnet_id("vnet-1"),
                location="eastus",
                address_space=_Obj(address_prefixes=["10.0.0.0/16", "10.1.0.0/16"]),
                subnets=[
                    _Obj(name="web", id=web_subnet, address_prefix="10.0.1.0/24", nat_gateway=_Obj(id="nat-1")),
                    _Obj(name="db", id=db_subnet, address_prefix="", address_prefixes=["10.0.2.0/24", "10.0.3.0/24"], nat_gateway=None),
                    _Obj(name="noprefix", id=f"{_vnet_id('vnet-1')}/subnets/noprefix", address_prefix=None, address_prefixes=None),
                    _Obj(name="", id="skip"),
                ],
            ),
            _Obj(name="vnet-bare", id=_vnet_id("vnet-bare"), address_space=None, subnets=None),
            _Obj(name="", id="skip"),
        ],
        "public_ips": [
            _Obj(
                name="pip-1",
                id=f"{RG}/rg-web/providers/Microsoft.Network/publicIPAddresses/pip-1",
                location="eastus",
                ip_address="203.0.113.10",
                public_ip_allocation_method="Static",
                ip_configuration=_Obj(id=f"{RG}/rg-web/providers/Microsoft.Network/networkInterfaces/nic-1/ipConfigurations/ipconfig1"),
            ),
            _Obj(name="pip-free", id="pip-2", location="westus", ip_address="", public_ip_allocation_method="Dynamic", ip_configuration=None),
            _Obj(name="", id="pip-nameless", ip_address="203.0.113.99", ip_configuration=_Obj(id="")),
        ],
        "nics": [
            _Obj(
                name="nic-1",
                id=f"{RG}/rg-web/providers/Microsoft.Network/networkInterfaces/nic-1",
                location="eastus",
                virtual_machine=_Obj(id=f"{RG}/rg-web/providers/Microsoft.Compute/virtualMachines/web-1"),
                network_security_group=_Obj(id=f"{RG}/rg-web/providers/Microsoft.Network/networkSecurityGroups/web-nsg"),
                ip_configurations=[
                    _Obj(private_ip_address="", subnet=None, public_ip_address=None),
                    _Obj(private_ip_address="10.0.1.5", subnet=_Obj(id=web_subnet), public_ip_address=_Obj(ip_address="", id="pip-ref-id")),
                    _Obj(private_ip_address="10.0.1.6", subnet=_Obj(id=db_subnet), public_ip_address=_Obj(ip_address="203.0.113.10", id="x")),
                ],
            ),
            _Obj(name="nic-bare", id="nic-2", virtual_machine=None, network_security_group=None, ip_configurations=None),
            _Obj(name="", id="skip"),
        ],
        "firewalls": [
            _Obj(
                name="fw-1",
                id=f"{RG}/rg-net/providers/Microsoft.Network/azureFirewalls/fw-1",
                location="eastus",
                ip_configurations=[
                    _Obj(private_ip_address="10.0.0.4", public_ip_address=_Obj(ip_address="203.0.113.50", id="fw-pip")),
                    _Obj(private_ip_address="10.0.0.5", public_ip_address=None),
                    _Obj(private_ip_address="", public_ip_address=_Obj(ip_address=None, id="fw-pip-2")),
                ],
            ),
            _Obj(name="fw-bare", id="fw-2", ip_configurations=None),
            _Obj(name="", id="skip"),
        ],
        "nat": [
            _Obj(name="nat-1", id="nat-1", location="eastus", subnets=[_Obj(id=""), _Obj(id=web_subnet), _Obj(id=db_subnet)]),
            _Obj(name="nat-orphan", id="nat-2", subnets=None),
            _Obj(name="", id="skip"),
        ],
        "route_tables": [
            _Obj(
                name="rt-public",
                id="rt-1",
                location="eastus",
                subnets=[_Obj(id="not-a-subnet"), _Obj(id=web_subnet)],
                routes=[_Obj(next_hop_type="VirtualAppliance", address_prefix="10.0.0.0/8"), _Obj(next_hop_type="Internet", address_prefix="0.0.0.0/0")],
            ),
            _Obj(name="rt-private", id="rt-2", subnets=[], routes=[_Obj(next_hop_type="VirtualAppliance", address_prefix="0.0.0.0/0")]),
            _Obj(name="rt-empty", id="rt-3", subnets=None, routes=None),
            _Obj(name="", id="skip"),
        ],
        "private_endpoints": [
            _Obj(
                name="pe-sql",
                id="pe-1",
                location="eastus",
                subnet=_Obj(id=db_subnet),
                private_link_service_connections=[_Obj(private_link_service_id=""), _Obj(private_link_service_id="sql-1-target")],
            ),
            _Obj(name="pe-bare", id="pe-2", subnet=None, private_link_service_connections=None),
            _Obj(name="", id="skip"),
        ],
        "load_balancers": [
            _Obj(
                name="lb-public",
                id=f"{RG}/rg-web/providers/Microsoft.Network/loadBalancers/lb-public",
                sku=_Obj(name="Standard"),
                frontend_ip_configurations=[
                    _Obj(public_ip_address=_Obj(id="pip-lb")),
                    _Obj(public_ip_address=None),
                    _Obj(public_ip_address=_Obj(id="")),
                ],
            ),
            _Obj(name="lb-internal", id="lb-2", sku=None, frontend_ip_configurations=None),
            _Obj(name="", id="skip"),
        ],
        "app_gateways": [
            _Obj(
                name="agw-waf-config",
                id="agw-1",
                sku=_Obj(name="Standard_v2", tier="Standard_v2"),
                web_application_firewall_configuration=_Obj(enabled=True),
                firewall_policy=None,
                frontend_ip_configurations=[_Obj(public_ip_address=_Obj(id="pip-agw"))],
            ),
            _Obj(
                name="agw-policy",
                id="agw-2",
                sku=_Obj(name="Standard_v2", tier="Standard_v2"),
                web_application_firewall_configuration=_Obj(enabled=False),
                firewall_policy=_Obj(id="policy-1"),
                frontend_ip_configurations=[],
            ),
            _Obj(name="agw-tier", id="agw-3", sku=_Obj(name="WAF_v2", tier="WAF_v2"), web_application_firewall_configuration=None, firewall_policy=None),
            _Obj(name="agw-plain", id="agw-4", sku=None, web_application_firewall_configuration=None, firewall_policy=_Obj(id="")),
            _Obj(name="", id="skip"),
        ],
        "front_doors": [
            _Obj(name="fd-1", id="fd-1", location=None, cname="fd-1.azurefd.net", enabled_state="Enabled"),
            _Obj(name="fd-2", id="fd-2", location="westeurope"),
            _Obj(name="", id="skip"),
        ],
        "apim": [
            _Obj(name="apim-ext", id="apim-1", sku=_Obj(name="Developer"), gateway_url="https://apim-ext.azure-api.net", virtual_network_type="External"),
            _Obj(name="apim-int", id="apim-2", sku=None, gateway_url="https://apim-int.azure-api.net", public_ip_addresses=["198.51.100.1"], virtual_network_type="Internal"),
            _Obj(name="apim-ips", id="apim-3", gateway_url="", public_ip_addresses=["", "198.51.100.2"], virtual_network_type="None"),
            _Obj(name="apim-dark", id="apim-4", gateway_url="", public_ip_addresses=None),
            _Obj(name="", id="skip"),
        ],
        "disks": [
            _Obj(
                name="disk-1",
                id=f"{RG}/rg-web/providers/Microsoft.Compute/disks/disk-1",
                location="eastus",
                disk_size_gb=128,
                encryption=_Obj(type="EncryptionAtRestWithPlatformKey"),
                public_network_access="Disabled",
            ),
            _Obj(name="disk-2", id="disk-2", encryption=None),
            _Obj(name="", id="skip"),
        ],
        "sites": [
            _Obj(name="webapp", id="site-1", kind="app,linux", default_host_name="webapp.azurewebsites.net", https_only=True, public_network_access="Enabled"),
            _Obj(name="funcapp", id="site-2", kind="functionapp", default_host_name="funcapp.azurewebsites.net", enabled=False),
            _Obj(name="nohost", id="site-3", kind=None, default_host_name=""),
            _Obj(name="", id="skip"),
        ],
        "management_groups": [
            _Obj(id="/providers/Microsoft.Management/managementGroups/root", name="root", display_name="Tenant Root"),
            _Obj(id="/providers/Microsoft.Management/managementGroups/broken", name="broken", display_name="Broken"),
            _Obj(id="/providers/Microsoft.Management/managementGroups/leaf", name="leaf", display_name="Leaf"),
            _Obj(id="skip", name=""),
        ],
        "management_group_children": {
            "root": [
                _Obj(id="/providers/Microsoft.Management/managementGroups/leaf", name="leaf", type="Microsoft.Management/managementGroups", display_name="Leaf"),
                _Obj(id=f"/subscriptions/{SUB}", name=SUB, type="/subscriptions", display_name="Prod"),
                _Obj(id="/subscriptions/dup", name=SUB, type="/subscriptions", display_name="Prod again"),
            ],
            "leaf": [
                _Obj(id="/subscriptions/sub-b", name="sub-b", type="/subscriptions", display_name="Dev"),
                _Obj(id="/subscriptions/blank", name="", type="/subscriptions", display_name="Blank"),
            ],
        },
    }


# ---------------------------------------------------------------------------
# Fake SDK modules
# ---------------------------------------------------------------------------


class _Ops:
    """One fake operations group; ``mode`` controls how each list call behaves."""

    def __init__(self, mode: str, items: list[Any]) -> None:
        self._mode = mode
        self._items = items

    def pager(self) -> Any:
        if self._mode == "empty":
            return _Pager([])
        if self._mode == "denied":
            return _Pager([], _denied())
        if self._mode == "throttled":
            raise _throttled()
        if self._mode == "midpage":
            return _Pager([self._items[:1]], _throttled())
        half = max(1, len(self._items) // 2)
        return _Pager([self._items[:half], self._items[half:]])

    def __getattr__(self, name: str) -> Any:
        if name in {"list", "list_all", "list_by_subscription", "list_for_subscription"}:
            return self.pager
        raise AttributeError(name)


def _client(mode: str, data: dict[str, Any], **groups: str) -> type:
    class _Client:
        def __init__(self, credential: Any, subscription_id: str | None = None) -> None:
            assert credential is not None
            for attr, key in groups.items():
                setattr(self, attr, _Ops(mode, data[key]))

    return _Client


class _RoleDefs:
    def __init__(self, data: dict[str, Any]) -> None:
        self._by_id = {d.id: d for d in data["role_definitions"]}

    def get_by_id(self, role_id: str) -> Any:
        return self._by_id[role_id]


class _MgOps:
    def __init__(self, mode: str, data: dict[str, Any]) -> None:
        self._mode = mode
        self._data = data

    def list(self) -> Any:
        return _Ops(self._mode, self._data["management_groups"]).pager()

    def get(self, *, group_id: str, expand: str, recurse: bool) -> Any:
        assert expand == "children" and recurse is False
        if group_id == "broken":
            raise _denied()
        return _Obj(children=self._data["management_group_children"].get(group_id))


def _install_sdk(monkeypatch: pytest.MonkeyPatch, mode: str, *, legacy_mg_client: bool = False, missing: bool = False) -> None:
    data = _data()

    def mod(name: str, **attrs: Any) -> None:
        if missing and name not in {"azure", "azure.identity", "azure.mgmt"}:
            monkeypatch.setitem(sys.modules, name, None)
            return
        module = types.ModuleType(name)
        for key, value in attrs.items():
            setattr(module, key, value)
        monkeypatch.setitem(sys.modules, name, module)

    class _AuthzClient:
        def __init__(self, credential: Any, subscription_id: str) -> None:
            self.role_assignments = _Ops(mode, data["role_assignments"])
            self.role_definitions = _RoleDefs(data)
            self.deny_assignments = _Ops(mode, data["deny_assignments"])

    class _MgClient:
        def __init__(self, credential: Any) -> None:
            self.management_groups = _MgOps(mode, data)

    mod("azure")
    mod("azure.identity", DefaultAzureCredential=lambda: _Obj(kind="default-credential"))
    mod("azure.mgmt")
    mod("azure.mgmt.storage", StorageManagementClient=_client(mode, data, storage_accounts="storage"))
    mod(
        "azure.mgmt.compute",
        ComputeManagementClient=_client(mode, data, virtual_machines="vms", disks="disks"),
    )
    mod("azure.mgmt.containerservice", ContainerServiceClient=_client(mode, data, managed_clusters="aks"))
    mod(
        "azure.mgmt.network",
        NetworkManagementClient=_client(
            mode,
            data,
            network_security_groups="nsgs",
            virtual_networks="vnets",
            public_ip_addresses="public_ips",
            network_interfaces="nics",
            azure_firewalls="firewalls",
            nat_gateways="nat",
            route_tables="route_tables",
            private_endpoints="private_endpoints",
            load_balancers="load_balancers",
            application_gateways="app_gateways",
        ),
    )
    mod("azure.mgmt.msi", ManagedServiceIdentityClient=_client(mode, data, user_assigned_identities="msi"))
    mod("azure.mgmt.authorization", AuthorizationManagementClient=_AuthzClient)
    mod("azure.mgmt.keyvault", KeyVaultManagementClient=_client(mode, data, vaults="vaults"))
    mod("azure.mgmt.containerregistry", ContainerRegistryManagementClient=_client(mode, data, registries="registries"))
    mod("azure.mgmt.cosmosdb", CosmosDBManagementClient=_client(mode, data, database_accounts="cosmos"))
    mod("azure.mgmt.sql", SqlManagementClient=_client(mode, data, servers="sql"))
    mod("azure.mgmt.rdbms")
    mod("azure.mgmt.rdbms.postgresql_flexibleservers", PostgreSQLManagementClient=_client(mode, data, servers="postgres"))
    mod("azure.mgmt.rdbms.mysql_flexibleservers", MySQLManagementClient=_client(mode, data, servers="mysql"))
    mod("azure.mgmt.eventhub", EventHubManagementClient=_client(mode, data, namespaces="eventhubs"))
    mod("azure.mgmt.servicebus", ServiceBusManagementClient=_client(mode, data, namespaces="servicebus"))
    mod("azure.mgmt.redis", RedisManagementClient=_client(mode, data, redis="redis"))
    mod("azure.mgmt.frontdoor", FrontDoorManagementClient=_client(mode, data, front_doors="front_doors"))
    mod("azure.mgmt.apimanagement", ApiManagementClient=_client(mode, data, api_management_service="apim"))
    mod("azure.mgmt.web", WebSiteManagementClient=_client(mode, data, web_apps="sites"))
    if legacy_mg_client:
        mod("azure.mgmt.managementgroups", ManagementGroupsAPI=_MgClient)
    else:
        mod("azure.mgmt.managementgroups", ManagementGroupsMgmtClient=_MgClient)


class _FakeGraph:
    def __init__(self, mode: str) -> None:
        self._mode = mode

    def list_service_principals(self) -> Any:
        if self._mode == "denied":
            raise _denied()
        return [
            {"id": "sp-1", "displayName": "ci-runner", "appId": "app-1", "servicePrincipalType": "Application"},
            {"id": "sp-2"},
            "not-a-dict",
            {"id": "  "},
        ]

    def list_groups(self) -> Any:
        if self._mode == "denied":
            raise _throttled()
        return [
            {"id": "grp-1", "displayName": "platform-admins"},
            "not-a-dict",
            {"id": ""},
            {"id": "grp-broken", "displayName": "broken"},
            {"id": "grp-over-cap"},
        ]

    def list_group_members(self, group_id: str) -> Any:
        if group_id == "grp-broken":
            raise _denied()
        return [
            {"id": "sp-1", "displayName": "ci-runner", "@odata.type": "#microsoft.graph.servicePrincipal"},
            {"id": "u-1", "@odata.type": "#microsoft.graph.user"},
            {"id": "g-nested", "displayName": "nested", "@odata.type": "#microsoft.graph.group"},
            {"id": "d-1", "@odata.type": "#microsoft.graph.device"},
            {"id": ""},
            None,
        ]


class _FixedDatetime:
    @staticmethod
    def now(tz: Any = None) -> datetime:
        return datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC)


class _Credential:
    """Inert token credential stand-in."""

    def __init__(self, subs: list[dict[str, Any]] | None = None, fail: bool = False) -> None:
        self._fail = fail

    def get_token(self, scope: str) -> Any:
        if self._fail:
            raise RuntimeError("token endpoint unreachable")
        return _Obj(token="fake-test-token-not-a-secret")


@pytest.fixture
def env(monkeypatch: pytest.MonkeyPatch) -> pytest.MonkeyPatch:
    for key in (
        azinv.INVENTORY_ENV_FLAG,
        azinv.ALL_SUBSCRIPTIONS_ENV_FLAG,
        "AZURE_SUBSCRIPTION_ID",
        entra_nhi._DISCOVERY_FLAG_ENV,
        entra_nhi._TOKEN_ENV,
        azure_blob_data_classifier.DSPM_AZURE_BLOB_SAMPLING_ENV_VAR,
    ):
        monkeypatch.delenv(key, raising=False)
    monkeypatch.setattr(azure_authorization_collector, "datetime", _FixedDatetime)
    monkeypatch.setattr(discovery_envelope, "datetime", _FixedDatetime)
    return monkeypatch


def _enable_entra(monkeypatch: pytest.MonkeyPatch, mode: str) -> None:
    monkeypatch.setenv(entra_nhi._DISCOVERY_FLAG_ENV, "1")
    monkeypatch.setenv(entra_nhi._TOKEN_ENV, "fake-graph-token-not-a-secret")
    monkeypatch.setattr(entra_nhi, "EntraClient", lambda token: _FakeGraph(mode))
    monkeypatch.setattr(azinv, "_ENTRA_MAX_GROUPS_EXPANDED", 2)


def _fake_urlopen(subs: list[dict[str, Any]]) -> Any:
    class _Resp:
        def __enter__(self) -> Any:
            return self

        def __exit__(self, *a: Any) -> None:
            return None

        def read(self) -> bytes:
            return json.dumps({"value": subs}).encode("utf-8")

    return lambda request, timeout: _Resp()


class _BlobService:
    def __init__(self, account_url: str, credential: Any) -> None:
        if "boom" in account_url or "privatelogs" in account_url:
            raise _denied()
        self.account_url = account_url

    def list_containers(self) -> Any:
        raise _throttled()

    def close(self) -> None:
        raise RuntimeError("close failed")


# ---------------------------------------------------------------------------
# Scenarios
# ---------------------------------------------------------------------------


def _inv(**kwargs: Any) -> Any:
    return lambda: azinv.discover_inventory(**kwargs)


def _sc_full(mp: pytest.MonkeyPatch) -> Any:
    _install_sdk(mp, "full")
    _enable_entra(mp, "full")
    return _inv(subscription_id=SUB, credential=_Credential(), force=True)


def _sc_full_blob_sampling(mp: pytest.MonkeyPatch) -> Any:
    _install_sdk(mp, "full")
    mp.setenv(azure_blob_data_classifier.DSPM_AZURE_BLOB_SAMPLING_ENV_VAR, "1")
    blob = types.ModuleType("azure.storage.blob")
    blob.BlobServiceClient = _BlobService  # type: ignore[attr-defined]
    mp.setitem(sys.modules, "azure.storage", types.ModuleType("azure.storage"))
    mp.setitem(sys.modules, "azure.storage.blob", blob)
    return _inv(subscription_id=SUB, credential=_Credential(), include_compute=False, include_network=False, include_data=False, force=True)


def _sc_mode(mode: str, entra_mode: str | None = None, **flags: Any) -> Any:
    def build(mp: pytest.MonkeyPatch) -> Any:
        _install_sdk(mp, mode)
        if entra_mode is not None:
            _enable_entra(mp, entra_mode)
        return _inv(subscription_id=SUB, credential=_Credential(), force=True, **flags)

    return build


def _sc_legacy_mg(mp: pytest.MonkeyPatch) -> Any:
    _install_sdk(mp, "full", legacy_mg_client=True)
    return _inv(
        subscription_id=SUB,
        credential=_Credential(),
        include_storage=False,
        include_compute=False,
        include_identity=False,
        include_data=False,
        include_network=False,
        force=True,
    )


def _sc_sdk_modules_missing(mp: pytest.MonkeyPatch) -> Any:
    _install_sdk(mp, "full", missing=True)
    return _inv(subscription_id=SUB, credential=_Credential(), force=True)


def _sc_selective_storage_only(mp: pytest.MonkeyPatch) -> Any:
    _install_sdk(mp, "full")
    return _inv(
        subscription_id=SUB,
        credential=_Credential(),
        include_compute=False,
        include_identity=False,
        include_data=False,
        include_network=False,
        include_hierarchy=False,
        force=True,
    )


def _sc_nothing_included(mp: pytest.MonkeyPatch) -> Any:
    _install_sdk(mp, "full")
    return _inv(
        subscription_id=SUB,
        credential=_Credential(),
        include_storage=False,
        include_compute=False,
        include_identity=False,
        include_data=False,
        include_network=False,
        include_hierarchy=False,
        force=True,
    )


def _sc_future_boundary_failure(mp: pytest.MonkeyPatch) -> Any:
    _install_sdk(mp, "empty")

    def denied(*_a: Any, **_k: Any) -> Any:
        raise _denied()

    def boom(*_a: Any, **_k: Any) -> Any:
        raise ValueError("unexpected SDK shape")

    mp.setattr(azinv, "_discover_key_vaults", denied)
    mp.setattr(azinv, "_discover_route_tables", boom)
    return _inv(subscription_id=SUB, credential=_Credential(), include_hierarchy=False, force=True)


def _sc_disabled(mp: pytest.MonkeyPatch) -> Any:
    _install_sdk(mp, "full")
    mp.setenv("AZURE_SUBSCRIPTION_ID", "env-sub")
    return _inv()


def _sc_enabled_by_flag(mp: pytest.MonkeyPatch) -> Any:
    _install_sdk(mp, "empty")
    mp.setenv(azinv.INVENTORY_ENV_FLAG, " YES ")
    mp.setenv("AZURE_SUBSCRIPTION_ID", "env-sub")
    return _inv(include_hierarchy=False)


def _sc_sdk_missing(mp: pytest.MonkeyPatch) -> Any:
    mp.setitem(sys.modules, "azure.identity", None)
    return _inv(subscription_id=SUB, force=True)


def _sc_no_credentials(mp: pytest.MonkeyPatch) -> Any:
    _install_sdk(mp, "empty")

    def broken() -> Any:
        raise RuntimeError("DefaultAzureCredential failed to retrieve a token")

    sys.modules["azure.identity"].DefaultAzureCredential = broken  # type: ignore[union-attr]
    return _inv(subscription_id=SUB, force=True)


def _sc_default_credential_used(mp: pytest.MonkeyPatch) -> Any:
    _install_sdk(mp, "empty")
    return _inv(subscription_id=SUB, include_hierarchy=False, force=True)


def _sc_no_subscription_token_fails(mp: pytest.MonkeyPatch) -> Any:
    _install_sdk(mp, "empty")
    return _inv(credential=_Credential(fail=True), force=True)


def _sc_no_subscription_listing_fails(mp: pytest.MonkeyPatch) -> Any:
    _install_sdk(mp, "empty")

    def urlopen(request: Any, timeout: int) -> Any:
        raise OSError("connection reset")

    mp.setattr("urllib.request.urlopen", urlopen)
    return _inv(credential=_Credential(), force=True)


def _sc_no_subscription_none_visible(mp: pytest.MonkeyPatch) -> Any:
    _install_sdk(mp, "empty")
    mp.setattr("urllib.request.urlopen", _fake_urlopen([{"displayName": "no id"}]))
    return _inv(credential=_Credential(), force=True)


def _sc_autoderive_multi(mp: pytest.MonkeyPatch) -> Any:
    _install_sdk(mp, "empty")
    subs = [
        {"subscriptionId": "sub-disabled", "state": "Disabled"},
        {"subscriptionId": "sub-first", "state": "Enabled"},
        {"subscriptionId": "sub-second"},
    ]
    mp.setattr("urllib.request.urlopen", _fake_urlopen(subs))
    return _inv(credential=_Credential(), include_hierarchy=False, force=True)


def _sc_autoderive_only_disabled(mp: pytest.MonkeyPatch) -> Any:
    _install_sdk(mp, "empty")
    mp.setattr("urllib.request.urlopen", _fake_urlopen([{"subscriptionId": "sub-only", "state": "Disabled"}]))
    return _inv(credential=_Credential(), include_hierarchy=False, force=True)


def _sc_entra_no_token(mp: pytest.MonkeyPatch) -> Any:
    _install_sdk(mp, "empty")
    mp.setenv(entra_nhi._DISCOVERY_FLAG_ENV, "true")
    return _inv(subscription_id=SUB, credential=_Credential(), include_hierarchy=False, force=True)


def _sc_entra_client_init_fails(mp: pytest.MonkeyPatch) -> Any:
    _install_sdk(mp, "empty")
    mp.setenv(entra_nhi._DISCOVERY_FLAG_ENV, "1")
    mp.setenv(entra_nhi._TOKEN_ENV, "fake-graph-token-not-a-secret")

    def broken(token: str) -> Any:
        raise RuntimeError("graph client init failed")

    mp.setattr(entra_nhi, "EntraClient", broken)
    return _inv(subscription_id=SUB, credential=_Credential(), include_hierarchy=False, force=True)


def _sc_all_subs(mp: pytest.MonkeyPatch) -> Any:
    _install_sdk(mp, "full")
    mp.setattr(azinv, "discover_inventory", _summarizing_inventory(azinv.discover_inventory))
    return lambda: azinv.discover_all_subscription_inventories(credential=_Credential(), force=True)


def _sc_all_subs_capped(mp: pytest.MonkeyPatch) -> Any:
    _install_sdk(mp, "full")
    mp.setattr(azinv, "_MAX_SUBSCRIPTIONS", 1)
    mp.setattr(azinv, "discover_inventory", _summarizing_inventory(azinv.discover_inventory))
    return lambda: azinv.discover_all_subscription_inventories(force=True)


def _sc_all_subs_env_fallback(mp: pytest.MonkeyPatch) -> Any:
    _install_sdk(mp, "denied")
    mp.setenv(azinv.INVENTORY_ENV_FLAG, "on")
    mp.setenv("AZURE_SUBSCRIPTION_ID", "env-sub")
    mp.setattr(azinv, "discover_inventory", _summarizing_inventory(azinv.discover_inventory))
    return lambda: azinv.discover_all_subscription_inventories(credential=_Credential())


def _sc_all_subs_disabled(mp: pytest.MonkeyPatch) -> Any:
    _install_sdk(mp, "full")
    return lambda: azinv.discover_all_subscription_inventories(credential=_Credential())


def _sc_all_subs_sdk_missing(mp: pytest.MonkeyPatch) -> Any:
    mp.setitem(sys.modules, "azure.identity", None)
    return lambda: azinv.discover_all_subscription_inventories(force=True)


def _sc_all_subs_no_credentials(mp: pytest.MonkeyPatch) -> Any:
    _install_sdk(mp, "full")

    def broken() -> Any:
        raise RuntimeError("no credential")

    sys.modules["azure.identity"].DefaultAzureCredential = broken  # type: ignore[union-attr]
    return lambda: azinv.discover_all_subscription_inventories(force=True)


def _sc_enumerate_full(mp: pytest.MonkeyPatch) -> Any:
    _install_sdk(mp, "full")
    return lambda: azinv.enumerate_subscription_ids(_Credential())


def _sc_enumerate_throttled_no_env(mp: pytest.MonkeyPatch) -> Any:
    _install_sdk(mp, "throttled")
    return lambda: azinv.enumerate_subscription_ids(_Credential())


def _sc_enumerate_mg_raises(mp: pytest.MonkeyPatch) -> Any:
    def raising(credential: Any) -> Any:
        raise _denied()

    mp.setattr(azinv, "_discover_management_groups", raising)
    mp.setenv("AZURE_SUBSCRIPTION_ID", "  env-sub  ")
    return lambda: azinv.enumerate_subscription_ids(_Credential())


def _sc_enumerate_sdk_missing(mp: pytest.MonkeyPatch) -> Any:
    _install_sdk(mp, "full", missing=True)
    return lambda: azinv.enumerate_subscription_ids(_Credential())


def _summarizing_inventory(real: Any) -> Any:
    def wrapper(**kwargs: Any) -> dict[str, Any]:
        payload = real(**kwargs)
        return {
            "kwargs": {k: v for k, v in kwargs.items() if k != "credential"},
            "status": payload["status"],
            "account_id": payload["account_id"],
            "counts": {k: len(v) for k, v in payload.items() if isinstance(v, list)},
            "warnings": payload["warnings"],
            "missing_permissions": payload["missing_permissions"],
        }

    return wrapper


SCENARIOS: dict[str, Any] = {
    "full": _sc_full,
    "full_blob_sampling": _sc_full_blob_sampling,
    "empty": _sc_mode("empty"),
    "denied": _sc_mode("denied", entra_mode="denied"),
    "throttled": _sc_mode("throttled"),
    "midpage_failure": _sc_mode("midpage"),
    "legacy_mg_client": _sc_legacy_mg,
    "sdk_modules_missing": _sc_sdk_modules_missing,
    "selective_storage_only": _sc_selective_storage_only,
    "nothing_included": _sc_nothing_included,
    "future_boundary_failure": _sc_future_boundary_failure,
    "disabled": _sc_disabled,
    "enabled_by_flag": _sc_enabled_by_flag,
    "sdk_missing": _sc_sdk_missing,
    "no_credentials": _sc_no_credentials,
    "default_credential_used": _sc_default_credential_used,
    "no_subscription_token_fails": _sc_no_subscription_token_fails,
    "no_subscription_listing_fails": _sc_no_subscription_listing_fails,
    "no_subscription_none_visible": _sc_no_subscription_none_visible,
    "autoderive_multi": _sc_autoderive_multi,
    "autoderive_only_disabled": _sc_autoderive_only_disabled,
    "entra_no_token": _sc_entra_no_token,
    "entra_client_init_fails": _sc_entra_client_init_fails,
    "all_subs": _sc_all_subs,
    "all_subs_capped": _sc_all_subs_capped,
    "all_subs_env_fallback": _sc_all_subs_env_fallback,
    "all_subs_disabled": _sc_all_subs_disabled,
    "all_subs_sdk_missing": _sc_all_subs_sdk_missing,
    "all_subs_no_credentials": _sc_all_subs_no_credentials,
    "enumerate_full": _sc_enumerate_full,
    "enumerate_throttled_no_env": _sc_enumerate_throttled_no_env,
    "enumerate_mg_raises": _sc_enumerate_mg_raises,
    "enumerate_sdk_missing": _sc_enumerate_sdk_missing,
}


def _jsonable(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(k): _jsonable(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_jsonable(v) for v in value]
    return value


def _run(name: str, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture) -> dict[str, Any]:
    call = SCENARIOS[name](monkeypatch)
    caplog.clear()
    with caplog.at_level(logging.DEBUG, logger="agent_bom"):
        result = call()
    logs = [[r.levelname, r.name, r.getMessage()] for r in caplog.records if r.name.startswith("agent_bom")]
    return {"result": _jsonable(result), "logs": logs}


def _load_golden() -> dict[str, Any]:
    return json.loads(GOLDEN.read_text(encoding="utf-8")) if GOLDEN.exists() else {}


@pytest.mark.parametrize("scenario", sorted(SCENARIOS))
def test_azure_inventory_matches_golden(scenario: str, env: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture) -> None:
    actual = _run(scenario, env, caplog)
    if os.environ.get("UPDATE_CLOUD_GOLDEN") == "1":
        golden = _load_golden()
        golden[scenario] = actual
        GOLDEN.parent.mkdir(parents=True, exist_ok=True)
        GOLDEN.write_text(json.dumps(dict(sorted(golden.items())), indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        return
    golden = _load_golden()
    assert scenario in golden, f"missing golden for {scenario}; regenerate with UPDATE_CLOUD_GOLDEN=1"
    assert actual == golden[scenario]


def test_golden_has_no_stale_scenarios() -> None:
    assert sorted(_load_golden()) == sorted(SCENARIOS)


def test_golden_covers_every_resource_family() -> None:
    full = _load_golden()["full"]["result"]
    skip = {"authorization_observed_at", "authorization_evidence", "discovery_envelope", "missing_permissions", "warnings", "deny_assignments"}
    empty_lists = [k for k, v in full.items() if isinstance(v, list) and not v and k not in skip]
    assert empty_lists == []
    assert full["status"] == "ok"
    denied = _load_golden()["denied"]["result"]
    assert len(denied["missing_permissions"]) >= 25


# ---------------------------------------------------------------------------
# Patch points: attributes tests patch on the façade must keep steering the
# code paths that consume them, wherever those paths live.
# ---------------------------------------------------------------------------


def test_patch_point_discover_management_groups_steers_enumeration(env: pytest.MonkeyPatch) -> None:
    env.setattr(azinv, "_discover_management_groups", lambda cred: ([{"children": [{"type": "/subscriptions", "name": "patched"}]}], ["w"]))
    assert azinv.enumerate_subscription_ids(_Credential()) == (["patched"], ["w"])


def test_patch_point_subscription_ids_from_mg_tree(env: pytest.MonkeyPatch) -> None:
    env.setattr(azinv, "_discover_management_groups", lambda cred: ([], []))
    env.setattr(azinv, "_subscription_ids_from_mg_tree", lambda groups: ["from-patched-tree"])
    assert azinv.enumerate_subscription_ids(_Credential()) == (["from-patched-tree"], [])


@pytest.mark.parametrize("name", ["inventory_enabled", "enumerate_subscription_ids", "discover_inventory", "_MAX_SUBSCRIPTIONS"])
def test_patch_point_all_subscription_fanout(name: str, env: pytest.MonkeyPatch) -> None:
    _install_sdk(env, "empty")
    env.setattr(azinv, "inventory_enabled", lambda: True)
    env.setattr(azinv, "enumerate_subscription_ids", lambda cred: (["s1", "s2"], []))
    env.setattr(azinv, "discover_inventory", lambda **kw: {"account_id": kw["subscription_id"]})
    if name == "inventory_enabled":
        env.setattr(azinv, "inventory_enabled", lambda: False)
        expected: list[Any] = []
    elif name == "enumerate_subscription_ids":
        env.setattr(azinv, "enumerate_subscription_ids", lambda cred: (["only"], []))
        expected = [{"account_id": "only"}]
    elif name == "discover_inventory":
        env.setattr(azinv, "discover_inventory", lambda **kw: {"patched": kw["subscription_id"]})
        expected = [{"patched": "s1"}, {"patched": "s2"}]
    else:
        env.setattr(azinv, "_MAX_SUBSCRIPTIONS", 1)
        expected = [{"account_id": "s1"}]
    assert azinv.discover_all_subscription_inventories(credential=_Credential()) == expected


def test_patch_point_discover_authorization_steers_role_assignments(env: pytest.MonkeyPatch) -> None:
    env.setattr(azinv, "_discover_authorization", lambda cred, sub, *, warnings, missing=None: {"role_assignments": ["patched"]})
    assert azinv._discover_role_assignments(_Credential(), SUB, warnings=[]) == ["patched"]


def test_patch_point_classify_storage_blobs_steers_storage_discovery(env: pytest.MonkeyPatch) -> None:
    _install_sdk(env, "full")

    def classify(credential: Any, record: dict[str, Any], *, warnings: list[str]) -> None:
        record["content_classification"] = "patched"

    env.setattr(azinv, "_classify_storage_account_blobs", classify)
    accounts = azinv._discover_storage_accounts(_Credential(), SUB, warnings=[])
    assert accounts and all(a["content_classification"] == "patched" for a in accounts)


def test_patch_point_derive_default_subscription(env: pytest.MonkeyPatch) -> None:
    _install_sdk(env, "empty")
    env.setattr(azinv, "_derive_default_subscription", lambda cred: ("derived-sub", "note"))
    payload = azinv.discover_inventory(credential=_Credential(), include_hierarchy=False, force=True)
    assert payload["subscription_id"] == "derived-sub" and payload["warnings"][0] == "note"


def test_patch_point_append_db_servers(env: pytest.MonkeyPatch) -> None:
    _install_sdk(env, "full")
    calls: list[str] = []
    env.setattr(azinv, "_append_db_servers", lambda dbs, servers, *, native_type, engine: calls.append(engine))
    azinv._discover_databases(_Credential(), SUB, warnings=[])
    assert calls == ["azure-sql", "postgresql", "mysql"]
