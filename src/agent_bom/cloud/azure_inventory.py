"""Azure general cloud-asset inventory — estate-wide, read-only, agentless.

Unlike :mod:`agent_bom.cloud.azure` (which discovers *AI* runtimes: Container
Apps, AI Foundry agents, Azure OpenAI deployments, Functions, ML endpoints),
this module enumerates the general Azure estate so that a resource with **no**
CIS finding, IaC target, or discovered AI runtime still becomes a first-class
graph node. That feeds the CNAPP exposure overlay, the CIEM effective-
permissions overlay, and the DSPM tiers, which were previously starved of
inventory input.

Three resource classes are enumerated subscription-wide (NOT filtered to
findings):

1. **Storage Accounts**       → emitted as ``DATA_STORE``-signalling
   ``CLOUD_RESOURCE`` so the DSPM / ``STORES`` / ``EXPOSED_TO`` overlays apply.
2. **VMs + Network Security Groups** → emitted as ``CLOUD_RESOURCE``.
3. **Managed Identities / Service Principals** → emitted as identity principals
   with a ``HAS_PERMISSION``-ready structure.

This scanner is **opt-in** and **default OFF**. It runs only when
``AGENT_BOM_AZURE_INVENTORY`` is truthy, mirroring the platform's other
optional-feature gates (e.g. ``AGENT_BOM_CLOUD_INVENTORY``).

Trust posture: read-only (``ScanMode.CLOUD_READ_ONLY``), reference-only, and
agentless. Authentication is **token / credential only** — no passwords — via
``azure-identity`` (``DefaultAzureCredential``: env service-principal token,
managed identity, Azure CLI token, workload-identity). Only ``list`` / ``get``
ARM APIs are called — no write APIs, no object-content reads, no credential
exfiltration. SDK absence or missing credentials degrades to an empty inventory
plus a clear status, never a crash.

Requires ``azure-identity`` and ``azure-mgmt-*``. Install with::

    pip install 'agent-bom[azure]'
"""

from __future__ import annotations

import logging
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any

from agent_bom.discovery_envelope import DiscoveryEnvelope, RedactionStatus, ScanMode

from .normalization import sanitize_discovery_warning

logger = logging.getLogger(__name__)

# Opt-in env flag. Default OFF — estate-wide enumeration must be explicitly
# requested by an operator. Mirrors the other AGENT_BOM_* feature gates.
INVENTORY_ENV_FLAG = "AGENT_BOM_AZURE_INVENTORY"

_TRUTHY = {"1", "true", "yes", "on"}

# Read-only ARM actions this scanner is allowed to exercise, by resource class.
# Kept here so the per-run discovery envelope `permissions_used` stays honest.
_AZURE_STORAGE_PERMISSIONS: tuple[str, ...] = ("Microsoft.Storage/storageAccounts/read",)
_AZURE_COMPUTE_PERMISSIONS: tuple[str, ...] = (
    "Microsoft.Compute/virtualMachines/read",
    "Microsoft.ContainerService/managedClusters/read",
    "Microsoft.Network/networkSecurityGroups/read",
)
_AZURE_IDENTITY_PERMISSIONS: tuple[str, ...] = ("Microsoft.ManagedIdentity/userAssignedIdentities/read",)
_AZURE_DATA_PERMISSIONS: tuple[str, ...] = (
    "Microsoft.KeyVault/vaults/read",
    "Microsoft.ContainerRegistry/registries/read",
    "Microsoft.DocumentDB/databaseAccounts/read",
    "Microsoft.Sql/servers/read",
    "Microsoft.DBforPostgreSQL/flexibleServers/read",
    "Microsoft.DBforMySQL/flexibleServers/read",
)
_AZURE_NETWORK_PERMISSIONS: tuple[str, ...] = (
    "Microsoft.Network/virtualNetworks/read",
    "Microsoft.Network/publicIPAddresses/read",
    "Microsoft.Network/loadBalancers/read",
)

# Open-to-the-world source-address ranges that mark an NSG inbound rule as
# internet-facing. The CNAPP overlay keys off this `network_exposure` shape.
_INTERNET_SOURCES = {"*", "0.0.0.0/0", "internet", "any", "::/0"}


def inventory_enabled() -> bool:
    """Return whether estate-wide Azure inventory enumeration is opted in.

    Default OFF. Operators enable it by setting ``AGENT_BOM_AZURE_INVENTORY``
    to a truthy value (``1`` / ``true`` / ``yes`` / ``on``).
    """
    return os.environ.get(INVENTORY_ENV_FLAG, "").strip().lower() in _TRUTHY


def discover_inventory(
    subscription_id: str | None = None,
    *,
    credential: Any = None,
    include_storage: bool = True,
    include_compute: bool = True,
    include_identity: bool = True,
    include_data: bool = True,
    include_network: bool = True,
    include_hierarchy: bool = True,
    force: bool = False,
) -> dict[str, Any]:
    """Enumerate the general Azure estate (storage, VMs + NSGs, identities).

    Returns a JSON-serialisable inventory payload destined for
    ``report_json["cloud_inventory"]``; the graph builder turns it into nodes.

    The payload always carries a ``status`` string so callers can surface a
    clear reason when nothing was enumerated:

    - ``"disabled"``           — the feature flag is off and ``force`` was not set.
    - ``"sdk_missing"``        — azure-identity / azure-mgmt is not installed.
    - ``"no_subscription"``    — no subscription id resolved.
    - ``"no_credentials"``     — no Azure credential resolved.
    - ``"ok"``                 — enumeration ran (possibly with per-service warnings).

    Never raises: SDK absence, missing credentials, and per-service access
    denials all degrade to an empty (or partial) inventory plus warnings.

    Authentication is token/credential only (no passwords). When ``credential``
    is not supplied, ``DefaultAzureCredential`` is used, which acquires
    short-lived tokens from env service principals, managed identity, the Azure
    CLI, or workload identity.
    """
    resolved_sub = subscription_id or os.environ.get("AZURE_SUBSCRIPTION_ID", "")
    empty: dict[str, Any] = {
        "provider": "azure",
        "status": "disabled",
        "subscription_id": resolved_sub,
        "account_id": resolved_sub,
        "region": "",
        "storage_accounts": [],
        "instances": [],
        "container_clusters": [],
        "security_groups": [],
        "managed_identities": [],
        "service_principals": [],
        "key_vaults": [],
        "container_registries": [],
        "databases": [],
        "virtual_networks": [],
        "public_ips": [],
        "load_balancers": [],
        "management_groups": [],
        "warnings": [],
        "discovery_envelope": None,
    }

    if not force and not inventory_enabled():
        return empty

    try:
        from azure.identity import DefaultAzureCredential  # noqa: F401
    except ImportError:
        return {
            **empty,
            "status": "sdk_missing",
            "warnings": ["azure-identity is required for Azure inventory. Install with: pip install 'agent-bom[azure]'"],
        }

    if not resolved_sub:
        return {
            **empty,
            "status": "no_subscription",
            "warnings": ["AZURE_SUBSCRIPTION_ID not set. Provide subscription_id or set the AZURE_SUBSCRIPTION_ID env var."],
        }

    if credential is None:
        try:
            credential = DefaultAzureCredential()
        except Exception as exc:  # noqa: BLE001 — credential chain errors must not crash a scan
            return {**empty, "status": "no_credentials", "warnings": [sanitize_discovery_warning(exc)]}

    warnings: list[str] = []

    # Discover each service concurrently — the ARM list calls are independent and
    # IO-bound, so a thread pool collapses the previously-sequential sum-of-latencies
    # sweep to roughly the slowest single call. Each task gets its own warnings list
    # (thread-safe) that is merged back in deterministic task order.
    discovery_tasks: list[tuple[str, Any]] = []
    if include_storage:
        discovery_tasks.append(("storage_accounts", _discover_storage_accounts))
    if include_compute:
        discovery_tasks.append(("instances", _discover_vms))
        discovery_tasks.append(("container_clusters", _discover_aks_clusters))
        discovery_tasks.append(("security_groups", _discover_nsgs))
    if include_identity:
        discovery_tasks.append(("managed_identities", _discover_managed_identities))
    if include_data:
        discovery_tasks.append(("key_vaults", _discover_key_vaults))
        discovery_tasks.append(("container_registries", _discover_container_registries))
        discovery_tasks.append(("databases", _discover_databases))
    if include_network:
        discovery_tasks.append(("virtual_networks", _discover_virtual_networks))
        discovery_tasks.append(("public_ips", _discover_public_ips))
        discovery_tasks.append(("load_balancers", _discover_load_balancers))

    collected: dict[str, list[dict[str, Any]]] = {}
    task_warnings: dict[str, list[str]] = {key: [] for key, _ in discovery_tasks}
    if discovery_tasks:
        with ThreadPoolExecutor(max_workers=min(8, len(discovery_tasks))) as executor:
            future_to_key = {executor.submit(fn, credential, resolved_sub, warnings=task_warnings[key]): key for key, fn in discovery_tasks}
            for future in as_completed(future_to_key):
                key = future_to_key[future]
                try:
                    collected[key] = future.result()
                except Exception as exc:  # noqa: BLE001 — one service failing must not sink the rest
                    collected[key] = []
                    task_warnings[key].append(sanitize_discovery_warning(exc))
    for key, _ in discovery_tasks:
        warnings.extend(task_warnings[key])

    storage_accounts = collected.get("storage_accounts", [])
    instances = collected.get("instances", [])
    container_clusters = collected.get("container_clusters", [])
    security_groups = collected.get("security_groups", [])
    managed_identities = collected.get("managed_identities", [])
    key_vaults = collected.get("key_vaults", [])
    container_registries = collected.get("container_registries", [])
    databases = collected.get("databases", [])
    virtual_networks = collected.get("virtual_networks", [])
    public_ips = collected.get("public_ips", [])
    load_balancers = collected.get("load_balancers", [])

    # Management groups are tenant-scoped (above the subscription), so they are
    # discovered with a single call rather than the per-subscription thread pool.
    management_groups: list[dict[str, Any]] = []
    if include_hierarchy:
        management_groups, mg_warnings = _discover_management_groups(credential)
        warnings.extend(mg_warnings)

    permissions_used: list[str] = []
    if include_storage:
        permissions_used.extend(_AZURE_STORAGE_PERMISSIONS)
    if include_compute:
        permissions_used.extend(_AZURE_COMPUTE_PERMISSIONS)
    if include_identity:
        permissions_used.extend(_AZURE_IDENTITY_PERMISSIONS)
    if include_data:
        permissions_used.extend(_AZURE_DATA_PERMISSIONS)
    if include_network:
        permissions_used.extend(_AZURE_NETWORK_PERMISSIONS)
    if include_hierarchy:
        permissions_used.append("Microsoft.Management/managementGroups/read")

    envelope = DiscoveryEnvelope(
        scan_mode=ScanMode.CLOUD_READ_ONLY,
        discovery_scope=(f"azure:subscription/{resolved_sub}",),
        permissions_used=tuple(sorted(set(permissions_used))),
        redaction_status=RedactionStatus.CENTRAL_SANITIZER_APPLIED,
    )

    return {
        "provider": "azure",
        "status": "ok",
        "subscription_id": resolved_sub,
        "account_id": resolved_sub,
        "region": "",
        "storage_accounts": storage_accounts,
        "instances": instances,
        "container_clusters": container_clusters,
        "security_groups": security_groups,
        "managed_identities": managed_identities,
        "service_principals": [],
        "key_vaults": key_vaults,
        "container_registries": container_registries,
        "databases": databases,
        "virtual_networks": virtual_networks,
        "public_ips": public_ips,
        "load_balancers": load_balancers,
        "management_groups": management_groups,
        "warnings": warnings,
        "discovery_envelope": envelope.to_dict(),
    }


# ---------------------------------------------------------------------------
# Storage accounts (subscription-wide list)
# ---------------------------------------------------------------------------


def _discover_storage_accounts(credential: Any, subscription_id: str, *, warnings: list[str]) -> list[dict[str, Any]]:
    """Enumerate every Storage Account in the subscription (read-only).

    Public-access posture is read from the account's
    ``allow_blob_public_access`` and network-rule default action — never from
    blob contents. Accounts become ``DATA_STORE``-signalling nodes so DSPM and
    exposure overlays apply.
    """
    try:
        from azure.mgmt.storage import StorageManagementClient
    except ImportError:
        warnings.append("azure-mgmt-storage not installed. Skipping Storage Account inventory.")
        return []

    accounts: list[dict[str, Any]] = []
    try:
        client = StorageManagementClient(credential, subscription_id)
        for account in client.storage_accounts.list():
            name = str(getattr(account, "name", "") or "").strip()
            if not name:
                continue
            account_id = str(getattr(account, "id", "") or "")
            network_rules = getattr(account, "network_rule_set", None)
            default_action = str(getattr(network_rules, "default_action", "") or "").lower()
            allow_public = bool(getattr(account, "allow_blob_public_access", False))
            # Publicly accessible when blob public access is allowed AND the
            # network firewall default action is not "deny".
            publicly_accessible = allow_public and default_action != "deny"
            accounts.append(
                {
                    "name": name,
                    "id": account_id,
                    "location": str(getattr(account, "location", "") or ""),
                    "resource_group": _resource_group_from_id(account_id),
                    "kind": str(getattr(account, "kind", "") or ""),
                    "publicly_accessible": publicly_accessible,
                    "allow_blob_public_access": allow_public,
                    "network_default_action": default_action,
                    "tags": _clean_tags(getattr(account, "tags", None)),
                    "subscription_id": subscription_id,
                }
            )
    except Exception as exc:  # noqa: BLE001
        warnings.append(f"Could not list Azure Storage Accounts: {sanitize_discovery_warning(exc)}")
    return accounts


# ---------------------------------------------------------------------------
# Virtual machines + network security groups (subscription-wide list)
# ---------------------------------------------------------------------------


def _discover_vms(credential: Any, subscription_id: str, *, warnings: list[str]) -> list[dict[str, Any]]:
    """Enumerate all VMs in the subscription (read-only, NOT tag-filtered)."""
    try:
        from azure.mgmt.compute import ComputeManagementClient
    except ImportError:
        warnings.append("azure-mgmt-compute not installed. Skipping VM inventory.")
        return []

    instances: list[dict[str, Any]] = []
    try:
        client = ComputeManagementClient(credential, subscription_id)
        for vm in client.virtual_machines.list_all():
            vm_id = str(getattr(vm, "id", "") or "")
            name = str(getattr(vm, "name", "") or "").strip()
            if not name:
                continue
            hardware = getattr(vm, "hardware_profile", None)
            vm_size = str(getattr(hardware, "vm_size", "") or "")
            instances.append(
                {
                    "instance_id": vm_id or name,
                    "name": name,
                    "instance_type": vm_size,
                    "location": str(getattr(vm, "location", "") or ""),
                    "resource_group": _resource_group_from_id(vm_id),
                    "managed_identity": _vm_identity(vm),
                    "user_assigned_identity_ids": _vm_user_assigned_identity_ids(vm),
                    "tags": _clean_tags(getattr(vm, "tags", None)),
                    "subscription_id": subscription_id,
                }
            )
    except Exception as exc:  # noqa: BLE001
        warnings.append(f"Could not list Azure virtual machines: {sanitize_discovery_warning(exc)}")
    return instances


def _discover_aks_clusters(credential: Any, subscription_id: str, *, warnings: list[str]) -> list[dict[str, Any]]:
    """Enumerate AKS (managed Kubernetes) clusters in the subscription (read-only).

    Captures control-plane metadata: Kubernetes version, the API-server FQDN
    (its public reachability is the exposure signal), whether the API server is
    private, and whether Kubernetes RBAC is enabled. Never reads workload or
    secret contents.
    """
    try:
        from azure.mgmt.containerservice import ContainerServiceClient
    except ImportError:
        warnings.append("azure-mgmt-containerservice not installed. Skipping AKS inventory.")
        return []

    clusters: list[dict[str, Any]] = []
    try:
        client = ContainerServiceClient(credential, subscription_id)
        for cluster in client.managed_clusters.list():
            cluster_id = str(getattr(cluster, "id", "") or "")
            name = str(getattr(cluster, "name", "") or "").strip()
            if not name:
                continue
            api_profile = getattr(cluster, "api_server_access_profile", None)
            private_cluster = bool(getattr(api_profile, "enable_private_cluster", False)) if api_profile else False
            fqdn = str(getattr(cluster, "fqdn", "") or "")
            clusters.append(
                {
                    "name": name,
                    "id": cluster_id,
                    "native_type": "Microsoft.ContainerService/managedClusters",
                    "location": str(getattr(cluster, "location", "") or ""),
                    "resource_group": _resource_group_from_id(cluster_id),
                    "tags": _clean_tags(getattr(cluster, "tags", None)),
                    "kubernetes_version": str(getattr(cluster, "kubernetes_version", "") or ""),
                    "api_server_fqdn": fqdn,
                    "private_cluster": private_cluster,
                    "rbac_enabled": bool(getattr(cluster, "enable_rbac", False)),
                    # A reachable API-server FQDN on a non-private cluster is internet-facing.
                    "internet_facing": bool(fqdn) and not private_cluster,
                }
            )
    except Exception as exc:  # noqa: BLE001
        warnings.append(f"Could not list Azure AKS clusters: {sanitize_discovery_warning(exc)}")
    return clusters


def _discover_nsgs(credential: Any, subscription_id: str, *, warnings: list[str]) -> list[dict[str, Any]]:
    """Enumerate all Network Security Groups in the subscription (read-only)."""
    try:
        from azure.mgmt.network import NetworkManagementClient
    except ImportError:
        warnings.append("azure-mgmt-network not installed. Skipping NSG inventory.")
        return []

    groups: list[dict[str, Any]] = []
    try:
        client = NetworkManagementClient(credential, subscription_id)
        for nsg in client.network_security_groups.list_all():
            nsg_id = str(getattr(nsg, "id", "") or "")
            name = str(getattr(nsg, "name", "") or "").strip()
            if not name:
                continue
            groups.append(_normalize_nsg(nsg, nsg_id=nsg_id, name=name, subscription_id=subscription_id))
    except Exception as exc:  # noqa: BLE001
        warnings.append(f"Could not list Azure network security groups: {sanitize_discovery_warning(exc)}")
    return groups


def _normalize_nsg(nsg: Any, *, nsg_id: str, name: str, subscription_id: str) -> dict[str, Any]:
    exposure = _nsg_internet_exposure(nsg)
    return {
        "group_id": nsg_id or name,
        "name": name,
        "location": str(getattr(nsg, "location", "") or ""),
        "resource_group": _resource_group_from_id(nsg_id),
        "internet_exposed": bool(exposure),
        "network_exposure": exposure,
        "subscription_id": subscription_id,
    }


def _nsg_internet_exposure(nsg: Any) -> list[dict[str, Any]]:
    """Return internet-facing inbound rules in the CNAPP overlay's shape.

    Each entry is ``{"scope": "internet", "from_port", "to_port", "protocol"}``
    so :func:`agent_bom.graph.cnapp_overlay.apply_cnapp_overlay` can attach
    structured exposure without keyword-matching free text.
    """
    exposure: list[dict[str, Any]] = []
    for rule in getattr(nsg, "security_rules", None) or []:
        direction = str(getattr(rule, "direction", "") or "").lower()
        access = str(getattr(rule, "access", "") or "").lower()
        if direction != "inbound" or access != "allow":
            continue
        sources = _rule_sources(rule)
        if not any(src.lower() in _INTERNET_SOURCES for src in sources):
            continue
        from_port, to_port = _rule_port_range(rule)
        exposure.append(
            {
                "scope": "internet",
                "from_port": from_port,
                "to_port": to_port,
                "protocol": str(getattr(rule, "protocol", "") or "tcp").lower(),
            }
        )
    return exposure


def _rule_sources(rule: Any) -> list[str]:
    sources: list[str] = []
    single = getattr(rule, "source_address_prefix", None)
    if single:
        sources.append(str(single))
    multiple = getattr(rule, "source_address_prefixes", None) or []
    for prefix in multiple:
        if prefix:
            sources.append(str(prefix))
    return sources


def _rule_port_range(rule: Any) -> tuple[int | None, int | None]:
    raw = getattr(rule, "destination_port_range", None)
    candidates = [raw] if raw else list(getattr(rule, "destination_port_ranges", None) or [])
    for candidate in candidates:
        text = str(candidate or "").strip()
        if not text or text == "*":
            return None, None
        if "-" in text:
            low, _, high = text.partition("-")
            return _safe_int(low), _safe_int(high)
        port = _safe_int(text)
        return port, port
    return None, None


def _safe_int(value: str) -> int | None:
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return None


# ---------------------------------------------------------------------------
# Managed identities (subscription-wide list)
# ---------------------------------------------------------------------------


def _discover_managed_identities(credential: Any, subscription_id: str, *, warnings: list[str]) -> list[dict[str, Any]]:
    """Enumerate user-assigned managed identities in the subscription (read-only).

    Each identity becomes a ``service_principal`` graph node carrying its
    principal id so the effective-permissions overlay can attach
    ``HAS_PERMISSION`` once role-assignment data is wired. Privilege defaults to
    ``unknown`` — inventory never guesses an inflated level.
    """
    try:
        from azure.mgmt.msi import ManagedServiceIdentityClient
    except ImportError:
        warnings.append("azure-mgmt-msi not installed. Skipping managed-identity inventory.")
        return []

    identities: list[dict[str, Any]] = []
    try:
        client = ManagedServiceIdentityClient(credential, subscription_id)
        for identity in client.user_assigned_identities.list_by_subscription():
            identity_id = str(getattr(identity, "id", "") or "")
            name = str(getattr(identity, "name", "") or "").strip()
            if not name:
                continue
            identities.append(
                {
                    "principal_type": "managed-identity",
                    "name": name,
                    "arn": identity_id or name,
                    "principal_id": str(getattr(identity, "principal_id", "") or ""),
                    "client_id": str(getattr(identity, "client_id", "") or ""),
                    "location": str(getattr(identity, "location", "") or ""),
                    "resource_group": _resource_group_from_id(identity_id),
                    "account_id": subscription_id,
                    "policies": [],
                    "trust_principals": [],
                    "privilege_level": "unknown",
                }
            )
    except Exception as exc:  # noqa: BLE001
        warnings.append(f"Could not list Azure managed identities: {sanitize_discovery_warning(exc)}")
    return identities


# ---------------------------------------------------------------------------
# Data / secrets / registry (subscription-wide list)
# ---------------------------------------------------------------------------


def _discover_key_vaults(credential: Any, subscription_id: str, *, warnings: list[str]) -> list[dict[str, Any]]:
    """Enumerate every Key Vault in the subscription (read-only).

    Reads only control-plane metadata (URI, RBAC mode, public-network posture);
    never reads secret/key/certificate material.
    """
    try:
        from azure.mgmt.keyvault import KeyVaultManagementClient
    except ImportError:
        warnings.append("azure-mgmt-keyvault not installed. Skipping Key Vault inventory.")
        return []

    vaults: list[dict[str, Any]] = []
    try:
        client = KeyVaultManagementClient(credential, subscription_id)
        for vault in client.vaults.list_by_subscription():
            vault_id = str(getattr(vault, "id", "") or "")
            name = str(getattr(vault, "name", "") or "").strip()
            if not name:
                continue
            props = getattr(vault, "properties", None)
            vaults.append(
                {
                    "name": name,
                    "id": vault_id,
                    "location": str(getattr(vault, "location", "") or ""),
                    "resource_group": _resource_group_from_id(vault_id),
                    "tags": _clean_tags(getattr(vault, "tags", None)),
                    "uri": str(getattr(props, "vault_uri", "") or "") if props else "",
                    "rbac_authorization": bool(getattr(props, "enable_rbac_authorization", False)) if props else False,
                    "public_network_access": str(getattr(props, "public_network_access", "") or "") if props else "",
                }
            )
    except Exception as exc:  # noqa: BLE001
        warnings.append(f"Could not list Azure Key Vaults: {sanitize_discovery_warning(exc)}")
    return vaults


def _discover_container_registries(credential: Any, subscription_id: str, *, warnings: list[str]) -> list[dict[str, Any]]:
    """Enumerate every Container Registry in the subscription (read-only)."""
    try:
        from azure.mgmt.containerregistry import ContainerRegistryManagementClient
    except ImportError:
        warnings.append("azure-mgmt-containerregistry not installed. Skipping Container Registry inventory.")
        return []

    registries: list[dict[str, Any]] = []
    try:
        client = ContainerRegistryManagementClient(credential, subscription_id)
        for registry in client.registries.list():
            registry_id = str(getattr(registry, "id", "") or "")
            name = str(getattr(registry, "name", "") or "").strip()
            if not name:
                continue
            sku = getattr(registry, "sku", None)
            registries.append(
                {
                    "name": name,
                    "id": registry_id,
                    "location": str(getattr(registry, "location", "") or ""),
                    "resource_group": _resource_group_from_id(registry_id),
                    "tags": _clean_tags(getattr(registry, "tags", None)),
                    "login_server": str(getattr(registry, "login_server", "") or ""),
                    "sku": str(getattr(sku, "name", "") or "") if sku else "",
                    "admin_user_enabled": bool(getattr(registry, "admin_user_enabled", False)),
                    "public_network_access": str(getattr(registry, "public_network_access", "") or ""),
                }
            )
    except Exception as exc:  # noqa: BLE001
        warnings.append(f"Could not list Azure Container Registries: {sanitize_discovery_warning(exc)}")
    return registries


def _append_db_servers(databases: list[dict[str, Any]], servers: Any, *, native_type: str, engine: str) -> None:
    """Append SQL-family servers (Azure SQL / PostgreSQL / MySQL) in the shared shape.

    Public-network posture lives either directly on the server (Azure SQL) or
    under ``server.network`` (the flexible-server engines); read both.
    """
    for server in servers:
        server_id = str(getattr(server, "id", "") or "")
        name = str(getattr(server, "name", "") or "").strip()
        if not name:
            continue
        network = getattr(server, "network", None)
        public_access = str(getattr(server, "public_network_access", "") or "") or (
            str(getattr(network, "public_network_access", "") or "") if network else ""
        )
        databases.append(
            {
                "name": name,
                "id": server_id,
                "native_type": native_type,
                "engine": engine,
                "location": str(getattr(server, "location", "") or ""),
                "resource_group": _resource_group_from_id(server_id),
                "tags": _clean_tags(getattr(server, "tags", None)),
                "public_network_access": public_access,
            }
        )


def _discover_databases(credential: Any, subscription_id: str, *, warnings: list[str]) -> list[dict[str, Any]]:
    """Enumerate managed databases in the subscription (read-only).

    Covers Cosmos DB, Azure SQL, PostgreSQL, and MySQL — each item carries its
    own ``native_type`` so the normalized model maps them all to ``DATABASE``
    without losing the provider-native type. Each engine is enumerated
    independently so a missing SDK or access denial never sinks the others;
    control-plane metadata only, never row / data-plane contents.
    """
    databases: list[dict[str, Any]] = []

    try:
        from azure.mgmt.cosmosdb import CosmosDBManagementClient

        client = CosmosDBManagementClient(credential, subscription_id)
        for account in client.database_accounts.list():
            account_id = str(getattr(account, "id", "") or "")
            name = str(getattr(account, "name", "") or "").strip()
            if not name:
                continue
            databases.append(
                {
                    "name": name,
                    "id": account_id,
                    "native_type": "Microsoft.DocumentDB/databaseAccounts",
                    "engine": "cosmosdb",
                    "location": str(getattr(account, "location", "") or ""),
                    "resource_group": _resource_group_from_id(account_id),
                    "tags": _clean_tags(getattr(account, "tags", None)),
                    "public_network_access": str(getattr(account, "public_network_access", "") or ""),
                    "is_virtual_network_filter_enabled": bool(getattr(account, "is_virtual_network_filter_enabled", False)),
                }
            )
    except ImportError:
        warnings.append("azure-mgmt-cosmosdb not installed. Skipping Cosmos DB inventory.")
    except Exception as exc:  # noqa: BLE001
        warnings.append(f"Could not list Azure Cosmos DB accounts: {sanitize_discovery_warning(exc)}")

    try:
        from azure.mgmt.sql import SqlManagementClient

        sql_client = SqlManagementClient(credential, subscription_id)
        _append_db_servers(databases, sql_client.servers.list(), native_type="Microsoft.Sql/servers", engine="azure-sql")
    except ImportError:
        warnings.append("azure-mgmt-sql not installed. Skipping Azure SQL inventory.")
    except Exception as exc:  # noqa: BLE001
        warnings.append(f"Could not list Azure SQL servers: {sanitize_discovery_warning(exc)}")

    try:
        from azure.mgmt.rdbms.postgresql_flexibleservers import PostgreSQLManagementClient

        pg_client = PostgreSQLManagementClient(credential, subscription_id)
        _append_db_servers(
            databases,
            pg_client.servers.list(),
            native_type="Microsoft.DBforPostgreSQL/flexibleServers",
            engine="postgresql",
        )
    except ImportError:
        warnings.append("azure-mgmt-rdbms not installed. Skipping PostgreSQL inventory.")
    except Exception as exc:  # noqa: BLE001
        warnings.append(f"Could not list Azure PostgreSQL servers: {sanitize_discovery_warning(exc)}")

    try:
        from azure.mgmt.rdbms.mysql_flexibleservers import MySQLManagementClient

        mysql_client = MySQLManagementClient(credential, subscription_id)
        _append_db_servers(databases, mysql_client.servers.list(), native_type="Microsoft.DBforMySQL/flexibleServers", engine="mysql")
    except ImportError:
        warnings.append("azure-mgmt-rdbms not installed. Skipping MySQL inventory.")
    except Exception as exc:  # noqa: BLE001
        warnings.append(f"Could not list Azure MySQL servers: {sanitize_discovery_warning(exc)}")

    return databases


# ---------------------------------------------------------------------------
# Network topology (subscription-wide list)
# ---------------------------------------------------------------------------


def _discover_virtual_networks(credential: Any, subscription_id: str, *, warnings: list[str]) -> list[dict[str, Any]]:
    """Enumerate every VNet in the subscription with its address space and subnets."""
    try:
        from azure.mgmt.network import NetworkManagementClient
    except ImportError:
        warnings.append("azure-mgmt-network not installed. Skipping virtual-network inventory.")
        return []

    vnets: list[dict[str, Any]] = []
    try:
        client = NetworkManagementClient(credential, subscription_id)
        for vnet in client.virtual_networks.list_all():
            vnet_id = str(getattr(vnet, "id", "") or "")
            name = str(getattr(vnet, "name", "") or "").strip()
            if not name:
                continue
            address_space = getattr(vnet, "address_space", None)
            prefixes = list(getattr(address_space, "address_prefixes", []) or []) if address_space else []
            subnets = [str(getattr(s, "name", "") or "") for s in (getattr(vnet, "subnets", None) or [])]
            vnets.append(
                {
                    "name": name,
                    "id": vnet_id,
                    "location": str(getattr(vnet, "location", "") or ""),
                    "resource_group": _resource_group_from_id(vnet_id),
                    "tags": _clean_tags(getattr(vnet, "tags", None)),
                    "address_prefixes": [str(p) for p in prefixes],
                    "subnets": [s for s in subnets if s],
                }
            )
    except Exception as exc:  # noqa: BLE001
        warnings.append(f"Could not list Azure virtual networks: {sanitize_discovery_warning(exc)}")
    return vnets


def _discover_public_ips(credential: Any, subscription_id: str, *, warnings: list[str]) -> list[dict[str, Any]]:
    """Enumerate public IP addresses — the internet-facing exposure surface."""
    try:
        from azure.mgmt.network import NetworkManagementClient
    except ImportError:
        warnings.append("azure-mgmt-network not installed. Skipping public-IP inventory.")
        return []

    public_ips: list[dict[str, Any]] = []
    try:
        client = NetworkManagementClient(credential, subscription_id)
        for pip in client.public_ip_addresses.list_all():
            pip_id = str(getattr(pip, "id", "") or "")
            name = str(getattr(pip, "name", "") or "").strip()
            if not name:
                continue
            public_ips.append(
                {
                    "name": name,
                    "id": pip_id,
                    "location": str(getattr(pip, "location", "") or ""),
                    "resource_group": _resource_group_from_id(pip_id),
                    "tags": _clean_tags(getattr(pip, "tags", None)),
                    "ip_address": str(getattr(pip, "ip_address", "") or ""),
                    "allocation_method": str(getattr(pip, "public_ip_allocation_method", "") or ""),
                }
            )
    except Exception as exc:  # noqa: BLE001
        warnings.append(f"Could not list Azure public IPs: {sanitize_discovery_warning(exc)}")
    return public_ips


def _discover_load_balancers(credential: Any, subscription_id: str, *, warnings: list[str]) -> list[dict[str, Any]]:
    """Enumerate load balancers with their SKU and public-frontend posture."""
    try:
        from azure.mgmt.network import NetworkManagementClient
    except ImportError:
        warnings.append("azure-mgmt-network not installed. Skipping load-balancer inventory.")
        return []

    load_balancers: list[dict[str, Any]] = []
    try:
        client = NetworkManagementClient(credential, subscription_id)
        for lb in client.load_balancers.list_all():
            lb_id = str(getattr(lb, "id", "") or "")
            name = str(getattr(lb, "name", "") or "").strip()
            if not name:
                continue
            sku = getattr(lb, "sku", None)
            frontends = getattr(lb, "frontend_ip_configurations", None) or []
            public_ip_ids = [
                str(getattr(getattr(fe, "public_ip_address", None), "id", "") or "")
                for fe in frontends
                if getattr(fe, "public_ip_address", None) is not None
            ]
            public_ip_ids = [pid for pid in public_ip_ids if pid]
            load_balancers.append(
                {
                    "name": name,
                    "id": lb_id,
                    "location": str(getattr(lb, "location", "") or ""),
                    "resource_group": _resource_group_from_id(lb_id),
                    "tags": _clean_tags(getattr(lb, "tags", None)),
                    "sku": str(getattr(sku, "name", "") or "") if sku else "",
                    "internet_facing": bool(public_ip_ids),
                    "public_ip_ids": public_ip_ids,
                }
            )
    except Exception as exc:  # noqa: BLE001
        warnings.append(f"Could not list Azure load balancers: {sanitize_discovery_warning(exc)}")
    return load_balancers


# ---------------------------------------------------------------------------
# Management-group hierarchy (tenant-scoped)
# ---------------------------------------------------------------------------


def _discover_management_groups(credential: Any) -> tuple[list[dict[str, Any]], list[str]]:
    """Enumerate the tenant's management-group hierarchy (read-only, tenant-scoped).

    Management groups sit above subscriptions and organize them into a tree.
    Each entry carries its direct children (nested management groups and
    subscriptions) so the graph can build the CONTAINS hierarchy across
    subscriptions. Requires the Management Group Reader role at the tenant root;
    absent that, this degrades to an empty list plus a warning.
    """
    try:
        from azure.mgmt.managementgroups import ManagementGroupsAPI
    except ImportError:
        return [], ["azure-mgmt-managementgroups not installed. Skipping management-group hierarchy."]

    groups: list[dict[str, Any]] = []
    warnings: list[str] = []
    try:
        client = ManagementGroupsAPI(credential)
        for mg in client.management_groups.list():
            name = str(getattr(mg, "name", "") or "").strip()
            if not name:
                continue
            children: list[dict[str, Any]] = []
            try:
                detail = client.management_groups.get(group_id=name, expand="children", recurse=False)
                for child in getattr(detail, "children", None) or []:
                    children.append(
                        {
                            "id": str(getattr(child, "id", "") or ""),
                            "name": str(getattr(child, "name", "") or ""),
                            # ".../managementGroups" (nested group) or "/subscriptions" (a subscription)
                            "type": str(getattr(child, "type", "") or ""),
                            "display_name": str(getattr(child, "display_name", "") or ""),
                        }
                    )
            except Exception as exc:  # noqa: BLE001 — child expansion is best-effort
                warnings.append(f"Could not expand management group {name}: {sanitize_discovery_warning(exc)}")
            groups.append(
                {
                    "id": str(getattr(mg, "id", "") or ""),
                    "name": name,
                    "display_name": str(getattr(mg, "display_name", "") or ""),
                    "children": children,
                }
            )
    except Exception as exc:  # noqa: BLE001
        warnings.append(f"Could not list Azure management groups: {sanitize_discovery_warning(exc)}")
    return groups, warnings


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _vm_identity(vm: Any) -> str:
    identity = getattr(vm, "identity", None)
    if identity is None:
        return ""
    return str(getattr(identity, "principal_id", "") or getattr(identity, "type", "") or "")


def _vm_user_assigned_identity_ids(vm: Any) -> list[str]:
    """ARM IDs of the user-assigned managed identities attached to a VM.

    The VM assumes each of these identities' permissions, so they drive the
    VM → managed-identity privilege edge in the graph. Returns the resource IDs
    only (the dict keys) — never any credential material.
    """
    identity = getattr(vm, "identity", None)
    if identity is None:
        return []
    user_assigned = getattr(identity, "user_assigned_identities", None)
    if not isinstance(user_assigned, dict):
        return []
    return [str(arm_id) for arm_id in user_assigned if arm_id]


def _resource_group_from_id(resource_id: str) -> str:
    """Extract the resourceGroups segment from an ARM resource id, else ''."""
    parts = [p for p in str(resource_id or "").split("/") if p]
    for index, part in enumerate(parts):
        if part.lower() == "resourcegroups" and index + 1 < len(parts):
            return parts[index + 1]
    return ""


def _clean_tags(tags: Any) -> dict[str, str]:
    if not isinstance(tags, dict):
        return {}
    return {str(key): str(value) for key, value in tags.items() if key is not None}


__all__ = [
    "INVENTORY_ENV_FLAG",
    "discover_inventory",
    "inventory_enabled",
]
