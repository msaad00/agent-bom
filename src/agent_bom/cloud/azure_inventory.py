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
    "Microsoft.Network/networkSecurityGroups/read",
)
_AZURE_IDENTITY_PERMISSIONS: tuple[str, ...] = ("Microsoft.ManagedIdentity/userAssignedIdentities/read",)

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
        "security_groups": [],
        "managed_identities": [],
        "service_principals": [],
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
    storage_accounts: list[dict[str, Any]] = []
    instances: list[dict[str, Any]] = []
    security_groups: list[dict[str, Any]] = []
    managed_identities: list[dict[str, Any]] = []

    if include_storage:
        storage_accounts = _discover_storage_accounts(credential, resolved_sub, warnings=warnings)
    if include_compute:
        instances = _discover_vms(credential, resolved_sub, warnings=warnings)
        security_groups = _discover_nsgs(credential, resolved_sub, warnings=warnings)
    if include_identity:
        managed_identities = _discover_managed_identities(credential, resolved_sub, warnings=warnings)

    permissions_used: list[str] = []
    if include_storage:
        permissions_used.extend(_AZURE_STORAGE_PERMISSIONS)
    if include_compute:
        permissions_used.extend(_AZURE_COMPUTE_PERMISSIONS)
    if include_identity:
        permissions_used.extend(_AZURE_IDENTITY_PERMISSIONS)

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
        "security_groups": security_groups,
        "managed_identities": managed_identities,
        "service_principals": [],
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
                    "tags": _clean_tags(getattr(vm, "tags", None)),
                    "subscription_id": subscription_id,
                }
            )
    except Exception as exc:  # noqa: BLE001
        warnings.append(f"Could not list Azure virtual machines: {sanitize_discovery_warning(exc)}")
    return instances


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
# Helpers
# ---------------------------------------------------------------------------


def _vm_identity(vm: Any) -> str:
    identity = getattr(vm, "identity", None)
    if identity is None:
        return ""
    return str(getattr(identity, "principal_id", "") or getattr(identity, "type", "") or "")


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
