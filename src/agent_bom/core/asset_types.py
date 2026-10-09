"""Map ``Finding.asset.asset_type`` strings onto the shared entity vocabulary.

``Asset.asset_type`` has historically been a freeform convention string
(``mcp_server``, ``identity``, …). Graph nodes use the strict
:class:`~agent_bom.core.entity_types.EntityType` enum. This module is the single
normalization + mapping surface so findings, paths, and the investigation UI
share one vocabulary without inventing a separate info-id taxonomy.
"""

from __future__ import annotations

from agent_bom.core.entity_types import EntityType

# Freeform / legacy asset_type → canonical EntityType.
# Unknown values stay unmapped (None) rather than fabricating a type.
_ASSET_TYPE_ALIASES: dict[str, EntityType] = {
    # Direct EntityType values
    **{et.value: et for et in EntityType},
    # Finding / inventory conventions
    "mcp_server": EntityType.SERVER,
    "mcp_tool": EntityType.TOOL,
    "server": EntityType.SERVER,
    "agent": EntityType.AGENT,
    "package": EntityType.PACKAGE,
    "container": EntityType.CONTAINER,
    "cloud_resource": EntityType.CLOUD_RESOURCE,
    "resource": EntityType.RESOURCE,
    "file": EntityType.SOURCE_FILE,
    "source_file": EntityType.SOURCE_FILE,
    "iac_resource": EntityType.CLOUD_RESOURCE,
    "prompt_template": EntityType.CONFIG_FILE,
    "browser_extension": EntityType.CONFIG_FILE,
    "application": EntityType.APPLICATION,
    "data_store": EntityType.DATA_STORE,
    "dataset": EntityType.DATASET,
    "model": EntityType.MODEL,
    "framework": EntityType.FRAMEWORK,
    "credential": EntityType.CREDENTIAL,
    "vulnerability": EntityType.VULNERABILITY,
    "misconfiguration": EntityType.MISCONFIGURATION,
    # Identity aliases — "identity" was used by NHI findings; map to managed_identity
    # when the graph node is an agent-bom issued identity, else service_account.
    "identity": EntityType.MANAGED_IDENTITY,
    "managed_identity": EntityType.MANAGED_IDENTITY,
    "service_account": EntityType.SERVICE_ACCOUNT,
    "service_principal": EntityType.SERVICE_PRINCIPAL,
    "role": EntityType.ROLE,
    "user": EntityType.USER,
    "group": EntityType.GROUP,
    "policy": EntityType.POLICY,
    "federated_identity": EntityType.FEDERATED_IDENTITY,
}


def normalize_asset_type(raw: str | None) -> str:
    """Return a lowercase snake-ish asset type token, or empty string."""
    if raw is None:
        return ""
    text = str(raw).strip().lower().replace("-", "_").replace(" ", "_")
    while "__" in text:
        text = text.replace("__", "_")
    return text


def entity_type_for_asset_type(raw: str | None) -> EntityType | None:
    """Map a Finding asset_type (or alias) to EntityType, or None if unknown."""
    key = normalize_asset_type(raw)
    if not key:
        return None
    return _ASSET_TYPE_ALIASES.get(key)


def canonical_asset_type(raw: str | None) -> str:
    """Prefer EntityType.value when known; otherwise return the normalized token."""
    et = entity_type_for_asset_type(raw)
    if et is not None:
        return et.value
    return normalize_asset_type(raw)
