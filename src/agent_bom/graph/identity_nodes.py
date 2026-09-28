"""Stable identity node keys shared by cloud graph projections."""

from agent_bom.graph.container import UnifiedGraph
from agent_bom.graph.types import EntityType

_IDENTITY_NODE_PREFIX: dict[EntityType, str] = {
    EntityType.ORG: "org",
    EntityType.ACCOUNT: "account",
    EntityType.USER: "user",
    EntityType.GROUP: "group",
    EntityType.ROLE: "role",
    EntityType.POLICY: "policy",
    EntityType.SERVICE_ACCOUNT: "service_account",
    EntityType.SERVICE_PRINCIPAL: "service_principal",
    EntityType.MANAGED_IDENTITY: "managed_identity",
    EntityType.FEDERATED_IDENTITY: "federated_identity",
}


def identity_node_id(entity_type: EntityType, provider: str, identity_id: str) -> str:
    prefix = _IDENTITY_NODE_PREFIX.get(entity_type, "identity")
    return f"{prefix}:{provider}:{identity_id}"


def principal_aliases(value: str) -> set[str]:
    """Normalize native directory IDs and typed GCP member identifiers."""
    normalized = value.strip().casefold()
    if not normalized:
        return set()
    aliases = {normalized}
    prefix, separator, suffix = normalized.partition(":")
    if separator and prefix in {"group", "serviceaccount", "user"} and suffix:
        aliases.add(suffix)
    return aliases


def find_native_principal(graph: UnifiedGraph, provider: str, entity_type: EntityType, principal_id: str) -> str | None:
    """Join only one compatible native identity; names and ambiguity confer no authority."""
    accepted = {entity_type}
    # Azure role assignments report managed identities as service principals.
    if provider == "azure" and entity_type == EntityType.SERVICE_PRINCIPAL:
        accepted.add(EntityType.MANAGED_IDENTITY)
    normalized = principal_aliases(principal_id)
    matches: list[str] = []
    for node in graph.nodes.values():
        if node.entity_type not in accepted or str(node.attributes.get("cloud_provider") or "").casefold() != provider:
            continue
        candidates: set[str] = set()
        keys = ("principal_id", "directory_principal_id", "principal_email")
        if node.attributes.get("source") == "cloud-inventory":
            # The inventory builder may synthesize principal_id from a display
            # name when discovery has no native ID. That is not an auth alias.
            keys = ("principal_resource_id", "directory_principal_id", "principal_email")
        for key in keys:
            candidates.update(principal_aliases(str(node.attributes.get(key) or "")))
        if normalized & candidates:
            matches.append(node.id)
    return matches[0] if len(matches) == 1 else None


def unresolved_principal_node_id(graph: UnifiedGraph, provider: str, entity_type: EntityType, principal_id: str) -> str:
    """Keep an unresolved native binding separate from a conflicting inventory key."""
    candidate = identity_node_id(entity_type, provider, principal_id)
    if candidate in graph.nodes:
        return f"authorization_principal:{provider}:{entity_type.value}:{principal_id}"
    return candidate
