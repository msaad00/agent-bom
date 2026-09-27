"""Stable identity node keys shared by cloud graph projections."""

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
