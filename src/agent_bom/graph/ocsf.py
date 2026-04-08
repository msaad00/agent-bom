"""OCSF category/class mapping for graph entity types.

Maps EntityType → OCSF category_uid + class_uid.  Credentials are
inventory (Category 5), NOT findings — they only become findings when
an actual exposure or misconfiguration is detected.
"""

from __future__ import annotations

from agent_bom.graph.types import EntityType

# ── Entity → OCSF mapping ────────────────────────────────────────────────
# Inventory entities → Category 5 (Discovery), Class 4001 (Device Inventory)
# Identity entities  → Category 3 (Identity & Access), Class 3001 (Account)
# Finding entities   → Category 2 (Findings), Class 2001/2003

ENTITY_OCSF_MAP: dict[str, dict[str, int]] = {
    # Inventory (Category 5)
    EntityType.AGENT: {"category_uid": 5, "class_uid": 4001},
    EntityType.SERVER: {"category_uid": 5, "class_uid": 4001},
    EntityType.PACKAGE: {"category_uid": 5, "class_uid": 4001},
    EntityType.TOOL: {"category_uid": 5, "class_uid": 4001},
    EntityType.MODEL: {"category_uid": 5, "class_uid": 4001},
    EntityType.DATASET: {"category_uid": 5, "class_uid": 4001},
    EntityType.CONTAINER: {"category_uid": 5, "class_uid": 4001},
    EntityType.CLOUD_RESOURCE: {"category_uid": 5, "class_uid": 4001},
    EntityType.CREDENTIAL: {"category_uid": 5, "class_uid": 4001},
    # Identity & access (Category 3)
    EntityType.USER: {"category_uid": 3, "class_uid": 3001},
    EntityType.GROUP: {"category_uid": 3, "class_uid": 3001},
    EntityType.SERVICE_ACCOUNT: {"category_uid": 3, "class_uid": 3001},
    # Findings (Category 2)
    EntityType.VULNERABILITY: {"category_uid": 2, "class_uid": 2001},
    EntityType.MISCONFIGURATION: {"category_uid": 2, "class_uid": 2003},
    # Organizational (virtual)
    EntityType.PROVIDER: {"category_uid": 0, "class_uid": 0},
    EntityType.ENVIRONMENT: {"category_uid": 0, "class_uid": 0},
    EntityType.FLEET: {"category_uid": 5, "class_uid": 4001},
    EntityType.CLUSTER: {"category_uid": 5, "class_uid": 4001},
}

# Entity types that represent actual security findings (for SIEM export)
FINDING_ENTITY_TYPES: frozenset[EntityType] = frozenset(
    {
        EntityType.VULNERABILITY,
        EntityType.MISCONFIGURATION,
    }
)


def ocsf_type_uid(entity_type: str | EntityType, activity_id: int = 1) -> int:
    """Compute OCSF type_uid = class_uid * 100 + activity_id."""
    et = entity_type if isinstance(entity_type, str) else entity_type.value
    mapping = ENTITY_OCSF_MAP.get(et, {"class_uid": 0})
    return mapping["class_uid"] * 100 + activity_id
