"""Backward-compatible mapping dicts for context_graph.py migration."""

from __future__ import annotations

from agent_bom.graph.types import EntityType, RelationshipType

# Map old NodeKind values → EntityType
NODE_KIND_TO_ENTITY: dict[str, EntityType] = {
    "agent": EntityType.AGENT,
    "server": EntityType.SERVER,
    "credential": EntityType.CREDENTIAL,
    "tool": EntityType.TOOL,
    "vulnerability": EntityType.VULNERABILITY,
}

# Map old EdgeKind values → RelationshipType
EDGE_KIND_TO_RELATIONSHIP: dict[str, RelationshipType] = {
    "uses": RelationshipType.USES,
    "exposes": RelationshipType.EXPOSES_CRED,
    "provides": RelationshipType.PROVIDES_TOOL,
    "vulnerable_to": RelationshipType.VULNERABLE_TO,
    "shares_server": RelationshipType.SHARES_SERVER,
    "shares_credential": RelationshipType.SHARES_CRED,
}
