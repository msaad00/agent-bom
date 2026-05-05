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
    # Legacy context_graph exposes cloud IAM / workload identities as
    # iam_role nodes. The canonical schema models those as service
    # accounts so identity context survives conversion to UnifiedGraph.
    "iam_role": EntityType.SERVICE_ACCOUNT,
}

# Map old EdgeKind values → RelationshipType
EDGE_KIND_TO_RELATIONSHIP: dict[str, RelationshipType] = {
    "uses": RelationshipType.USES,
    "exposes": RelationshipType.EXPOSES_CRED,
    "provides": RelationshipType.PROVIDES_TOOL,
    "vulnerable_to": RelationshipType.VULNERABLE_TO,
    "shares_server": RelationshipType.SHARES_SERVER,
    "shares_credential": RelationshipType.SHARES_CRED,
    # Legacy iam_role -> agent attachment bridges to canonical identity
    # membership. Keeping this mapping avoids silently dropping identity
    # edges during to_unified_graph().
    "attached_to": RelationshipType.MEMBER_OF,
}
