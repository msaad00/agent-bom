"""Backward-compatible re-export — all types now live in ``agent_bom.graph``.

Existing imports like ``from agent_bom.graph_schema import UnifiedGraph``
continue to work.  New code should import from ``agent_bom.graph`` directly.
"""

# ruff: noqa: F401 — re-exports
from agent_bom.graph import (
    EDGE_KIND_TO_RELATIONSHIP as _EDGE_KIND_TO_RELATIONSHIP,
)
from agent_bom.graph import (
    ENTITY_LEGEND,
    ENTITY_OCSF_MAP,
    FINDING_ENTITY_TYPES,
    OCSF_SEVERITY_NAMES,
    OCSF_TO_SYSLOG,
    RELATIONSHIP_LEGEND,
    SEVERITY_BADGE,
    SEVERITY_RANK,
    SEVERITY_RISK_SCORE,
    SEVERITY_TO_OCSF,
    AttackPath,
    EntityType,
    GraphFilterOptions,
    GraphLayout,
    InteractionRisk,
    LegendEntry,
    NodeDimensions,
    NodeStatus,
    OCSFSeverity,
    RelationshipType,
    UnifiedEdge,
    UnifiedGraph,
    UnifiedNode,
    _now_iso,
    ocsf_to_severity,
    ocsf_type_uid,
    severity_rank,
    severity_to_ocsf,
    stable_node_id,
)
from agent_bom.graph import (
    NODE_KIND_TO_ENTITY as _NODE_KIND_TO_ENTITY,
)
