"""Unified Graph Schema — single source of truth for all graph types.

Re-exports everything from submodules so consumers can do::

    from agent_bom.graph import UnifiedGraph, EntityType, SEVERITY_RANK
"""

from agent_bom.graph.builder import build_unified_graph_from_report
from agent_bom.graph.compat import EDGE_KIND_TO_RELATIONSHIP, NODE_KIND_TO_ENTITY
from agent_bom.graph.container import (
    ENTITY_LEGEND,
    RELATIONSHIP_LEGEND,
    AttackPath,
    GraphFilterOptions,
    InteractionRisk,
    LegendEntry,
    UnifiedGraph,
)
from agent_bom.graph.edge import UnifiedEdge
from agent_bom.graph.node import NodeDimensions, UnifiedNode, stable_node_id
from agent_bom.graph.ocsf import ENTITY_OCSF_MAP, FINDING_ENTITY_TYPES, ocsf_type_uid
from agent_bom.graph.severity import (
    OCSF_SEVERITY_NAMES,
    OCSF_TO_SYSLOG,
    SEVERITY_BADGE,
    SEVERITY_RANK,
    SEVERITY_RISK_SCORE,
    SEVERITY_TO_OCSF,
    OCSFSeverity,
    ocsf_to_severity,
    severity_rank,
    severity_to_ocsf,
)
from agent_bom.graph.types import EntityType, GraphLayout, NodeStatus, RelationshipType
from agent_bom.graph.util import _now_iso
from agent_bom.graph.webhooks import compute_delta_alerts, format_alerts_for_siem

__all__ = [
    # Types
    "EntityType",
    "RelationshipType",
    "NodeStatus",
    "GraphLayout",
    "OCSFSeverity",
    # Severity
    "SEVERITY_TO_OCSF",
    "OCSF_SEVERITY_NAMES",
    "SEVERITY_RANK",
    "SEVERITY_RISK_SCORE",
    "SEVERITY_BADGE",
    "OCSF_TO_SYSLOG",
    "severity_rank",
    "severity_to_ocsf",
    "ocsf_to_severity",
    # OCSF
    "ENTITY_OCSF_MAP",
    "FINDING_ENTITY_TYPES",
    "ocsf_type_uid",
    # Node
    "UnifiedNode",
    "NodeDimensions",
    "stable_node_id",
    # Edge
    "UnifiedEdge",
    # Container
    "UnifiedGraph",
    "AttackPath",
    "InteractionRisk",
    "GraphFilterOptions",
    "LegendEntry",
    "ENTITY_LEGEND",
    "RELATIONSHIP_LEGEND",
    # Compat
    "NODE_KIND_TO_ENTITY",
    "EDGE_KIND_TO_RELATIONSHIP",
    # Builder
    "build_unified_graph_from_report",
    # Util
    "_now_iso",
]
