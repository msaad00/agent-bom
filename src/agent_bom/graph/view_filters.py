"""Shared graph view filter contract, independent of storage and transport."""

from dataclasses import dataclass, field
from typing import Any

from agent_bom.graph.types import EntityType, RelationshipType


@dataclass(slots=True)
class GraphFilterOptions:
    """User-controlled filter options for graph views.

    Used by both Python API and TypeScript UI (mirrored in graph-schema.ts).
    """

    # Depth/hops
    max_depth: int = 6
    max_hops: int = 0  # 0 = unlimited

    # Severity filter
    min_severity: str = ""  # "critical" / "high" / "medium" / "low"

    # Entity type toggles (empty = all)
    entity_types: set[EntityType] = field(default_factory=set)

    # Relationship type toggles (empty = all)
    relationship_types: set[RelationshipType] = field(default_factory=set)

    # Static vs dynamic edge filters
    static_only: bool = False
    dynamic_only: bool = False

    # Include/exclude specific node IDs
    include_ids: set[str] = field(default_factory=set)
    exclude_ids: set[str] = field(default_factory=set)

    # Layout
    layout: str = "dagre"  # dagre / force / radial / hierarchical / grid

    def to_dict(self) -> dict[str, Any]:
        return {
            "max_depth": self.max_depth,
            "max_hops": self.max_hops,
            "min_severity": self.min_severity,
            "entity_types": sorted(et.value for et in self.entity_types),
            "relationship_types": sorted(rt.value for rt in self.relationship_types),
            "static_only": self.static_only,
            "dynamic_only": self.dynamic_only,
            "include_ids": sorted(self.include_ids),
            "exclude_ids": sorted(self.exclude_ids),
            "layout": self.layout,
        }
