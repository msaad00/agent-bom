"""UnifiedEdge — canonical graph edge with direction-aware traversal."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from agent_bom.canonical_ids import canonical_graph_edge_id
from agent_bom.graph.types import RelationshipType
from agent_bom.graph.util import _now_iso


@dataclass(slots=True)
class UnifiedEdge:
    """Canonical graph edge — used across every graph surface.

    ``direction`` controls traversal:
    - ``"directed"``: only traversable source → target
    - ``"bidirectional"``: traversable both directions
    """

    source: str
    target: str
    relationship: RelationshipType

    # Traversal
    direction: str = "directed"  # "directed" | "bidirectional"
    weight: float = 1.0  # 0.0-10.0 (risk-weighted)
    traversable: bool = True  # include in attack path BFS?

    # Temporal
    first_seen: str = ""
    last_seen: str = ""
    valid_from: str = ""
    valid_to: str | None = None
    source_scan_id: str = ""
    source_run_id: str = ""

    # Evidence
    evidence: dict[str, Any] = field(default_factory=dict)
    confidence: float = 1.0
    provenance: dict[str, Any] = field(default_factory=dict)

    # OCSF activity
    activity_id: int = 1  # 1=Create, 2=Update, 3=Close

    def __post_init__(self) -> None:
        if not self.first_seen:
            self.first_seen = _now_iso()
        if not self.last_seen:
            self.last_seen = self.first_seen
        if not self.valid_from:
            self.valid_from = self.first_seen
        self.confidence = float(self.confidence)
        if self.confidence < 0.0 or self.confidence > 1.0:
            raise ValueError("edge confidence must be between 0.0 and 1.0")

    @property
    def is_bidirectional(self) -> bool:
        return self.direction == "bidirectional"

    @property
    def id(self) -> str:
        rel = self.relationship.value if isinstance(self.relationship, RelationshipType) else self.relationship
        return f"{rel}:{self.source}:{self.target}"

    @property
    def canonical_id(self) -> str:
        """Stable edge identity for scan-history joins without changing edge.id."""
        rel = self.relationship.value if isinstance(self.relationship, RelationshipType) else str(self.relationship)
        return canonical_graph_edge_id(self.source, self.target, rel)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "canonical_id": self.canonical_id,
            "source": self.source,
            "target": self.target,
            "source_id": self.source,
            "target_id": self.target,
            "relationship": self.relationship.value if isinstance(self.relationship, RelationshipType) else self.relationship,
            "direction": self.direction,
            "weight": self.weight,
            "traversable": self.traversable,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "valid_from": self.valid_from,
            "valid_to": self.valid_to,
            "confidence": self.confidence,
            "provenance": self.provenance,
            "source_scan_id": self.source_scan_id,
            "source_run_id": self.source_run_id,
            "evidence": self.evidence,
            "activity_id": self.activity_id,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> UnifiedEdge:
        return cls(
            source=data["source"],
            target=data["target"],
            relationship=RelationshipType(data["relationship"]),
            direction=data.get("direction", "directed"),
            weight=data.get("weight", 1.0),
            traversable=data.get("traversable", True),
            first_seen=data.get("first_seen", ""),
            last_seen=data.get("last_seen", ""),
            valid_from=data.get("valid_from", ""),
            valid_to=data.get("valid_to"),
            confidence=data.get("confidence", 1.0),
            provenance=data.get("provenance", {}),
            source_scan_id=data.get("source_scan_id", ""),
            source_run_id=data.get("source_run_id", ""),
            evidence=data.get("evidence", {}),
            activity_id=data.get("activity_id", 1),
        )
