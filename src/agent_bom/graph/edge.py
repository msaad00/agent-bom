"""UnifiedEdge — canonical graph edge with direction-aware traversal."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

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

    # Evidence
    evidence: dict[str, Any] = field(default_factory=dict)

    # OCSF activity
    activity_id: int = 1  # 1=Create, 2=Update, 3=Close

    def __post_init__(self) -> None:
        if not self.first_seen:
            self.first_seen = _now_iso()
        if not self.last_seen:
            self.last_seen = self.first_seen

    @property
    def is_bidirectional(self) -> bool:
        return self.direction == "bidirectional"

    @property
    def id(self) -> str:
        rel = self.relationship.value if isinstance(self.relationship, RelationshipType) else self.relationship
        return f"{rel}:{self.source}:{self.target}"

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "source": self.source,
            "target": self.target,
            "relationship": self.relationship.value if isinstance(self.relationship, RelationshipType) else self.relationship,
            "direction": self.direction,
            "weight": self.weight,
            "traversable": self.traversable,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
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
            evidence=data.get("evidence", {}),
            activity_id=data.get("activity_id", 1),
        )
