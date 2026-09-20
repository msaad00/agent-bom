"""UnifiedEdge — canonical graph edge with direction-aware traversal."""

from __future__ import annotations

import json
from copy import deepcopy
from dataclasses import dataclass, field
from typing import Any

from agent_bom.canonical_ids import canonical_graph_edge_id
from agent_bom.graph.types import RelationshipType
from agent_bom.graph.util import _now_iso


def merge_edge_evidence(stored: dict[str, Any], incoming: dict[str, Any]) -> bool:
    """Merge evidence without collapsing provider action/binding receipts.

    Other evidence keeps the established non-empty-first behavior. Authorization
    decisions are complete records: merging actions and bindings independently
    would manufacture combinations the evaluator never assessed.
    """
    changed = False
    decisions: dict[str, dict[str, Any]] = {}
    grants: dict[str, dict[str, Any]] = {}
    for evidence in (stored, incoming):
        native_grants = evidence.get("grant_receipts")
        if native_grants is None and evidence.get("source") == "snowflake-objects" and isinstance(evidence.get("privilege"), str):
            native_grants = [
                {key: evidence[key] for key in ("source", "account", "role", "privilege", "object_fqn", "object_type") if key in evidence}
            ]
        if isinstance(native_grants, list):
            for record in native_grants:
                if isinstance(record, dict):
                    grants[json.dumps(record, sort_keys=True, default=str)] = deepcopy(record)
        records = evidence.get("authorization_decisions")
        if records is None and evidence.get("source") == "authorization-evidence" and isinstance(evidence.get("action"), str):
            records = [
                {
                    key: evidence[key]
                    for key in ("source", "provider", "principal_id", "decision", "action", "resource", "binding_ids", "observed_at")
                    if key in evidence
                }
            ]
        if isinstance(records, list):
            for record in records:
                if isinstance(record, dict):
                    decisions[json.dumps(record, sort_keys=True, default=str)] = deepcopy(record)
    grant_privileges = {json.dumps(record.get("privilege"), sort_keys=True, default=str) for record in grants.values()}
    for key, value in incoming.items():
        if key == "privilege" and len(grant_privileges) > 1:
            continue
        if value in (None, "", [], {}):
            continue
        if key not in stored or stored[key] in (None, "", [], {}):
            stored[key] = deepcopy(value)
            changed = True
    if decisions:
        records = [decisions[key] for key in sorted(decisions)]
        if stored.get("authorization_decisions") != records:
            stored["authorization_decisions"] = records
            changed = True
        # Keep compatibility scalars only when every receipt agrees. Missing
        # fields on legacy records remain unknown, never filled from a new grant.
        for key in ("action", "decision", "provider", "resource", "principal_id", "observed_at"):
            values = {json.dumps(record.get(key), sort_keys=True, default=str) for record in records}
            if len(values) > 1 and key in stored:
                stored.pop(key)
                changed = True
        bindings = sorted(
            {
                binding
                for record in records
                if isinstance(record.get("binding_ids"), list)
                for binding in record["binding_ids"]
                if isinstance(binding, str)
            }
        )
        if stored.get("binding_ids") != bindings:
            stored["binding_ids"] = bindings
            changed = True
    if grants:
        records = [grants[key] for key in sorted(grants)]
        if stored.get("grant_receipts") != records:
            stored["grant_receipts"] = records
            changed = True
        privileges = sorted({record["privilege"] for record in records if isinstance(record.get("privilege"), str) and record["privilege"]})
        if stored.get("privileges") != privileges:
            stored["privileges"] = privileges
            changed = True
        # A scalar cannot represent multiple grants. Do not imply that one
        # privilege was the only recorded action or fill unknown legacy scope.
        if len(grant_privileges) > 1:
            if "privilege" in stored:
                stored.pop("privilege")
                changed = True
    return changed


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
