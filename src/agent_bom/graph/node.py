"""UnifiedNode — canonical graph node with OCSF classification."""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from typing import Any

from agent_bom.graph.ocsf import ENTITY_OCSF_MAP
from agent_bom.graph.severity import (
    OCSF_SEVERITY_NAMES,
    SEVERITY_TO_OCSF,
    OCSFSeverity,
)
from agent_bom.graph.types import EntityType, NodeStatus
from agent_bom.graph.util import _now_iso

# Stable UUID namespace (shared with finding.py)
_AGENT_BOM_NS = uuid.UUID("7f3e4b2a-9c1d-5f8e-a0b4-12c3d4e5f6a7")


def stable_node_id(*parts: str) -> str:
    """Deterministic UUID v5 from content parts."""
    fingerprint = ":".join(p.lower().strip() for p in parts if p)
    return str(uuid.uuid5(_AGENT_BOM_NS, fingerprint))


@dataclass(slots=True)
class NodeDimensions:
    """Filterable facet dimensions attached to every node."""

    ecosystem: str = ""
    cloud_provider: str = ""
    agent_type: str = ""
    surface: str = ""
    environment: str = ""

    def to_dict(self) -> dict[str, str]:
        return {
            k: v
            for k, v in {
                "ecosystem": self.ecosystem,
                "cloud_provider": self.cloud_provider,
                "agent_type": self.agent_type,
                "surface": self.surface,
                "environment": self.environment,
            }.items()
            if v
        }

    @classmethod
    def from_dict(cls, data: dict[str, str]) -> NodeDimensions:
        return cls(
            ecosystem=data.get("ecosystem", ""),
            cloud_provider=data.get("cloud_provider", ""),
            agent_type=data.get("agent_type", ""),
            surface=data.get("surface", ""),
            environment=data.get("environment", ""),
        )

    def merge(self, other: NodeDimensions) -> NodeDimensions:
        """Merge: non-empty values from *other* win."""
        return NodeDimensions(
            ecosystem=other.ecosystem or self.ecosystem,
            cloud_provider=other.cloud_provider or self.cloud_provider,
            agent_type=other.agent_type or self.agent_type,
            surface=other.surface or self.surface,
            environment=other.environment or self.environment,
        )


@dataclass(slots=True)
class UnifiedNode:
    """Canonical graph node — used across every graph surface."""

    # Identity
    id: str
    entity_type: EntityType
    label: str

    # OCSF classification (derived from entity_type)
    category_uid: int = 0
    class_uid: int = 0
    type_uid: int = 0

    # State
    status: NodeStatus = NodeStatus.ACTIVE
    risk_score: float = 0.0
    severity: str = ""
    severity_id: int = OCSFSeverity.UNKNOWN

    # Temporal
    first_seen: str = ""
    last_seen: str = ""

    # Entity-specific attributes
    attributes: dict[str, Any] = field(default_factory=dict)

    # Tags (filterable)
    compliance_tags: list[str] = field(default_factory=list)
    data_sources: list[str] = field(default_factory=list)

    # Dimensions (filterable facets)
    dimensions: NodeDimensions = field(default_factory=NodeDimensions)

    def __post_init__(self) -> None:
        et_val = self.entity_type.value if isinstance(self.entity_type, EntityType) else self.entity_type
        mapping = ENTITY_OCSF_MAP.get(et_val, {"category_uid": 0, "class_uid": 0})
        if not self.category_uid:
            self.category_uid = mapping["category_uid"]
        if not self.class_uid:
            self.class_uid = mapping["class_uid"]
        if not self.type_uid:
            self.type_uid = self.class_uid * 100 + 1
        if self.severity and self.severity_id == OCSFSeverity.UNKNOWN:
            self.severity_id = SEVERITY_TO_OCSF.get(self.severity.lower(), OCSFSeverity.UNKNOWN)
        if not self.first_seen:
            self.first_seen = _now_iso()
        if not self.last_seen:
            self.last_seen = self.first_seen

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "entity_type": self.entity_type.value if isinstance(self.entity_type, EntityType) else self.entity_type,
            "label": self.label,
            "category_uid": self.category_uid,
            "class_uid": self.class_uid,
            "type_uid": self.type_uid,
            "status": self.status.value if isinstance(self.status, NodeStatus) else self.status,
            "risk_score": self.risk_score,
            "severity": self.severity,
            "severity_id": self.severity_id,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "attributes": self.attributes,
            "compliance_tags": self.compliance_tags,
            "data_sources": self.data_sources,
            "dimensions": self.dimensions.to_dict(),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> UnifiedNode:
        dims = data.get("dimensions", {})
        return cls(
            id=data["id"],
            entity_type=EntityType(data["entity_type"]),
            label=data["label"],
            category_uid=data.get("category_uid", 0),
            class_uid=data.get("class_uid", 0),
            type_uid=data.get("type_uid", 0),
            status=NodeStatus(data.get("status", "active")),
            risk_score=data.get("risk_score", 0.0),
            severity=data.get("severity", ""),
            severity_id=data.get("severity_id", OCSFSeverity.UNKNOWN),
            first_seen=data.get("first_seen", ""),
            last_seen=data.get("last_seen", ""),
            attributes=data.get("attributes", {}),
            compliance_tags=data.get("compliance_tags", []),
            data_sources=data.get("data_sources", []),
            dimensions=NodeDimensions.from_dict(dims) if isinstance(dims, dict) else NodeDimensions(),
        )

    def to_ocsf_event(self, product_version: str = "0.0.0") -> dict[str, Any]:
        """Convert to an OCSF event.  Only meaningful for finding entities."""
        now_ms = int(time.time() * 1000)
        event: dict[str, Any] = {
            "class_uid": self.class_uid,
            "category_uid": self.category_uid,
            "type_uid": self.type_uid,
            "activity_id": 1,
            "activity_name": "Create",
            "severity_id": self.severity_id,
            "severity": OCSF_SEVERITY_NAMES.get(self.severity_id, "Unknown"),
            "status_id": 1,
            "status": "New",
            "time": now_ms,
            "message": f"{self.entity_type.value}:{self.label}",
            "metadata": {
                "product": {
                    "name": "agent-bom",
                    "vendor_name": "msaad00",
                    "version": product_version,
                },
                "version": "1.1.0",
            },
            "resources": [
                {
                    "type": self.entity_type.value,
                    "name": self.label,
                    "uid": self.id,
                    "data": {k: v for k, v in self.attributes.items() if isinstance(v, (str, int, float, bool))},
                },
            ],
        }
        if self.class_uid == 2001:
            event["finding_info"] = {
                "title": self.label,
                "uid": self.id,
                "types": [self.entity_type.value],
            }
        if self.compliance_tags:
            event["compliance"] = {"standards": self.compliance_tags}
        return event
