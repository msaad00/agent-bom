"""Unified Graph Schema — single source of truth for all graph types.

OCSF-aligned entity and relationship model that standardises nodes, edges,
severity, node IDs, and traversal across every graph surface in agent-bom:
context graph, output graph, graph export, mesh graph, attack flow, and
runtime session graph.

Design principles:
- OCSF category/class UIDs on every node for SIEM interoperability
- Deterministic node IDs: ``{entity_type}:{namespace}:{name}``
- Single severity system (OCSF 1-5 scale mapped to critical→info)
- Temporal fields (first_seen / last_seen) on every node and edge
- Traversal-aware edges (weight, direction, traversable flag)
- Filterable dimensions (ecosystem, cloud_provider, agent_type, surface, environment)
- Zero new dependencies — stdlib only
"""

from __future__ import annotations

import time
import uuid
from collections import defaultdict, deque
from dataclasses import dataclass, field
from enum import Enum, IntEnum
from typing import Any, Optional

# ── Stable UUID namespace (shared with finding.py) ───────────────────────
_AGENT_BOM_NS = uuid.UUID("7f3e4b2a-9c1d-5f8e-a0b4-12c3d4e5f6a7")


def stable_node_id(*parts: str) -> str:
    """Deterministic UUID v5 from content parts.

    Same inputs always produce the same ID across scans and machines.
    """
    fingerprint = ":".join(p.lower().strip() for p in parts if p)
    return str(uuid.uuid5(_AGENT_BOM_NS, fingerprint))


# ═══════════════════════════════════════════════════════════════════════════
# Enums
# ═══════════════════════════════════════════════════════════════════════════


class EntityType(str, Enum):
    """Node entity types, mapped to OCSF classes.

    Category 5 (Discovery/Inventory) → class_uid 4001 (Device Inventory Info)
    Category 2 (Findings)            → class_uid 2001 / 2003
    """

    # ── Inventory entities (OCSF Category 5) ──
    AGENT = "agent"
    SERVER = "server"
    PACKAGE = "package"
    TOOL = "tool"
    MODEL = "model"
    DATASET = "dataset"
    CONTAINER = "container"
    CLOUD_RESOURCE = "cloud_resource"

    # ── Finding entities (OCSF Category 2) ──
    VULNERABILITY = "vulnerability"
    CREDENTIAL = "credential"
    MISCONFIGURATION = "misconfiguration"

    # ── Grouping (virtual, not stored in DB) ──
    PROVIDER = "provider"
    ENVIRONMENT = "environment"


class RelationshipType(str, Enum):
    """Edge relationship types across all graph surfaces."""

    # ── Static inventory relationships ──
    HOSTS = "hosts"  # provider → agent
    USES = "uses"  # agent → server
    DEPENDS_ON = "depends_on"  # server → package
    PROVIDES_TOOL = "provides_tool"  # server → tool
    EXPOSES_CRED = "exposes_cred"  # server → credential
    SERVES_MODEL = "serves_model"  # server → model
    CONTAINS = "contains"  # container → package

    # ── Vulnerability relationships ──
    AFFECTS = "affects"  # vulnerability → package
    VULNERABLE_TO = "vulnerable_to"  # server/package → vulnerability
    EXPLOITABLE_VIA = "exploitable_via"  # vulnerability → tool/credential

    # ── Lateral movement (computed) ──
    SHARES_SERVER = "shares_server"  # agent ↔ agent
    SHARES_CRED = "shares_cred"  # agent ↔ agent
    LATERAL_PATH = "lateral_path"  # agent → agent (precomputed attack path)

    # ── Runtime events (dynamic) ──
    INVOKED = "invoked"  # agent → tool (runtime)
    ACCESSED = "accessed"  # tool → resource (runtime)
    DELEGATED_TO = "delegated_to"  # agent → agent (runtime)


class NodeStatus(str, Enum):
    """Lifecycle status of a graph node."""

    ACTIVE = "active"
    INACTIVE = "inactive"
    VULNERABLE = "vulnerable"
    REMEDIATED = "remediated"


# ═══════════════════════════════════════════════════════════════════════════
# OCSF Mapping — single source of truth
# ═══════════════════════════════════════════════════════════════════════════


class OCSFSeverity(IntEnum):
    """OCSF v1.1.0 severity_id values.

    Used by output/ocsf.py, siem/ocsf.py, and every graph surface.
    """

    UNKNOWN = 0
    INFORMATIONAL = 1
    LOW = 2
    MEDIUM = 3
    HIGH = 4
    CRITICAL = 5


# String severity → OCSF severity_id (canonical mapping for the entire codebase)
SEVERITY_TO_OCSF: dict[str, int] = {
    "critical": OCSFSeverity.CRITICAL,
    "high": OCSFSeverity.HIGH,
    "medium": OCSFSeverity.MEDIUM,
    "low": OCSFSeverity.LOW,
    "info": OCSFSeverity.INFORMATIONAL,
    "informational": OCSFSeverity.INFORMATIONAL,
    "none": OCSFSeverity.UNKNOWN,
    "unknown": OCSFSeverity.UNKNOWN,
}

# OCSF severity_id → display name
OCSF_SEVERITY_NAMES: dict[int, str] = {
    OCSFSeverity.CRITICAL: "Critical",
    OCSFSeverity.HIGH: "High",
    OCSFSeverity.MEDIUM: "Medium",
    OCSFSeverity.LOW: "Low",
    OCSFSeverity.INFORMATIONAL: "Informational",
    OCSFSeverity.UNKNOWN: "Unknown",
}

# String severity → numeric rank for sorting/comparison (0-5, higher = worse)
SEVERITY_RANK: dict[str, int] = {
    "critical": 5,
    "high": 4,
    "medium": 3,
    "low": 2,
    "info": 1,
    "informational": 1,
    "none": 0,
    "unknown": 0,
}

# Severity → risk score contribution for composite risk calculation
SEVERITY_RISK_SCORE: dict[str, float] = {
    "critical": 8.0,
    "high": 6.0,
    "medium": 4.0,
    "low": 2.0,
    "info": 0.5,
    "informational": 0.5,
    "none": 0.0,
    "unknown": 0.0,
}

# Severity → compact badge for CLI/graph display
SEVERITY_BADGE: dict[str, str] = {
    "critical": "R2",
    "high": "R1",
    "medium": "M",
    "low": "L",
    "info": "I",
    "unknown": "?",
}

# OCSF severity_id → RFC 5424 syslog severity
OCSF_TO_SYSLOG: dict[int, int] = {
    OCSFSeverity.CRITICAL: 2,  # Syslog Critical
    OCSFSeverity.HIGH: 3,  # Syslog Error
    OCSFSeverity.MEDIUM: 4,  # Syslog Warning
    OCSFSeverity.LOW: 5,  # Syslog Notice
    OCSFSeverity.INFORMATIONAL: 6,  # Syslog Informational
    OCSFSeverity.UNKNOWN: 6,  # Default to Informational
}


# ── OCSF class/category mapping per entity type ──────────────────────────

ENTITY_OCSF_MAP: dict[str, dict[str, int]] = {
    # Inventory entities → OCSF Category 5 (Discovery), Class 4001 (Device Inventory)
    EntityType.AGENT: {"category_uid": 5, "class_uid": 4001},
    EntityType.SERVER: {"category_uid": 5, "class_uid": 4001},
    EntityType.PACKAGE: {"category_uid": 5, "class_uid": 4001},
    EntityType.TOOL: {"category_uid": 5, "class_uid": 4001},
    EntityType.MODEL: {"category_uid": 5, "class_uid": 4001},
    EntityType.DATASET: {"category_uid": 5, "class_uid": 4001},
    EntityType.CONTAINER: {"category_uid": 5, "class_uid": 4001},
    EntityType.CLOUD_RESOURCE: {"category_uid": 5, "class_uid": 4001},
    # Finding entities → OCSF Category 2 (Findings)
    EntityType.VULNERABILITY: {"category_uid": 2, "class_uid": 2001},  # Security Finding
    EntityType.CREDENTIAL: {"category_uid": 2, "class_uid": 2001},  # Security Finding
    EntityType.MISCONFIGURATION: {"category_uid": 2, "class_uid": 2003},  # Compliance Finding
    # Grouping (virtual — no OCSF mapping)
    EntityType.PROVIDER: {"category_uid": 0, "class_uid": 0},
    EntityType.ENVIRONMENT: {"category_uid": 0, "class_uid": 0},
}


def ocsf_type_uid(entity_type: str | EntityType, activity_id: int = 1) -> int:
    """Compute OCSF type_uid = class_uid * 100 + activity_id."""
    et = entity_type if isinstance(entity_type, str) else entity_type.value
    mapping = ENTITY_OCSF_MAP.get(et, {"class_uid": 0})
    return mapping["class_uid"] * 100 + activity_id


# ═══════════════════════════════════════════════════════════════════════════
# Core data structures
# ═══════════════════════════════════════════════════════════════════════════


@dataclass(slots=True)
class NodeDimensions:
    """Filterable facet dimensions attached to every node."""

    ecosystem: str = ""  # npm / pypi / go / cargo / maven / nuget / hex / pub
    cloud_provider: str = ""  # aws / azure / gcp / snowflake
    agent_type: str = ""  # claude-desktop / cursor / windsurf / ...
    surface: str = ""  # mcp-server / container / filesystem / sbom / cloud-cis
    environment: str = ""  # production / staging / dev

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


@dataclass(slots=True)
class UnifiedNode:
    """Canonical graph node — used across every graph surface.

    Every field is meaningful, nothing is optional scaffolding.
    """

    # ── Identity ──
    id: str  # stable_node_id or "{entity_type}:{ns}:{name}"
    entity_type: EntityType
    label: str  # human-readable display name

    # ── OCSF classification (derived from entity_type) ──
    category_uid: int = 0
    class_uid: int = 0
    type_uid: int = 0

    # ── State ──
    status: NodeStatus = NodeStatus.ACTIVE
    risk_score: float = 0.0  # 0-10 composite
    severity: str = ""  # critical / high / medium / low / info
    severity_id: int = OCSFSeverity.UNKNOWN  # OCSF severity_id (0-5)

    # ── Temporal ──
    first_seen: str = ""  # ISO-8601 UTC
    last_seen: str = ""  # ISO-8601 UTC

    # ── Entity-specific attributes ──
    attributes: dict[str, Any] = field(default_factory=dict)

    # ── Tags (filterable) ──
    compliance_tags: list[str] = field(default_factory=list)
    data_sources: list[str] = field(default_factory=list)

    # ── Dimensions (filterable facets) ──
    dimensions: NodeDimensions = field(default_factory=NodeDimensions)

    def __post_init__(self) -> None:
        # Auto-populate OCSF fields from entity_type
        mapping = ENTITY_OCSF_MAP.get(
            self.entity_type.value if isinstance(self.entity_type, EntityType) else self.entity_type,
            {"category_uid": 0, "class_uid": 0},
        )
        if not self.category_uid:
            self.category_uid = mapping["category_uid"]
        if not self.class_uid:
            self.class_uid = mapping["class_uid"]
        if not self.type_uid:
            self.type_uid = self.class_uid * 100 + 1  # activity_id=1 (Create)
        # Auto-populate severity_id from severity string
        if self.severity and self.severity_id == OCSFSeverity.UNKNOWN:
            self.severity_id = SEVERITY_TO_OCSF.get(self.severity.lower(), OCSFSeverity.UNKNOWN)
        # Auto-populate timestamps
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

    # ── OCSF event generation ────────────────────────────────────────────

    def to_ocsf_event(self, product_version: str = "0.0.0") -> dict[str, Any]:
        """Convert this node to an OCSF-compliant event dict.

        Inventory nodes → Device Inventory (4001).
        Finding nodes → Security Finding (2001) or Compliance Finding (2003).
        """
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
        if self.class_uid == 2001:  # Security Finding
            event["finding_info"] = {
                "title": self.label,
                "uid": self.id,
                "types": [self.entity_type.value],
            }
        if self.compliance_tags:
            event["compliance"] = {"standards": self.compliance_tags}
        return event


@dataclass(slots=True)
class UnifiedEdge:
    """Canonical graph edge — used across every graph surface."""

    # ── Identity ──
    source: str  # node.id
    target: str  # node.id
    relationship: RelationshipType

    # ── Traversal ──
    direction: str = "directed"  # "directed" | "bidirectional"
    weight: float = 1.0  # 0.0-10.0 (risk-weighted)
    traversable: bool = True  # include in attack path BFS?

    # ── Temporal ──
    first_seen: str = ""
    last_seen: str = ""

    # ── Evidence ──
    evidence: dict[str, Any] = field(default_factory=dict)

    # ── OCSF activity ──
    activity_id: int = 1  # 1=Create, 2=Update, 3=Close

    def __post_init__(self) -> None:
        if not self.first_seen:
            self.first_seen = _now_iso()
        if not self.last_seen:
            self.last_seen = self.first_seen

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


# ═══════════════════════════════════════════════════════════════════════════
# Attack path & interaction risk
# ═══════════════════════════════════════════════════════════════════════════


@dataclass(slots=True)
class AttackPath:
    """Precomputed attack path between two nodes."""

    source: str
    target: str
    hops: list[str]  # ordered node IDs
    edges: list[str]  # relationship type values along path
    composite_risk: float = 0.0  # 0-10
    summary: str = ""  # human-readable "A → B → C"
    credential_exposure: list[str] = field(default_factory=list)
    tool_exposure: list[str] = field(default_factory=list)
    vuln_ids: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "target": self.target,
            "hops": self.hops,
            "edges": self.edges,
            "composite_risk": self.composite_risk,
            "summary": self.summary,
            "credential_exposure": self.credential_exposure,
            "tool_exposure": self.tool_exposure,
            "vuln_ids": self.vuln_ids,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> AttackPath:
        return cls(
            source=data["source"],
            target=data["target"],
            hops=data.get("hops", []),
            edges=data.get("edges", []),
            composite_risk=data.get("composite_risk", 0.0),
            summary=data.get("summary", ""),
            credential_exposure=data.get("credential_exposure", []),
            tool_exposure=data.get("tool_exposure", []),
            vuln_ids=data.get("vuln_ids", []),
        )


@dataclass(slots=True)
class InteractionRisk:
    """Cross-agent interaction risk pattern."""

    pattern: str  # shared_credential / shared_server / tool_overlap_execute / multi_hop_vuln
    agents: list[str]
    risk_score: float
    description: str
    owasp_agentic_tag: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "pattern": self.pattern,
            "agents": self.agents,
            "risk_score": self.risk_score,
            "description": self.description,
            "owasp_agentic_tag": self.owasp_agentic_tag,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> InteractionRisk:
        return cls(
            pattern=data["pattern"],
            agents=data.get("agents", []),
            risk_score=data.get("risk_score", 0.0),
            description=data.get("description", ""),
            owasp_agentic_tag=data.get("owasp_agentic_tag"),
        )


# ═══════════════════════════════════════════════════════════════════════════
# Unified Graph — the single container
# ═══════════════════════════════════════════════════════════════════════════


@dataclass
class UnifiedGraph:
    """The canonical graph structure for agent-bom.

    All graph surfaces (context, mesh, export, attack flow, runtime)
    build from or convert to this structure.

    Provides O(1) node/edge lookup, BFS traversal, filtering, and
    serialisation to dict / OCSF events.
    """

    nodes: dict[str, UnifiedNode] = field(default_factory=dict)
    edges: list[UnifiedEdge] = field(default_factory=list)
    adjacency: dict[str, list[UnifiedEdge]] = field(default_factory=lambda: defaultdict(list))
    _edge_keys: set[tuple[str, str, str]] = field(default_factory=set, repr=False)

    # ── Precomputed results ──
    attack_paths: list[AttackPath] = field(default_factory=list)
    interaction_risks: list[InteractionRisk] = field(default_factory=list)

    # ── Metadata ──
    scan_id: str = ""
    tenant_id: str = ""
    created_at: str = ""

    def __post_init__(self) -> None:
        if not self.created_at:
            self.created_at = _now_iso()

    # ── Mutation ─────────────────────────────────────────────────────────

    def add_node(self, node: UnifiedNode) -> None:
        """Add or update a node. Last-seen is bumped on update."""
        existing = self.nodes.get(node.id)
        if existing:
            existing.last_seen = node.last_seen or _now_iso()
            existing.attributes.update(node.attributes)
            if node.risk_score > existing.risk_score:
                existing.risk_score = node.risk_score
            if SEVERITY_RANK.get(node.severity, 0) > SEVERITY_RANK.get(existing.severity, 0):
                existing.severity = node.severity
                existing.severity_id = node.severity_id
            return
        self.nodes[node.id] = node

    def add_edge(self, edge: UnifiedEdge) -> None:
        """Add an edge with O(1) deduplication by (source, target, relationship)."""
        rel = edge.relationship.value if isinstance(edge.relationship, RelationshipType) else str(edge.relationship)
        key = (edge.source, edge.target, rel)
        if key in self._edge_keys:
            return
        self._edge_keys.add(key)
        self.edges.append(edge)
        self.adjacency[edge.source].append(edge)
        # Bidirectional adjacency for traversal
        reverse = UnifiedEdge(
            source=edge.target,
            target=edge.source,
            relationship=edge.relationship,
            direction=edge.direction,
            weight=edge.weight,
            traversable=edge.traversable,
            first_seen=edge.first_seen,
            last_seen=edge.last_seen,
            evidence=edge.evidence,
            activity_id=edge.activity_id,
        )
        self.adjacency[edge.target].append(reverse)

    # ── Query ────────────────────────────────────────────────────────────

    def get_node(self, node_id: str) -> Optional[UnifiedNode]:
        return self.nodes.get(node_id)

    def nodes_by_type(self, entity_type: EntityType) -> list[UnifiedNode]:
        return [n for n in self.nodes.values() if n.entity_type == entity_type]

    def edges_from(self, node_id: str) -> list[UnifiedEdge]:
        return self.adjacency.get(node_id, [])

    def neighbors(self, node_id: str) -> list[str]:
        return [e.target for e in self.adjacency.get(node_id, [])]

    def has_node(self, node_id: str) -> bool:
        return node_id in self.nodes

    def has_edge(self, source: str, target: str) -> bool:
        return any(e.target == target for e in self.adjacency.get(source, []))

    # ── Filtering ────────────────────────────────────────────────────────

    def filter_nodes(
        self,
        *,
        entity_types: set[EntityType] | None = None,
        min_severity: str = "",
        status: NodeStatus | None = None,
        data_source: str = "",
        dimension_filters: dict[str, str] | None = None,
    ) -> list[UnifiedNode]:
        """Filter nodes by type, severity, status, data source, or dimensions."""
        result: list[UnifiedNode] = []
        min_rank = SEVERITY_RANK.get(min_severity, 0)
        for node in self.nodes.values():
            if entity_types and node.entity_type not in entity_types:
                continue
            if min_severity and SEVERITY_RANK.get(node.severity, 0) < min_rank:
                continue
            if status and node.status != status:
                continue
            if data_source and data_source not in node.data_sources:
                continue
            if dimension_filters:
                dims = node.dimensions.to_dict()
                if not all(dims.get(k) == v for k, v in dimension_filters.items()):
                    continue
            result.append(node)
        return result

    def filter_edges(
        self,
        *,
        relationships: set[RelationshipType] | None = None,
        traversable_only: bool = False,
        min_weight: float = 0.0,
    ) -> list[UnifiedEdge]:
        """Filter edges by relationship type, traversability, or weight."""
        result: list[UnifiedEdge] = []
        for edge in self.edges:
            if relationships and edge.relationship not in relationships:
                continue
            if traversable_only and not edge.traversable:
                continue
            if edge.weight < min_weight:
                continue
            result.append(edge)
        return result

    # ── Traversal ────────────────────────────────────────────────────────

    def bfs(
        self,
        source: str,
        max_depth: int = 4,
        traversable_only: bool = True,
    ) -> list[list[str]]:
        """BFS from source, returning all reachable paths within max_depth."""
        if source not in self.nodes:
            return []
        paths: list[list[str]] = []
        queue: deque[tuple[str, list[str]]] = deque([(source, [source])])
        visited: set[str] = {source}
        while queue:
            current, path = queue.popleft()
            if len(path) > max_depth + 1:
                continue
            if len(path) > 1:
                paths.append(path)
            for edge in self.adjacency.get(current, []):
                if traversable_only and not edge.traversable:
                    continue
                if edge.target not in visited:
                    visited.add(edge.target)
                    queue.append((edge.target, path + [edge.target]))
        return paths

    def shortest_path(self, source: str, target: str) -> list[str] | None:
        """BFS shortest path between two nodes."""
        if source not in self.nodes or target not in self.nodes:
            return None
        if source == target:
            return [source]
        queue: deque[tuple[str, list[str]]] = deque([(source, [source])])
        visited: set[str] = {source}
        while queue:
            current, path = queue.popleft()
            for edge in self.adjacency.get(current, []):
                if edge.target == target:
                    return path + [target]
                if edge.target not in visited:
                    visited.add(edge.target)
                    queue.append((edge.target, path + [edge.target]))
        return None

    def reachable_from(self, source: str, max_depth: int = 6) -> set[str]:
        """Return all node IDs reachable from source within max_depth."""
        if source not in self.nodes:
            return set()
        visited: set[str] = {source}
        queue: deque[tuple[str, int]] = deque([(source, 0)])
        while queue:
            current, depth = queue.popleft()
            if depth >= max_depth:
                continue
            for edge in self.adjacency.get(current, []):
                if edge.target not in visited:
                    visited.add(edge.target)
                    queue.append((edge.target, depth + 1))
        return visited

    # ── Centrality ───────────────────────────────────────────────────────

    def degree_centrality(self) -> dict[str, float]:
        """Normalised degree centrality for each node."""
        if not self.nodes:
            return {}
        max_possible = max(len(self.nodes) - 1, 1)
        return {nid: len(self.adjacency.get(nid, [])) / max_possible for nid in self.nodes}

    def bottleneck_nodes(self, top_n: int = 5) -> list[tuple[str, float]]:
        """Approximate betweenness centrality using sampled BFS."""
        if not self.nodes:
            return []
        scores: dict[str, float] = {nid: 0.0 for nid in self.nodes}
        sample = list(self.nodes.keys())[: min(50, len(self.nodes))]
        for src in sample:
            visited: dict[str, list[str]] = {src: [src]}
            queue: deque[str] = deque([src])
            while queue:
                current = queue.popleft()
                for edge in self.adjacency.get(current, []):
                    if edge.target not in visited:
                        visited[edge.target] = visited[current] + [edge.target]
                        queue.append(edge.target)
            for path in visited.values():
                for node in path[1:-1]:
                    scores[node] += 1.0
        total = sum(scores.values()) or 1.0
        normalised = {nid: score / total for nid, score in scores.items()}
        return sorted(normalised.items(), key=lambda x: x[1], reverse=True)[:top_n]

    # ── Stats ────────────────────────────────────────────────────────────

    def stats(self) -> dict[str, Any]:
        """Compute graph statistics."""
        type_counts: dict[str, int] = defaultdict(int)
        severity_counts: dict[str, int] = defaultdict(int)
        for node in self.nodes.values():
            et = node.entity_type.value if isinstance(node.entity_type, EntityType) else node.entity_type
            type_counts[et] += 1
            if node.severity:
                severity_counts[node.severity] += 1

        rel_counts: dict[str, int] = defaultdict(int)
        for edge in self.edges:
            rel = edge.relationship.value if isinstance(edge.relationship, RelationshipType) else edge.relationship
            rel_counts[rel] += 1

        return {
            "total_nodes": len(self.nodes),
            "total_edges": len(self.edges),
            "node_types": dict(type_counts),
            "severity_counts": dict(severity_counts),
            "relationship_types": dict(rel_counts),
            "attack_path_count": len(self.attack_paths),
            "interaction_risk_count": len(self.interaction_risks),
            "max_attack_path_risk": max((p.composite_risk for p in self.attack_paths), default=0.0),
            "highest_interaction_risk": max((r.risk_score for r in self.interaction_risks), default=0.0),
        }

    # ── Serialisation ────────────────────────────────────────────────────

    def to_dict(self) -> dict[str, Any]:
        """Full serialisation — JSON-compatible dict."""
        return {
            "scan_id": self.scan_id,
            "tenant_id": self.tenant_id,
            "created_at": self.created_at,
            "nodes": [n.to_dict() for n in self.nodes.values()],
            "edges": [e.to_dict() for e in self.edges],
            "attack_paths": [p.to_dict() for p in self.attack_paths],
            "interaction_risks": [r.to_dict() for r in self.interaction_risks],
            "stats": self.stats(),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> UnifiedGraph:
        graph = cls(
            scan_id=data.get("scan_id", ""),
            tenant_id=data.get("tenant_id", ""),
            created_at=data.get("created_at", ""),
        )
        for nd in data.get("nodes", []):
            graph.add_node(UnifiedNode.from_dict(nd))
        for ed in data.get("edges", []):
            graph.add_edge(UnifiedEdge.from_dict(ed))
        for pd in data.get("attack_paths", []):
            graph.attack_paths.append(AttackPath.from_dict(pd))
        for rd in data.get("interaction_risks", []):
            graph.interaction_risks.append(InteractionRisk.from_dict(rd))
        return graph

    # ── OCSF batch export ────────────────────────────────────────────────

    def to_ocsf_events(self, product_version: str = "0.0.0") -> list[dict[str, Any]]:
        """Export all finding-type nodes as OCSF events."""
        finding_types = {EntityType.VULNERABILITY, EntityType.CREDENTIAL, EntityType.MISCONFIGURATION}
        return [node.to_ocsf_event(product_version) for node in self.nodes.values() if node.entity_type in finding_types]

    # ── Graph views (subgraphs) ──────────────────────────────────────────

    def inventory_view(self) -> UnifiedGraph:
        """Subgraph: all active inventory entities and static relationships."""
        return self._subgraph(
            node_filter=lambda n: n.status == NodeStatus.ACTIVE
            and n.entity_type
            not in (
                EntityType.VULNERABILITY,
                EntityType.MISCONFIGURATION,
            ),
            edge_filter=lambda e: e.relationship
            in (
                RelationshipType.HOSTS,
                RelationshipType.USES,
                RelationshipType.DEPENDS_ON,
                RelationshipType.PROVIDES_TOOL,
                RelationshipType.EXPOSES_CRED,
                RelationshipType.SERVES_MODEL,
                RelationshipType.CONTAINS,
            ),
        )

    def attack_path_view(self) -> UnifiedGraph:
        """Subgraph: vulnerability → package → server → agent → credential chains."""
        return self._subgraph(
            edge_filter=lambda e: e.traversable,
        )

    def lateral_movement_view(self) -> UnifiedGraph:
        """Subgraph: agent-to-agent reachability via shared resources."""
        lateral_rels = {
            RelationshipType.SHARES_SERVER,
            RelationshipType.SHARES_CRED,
            RelationshipType.LATERAL_PATH,
            RelationshipType.USES,
            RelationshipType.EXPOSES_CRED,
            RelationshipType.PROVIDES_TOOL,
            RelationshipType.VULNERABLE_TO,
        }
        return self._subgraph(
            edge_filter=lambda e: e.relationship in lateral_rels,
        )

    def compliance_view(self, framework: str = "") -> UnifiedGraph:
        """Subgraph: nodes with compliance tags (optionally filtered by framework)."""

        def node_filter(n: UnifiedNode) -> bool:
            if not n.compliance_tags:
                return False
            if framework:
                return any(framework.upper() in t.upper() for t in n.compliance_tags)
            return True

        return self._subgraph(node_filter=node_filter)

    def runtime_view(self) -> UnifiedGraph:
        """Subgraph: runtime event edges (invoked, accessed, delegated_to)."""
        runtime_rels = {
            RelationshipType.INVOKED,
            RelationshipType.ACCESSED,
            RelationshipType.DELEGATED_TO,
        }
        return self._subgraph(
            edge_filter=lambda e: e.relationship in runtime_rels,
        )

    def _subgraph(
        self,
        node_filter: Any = None,
        edge_filter: Any = None,
    ) -> UnifiedGraph:
        """Build a subgraph from filtered nodes and edges."""
        sub = UnifiedGraph(scan_id=self.scan_id, tenant_id=self.tenant_id, created_at=self.created_at)
        # If only edge filter, include all nodes referenced by matching edges
        if edge_filter and not node_filter:
            matching_edges = [e for e in self.edges if edge_filter(e)]
            referenced_ids = set()
            for e in matching_edges:
                referenced_ids.add(e.source)
                referenced_ids.add(e.target)
            for nid in referenced_ids:
                node = self.nodes.get(nid)
                if node:
                    sub.add_node(node)
            for e in matching_edges:
                sub.add_edge(e)
        elif node_filter:
            node_ids = set()
            for node in self.nodes.values():
                if node_filter(node):
                    sub.add_node(node)
                    node_ids.add(node.id)
            for edge in self.edges:
                if edge.source in node_ids and edge.target in node_ids:
                    if not edge_filter or edge_filter(edge):
                        sub.add_edge(edge)
        return sub


# ═══════════════════════════════════════════════════════════════════════════
# Backward-compatible aliases (for context_graph.py migration)
# ═══════════════════════════════════════════════════════════════════════════

# Map old NodeKind values → EntityType
_NODE_KIND_TO_ENTITY: dict[str, EntityType] = {
    "agent": EntityType.AGENT,
    "server": EntityType.SERVER,
    "credential": EntityType.CREDENTIAL,
    "tool": EntityType.TOOL,
    "vulnerability": EntityType.VULNERABILITY,
}

# Map old EdgeKind values → RelationshipType
_EDGE_KIND_TO_RELATIONSHIP: dict[str, RelationshipType] = {
    "uses": RelationshipType.USES,
    "exposes": RelationshipType.EXPOSES_CRED,
    "provides": RelationshipType.PROVIDES_TOOL,
    "vulnerable_to": RelationshipType.VULNERABLE_TO,
    "shares_server": RelationshipType.SHARES_SERVER,
    "shares_credential": RelationshipType.SHARES_CRED,
}


# ═══════════════════════════════════════════════════════════════════════════
# Helpers
# ═══════════════════════════════════════════════════════════════════════════


def _now_iso() -> str:
    """Current UTC time as ISO-8601 string."""
    from datetime import datetime, timezone

    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def severity_rank(sev: str) -> int:
    """Return numeric rank for a severity string. Higher = worse."""
    return SEVERITY_RANK.get(sev.lower() if sev else "", 0)


def severity_to_ocsf(sev: str) -> int:
    """Convert severity string to OCSF severity_id."""
    return SEVERITY_TO_OCSF.get(sev.lower() if sev else "", OCSFSeverity.UNKNOWN)


def ocsf_to_severity(severity_id: int) -> str:
    """Convert OCSF severity_id to lowercase severity string."""
    return OCSF_SEVERITY_NAMES.get(severity_id, "Unknown").lower()
