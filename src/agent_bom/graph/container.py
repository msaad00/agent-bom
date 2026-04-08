"""UnifiedGraph — the single graph container with traversal, filtering, and views."""

from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Any, Optional

from agent_bom.graph.edge import UnifiedEdge
from agent_bom.graph.node import UnifiedNode
from agent_bom.graph.ocsf import FINDING_ENTITY_TYPES
from agent_bom.graph.severity import SEVERITY_RANK
from agent_bom.graph.types import EntityType, NodeStatus, RelationshipType
from agent_bom.graph.util import _now_iso


@dataclass(slots=True)
class AttackPath:
    """Precomputed attack path between two nodes."""

    source: str
    target: str
    hops: list[str] = field(default_factory=list)
    edges: list[str] = field(default_factory=list)
    composite_risk: float = 0.0
    summary: str = ""
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

    pattern: str
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


@dataclass
class UnifiedGraph:
    """The canonical graph structure for agent-bom.

    Direction-aware: only bidirectional edges get reverse adjacency entries.
    """

    nodes: dict[str, UnifiedNode] = field(default_factory=dict)
    edges: list[UnifiedEdge] = field(default_factory=list)
    adjacency: dict[str, list[UnifiedEdge]] = field(default_factory=lambda: defaultdict(list))
    reverse_adjacency: dict[str, list[UnifiedEdge]] = field(default_factory=lambda: defaultdict(list))
    _edge_keys: set[tuple[str, str, str]] = field(default_factory=set, repr=False)

    attack_paths: list[AttackPath] = field(default_factory=list)
    interaction_risks: list[InteractionRisk] = field(default_factory=list)

    scan_id: str = ""
    tenant_id: str = ""
    created_at: str = ""

    def __post_init__(self) -> None:
        if not self.created_at:
            self.created_at = _now_iso()

    # ── Mutation ─────────────────────────────────────────────────────────

    def add_node(self, node: UnifiedNode) -> None:
        """Add or merge a node.  Cross-source metadata is unioned."""
        existing = self.nodes.get(node.id)
        if existing:
            existing.last_seen = node.last_seen or _now_iso()
            existing.attributes.update(node.attributes)
            # Severity: higher wins
            if SEVERITY_RANK.get(node.severity, 0) > SEVERITY_RANK.get(existing.severity, 0):
                existing.severity = node.severity
                existing.severity_id = node.severity_id
            # Risk score: higher wins
            if node.risk_score > existing.risk_score:
                existing.risk_score = node.risk_score
            # Union data_sources
            existing_sources = set(existing.data_sources)
            for ds in node.data_sources:
                if ds not in existing_sources:
                    existing.data_sources.append(ds)
                    existing_sources.add(ds)
            # Union compliance_tags
            existing_tags = set(existing.compliance_tags)
            for tag in node.compliance_tags:
                if tag not in existing_tags:
                    existing.compliance_tags.append(tag)
                    existing_tags.add(tag)
            # Merge dimensions (non-empty wins)
            existing.dimensions = existing.dimensions.merge(node.dimensions)
            return
        self.nodes[node.id] = node

    def add_edge(self, edge: UnifiedEdge) -> None:
        """Add an edge with O(1) deduplication.

        Reverse adjacency is ONLY added for bidirectional edges.
        Directed edges are one-way in the adjacency map.
        """
        rel = edge.relationship.value if isinstance(edge.relationship, RelationshipType) else str(edge.relationship)
        key = (edge.source, edge.target, rel)
        if key in self._edge_keys:
            return
        self._edge_keys.add(key)
        self.edges.append(edge)
        self.adjacency[edge.source].append(edge)
        # Reverse index: "what points at this node?" — always populated
        self.reverse_adjacency[edge.target].append(edge)
        # Forward adjacency for bidirectional edges (traversal both ways)
        if edge.is_bidirectional:
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
            self.reverse_adjacency[edge.source].append(reverse)

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

    # ── Reverse queries ("what points at X?") ────────────────────────────

    def edges_to(self, node_id: str) -> list[UnifiedEdge]:
        """All edges whose target is this node (O(1) via reverse index)."""
        return self.reverse_adjacency.get(node_id, [])

    def sources_of(self, node_id: str) -> list[str]:
        """All node IDs that have an edge pointing at this node."""
        return [e.source for e in self.reverse_adjacency.get(node_id, [])]

    def impact_of(self, node_id: str, max_depth: int = 4) -> dict:
        """Compute blast radius / impact stats for a node.

        Follows edges IN REVERSE: "what is affected by this node?"
        Uses reverse_adjacency for directed edges, forward adjacency
        for bidirectional edges.

        Returns:
            {
                "node_id": str,
                "affected_nodes": [str],
                "affected_by_type": {"agent": N, "server": N, ...},
                "affected_count": int,
                "max_depth_reached": int,
            }
        """
        if node_id not in self.nodes:
            return {"node_id": node_id, "affected_nodes": [], "affected_by_type": {}, "affected_count": 0, "max_depth_reached": 0}

        # BFS in reverse direction
        visited: set[str] = {node_id}
        queue: deque[tuple[str, int]] = deque([(node_id, 0)])
        max_depth_reached = 0

        while queue:
            current, depth = queue.popleft()
            if depth >= max_depth:
                continue
            # Follow reverse edges (who depends on / points to current?)
            for edge in self.reverse_adjacency.get(current, []):
                if edge.source not in visited:
                    visited.add(edge.source)
                    queue.append((edge.source, depth + 1))
                    max_depth_reached = max(max_depth_reached, depth + 1)

        visited.discard(node_id)
        by_type: dict[str, int] = defaultdict(int)
        for nid in visited:
            node = self.nodes.get(nid)
            if node:
                et = node.entity_type.value if isinstance(node.entity_type, EntityType) else node.entity_type
                by_type[et] += 1

        return {
            "node_id": node_id,
            "affected_nodes": sorted(visited),
            "affected_by_type": dict(by_type),
            "affected_count": len(visited),
            "max_depth_reached": max_depth_reached,
        }

    def search_nodes(self, query: str, limit: int = 50) -> list[UnifiedNode]:
        """Search nodes by label, attributes, or compliance tags.

        Case-insensitive substring match across label, entity_type,
        severity, data_sources, compliance_tags, and string attribute values.
        """
        q = query.lower()
        results: list[UnifiedNode] = []
        for node in self.nodes.values():
            if len(results) >= limit:
                break
            if q in node.label.lower():
                results.append(node)
                continue
            if q in (node.entity_type.value if isinstance(node.entity_type, EntityType) else node.entity_type):
                results.append(node)
                continue
            if q in node.severity.lower():
                results.append(node)
                continue
            if any(q in ds.lower() for ds in node.data_sources):
                results.append(node)
                continue
            if any(q in tag.lower() for tag in node.compliance_tags):
                results.append(node)
                continue
            if any(q in str(v).lower() for v in node.attributes.values() if isinstance(v, str)):
                results.append(node)
                continue
        return results

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
        static_only: bool = False,
        dynamic_only: bool = False,
    ) -> list[UnifiedEdge]:
        result: list[UnifiedEdge] = []
        for edge in self.edges:
            if relationships and edge.relationship not in relationships:
                continue
            if traversable_only and not edge.traversable:
                continue
            if edge.weight < min_weight:
                continue
            if static_only and edge.relationship in _DYNAMIC_RELS:
                continue
            if dynamic_only and edge.relationship not in _DYNAMIC_RELS:
                continue
            result.append(edge)
        return result

    # ── Traversal (direction-aware) ──────────────────────────────────────

    def bfs(
        self,
        source: str,
        max_depth: int = 4,
        traversable_only: bool = True,
    ) -> list[list[str]]:
        """BFS from source, respecting edge direction via adjacency map."""
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
        """BFS shortest path, direction-aware."""
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
        """All node IDs reachable from source, direction-aware."""
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
        if not self.nodes:
            return {}
        max_possible = max(len(self.nodes) - 1, 1)
        return {nid: len(self.adjacency.get(nid, [])) / max_possible for nid in self.nodes}

    def bottleneck_nodes(self, top_n: int = 5) -> list[tuple[str, float]]:
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

    # ── OCSF export (findings only) ──────────────────────────────────────

    def to_ocsf_events(self, product_version: str = "0.0.0", *, enrich_neighbors: bool = True) -> list[dict[str, Any]]:
        """Export finding-type nodes as OCSF events.

        When ``enrich_neighbors=True`` (default), each event includes a
        ``graph_context`` block with affected agents, servers, credentials,
        and attack path depth — so SOC analysts see blast radius in the SIEM
        without querying the graph API separately.
        """
        events = []
        for node in self.nodes.values():
            if node.entity_type not in FINDING_ENTITY_TYPES:
                continue
            event = node.to_ocsf_event(product_version)
            if enrich_neighbors:
                sources = self.sources_of(node.id)
                impact = self.impact_of(node.id)
                source_nodes = [self.nodes[s] for s in sources if s in self.nodes]
                event["graph_context"] = {
                    "affected_agents": [n.label for n in source_nodes if n.entity_type == EntityType.AGENT],
                    "affected_servers": [n.label for n in source_nodes if n.entity_type == EntityType.SERVER],
                    "affected_packages": [n.label for n in source_nodes if n.entity_type == EntityType.PACKAGE],
                    "exposed_credentials": [n.label for n in source_nodes if n.entity_type == EntityType.CREDENTIAL],
                    "blast_radius": impact["affected_count"],
                    "blast_by_type": impact["affected_by_type"],
                }
            events.append(event)
        return events

    # ── Graph views (subgraphs) ──────────────────────────────────────────

    def inventory_view(self) -> UnifiedGraph:
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
        return self._subgraph(edge_filter=lambda e: e.traversable)

    def lateral_movement_view(self) -> UnifiedGraph:
        lateral_rels = {
            RelationshipType.SHARES_SERVER,
            RelationshipType.SHARES_CRED,
            RelationshipType.LATERAL_PATH,
            RelationshipType.USES,
            RelationshipType.EXPOSES_CRED,
            RelationshipType.PROVIDES_TOOL,
            RelationshipType.VULNERABLE_TO,
        }
        return self._subgraph(edge_filter=lambda e: e.relationship in lateral_rels)

    def compliance_view(self, framework: str = "") -> UnifiedGraph:
        def node_filter(n: UnifiedNode) -> bool:
            if not n.compliance_tags:
                return False
            if framework:
                return any(framework.upper() in t.upper() for t in n.compliance_tags)
            return True

        return self._subgraph(node_filter=node_filter)

    def runtime_view(self) -> UnifiedGraph:
        runtime_rels = {
            RelationshipType.INVOKED,
            RelationshipType.ACCESSED,
            RelationshipType.DELEGATED_TO,
        }
        return self._subgraph(edge_filter=lambda e: e.relationship in runtime_rels)

    def filtered_view(self, filters: GraphFilterOptions) -> UnifiedGraph:
        """Build a subgraph from user-controlled filter options."""
        entity_set = filters.entity_types if filters.entity_types else None
        rel_set = filters.relationship_types if filters.relationship_types else None

        def node_filter(n: UnifiedNode) -> bool:
            if entity_set and n.entity_type not in entity_set:
                return False
            if filters.min_severity and SEVERITY_RANK.get(n.severity, 0) < SEVERITY_RANK.get(filters.min_severity, 0):
                return False
            if filters.include_ids and n.id not in filters.include_ids:
                return False
            if filters.exclude_ids and n.id in filters.exclude_ids:
                return False
            return True

        def edge_filter(e: UnifiedEdge) -> bool:
            if rel_set and e.relationship not in rel_set:
                return False
            if filters.static_only and e.relationship in _DYNAMIC_RELS:
                return False
            if filters.dynamic_only and e.relationship not in _DYNAMIC_RELS:
                return False
            return True

        return self._subgraph(node_filter=node_filter, edge_filter=edge_filter)

    def _subgraph(
        self,
        node_filter: Any = None,
        edge_filter: Any = None,
    ) -> UnifiedGraph:
        sub = UnifiedGraph(scan_id=self.scan_id, tenant_id=self.tenant_id, created_at=self.created_at)
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


# ── Dynamic relationship set ─────────────────────────────────────────────

_DYNAMIC_RELS = {RelationshipType.INVOKED, RelationshipType.ACCESSED, RelationshipType.DELEGATED_TO}


# ═══════════════════════════════════════════════════════════════════════════
# Graph filter options & legend
# ═══════════════════════════════════════════════════════════════════════════


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


@dataclass(slots=True)
class LegendEntry:
    """Single entry in the graph legend."""

    key: str
    label: str
    color: str
    shape: str = "circle"  # circle / diamond / square / triangle


# Entity legend
ENTITY_LEGEND: list[LegendEntry] = [
    LegendEntry(key="agent", label="AI Agent", color="#10b981", shape="circle"),
    LegendEntry(key="server", label="MCP Server", color="#3b82f6", shape="circle"),
    LegendEntry(key="package", label="Package", color="#52525b", shape="square"),
    LegendEntry(key="tool", label="Tool", color="#a855f7", shape="diamond"),
    LegendEntry(key="vulnerability", label="Vulnerability", color="#ef4444", shape="triangle"),
    LegendEntry(key="credential", label="Credential", color="#f59e0b", shape="diamond"),
    LegendEntry(key="misconfiguration", label="Misconfiguration", color="#f97316", shape="triangle"),
    LegendEntry(key="model", label="Model", color="#8b5cf6", shape="square"),
    LegendEntry(key="container", label="Container", color="#6366f1", shape="square"),
    LegendEntry(key="cloud_resource", label="Cloud Resource", color="#0ea5e9", shape="square"),
    LegendEntry(key="user", label="User", color="#14b8a6", shape="circle"),
    LegendEntry(key="group", label="Group", color="#0d9488", shape="circle"),
    LegendEntry(key="service_account", label="Service Account", color="#0f766e", shape="circle"),
    LegendEntry(key="fleet", label="Fleet", color="#6b7280", shape="square"),
    LegendEntry(key="cluster", label="Cluster", color="#4b5563", shape="square"),
    LegendEntry(key="dataset", label="Dataset", color="#06b6d4", shape="square"),
    LegendEntry(key="environment", label="Environment", color="#9ca3af", shape="square"),
    LegendEntry(key="provider", label="Provider", color="#d1d5db", shape="square"),
]

RELATIONSHIP_LEGEND: list[LegendEntry] = [
    # Static inventory
    LegendEntry(key="hosts", label="Hosts", color="#6b7280"),
    LegendEntry(key="uses", label="Uses", color="#10b981"),
    LegendEntry(key="depends_on", label="Depends On", color="#52525b"),
    LegendEntry(key="provides_tool", label="Provides Tool", color="#a855f7"),
    LegendEntry(key="exposes_cred", label="Exposes Credential", color="#f59e0b"),
    LegendEntry(key="serves_model", label="Serves Model", color="#8b5cf6"),
    LegendEntry(key="contains", label="Contains", color="#6366f1"),
    # Vulnerability
    LegendEntry(key="vulnerable_to", label="Vulnerable To", color="#ef4444"),
    LegendEntry(key="affects", label="Affects", color="#dc2626"),
    LegendEntry(key="exploitable_via", label="Exploitable Via", color="#b91c1c"),
    LegendEntry(key="remediates", label="Remediates", color="#22c55e"),
    LegendEntry(key="triggers", label="Triggers", color="#f97316"),
    # Lateral movement
    LegendEntry(key="shares_server", label="Shares Server", color="#22d3ee"),
    LegendEntry(key="shares_cred", label="Shares Credential", color="#f97316"),
    LegendEntry(key="lateral_path", label="Lateral Path", color="#ea580c"),
    # Ownership
    LegendEntry(key="manages", label="Manages", color="#14b8a6"),
    LegendEntry(key="owns", label="Owns", color="#0d9488"),
    LegendEntry(key="part_of", label="Part Of", color="#6b7280"),
    LegendEntry(key="member_of", label="Member Of", color="#4b5563"),
    # Runtime
    LegendEntry(key="invoked", label="Invoked (runtime)", color="#10b981"),
    LegendEntry(key="accessed", label="Accessed (runtime)", color="#3b82f6"),
    LegendEntry(key="delegated_to", label="Delegated To (runtime)", color="#a855f7"),
]
