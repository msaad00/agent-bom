"""Estate-scale graph roll-up — collapse the CONTAINS hierarchy into a small,
readable top-level view with on-demand drill-down.

Past a few hundred nodes the raw topology graph is an unreadable hairball. The
estate is, however, organised as a containment tree (``CONTAINS`` edges:
org → account/folder/project → app → resource). This module rolls the graph up
along that tree so a 1000+ node estate renders as a handful of top-level
container nodes, each carrying aggregate child counts, worst-severity, a
per-severity histogram, and exposure / toxic-combination flags propagated from
every descendant. The UI then drills down one level at a time
(:func:`drill_down`) instead of loading everything at once.

Everything here is a *pure read* over an existing :class:`UnifiedGraph`:
deterministic (sorted, stable ordering), bounded, and side-effect free — the
source graph is never mutated. This is the backend that the UI graph-navigation
follow-up consumes.
"""

from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Any, Optional

from agent_bom.graph.container import UnifiedGraph
from agent_bom.graph.node import UnifiedNode
from agent_bom.graph.severity import OCSF_SEVERITY_NAMES, SEVERITY_RANK
from agent_bom.graph.types import EntityType, RelationshipType

# Severity buckets reported in every roll-up histogram, worst → least.
_SEVERITY_ORDER: tuple[str, ...] = ("critical", "high", "medium", "low", "info", "none")

# Container entity types form the readable top-level scaffold of the estate.
# A node of one of these types is a candidate roll-up container; everything else
# is a leaf that aggregates into its nearest container ancestor.
_CONTAINER_TYPES: frozenset[str] = frozenset(
    {
        EntityType.ORG.value,
        EntityType.ACCOUNT.value,
        EntityType.PROVIDER.value,
        EntityType.ENVIRONMENT.value,
        EntityType.FLEET.value,
        EntityType.CLUSTER.value,
        EntityType.APPLICATION.value,
        EntityType.SERVER.value,
        EntityType.CONTAINER.value,
        EntityType.CLOUD_RESOURCE.value,
        # A directory is a CODE-layer container: the repo folder tree collapses
        # along its CONTAINS edges (repo root → sub-directory → file) exactly the
        # way the cloud org → account → resource hierarchy does, so a deep
        # source tree renders as a handful of top-level folders with drill-down.
        EntityType.DIRECTORY.value,
    }
)

# Attributes that mark a node (or a descendant rolled up into a container) as
# internet-exposed. Any one being truthy flags the container as exposed.
_EXPOSED_ATTRS: tuple[str, ...] = (
    "internet_exposed",
    "toxic_exposed_vulnerable",
    "toxic_exposed_sensitive",
)

# Attributes that mark a node as part of a toxic combination (stacked risk).
_TOXIC_ATTRS: tuple[str, ...] = (
    "toxic_exposed_vulnerable",
    "toxic_exposed_sensitive",
)


def _node_type_value(node: UnifiedNode) -> str:
    return node.entity_type.value if isinstance(node.entity_type, EntityType) else str(node.entity_type)


def _severity_bucket(node: UnifiedNode) -> str:
    sev = (node.severity or "").lower()
    if sev in {"informational"}:
        return "info"
    if sev in _SEVERITY_ORDER:
        return sev
    return "none"


def _is_exposed(node: UnifiedNode) -> bool:
    attrs = node.attributes or {}
    return any(bool(attrs.get(key)) for key in _EXPOSED_ATTRS)


def _is_toxic(node: UnifiedNode) -> bool:
    attrs = node.attributes or {}
    return any(bool(attrs.get(key)) for key in _TOXIC_ATTRS)


@dataclass(slots=True)
class RollupAggregate:
    """Aggregate risk facts rolled up from a container's descendants."""

    descendant_count: int = 0
    by_type: dict[str, int] = field(default_factory=dict)
    severity_counts: dict[str, int] = field(default_factory=dict)
    worst_severity: str = "none"
    worst_severity_rank: int = 0
    internet_exposed: bool = False
    toxic_combo: bool = False
    exposed_count: int = 0
    toxic_count: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "descendant_count": self.descendant_count,
            "by_type": dict(sorted(self.by_type.items())),
            "severity_counts": {sev: self.severity_counts.get(sev, 0) for sev in _SEVERITY_ORDER},
            "worst_severity": self.worst_severity,
            "worst_severity_rank": self.worst_severity_rank,
            "internet_exposed": self.internet_exposed,
            "toxic_combo": self.toxic_combo,
            "exposed_count": self.exposed_count,
            "toxic_count": self.toxic_count,
        }


@dataclass(slots=True)
class RollupContainer:
    """A top-level (or drilled-into) container node carrying its roll-up."""

    id: str
    label: str
    entity_type: str
    severity: str
    is_container: bool
    has_children: bool
    direct_child_count: int
    aggregate: RollupAggregate

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "label": self.label,
            "entity_type": self.entity_type,
            "severity": self.severity,
            "is_container": self.is_container,
            "has_children": self.has_children,
            "direct_child_count": self.direct_child_count,
            "aggregate": self.aggregate.to_dict(),
        }


@dataclass(slots=True)
class RollupFilters:
    """Optional pre-roll-up filters that focus the view on risk.

    Filters are applied to *descendants* before aggregation: a container is kept
    if any descendant survives the filter (so risk is never hidden behind an
    empty container), and its aggregates count only the surviving descendants.
    """

    min_severity: str = ""
    exposed_only: bool = False
    toxic_only: bool = False

    def active(self) -> bool:
        return bool(self.min_severity) or self.exposed_only or self.toxic_only

    def matches(self, node: UnifiedNode) -> bool:
        if self.min_severity:
            min_rank = SEVERITY_RANK.get(self.min_severity.lower(), 0)
            if SEVERITY_RANK.get((node.severity or "").lower(), 0) < min_rank:
                return False
        if self.exposed_only and not _is_exposed(node):
            return False
        if self.toxic_only and not _is_toxic(node):
            return False
        return True


def _contains_children(graph: UnifiedGraph) -> dict[str, list[str]]:
    """Map container_id -> sorted direct CONTAINS children (deterministic).

    Self-loops are ignored. Children are de-duplicated and sorted by id so the
    output is stable across runs regardless of edge insertion order.
    """
    children: dict[str, set[str]] = defaultdict(set)
    for edge in graph.edges:
        rel = edge.relationship.value if isinstance(edge.relationship, RelationshipType) else str(edge.relationship)
        if rel != RelationshipType.CONTAINS.value:
            continue
        if edge.source == edge.target:
            continue
        if edge.source not in graph.nodes or edge.target not in graph.nodes:
            continue
        children[edge.source].add(edge.target)
    return {parent: sorted(kids) for parent, kids in children.items()}


def _contains_parents(children: dict[str, list[str]]) -> dict[str, set[str]]:
    parents: dict[str, set[str]] = defaultdict(set)
    for parent, kids in children.items():
        for kid in kids:
            parents[kid].add(parent)
    return parents


def _roots(graph: UnifiedGraph, children: dict[str, list[str]], parents: dict[str, set[str]]) -> list[str]:
    """Top-level CONTAINS roots: nodes with children but no CONTAINS parent.

    Cycle-safe: if every node in a CONTAINS cycle has a parent (so there is no
    natural root), the lowest-id member is promoted to a root so the component
    still renders rather than vanishing.
    """
    roots = [nid for nid in children if not parents.get(nid)]
    if roots:
        return sorted(roots)
    # Degenerate: containment forms cycles with no acyclic root. Promote the
    # lowest-id container so the estate still has a stable entry point.
    if children:
        return [min(children)]
    return []


def _descendants(root: str, children: dict[str, list[str]]) -> list[str]:
    """All transitive CONTAINS descendants of *root* (excludes root). Bounded by
    a visited set so cycles terminate; returned sorted for determinism."""
    seen: set[str] = set()
    queue: deque[str] = deque(children.get(root, []))
    while queue:
        current = queue.popleft()
        if current in seen or current == root:
            continue
        seen.add(current)
        for kid in children.get(current, []):
            if kid not in seen:
                queue.append(kid)
    return sorted(seen)


def _aggregate(
    descendant_ids: list[str],
    graph: UnifiedGraph,
    *,
    filters: Optional[RollupFilters] = None,
) -> RollupAggregate:
    agg = RollupAggregate()
    severity_counts: dict[str, int] = defaultdict(int)
    by_type: dict[str, int] = defaultdict(int)
    for nid in descendant_ids:
        node = graph.nodes.get(nid)
        if node is None:
            continue
        if filters is not None and filters.active() and not filters.matches(node):
            continue
        agg.descendant_count += 1
        by_type[_node_type_value(node)] += 1
        bucket = _severity_bucket(node)
        severity_counts[bucket] += 1
        rank = SEVERITY_RANK.get((node.severity or "").lower(), 0)
        if rank > agg.worst_severity_rank:
            agg.worst_severity_rank = rank
            agg.worst_severity = bucket
        if _is_exposed(node):
            agg.internet_exposed = True
            agg.exposed_count += 1
        if _is_toxic(node):
            agg.toxic_combo = True
            agg.toxic_count += 1
    agg.by_type = dict(by_type)
    agg.severity_counts = dict(severity_counts)
    return agg


def _container_for(node: UnifiedNode, child_map: dict[str, list[str]]) -> bool:
    return _node_type_value(node) in _CONTAINER_TYPES or bool(child_map.get(node.id))


def rollup_view(
    graph: UnifiedGraph,
    *,
    filters: Optional[RollupFilters] = None,
) -> dict[str, Any]:
    """Collapse the graph along CONTAINS into a small top-level container view.

    Returns top-level container roots, each carrying aggregate descendant
    counts, worst-severity, a per-severity histogram, and exposure / toxic
    flags rolled up from every descendant. An estate of thousands of nodes
    renders as a handful of account / app containers.

    Deterministic and bounded; the source graph is never mutated.
    """
    children = _contains_children(graph)
    parents = _contains_parents(children)
    root_ids = _roots(graph, children, parents)

    containers: list[RollupContainer] = []
    rolled_up_ids: set[str] = set()
    for root_id in root_ids:
        node = graph.nodes.get(root_id)
        if node is None:
            continue
        descendants = _descendants(root_id, children)
        agg = _aggregate(descendants, graph, filters=filters)
        # When filters are active, drop containers whose descendants were all
        # filtered out — they carry no risk worth surfacing.
        if filters is not None and filters.active() and agg.descendant_count == 0 and not (filters.matches(node)):
            continue
        direct = children.get(root_id, [])
        containers.append(
            RollupContainer(
                id=node.id,
                label=node.label,
                entity_type=_node_type_value(node),
                severity=node.severity or "",
                is_container=True,
                has_children=bool(direct),
                direct_child_count=len(direct),
                aggregate=agg,
            )
        )
        rolled_up_ids.add(root_id)
        rolled_up_ids.update(descendants)

    # Nodes outside any CONTAINS tree (orphans / flat estates) are surfaced as
    # their own single-node entries so nothing silently disappears from the view.
    orphans: list[RollupContainer] = []
    for nid in sorted(graph.nodes):
        if nid in rolled_up_ids:
            continue
        node = graph.nodes[nid]
        if filters is not None and filters.active() and not filters.matches(node):
            continue
        orphans.append(
            RollupContainer(
                id=node.id,
                label=node.label,
                entity_type=_node_type_value(node),
                severity=node.severity or "",
                is_container=_container_for(node, children),
                has_children=bool(children.get(nid)),
                direct_child_count=len(children.get(nid, [])),
                aggregate=_aggregate(_descendants(nid, children), graph, filters=filters),
            )
        )

    top_level = containers + orphans
    top_level.sort(key=lambda c: (-c.aggregate.worst_severity_rank, -c.aggregate.descendant_count, c.id))

    return {
        "scan_id": graph.scan_id,
        "tenant_id": graph.tenant_id,
        "created_at": graph.created_at,
        "mode": "rollup",
        "filters": _filters_dict(filters),
        "top_level": [c.to_dict() for c in top_level],
        "summary": {
            "total_nodes": len(graph.nodes),
            "total_edges": len(graph.edges),
            "top_level_count": len(top_level),
            "container_count": len(containers),
            "orphan_count": len(orphans),
        },
    }


def drill_down(
    graph: UnifiedGraph,
    node_id: str,
    *,
    filters: Optional[RollupFilters] = None,
) -> dict[str, Any]:
    """Return one level of direct CONTAINS children of *node_id*.

    Each child carries its own roll-up so the UI can keep expanding on demand.
    O(direct children); never loads the whole graph.
    """
    if node_id not in graph.nodes:
        return {
            "scan_id": graph.scan_id,
            "tenant_id": graph.tenant_id,
            "created_at": graph.created_at,
            "mode": "drilldown",
            "node": None,
            "filters": _filters_dict(filters),
            "children": [],
            "summary": {"direct_child_count": 0, "returned_child_count": 0},
        }

    children = _contains_children(graph)
    direct = children.get(node_id, [])
    parent = graph.nodes[node_id]

    child_entries: list[RollupContainer] = []
    for child_id in direct:
        child = graph.nodes.get(child_id)
        if child is None:
            continue
        descendants = _descendants(child_id, children)
        agg = _aggregate(descendants, graph, filters=filters)
        if filters is not None and filters.active() and agg.descendant_count == 0 and not filters.matches(child):
            continue
        child_entries.append(
            RollupContainer(
                id=child.id,
                label=child.label,
                entity_type=_node_type_value(child),
                severity=child.severity or "",
                is_container=_container_for(child, children),
                has_children=bool(children.get(child_id)),
                direct_child_count=len(children.get(child_id, [])),
                aggregate=agg,
            )
        )

    child_entries.sort(key=lambda c: (-c.aggregate.worst_severity_rank, -c.aggregate.descendant_count, c.id))

    return {
        "scan_id": graph.scan_id,
        "tenant_id": graph.tenant_id,
        "created_at": graph.created_at,
        "mode": "drilldown",
        "node": {
            "id": parent.id,
            "label": parent.label,
            "entity_type": _node_type_value(parent),
            "severity": parent.severity or "",
        },
        "filters": _filters_dict(filters),
        "children": [c.to_dict() for c in child_entries],
        "summary": {
            "direct_child_count": len(direct),
            "returned_child_count": len(child_entries),
        },
    }


def attack_path_view(
    graph: UnifiedGraph,
    attack_paths: list[Any],
    *,
    filters: Optional[RollupFilters] = None,
    max_paths: int = 50,
) -> dict[str, Any]:
    """Attack-path-first readable view: the nodes/edges on materialised attack
    paths up front (the "what matters" view), with everything else collapsed
    into a small CONTAINS roll-up.

    *attack_paths* is the list of path-like objects (each exposing ``hops`` and
    ``edges``) the caller already materialised — this function does not derive
    paths, it only assembles the readable view around them.
    """
    ranked = sorted(
        attack_paths,
        key=lambda p: (getattr(p, "composite_risk", 0.0), len(getattr(p, "hops", []))),
        reverse=True,
    )[: max(0, max_paths)]

    path_node_ids: list[str] = []
    seen_nodes: set[str] = set()
    for path in ranked:
        for hop in getattr(path, "hops", []):
            if hop in graph.nodes and hop not in seen_nodes:
                seen_nodes.add(hop)
                path_node_ids.append(hop)

    # Edges between any two on-path nodes (the readable subgraph the paths walk).
    path_edges: list[dict[str, Any]] = []
    seen_edge_keys: set[tuple[str, str, str]] = set()
    for edge in graph.edges:
        if edge.source in seen_nodes and edge.target in seen_nodes:
            rel = edge.relationship.value if isinstance(edge.relationship, RelationshipType) else str(edge.relationship)
            key = (edge.source, edge.target, rel)
            if key in seen_edge_keys:
                continue
            seen_edge_keys.add(key)
            path_edges.append(edge.to_dict())
    path_edges.sort(key=lambda e: (e["source"], e["target"], e["relationship"]))

    path_nodes = [graph.nodes[nid].to_dict() for nid in path_node_ids]

    # Everything not on a path is collapsed into the standard CONTAINS roll-up so
    # the operator still has the estate context, just not the hairball.
    collapsed = rollup_view(graph, filters=filters)["top_level"]
    collapsed_off_path = [c for c in collapsed if c["id"] not in seen_nodes]

    paths_payload = [_attack_path_summary(path) for path in ranked]

    return {
        "scan_id": graph.scan_id,
        "tenant_id": graph.tenant_id,
        "created_at": graph.created_at,
        "mode": "attack_path",
        "filters": _filters_dict(filters),
        "attack_paths": paths_payload,
        "path_nodes": path_nodes,
        "path_edges": path_edges,
        "collapsed": collapsed_off_path,
        "summary": {
            "total_nodes": len(graph.nodes),
            "path_count": len(paths_payload),
            "path_node_count": len(path_nodes),
            "path_edge_count": len(path_edges),
            "collapsed_count": len(collapsed_off_path),
        },
    }


def _attack_path_summary(path: Any) -> dict[str, Any]:
    return {
        "source": getattr(path, "source", ""),
        "target": getattr(path, "target", ""),
        "hops": list(getattr(path, "hops", [])),
        "composite_risk": getattr(path, "composite_risk", 0.0),
        "summary": getattr(path, "summary", ""),
    }


def _filters_dict(filters: Optional[RollupFilters]) -> dict[str, Any]:
    if filters is None:
        return {"min_severity": "", "exposed_only": False, "toxic_only": False}
    return {
        "min_severity": filters.min_severity,
        "exposed_only": filters.exposed_only,
        "toxic_only": filters.toxic_only,
    }


# Re-exported for callers that want the OCSF display name of a rolled-up bucket.
__all__ = [
    "RollupAggregate",
    "RollupContainer",
    "RollupFilters",
    "attack_path_view",
    "drill_down",
    "rollup_view",
    "OCSF_SEVERITY_NAMES",
]
