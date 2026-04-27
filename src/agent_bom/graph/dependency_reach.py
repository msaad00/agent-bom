"""Graph-walk dependency reachability engine.

Closes #1896. The blast-radius scoring before this module gave every CVE
the same prominence whether the vulnerable package was a direct
import of a runtime entrypoint or three hops down a dependency tree
that no live code exercises. Operators with thousands of findings need
to triage the *reachable* CVEs first; the lockfile alone cannot tell
them which is which.

This engine answers two questions for every vulnerability node in the
unified graph:

1. **Is it reachable from any agent entrypoint?** — boolean. ``False``
   means the package sits in the dependency closure of an agent's MCP
   server but no traversal of ``USES`` → ``DEPENDS_ON`` edges connects
   the agent to that package. (In practice this is rare given how the
   builder wires edges, so it works as a structural sanity gate.)
2. **What is the shortest reach distance?** — integer hop count from
   the closest agent. ``1`` means an agent's own MCP server depends on
   the vulnerable package directly; higher values are deeper transitive
   dependencies. The smaller the distance, the more directly the agent
   is exposed.

The result is a ``VulnerabilityReachability`` per vulnerability node
plus a per-package summary the report layer can join into the existing
blast-radius rows. The walker is purely a read-side function — no graph
mutation — so it is safe to call from the API, the CLI, or a snapshot
re-analysis pipeline.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass

from agent_bom.graph.container import UnifiedGraph
from agent_bom.graph.edge import UnifiedEdge
from agent_bom.graph.types import EntityType, RelationshipType

# Edges the walker is allowed to follow when expanding from an agent
# toward its dependency closure. Anything else (vuln edges, runtime
# events, lateral movement) would inflate reach with paths that are
# not "this agent depends on that code".
_REACH_EDGE_TYPES: frozenset[RelationshipType] = frozenset(
    {
        RelationshipType.USES,
        RelationshipType.DEPENDS_ON,
        RelationshipType.CONTAINS,
        RelationshipType.PROVIDES_TOOL,
    }
)

# Edges that connect a vulnerability to its affected package.
_VULN_TO_PACKAGE_EDGE_TYPES: frozenset[RelationshipType] = frozenset(
    {
        RelationshipType.AFFECTS,
        RelationshipType.VULNERABLE_TO,
    }
)


@dataclass(frozen=True)
class PackageReachability:
    """Reach information for a single package node."""

    package_id: str
    reachable_from: tuple[str, ...]
    """Agent node ids whose dependency closure includes this package."""

    min_hop_distance: int
    """Smallest number of edges from any reaching agent. ``0`` when no agent reaches the package."""

    @property
    def reachable(self) -> bool:
        return bool(self.reachable_from)


@dataclass(frozen=True)
class VulnerabilityReachability:
    """Reach information for a vulnerability node, derived from its packages."""

    vulnerability_id: str
    package_ids: tuple[str, ...]
    """Package nodes the vulnerability is attached to."""

    reachable_from: tuple[str, ...]
    """Agent node ids that reach at least one affected package."""

    min_hop_distance: int
    """Smallest hop distance to any affected package. ``0`` when unreachable."""

    @property
    def reachable(self) -> bool:
        return bool(self.reachable_from)


@dataclass(frozen=True)
class ReachabilityReport:
    """Complete reachability analysis for one graph."""

    packages: dict[str, PackageReachability]
    vulnerabilities: dict[str, VulnerabilityReachability]

    @property
    def reachable_vulnerability_ids(self) -> tuple[str, ...]:
        return tuple(sorted(v.vulnerability_id for v in self.vulnerabilities.values() if v.reachable))


def compute_dependency_reach(graph: UnifiedGraph) -> ReachabilityReport:
    """Walk the graph from every agent entrypoint and compute reachability.

    Two-pass BFS:
      1. From each agent node, BFS along ``_REACH_EDGE_TYPES`` and record
         the minimum hop distance per package node it can reach.
      2. For every vulnerability node, look at the packages it is bound
         to via ``AFFECTS`` / ``VULNERABLE_TO`` and surface the union of
         reaching agents plus the smallest hop count across them.
    """
    package_reach: dict[str, dict[str, int]] = {}

    agent_ids = [node.id for node in graph.nodes_by_type(EntityType.AGENT)]
    for agent_id in agent_ids:
        for node_id, hops in _bfs_distances_along(graph, agent_id, _REACH_EDGE_TYPES).items():
            target = graph.get_node(node_id)
            if target is None or target.entity_type is not EntityType.PACKAGE:
                continue
            current = package_reach.setdefault(node_id, {})
            existing = current.get(agent_id)
            if existing is None or hops < existing:
                current[agent_id] = hops

    packages: dict[str, PackageReachability] = {}
    for node in graph.nodes_by_type(EntityType.PACKAGE):
        reach_map = package_reach.get(node.id, {})
        if reach_map:
            sorted_agents = tuple(sorted(reach_map))
            min_hops = min(reach_map.values())
        else:
            sorted_agents = ()
            min_hops = 0
        packages[node.id] = PackageReachability(
            package_id=node.id,
            reachable_from=sorted_agents,
            min_hop_distance=min_hops,
        )

    vulnerabilities: dict[str, VulnerabilityReachability] = {}
    for node in graph.nodes_by_type(EntityType.VULNERABILITY):
        affected_packages = _vulnerability_packages(graph, node.id)
        agents_reaching: set[str] = set()
        best_hops: int | None = None
        for pkg_id in affected_packages:
            pkg_info = packages.get(pkg_id)
            if pkg_info is None or not pkg_info.reachable:
                continue
            agents_reaching.update(pkg_info.reachable_from)
            if best_hops is None or pkg_info.min_hop_distance < best_hops:
                best_hops = pkg_info.min_hop_distance
        vulnerabilities[node.id] = VulnerabilityReachability(
            vulnerability_id=node.id,
            package_ids=tuple(sorted(affected_packages)),
            reachable_from=tuple(sorted(agents_reaching)),
            min_hop_distance=best_hops if best_hops is not None else 0,
        )

    return ReachabilityReport(packages=packages, vulnerabilities=vulnerabilities)


def _bfs_distances_along(
    graph: UnifiedGraph,
    start_id: str,
    allowed_relationships: frozenset[RelationshipType],
) -> dict[str, int]:
    """Return ``{node_id: min_hop_distance}`` reachable from start_id.

    Walks only edges whose relationship is in ``allowed_relationships``.
    Honors edge direction: bidirectional edges are stored under both
    endpoints' adjacency lists already, so a simple forward BFS is
    enough.
    """
    distances: dict[str, int] = {start_id: 0}
    queue: deque[str] = deque([start_id])
    while queue:
        current_id = queue.popleft()
        current_dist = distances[current_id]
        edges: list[UnifiedEdge] = graph.adjacency.get(current_id, [])
        for edge in edges:
            if edge.relationship not in allowed_relationships:
                continue
            # The forward index already includes bidirectional reversals,
            # so the "next hop" is simply the edge target as the engine
            # sees it from this side.
            neighbour = edge.target if edge.source == current_id else edge.source
            if neighbour in distances:
                continue
            distances[neighbour] = current_dist + 1
            queue.append(neighbour)
    return distances


def _vulnerability_packages(graph: UnifiedGraph, vuln_id: str) -> set[str]:
    """Return package node ids that this vulnerability is attached to."""
    out: set[str] = set()
    for edge in graph.adjacency.get(vuln_id, []):
        if edge.relationship not in _VULN_TO_PACKAGE_EDGE_TYPES:
            continue
        other = edge.target if edge.source == vuln_id else edge.source
        node = graph.get_node(other)
        if node is None or node.entity_type is not EntityType.PACKAGE:
            continue
        out.add(other)
    for edge in graph.reverse_adjacency.get(vuln_id, []):
        if edge.relationship not in _VULN_TO_PACKAGE_EDGE_TYPES:
            continue
        other = edge.source if edge.target == vuln_id else edge.target
        node = graph.get_node(other)
        if node is None or node.entity_type is not EntityType.PACKAGE:
            continue
        out.add(other)
    return out
