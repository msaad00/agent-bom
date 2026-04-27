"""Graph-walk dependency reachability tests (#1896).

Locks the engine's reach math so a future graph-builder change can't
silently invert which CVEs are flagged as reachable. Each test builds
a small UnifiedGraph by hand — no scan-report shape to debug, no
network — so failures point straight at the walker logic.
"""

from __future__ import annotations

from agent_bom.graph.container import UnifiedGraph
from agent_bom.graph.dependency_reach import compute_dependency_reach
from agent_bom.graph.edge import UnifiedEdge
from agent_bom.graph.node import UnifiedNode
from agent_bom.graph.types import EntityType, RelationshipType


def _node(node_id: str, entity_type: EntityType, label: str | None = None) -> UnifiedNode:
    return UnifiedNode(id=node_id, entity_type=entity_type, label=label or node_id)


def _edge(src: str, dst: str, relationship: RelationshipType) -> UnifiedEdge:
    return UnifiedEdge(source=src, target=dst, relationship=relationship)


def _build_chain_graph() -> UnifiedGraph:
    """agent → server → package(direct) → package(transitive) ← vuln."""
    g = UnifiedGraph(scan_id="chain", tenant_id="t1")
    g.add_node(_node("agent:cursor", EntityType.AGENT))
    g.add_node(_node("server:mcp-fs", EntityType.SERVER))
    g.add_node(_node("pkg:direct@1.0", EntityType.PACKAGE))
    g.add_node(_node("pkg:transitive@2.0", EntityType.PACKAGE))
    g.add_node(_node("vuln:CVE-2026-0001", EntityType.VULNERABILITY))

    g.add_edge(_edge("agent:cursor", "server:mcp-fs", RelationshipType.USES))
    g.add_edge(_edge("server:mcp-fs", "pkg:direct@1.0", RelationshipType.DEPENDS_ON))
    g.add_edge(_edge("pkg:direct@1.0", "pkg:transitive@2.0", RelationshipType.DEPENDS_ON))
    g.add_edge(_edge("pkg:transitive@2.0", "vuln:CVE-2026-0001", RelationshipType.VULNERABLE_TO))
    return g


def test_direct_dependency_is_reachable_at_distance_two() -> None:
    g = _build_chain_graph()

    report = compute_dependency_reach(g)
    direct = report.packages["pkg:direct@1.0"]

    # agent → server (1 hop) → pkg (1 hop) = 2 hops total.
    assert direct.reachable
    assert direct.reachable_from == ("agent:cursor",)
    assert direct.min_hop_distance == 2


def test_transitive_dependency_keeps_climbing_distance() -> None:
    g = _build_chain_graph()

    report = compute_dependency_reach(g)
    transitive = report.packages["pkg:transitive@2.0"]

    assert transitive.reachable
    assert transitive.min_hop_distance == 3


def test_vulnerability_reach_picks_smallest_package_distance() -> None:
    g = _build_chain_graph()
    # Add an unrelated agent that depends directly on the transitive
    # package — its distance to the vulnerable package is shorter.
    g.add_node(_node("agent:claude", EntityType.AGENT))
    g.add_node(_node("server:other", EntityType.SERVER))
    g.add_edge(_edge("agent:claude", "server:other", RelationshipType.USES))
    g.add_edge(_edge("server:other", "pkg:transitive@2.0", RelationshipType.DEPENDS_ON))

    report = compute_dependency_reach(g)
    vuln = report.vulnerabilities["vuln:CVE-2026-0001"]

    assert vuln.reachable
    # Minimum reach is the closer route: agent:claude → server → pkg = 2.
    assert vuln.min_hop_distance == 2
    assert set(vuln.reachable_from) == {"agent:cursor", "agent:claude"}


def test_island_vulnerability_is_not_reachable() -> None:
    """A vulnerability on an orphan package — no agent owns it."""
    g = UnifiedGraph(scan_id="island", tenant_id="t1")
    g.add_node(_node("agent:cursor", EntityType.AGENT))
    g.add_node(_node("pkg:orphan@1", EntityType.PACKAGE))
    g.add_node(_node("vuln:CVE-2026-9999", EntityType.VULNERABILITY))
    # No USES / DEPENDS_ON edge from agent reaches pkg:orphan.
    g.add_edge(_edge("pkg:orphan@1", "vuln:CVE-2026-9999", RelationshipType.VULNERABLE_TO))

    report = compute_dependency_reach(g)
    pkg = report.packages["pkg:orphan@1"]
    vuln = report.vulnerabilities["vuln:CVE-2026-9999"]

    assert not pkg.reachable
    assert pkg.reachable_from == ()
    assert pkg.min_hop_distance == 0
    assert not vuln.reachable
    assert vuln.reachable_from == ()


def test_vuln_attached_via_affects_edge_is_recognized() -> None:
    """``AFFECTS`` (vuln → package) and ``VULNERABLE_TO`` (package → vuln)
    are both valid attachments. The walker must accept either direction
    so an upstream vendor's directional convention does not mask reach."""
    g = UnifiedGraph(scan_id="affects", tenant_id="t1")
    g.add_node(_node("agent:cursor", EntityType.AGENT))
    g.add_node(_node("server:mcp", EntityType.SERVER))
    g.add_node(_node("pkg:p", EntityType.PACKAGE))
    g.add_node(_node("vuln:CVE-2026-1234", EntityType.VULNERABILITY))
    g.add_edge(_edge("agent:cursor", "server:mcp", RelationshipType.USES))
    g.add_edge(_edge("server:mcp", "pkg:p", RelationshipType.DEPENDS_ON))
    g.add_edge(_edge("vuln:CVE-2026-1234", "pkg:p", RelationshipType.AFFECTS))

    report = compute_dependency_reach(g)
    vuln = report.vulnerabilities["vuln:CVE-2026-1234"]

    assert vuln.reachable
    assert vuln.min_hop_distance == 2


def test_vulnerability_with_no_packages_is_unreachable() -> None:
    """A vulnerability node with no AFFECTS / VULNERABLE_TO edge is structurally
    detached and cannot be reached, regardless of agents present."""
    g = UnifiedGraph(scan_id="dangling", tenant_id="t1")
    g.add_node(_node("agent:cursor", EntityType.AGENT))
    g.add_node(_node("vuln:CVE-2026-0042", EntityType.VULNERABILITY))

    report = compute_dependency_reach(g)
    vuln = report.vulnerabilities["vuln:CVE-2026-0042"]

    assert vuln.package_ids == ()
    assert not vuln.reachable
    assert vuln.min_hop_distance == 0


def test_reachable_vulnerability_ids_summary_is_sorted() -> None:
    g = _build_chain_graph()
    g.add_node(_node("vuln:CVE-2026-0002", EntityType.VULNERABILITY))
    g.add_edge(_edge("pkg:direct@1.0", "vuln:CVE-2026-0002", RelationshipType.VULNERABLE_TO))

    report = compute_dependency_reach(g)

    assert report.reachable_vulnerability_ids == ("vuln:CVE-2026-0001", "vuln:CVE-2026-0002")


def test_walker_does_not_traverse_runtime_or_lateral_edges() -> None:
    """Only DEPENDS_ON / USES / CONTAINS / PROVIDES_TOOL count as
    structural reach. Runtime INVOKED / SHARES_SERVER edges are
    different concerns and must not inflate reach distance."""
    g = UnifiedGraph(scan_id="lateral", tenant_id="t1")
    g.add_node(_node("agent:a", EntityType.AGENT))
    g.add_node(_node("agent:b", EntityType.AGENT))
    g.add_node(_node("pkg:lateral@1", EntityType.PACKAGE))
    # agent:a is laterally connected to agent:b, but nothing depends on
    # the package — reach should not flow through SHARES_SERVER.
    g.add_edge(_edge("agent:a", "agent:b", RelationshipType.SHARES_SERVER))
    g.add_edge(_edge("agent:b", "pkg:lateral@1", RelationshipType.SHARES_SERVER))

    report = compute_dependency_reach(g)
    assert not report.packages["pkg:lateral@1"].reachable
