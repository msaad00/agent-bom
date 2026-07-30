"""Bottleneck ranking must not depend on the order nodes were inserted.

``bottleneck_nodes`` sampled ``list(self.nodes)[:50]`` — the first 50 keys in
INSERTION order — ran a BFS from each, and returned the top scores as fact.

Ground truth here: 120 agents all reach 120 packages through ONE server, so
every path in the estate crosses ``server:CHOKE``. It is the only bottleneck
that exists. Insert 60 vulnerability nodes first (which is what a real build
does — findings are added before topology) and the old sample was 50 CVE nodes
with no outgoing edges: five score-``0.0`` CVEs came back ranked, and CHOKE was
not in the answer at all. Insert topology first and the same graph answered
``server:CHOKE``. Same estate, different answer, no warning either way.

Three separate dishonesties, all fixed here:
  * the sample is insertion-ordered, so the answer is an artifact of build order;
  * ``total = sum(scores) or 1.0`` normalises an all-zero result into zeros that
    render exactly like real scores;
  * the caller is handed a SAMPLE with no way to know it was one.
"""

from __future__ import annotations

import pytest

from agent_bom.graph.container import UnifiedGraph
from agent_bom.graph.edge import UnifiedEdge
from agent_bom.graph.node import UnifiedNode
from agent_bom.graph.types import EntityType, RelationshipType
from agent_bom.graph_backend import InMemoryBackend, get_backend

AGENTS = 120
PACKAGES = 120
VULNS = 60
CHOKE = "server:CHOKE"


def _choke_point_estate(*, vulns_first: bool) -> UnifiedGraph:
    """120 agents -> ONE server -> 120 packages. Every path crosses the server."""
    graph = UnifiedGraph(scan_id="s", tenant_id="t")

    def add_vulns() -> None:
        for index in range(VULNS):
            graph.add_node(
                UnifiedNode(id=f"cve:{index:03d}", entity_type=EntityType.VULNERABILITY, label=f"CVE-{index}", severity="critical")
            )

    if vulns_first:
        add_vulns()

    graph.add_node(UnifiedNode(id=CHOKE, entity_type=EntityType.SERVER, label="choke"))
    for index in range(AGENTS):
        agent_id = f"agent:{index:03d}"
        graph.add_node(UnifiedNode(id=agent_id, entity_type=EntityType.AGENT, label=agent_id))
        graph.add_edge(UnifiedEdge(source=agent_id, target=CHOKE, relationship=RelationshipType.USES))
    for index in range(PACKAGES):
        package_id = f"pkg:{index:03d}"
        graph.add_node(UnifiedNode(id=package_id, entity_type=EntityType.PACKAGE, label=package_id))
        graph.add_edge(UnifiedEdge(source=CHOKE, target=package_id, relationship=RelationshipType.DEPENDS_ON))

    if not vulns_first:
        add_vulns()
    return graph


@pytest.mark.parametrize("vulns_first", [True, False], ids=["findings-inserted-first", "topology-inserted-first"])
def test_the_only_bottleneck_is_found_regardless_of_insertion_order(vulns_first: bool):
    ranked = _choke_point_estate(vulns_first=vulns_first).bottleneck_nodes(top_n=5)
    assert ranked, "the estate has exactly one bottleneck; an empty answer is wrong"
    assert ranked[0][0] == CHOKE, f"top bottleneck was {ranked[0][0]!r}, not the node every path crosses"
    assert ranked[0][1] == pytest.approx(1.0)


def test_the_answer_does_not_change_with_insertion_order():
    assert _choke_point_estate(vulns_first=True).bottleneck_nodes(top_n=5) == _choke_point_estate(vulns_first=False).bottleneck_nodes(
        top_n=5
    )


def test_scoreless_nodes_are_dropped_not_ranked_at_zero():
    """A 0.0 score is "not a bottleneck", not "the 5th biggest bottleneck"."""
    ranked = _choke_point_estate(vulns_first=True).bottleneck_nodes(top_n=5)
    assert all(score > 0.0 for _nid, score in ranked), f"zero-score entries presented as rankings: {ranked}"
    assert [nid for nid, _score in ranked] == [CHOKE]


def test_a_graph_with_no_bottleneck_returns_nothing():
    """Isolated nodes: normalising by ``or 1.0`` used to emit a full ranking of zeros."""
    graph = UnifiedGraph(scan_id="s", tenant_id="t")
    for index in range(10):
        graph.add_node(UnifiedNode(id=f"iso:{index}", entity_type=EntityType.PACKAGE, label=str(index)))

    assert graph.bottleneck_nodes(top_n=5) == []


def test_result_is_stable_across_repeated_calls():
    graph = _choke_point_estate(vulns_first=True)
    assert graph.bottleneck_nodes(top_n=5) == graph.bottleneck_nodes(top_n=5)


def test_provenance_declares_the_sample_it_was_computed_from():
    graph = _choke_point_estate(vulns_first=True)
    analysis = graph.bottleneck_analysis(top_n=5)

    assert analysis.total_nodes == len(graph.nodes)
    assert 0 < analysis.sampled_sources <= analysis.total_nodes
    assert analysis.sampled is True, "a partial source sample must not be presented as exhaustive"
    assert analysis.nodes == graph.bottleneck_nodes(top_n=5)

    payload = analysis.to_dict()
    assert payload["sampled_sources"] == analysis.sampled_sources
    assert payload["total_nodes"] == analysis.total_nodes
    assert payload["sampled"] is True


def test_a_small_graph_is_analysed_exhaustively_and_says_so():
    graph = UnifiedGraph(scan_id="s", tenant_id="t")
    for name in ("a", "b", "c"):
        graph.add_node(UnifiedNode(id=name, entity_type=EntityType.AGENT, label=name))
    graph.add_edge(UnifiedEdge(source="a", target="b", relationship=RelationshipType.USES))
    graph.add_edge(UnifiedEdge(source="b", target="c", relationship=RelationshipType.USES))

    analysis = graph.bottleneck_analysis(top_n=5)
    assert analysis.sampled_sources == analysis.total_nodes == 3
    assert analysis.sampled is False
    assert [nid for nid, _score in analysis.nodes] == ["b"]


def test_sample_size_grows_with_the_graph():
    small = _choke_point_estate(vulns_first=True).bottleneck_analysis()
    big = UnifiedGraph(scan_id="s", tenant_id="t")
    for index in range(60_000):
        big.add_node(UnifiedNode(id=f"n:{index:06d}", entity_type=EntityType.PACKAGE, label=str(index)))

    assert big.bottleneck_analysis().sampled_sources > small.sampled_sources


# ── degree_centrality ───────────────────────────────────────────────────────


def test_degree_centrality_counts_edges_arriving_as_well_as_leaving():
    """A node 50 other nodes point AT is central; out-degree alone scored it 0."""
    graph = UnifiedGraph(scan_id="s", tenant_id="t")
    graph.add_node(UnifiedNode(id="sink", entity_type=EntityType.CREDENTIAL, label="sink"))
    for index in range(50):
        source_id = f"agent:{index:03d}"
        graph.add_node(UnifiedNode(id=source_id, entity_type=EntityType.AGENT, label=source_id))
        graph.add_edge(UnifiedEdge(source=source_id, target="sink", relationship=RelationshipType.EXPOSES_CRED, direction="directed"))

    scores = graph.degree_centrality()
    assert scores["sink"] > 0.0, "a node with 50 in-edges and no out-edges scored zero"
    assert scores["sink"] == max(scores.values())


# ── graph_backend parity (the surface the CLI actually calls) ────────────────


def _choke_point_backend(kind: str, *, vulns_first: bool):
    backend = get_backend(kind)
    if vulns_first:
        for index in range(VULNS):
            backend.add_node(f"cve:{index:03d}", kind="vulnerability", label=f"CVE-{index}")
    backend.add_node(CHOKE, kind="server", label="choke")
    for index in range(AGENTS):
        backend.add_node(f"agent:{index:03d}", kind="agent", label=f"agent:{index:03d}")
        backend.add_edge(f"agent:{index:03d}", CHOKE, kind="uses", directed=True)
    for index in range(PACKAGES):
        backend.add_node(f"pkg:{index:03d}", kind="package", label=f"pkg:{index:03d}")
        backend.add_edge(CHOKE, f"pkg:{index:03d}", kind="depends_on", directed=True)
    if not vulns_first:
        for index in range(VULNS):
            backend.add_node(f"cve:{index:03d}", kind="vulnerability", label=f"CVE-{index}")
    return backend


@pytest.mark.parametrize("vulns_first", [True, False])
def test_in_memory_backend_finds_the_choke_point_too(vulns_first: bool):
    """The CLI reaches this implementation, not UnifiedGraph's — same bug, same fix."""
    ranked = _choke_point_backend("memory", vulns_first=vulns_first).bottleneck_nodes(top_n=5)
    assert ranked[0][0] == CHOKE
    assert all(score > 0.0 for _nid, score in ranked)


def test_in_memory_backend_reports_its_sampling():
    analysis = _choke_point_backend("memory", vulns_first=True).bottleneck_analysis(top_n=5)
    assert analysis.total_nodes == AGENTS + PACKAGES + VULNS + 1
    assert analysis.sampled is True
    assert analysis.nodes[0][0] == CHOKE


def test_in_memory_backend_centrality_counts_in_edges():
    backend = InMemoryBackend()
    backend.add_node("sink", kind="credential", label="sink")
    for index in range(50):
        backend.add_node(f"agent:{index:03d}", kind="agent", label=str(index))
        backend.add_edge(f"agent:{index:03d}", "sink", kind="exposes_cred", directed=True)

    scores = backend.centrality_scores()
    assert scores["sink"] == max(scores.values())


def test_networkx_backend_exposes_the_same_provenance_contract():
    pytest.importorskip("networkx")
    analysis = _choke_point_backend("networkx", vulns_first=True).bottleneck_analysis(top_n=5)
    assert analysis.nodes[0][0] == CHOKE
    assert all(score > 0.0 for _nid, score in analysis.nodes)
    # Exact betweenness: every node is a source, so nothing was sampled away.
    assert analysis.sampled_sources == analysis.total_nodes
    assert analysis.sampled is False
