"""Streaming graph producer: bounded prior-snapshot digest for delta alerts.

Wires the #4074 streaming primitives through the production persist path
(#4075): the delta-alert computation no longer materialises a second full
``UnifiedGraph`` for the previous snapshot — it streams a bounded
``PriorSnapshotDigest`` instead. These tests assert the streamed path is
byte-identical to the old full-load path AND that its peak Python-heap footprint
is a fraction of the full-load path's on the same snapshot.
"""

from __future__ import annotations

import tracemalloc

import pytest

from agent_bom.api.graph_store import SQLiteGraphStore
from agent_bom.graph import (
    AttackPath,
    EntityType,
    InteractionRisk,
    RelationshipType,
    UnifiedEdge,
    UnifiedGraph,
    UnifiedNode,
)
from agent_bom.graph.delta_digest import PriorSnapshotDigest
from agent_bom.graph.webhooks import compute_delta_alerts, compute_delta_alerts_from_digest


def _prior_graph(scan_id: str = "s1", tenant_id: str = "t") -> UnifiedGraph:
    """A rich prior snapshot exercising every delta-alert branch."""
    g = UnifiedGraph(scan_id=scan_id, tenant_id=tenant_id)
    # Bulk unchanged inventory (dominates the full-load memory cost).
    for i in range(200):
        g.add_node(UnifiedNode(id=f"package:p{i}", entity_type=EntityType.PACKAGE, label=f"p{i}"))
    g.add_node(UnifiedNode(id="agent:kept", entity_type=EntityType.AGENT, label="kept"))
    g.add_node(UnifiedNode(id="agent:removed", entity_type=EntityType.AGENT, label="removed"))
    g.add_node(UnifiedNode(id="vuln:OLD", entity_type=EntityType.VULNERABILITY, label="OLD", severity="critical"))
    g.add_edge(UnifiedEdge(source="agent:kept", target="vuln:OLD", relationship=RelationshipType.VULNERABLE_TO))
    g.attack_paths.append(AttackPath(source="agent:kept", target="vuln:OLD", hops=["agent:kept", "vuln:OLD"], composite_risk=8.0))
    g.interaction_risks.append(
        InteractionRisk(pattern="existing_pattern", agents=["agent:kept", "agent:removed"], risk_score=8.0, description="d")
    )
    return g


def _new_graph(scan_id: str = "s2", tenant_id: str = "t") -> UnifiedGraph:
    """A follow-up snapshot with a new vuln, misconfig, path, risk, and a removed agent."""
    g = UnifiedGraph(scan_id=scan_id, tenant_id=tenant_id)
    for i in range(200):
        g.add_node(UnifiedNode(id=f"package:p{i}", entity_type=EntityType.PACKAGE, label=f"p{i}"))
    g.add_node(UnifiedNode(id="agent:kept", entity_type=EntityType.AGENT, label="kept"))
    # agent:removed is gone -> removed-agent alert
    g.add_node(UnifiedNode(id="vuln:OLD", entity_type=EntityType.VULNERABILITY, label="OLD", severity="critical"))
    g.add_node(
        UnifiedNode(
            id="vuln:NEW",
            entity_type=EntityType.VULNERABILITY,
            label="NEW",
            severity="critical",
            attributes={"cvss_score": 9.8, "is_kev": True, "affected_agent_count": 3},
        )
    )
    g.add_node(UnifiedNode(id="misconfig:NEW", entity_type=EntityType.MISCONFIGURATION, label="MISC", severity="high"))
    g.attack_paths.append(AttackPath(source="agent:kept", target="vuln:OLD", hops=["agent:kept", "vuln:OLD"], composite_risk=8.0))
    g.attack_paths.append(AttackPath(source="agent:kept", target="vuln:NEW", hops=["agent:kept", "vuln:NEW"], composite_risk=9.5))
    g.interaction_risks.append(
        InteractionRisk(pattern="existing_pattern", agents=["agent:kept", "agent:removed"], risk_score=8.0, description="d")
    )
    g.interaction_risks.append(
        InteractionRisk(pattern="new_pattern", agents=["agent:kept"], risk_score=9.0, description="new", owasp_agentic_tag="AAI01")
    )
    return g


@pytest.fixture
def store(tmp_path):
    return SQLiteGraphStore(db_path=tmp_path / "graph.db")


def test_from_graph_projects_exactly_what_delta_needs():
    prior = PriorSnapshotDigest.from_graph(_prior_graph())
    assert "package:p0" in prior.node_ids
    assert prior.node_ids == frozenset(_prior_graph().nodes.keys())
    # Only AGENT nodes are retained in full (bounded), not the 200 packages.
    assert set(prior.agent_nodes) == {"agent:kept", "agent:removed"}
    assert prior.attack_path_keys == frozenset({("agent:kept", "vuln:OLD")})
    assert prior.interaction_risk_keys == frozenset({("existing_pattern", ("agent:kept", "agent:removed"))})


def test_from_graph_none_is_empty():
    prior = PriorSnapshotDigest.from_graph(None)
    assert prior == PriorSnapshotDigest.empty()
    assert prior.node_ids == frozenset()
    assert prior.agent_nodes == {}


def test_digest_alerts_byte_identical_to_full_load(store):
    """The streamed digest path fires exactly the same alerts as the full-load path."""
    old = _prior_graph()
    new = _new_graph()
    store.save_graph(old)

    # Anchor: in-memory full-graph diff (the historical behaviour).
    baseline = compute_delta_alerts(old, new)
    # Old production approach: load the whole prior graph, then diff.
    full_load = compute_delta_alerts(store.load_graph(tenant_id="t", scan_id="s1"), new)
    # New production approach: bounded streamed digest, then diff.
    digest = store.prior_delta_digest(tenant_id="t", scan_id="s1")
    streamed = compute_delta_alerts_from_digest(digest, new)

    # Every branch must be present so the equality is meaningful.
    types = {a["type"] for a in baseline}
    assert types == {"new_vulnerability", "new_misconfiguration", "new_attack_path", "new_interaction_risk", "agent_removed"}

    assert full_load == baseline
    assert streamed == baseline  # byte-identical, computed via the bounded path


def test_prior_delta_digest_matches_from_graph(store):
    old = _prior_graph()
    store.save_graph(old)

    streamed = store.prior_delta_digest(tenant_id="t", scan_id="s1")
    reference = PriorSnapshotDigest.from_graph(store.load_graph(tenant_id="t", scan_id="s1"))

    assert streamed.node_ids == reference.node_ids
    assert set(streamed.agent_nodes) == set(reference.agent_nodes)
    assert streamed.attack_path_keys == reference.attack_path_keys
    assert streamed.interaction_risk_keys == reference.interaction_risk_keys


def test_empty_prior_digest_for_missing_snapshot(store):
    # No snapshot persisted yet -> empty digest, no crash, no alerts suppressed.
    digest = store.prior_delta_digest(tenant_id="t", scan_id="does-not-exist")
    assert digest == PriorSnapshotDigest.empty()


def test_digest_peak_memory_is_a_fraction_of_full_load(store):
    """Production-path regression: the bounded digest peak << full load_graph peak.

    Deterministic Python-heap measurement via ``tracemalloc`` (not ru_maxrss,
    which is platform-variant). ``load_graph`` materialises every node with its
    attributes/dimensions payload plus edges; the digest holds only id strings
    and the few agent nodes, so its peak must be a small fraction.
    """
    n = 20_000
    g = UnifiedGraph(scan_id="big", tenant_id="t")
    for i in range(n):
        g.add_node(
            UnifiedNode(
                id=f"package:p{i}",
                entity_type=EntityType.PACKAGE,
                label=f"package-{i}",
                attributes={"version": f"1.2.{i}", "ecosystem": "pypi", "purl": f"pkg:pypi/p{i}@1.2.{i}"},
            )
        )
    g.add_node(UnifiedNode(id="agent:solo", entity_type=EntityType.AGENT, label="solo"))
    store.save_graph(g)

    tracemalloc.start()
    tracemalloc.reset_peak()
    loaded = store.load_graph(tenant_id="t", scan_id="big")
    _, peak_full = tracemalloc.get_traced_memory()
    assert len(loaded.nodes) == n + 1
    del loaded
    tracemalloc.stop()

    tracemalloc.start()
    tracemalloc.reset_peak()
    digest = store.prior_delta_digest(tenant_id="t", scan_id="big")
    _, peak_digest = tracemalloc.get_traced_memory()
    assert len(digest.node_ids) == n + 1
    tracemalloc.stop()

    # The bounded digest must cost well under half the full materialisation.
    assert peak_digest < peak_full * 0.5, f"digest peak {peak_digest} not < 50% of full-load peak {peak_full}"
