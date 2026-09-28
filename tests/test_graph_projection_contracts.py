"""Report projections preserve bounded provenance, stable IDs and edge meaning."""

import copy

from agent_bom.graph import RelationshipType, UnifiedGraph
from agent_bom.graph.builder import (
    _add_agentic_identity_graph_projections,
    _agent_node_id,
    _package_evidence,
    _package_node_id,
    _resolve_affected_server_ids,
)


def test_runtime_projection_reuse_preserves_inputs_and_rejects_dangling_edges():
    projection = {
        "schema_version": "agentic_identity_graph.v1",
        "source": "fixture",
        "nodes": [
            {"id": "agent:one", "entity_type": "agent", "attributes": {"token": "private-fixture-value"}},
            {"id": "tool:read", "entity_type": "tool"},
            {"id": "unknown:type", "entity_type": "unrecognized"},
        ],
        "edges": [
            {"source": "agent:one", "target": "tool:read", "relationship": "called", "evidence": {"event_id": "observed-one"}},
            {"source": "agent:one", "target": "missing", "relationship": "called"},
            {"source": "agent:one", "target": "tool:read", "relationship": "unrecognized"},
        ],
    }
    report = {"agentic_identity_graph": projection, "audit_events": [{"details": {"agentic_identity_graph": projection}}]}
    original = copy.deepcopy(report)
    graph = UnifiedGraph()
    _add_agentic_identity_graph_projections(graph, report, "scan:one", "tenant-a")
    assert report == original
    assert set(graph.nodes) == {"agent:one", "tool:read"}
    assert len(graph.edges) == 1
    edge = graph.edges[0]
    assert edge.relationship == RelationshipType.CALLED
    assert edge.evidence["event_id"] == "observed-one"
    assert edge.evidence["tenant_id"] == "tenant-a"
    assert "private-fixture-value" not in str(graph.to_dict())


def test_package_projection_bounds_occurrences_without_losing_known_count():
    package = {"name": "Requests", "ecosystem": "pypi", "version": "2.32.0", "occurrences": [{"line": i} for i in range(15)]}
    original = copy.deepcopy(package)
    evidence = _package_evidence(package, "scan:one")
    assert len(evidence["occurrences"]) == 10
    assert evidence["occurrence_count"] == 15
    assert evidence["source"] == "scan:one"
    assert _package_node_id(package) == _package_node_id({**package, "name": "requests"})
    assert package == original


def test_blast_radius_hints_narrow_hosts_without_inventing_cross_product():
    package = {"name": "requests", "version": "2.32.0", "ecosystem": "pypi"}
    key = _package_node_id(package).removeprefix("pkg:")
    assert _resolve_affected_server_ids(
        {"affected_servers": ["shared"], "affected_agents": ["one"]},
        pkg_name="requests",
        pkg_version="2.32.0",
        ecosystem="pypi",
        pkg_key_to_servers={key: ["server:one", "server:two"]},
        server_name_to_agent_servers={"shared": {"one": "server:one", "two": "server:two"}},
        agent_to_server_ids={"one": {"server:one"}, "two": {"server:two"}},
    ) == ["server:one"]
    assert _agent_node_id("one", "device:alpha") == "agent:device%3Aalpha:one"
    assert _agent_node_id("one", "device:alpha") != _agent_node_id("one", "device:beta")
