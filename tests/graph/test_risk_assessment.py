"""A graph score never substitutes for explicit assessment provenance."""

from __future__ import annotations

import pytest
from starlette.testclient import TestClient

from agent_bom.api import stores
from agent_bom.api.graph_store import SQLiteGraphStore
from agent_bom.api.inventory_service import asset_row
from agent_bom.api.server import app
from agent_bom.graph import EntityType, UnifiedGraph, UnifiedNode
from agent_bom.graph.delta_digest import digest_from_graph
from agent_bom.graph.store_backed import _merge_node
from agent_bom.mcp_tools.graph import _node_ref

UNKNOWN = {"status": "not_assessed", "basis": None, "scope": None}


def node(score: float = 0, assessed: bool = False, basis: str = "test_method") -> UnifiedNode:
    result = UnifiedNode(id="agent:assessment", entity_type=EntityType.AGENT, label="Assessment", risk_score=score)
    if assessed:
        result.mark_risk_assessed(basis=basis, scope="recorded_test_evidence")
    return result


@pytest.mark.parametrize("score", [0.0, 9.0])
def test_legacy_score_does_not_establish_assessment(score: float) -> None:
    original = node(score)
    assert original.risk_assessment == UNKNOWN
    assert UnifiedNode.from_dict(original.to_dict()).risk_assessment == UNKNOWN
    assert original.to_dict()["risk_score"] == score


def test_assessed_zero_survives_serialization_and_references() -> None:
    original = node(0, True)
    expected = {"status": "assessed", "basis": "test_method", "scope": "recorded_test_evidence"}
    assert original.risk_assessment == expected
    assert UnifiedNode.from_dict(original.to_dict()).risk_assessment == expected
    assert asset_row(original)["risk_assessment"] == expected
    assert _node_ref(original.id, {original.id: original})["risk_assessment"] == expected
    from agent_bom.api.routes.graph import _exposure_ref_for_node

    reference = _exposure_ref_for_node(original.id, {original.id: original})
    assert reference["riskScore"] == 0
    assert reference["risk_assessment"] == expected


@pytest.mark.parametrize(
    "metadata",
    [
        None,
        {},
        {"status": "assessed"},
        {"status": "assessed", "basis": "x", "scope": ""},
        {"status": "assessed", "basis": "x", "scope": "y", "scored_value": True},
    ],
)
def test_malformed_assessment_is_unknown(metadata: object) -> None:
    original = node(1)
    original.attributes["risk_assessment"] = metadata
    assert original.risk_assessment == UNKNOWN


def test_raw_score_mutation_invalidates_bound_assessment() -> None:
    original = node(2, True)
    original.risk_score = 9
    assert original.risk_assessment == UNKNOWN
    assert UnifiedNode.from_dict(original.to_dict()).risk_assessment == UNKNOWN


@pytest.mark.parametrize("merge_kind", ["memory", "store"])
@pytest.mark.parametrize(
    "old_score,old_assessed,new_score,new_assessed,expected_score,expected_basis",
    [
        (9, True, 2, True, 9, "old"),
        (2, True, 9, False, 9, None),
        (2, False, 9, True, 9, "new"),
        (0, False, 0, True, 0, "new"),
        (0, True, 0, False, 0, "old"),
    ],
)
def test_merge_preserves_score_provenance_pair(
    merge_kind, old_score, old_assessed, new_score, new_assessed, expected_score, expected_basis
) -> None:
    old = node(old_score, old_assessed, "old")
    incoming = node(new_score, new_assessed, "new")
    if merge_kind == "memory":
        graph = UnifiedGraph(scan_id="merge")
        graph.add_node(old)
        graph.add_node(incoming)
    else:
        _merge_node(old, incoming)
    assert old.risk_score == expected_score
    assert old.risk_assessment["basis"] == expected_basis
    assert old.risk_assessment["status"] == ("assessed" if expected_basis else "not_assessed")


def test_sqlite_api_and_delta_roundtrip(tmp_path, monkeypatch) -> None:
    store = SQLiteGraphStore(tmp_path / "risk.db")
    graph = UnifiedGraph(scan_id="assessment-scan", tenant_id="default")
    original = node(0, True)
    graph.add_node(original)
    store.save_graph(graph)
    loaded = store.load_graph(scan_id=graph.scan_id, tenant_id="default")
    assert loaded is not None
    assert loaded.nodes[original.id].risk_assessment == original.risk_assessment
    assert digest_from_graph(loaded).nodes[original.id].risk_assessment == original.risk_assessment
    digest = store.prior_delta_digest(scan_id=graph.scan_id, tenant_id="default")
    assert digest.nodes[original.id].risk_assessment == original.risk_assessment
    monkeypatch.setattr(stores, "_graph_store", store)
    client = TestClient(app)
    response = client.get("/v1/graph/agents?scan_id=assessment-scan")
    assert response.status_code == 200
    assert response.json()["agents"][0]["risk_assessment"] == original.risk_assessment
    response = client.get("/v1/graph/search?scan_id=assessment-scan&q=Assessment")
    assert response.status_code == 200
    assert response.json()["results"][0]["risk_assessment"] == original.risk_assessment


@pytest.mark.parametrize("high_assessed", [False, True])
def test_correlation_uses_winning_observations_assessment(high_assessed: bool) -> None:
    from agent_bom.graph.correlation import CorrelationSnapshot, _NodeObservation
    from agent_bom.graph.correlation import _merge_node as correlate_node

    high = node(9, high_assessed, "high_score_method")
    low = node(2, True, "newer_low_score_method")
    snapshots = [
        UnifiedGraph(scan_id="old", tenant_id="default", created_at="2026-09-01T00:00:00Z"),
        UnifiedGraph(scan_id="new", tenant_id="default", created_at="2026-09-02T00:00:00Z"),
    ]
    observations = [_NodeObservation(CorrelationSnapshot.from_graph(graph), value, "test") for graph, value in zip(snapshots, (high, low))]
    merged = correlate_node(observations)
    assert merged.risk_score == 9
    assert merged.risk_assessment == high.risk_assessment


def test_removed_agent_webhook_keeps_assessment_through_sqlite_digest(tmp_path) -> None:
    from agent_bom.graph.webhooks import compute_delta_alerts

    graph = UnifiedGraph(scan_id="old", tenant_id="default")
    original = node(0, True)
    graph.add_node(original)
    store = SQLiteGraphStore(tmp_path / "delta.db")
    store.save_graph(graph)
    digest = store.prior_delta_digest(scan_id="old", tenant_id="default")
    new_graph = UnifiedGraph(scan_id="new", tenant_id="default")
    full_alerts = compute_delta_alerts(graph, new_graph)
    assert compute_delta_alerts(digest, new_graph) == full_alerts
    assert full_alerts
    from agent_bom.graph.webhooks import _graph_node_ref

    reference = _graph_node_ref(digest, original.id, role="removed")
    assert reference is not None
    assert reference["attributes"]["risk_assessment_status"] == "assessed"
    assert reference["attributes"]["risk_assessment_basis"] == original.risk_assessment["basis"]
    assert reference["attributes"]["risk_assessment_scope"] == original.risk_assessment["scope"]
