"""Exposure-path surfaces preserve independent, server-authored evidence."""

import pytest

from agent_bom.api.routes.graph import _exposure_path_for_attack_path
from agent_bom.graph import AttackPath, EntityType, RelationshipType, UnifiedEdge, UnifiedNode
from agent_bom.mcp_tools.graph import _exposure_path_payload


def _serialize_both(
    path: AttackPath,
    *,
    nodes: list[UnifiedNode],
    edges: list[UnifiedEdge],
) -> tuple[dict, dict]:
    nodes_by_id = {node.id: node for node in nodes}
    return (
        _exposure_path_payload(path, nodes_by_id=nodes_by_id, edges=edges, rank=1, scan_id="scan-1"),
        _exposure_path_for_attack_path(path, nodes_by_id=nodes_by_id, edges=edges, rank=1, scan_id="scan-1"),
    )


@pytest.mark.parametrize("prefix", ["", "Unverified structural candidate. "])
def test_legacy_structural_summary_is_qualified_after_restart(tmp_path, prefix) -> None:
    from agent_bom.api.graph_store import SQLiteGraphStore
    from agent_bom.graph import UnifiedGraph
    from agent_bom.graph.path_evidence import annotate_attack_path_evidence

    legacy_summary = prefix + (
        "Evidence-backed graph path: vulnerable package/server is reachable from an agent "
        "and inherits the server's credential/tool exposure."
    )
    graph = UnifiedGraph(scan_id="scan-1")
    graph.add_node(UnifiedNode(id="agent:a", entity_type=EntityType.AGENT, label="assistant"))
    graph.add_node(UnifiedNode(id="vuln:a", entity_type=EntityType.VULNERABILITY, label="advisory"))
    graph.add_edge(UnifiedEdge(source="agent:a", target="vuln:a", relationship=RelationshipType.VULNERABLE_TO))
    graph.attack_paths = [
        AttackPath(source="agent:a", target="vuln:a", hops=["agent:a", "vuln:a"], edges=["vulnerable_to"], summary=legacy_summary)
    ]
    db = tmp_path / "legacy-path.db"
    SQLiteGraphStore(db).save_graph(graph)
    restored = SQLiteGraphStore(db).load_graph(scan_id="scan-1")
    assert restored is not None
    for payload in _serialize_both(restored.attack_paths[0], nodes=list(restored.nodes.values()), edges=restored.edges):
        assert "effective permission, successful use, and exploitation require separate evidence" in payload["summary"]
        assert "inherits" not in payload["summary"]
        assert payload["reachability"] == "unknown"
    annotated = annotate_attack_path_evidence(restored.attack_paths[0], restored)
    assert "effective permission, successful use, and exploitation require separate evidence" in annotated.summary
    # Read-time compatibility does not rewrite historical persisted evidence.
    assert SQLiteGraphStore(db).load_graph(scan_id="scan-1").attack_paths[0].summary == legacy_summary


def test_custom_source_summary_is_retained() -> None:
    summary = "Source notes: synthetic package inventory; exact action evidence not collected."
    path = AttackPath(source="agent:a", target="resource:b", summary=summary)
    for payload in _serialize_both(path, nodes=[], edges=[]):
        assert payload["summary"] == summary


def test_exposure_path_surfaces_carry_independent_evidence_dimensions() -> None:
    target = UnifiedNode(
        id="vuln:cve",
        entity_type=EntityType.VULNERABILITY,
        label="CVE-2026-1",
        severity="high",
        attributes={
            "network_exploitable": True,
            "impact_category": "code-execution",
            "actionable": True,
            "is_kev": True,
        },
    )
    path = AttackPath(
        source="agent:a",
        target=target.id,
        hops=["agent:a", target.id],
        edges=["vulnerable_to"],
        composite_risk=99.0,
        reachability="confirmed",
        reachability_basis=["directed_provenance_backed_hops"],
        hop_evidence=[
            {
                "source_node_id": "agent:a",
                "target_node_id": target.id,
                "relationship": "vulnerable_to",
                "direction": "directed",
                "traversable": True,
                "source_snapshot_ids": ["scan-1"],
                "relationship_provenance": "recorded",
                "correlation_identity_status": "current",
                "freshness": "fresh",
                "complete": True,
                "truncated": False,
            }
        ],
        analysis={"status": "complete", "reason_codes": [], "limits": {}, "observed": {"hop_count": 1}},
    )
    edge = UnifiedEdge(
        source="agent:a",
        target=target.id,
        relationship=RelationshipType.VULNERABLE_TO,
        traversable=True,
    )

    for payload in _serialize_both(path, nodes=[target], edges=[edge]):
        dimensions = payload["evidenceDimensions"]
        assert dimensions["reachability"] == {
            "status": "complete",
            "verdict": "confirmed",
            "basis": ["directed_provenance_backed_hops"],
        }
        # AV:N is advisory metadata; it does not assess this environment.
        assert dimensions["exploitability"]["verdict"] is None
        assert dimensions["impact"]["category"] == "code-execution"
        assert dimensions["actionability"]["actionable"] is True
        assert dimensions["completeness"]["status"] == "complete"
        assert payload["relationships"][0]["traversable"] is True
        assert payload["hopEvidence"][0]["source_snapshot_ids"] == ["scan-1"]
        assert payload["hopEvidence"][0]["runtime_outcome"] == "unknown"


def test_exposure_receipts_discard_unclassified_payloads_and_retain_unknowns() -> None:
    path = AttackPath(
        source="agent:a",
        target="resource:b",
        hops=["agent:a", "resource:b"],
        edges=["accessed"],
        hop_evidence=[
            {
                "source_node_id": "agent:a",
                "target_node_id": "resource:b",
                "relationship": "accessed",
                "raw_response": "secret-body",
                "prompt": "ignore previous instructions",
            }
        ],
    )
    for payload in _serialize_both(path, nodes=[], edges=[]):
        receipt = payload["hopEvidence"][0]
        assert "raw_response" not in receipt and "prompt" not in receipt
        assert receipt["complete"] is False
        assert receipt["freshness"] == "unknown"
        assert receipt["runtime_outcome"] == "unknown"


def test_mismatched_receipt_never_attaches_to_a_different_hop() -> None:
    path = AttackPath(
        source="agent:a",
        target="resource:b",
        hops=["agent:a", "resource:b"],
        edges=["accessed"],
        hop_evidence=[{"source_node_id": "other:a", "target_node_id": "other:b", "relationship": "accessed", "complete": True}],
    )
    for payload in _serialize_both(path, nodes=[], edges=[]):
        assert payload["hopEvidence"][0]["complete"] is False
        assert payload["hopEvidence"][0]["reason_codes"] == ["invalid_hop_receipt"]


def test_missing_path_evidence_stays_unavailable_and_does_not_alias_risk() -> None:
    target = UnifiedNode(
        id="vuln:cve",
        entity_type=EntityType.VULNERABILITY,
        label="CVE-2026-1",
        risk_score=99.0,
    )
    path = AttackPath(
        source="agent:a",
        target=target.id,
        hops=["agent:a", target.id],
        edges=["vulnerable_to"],
        composite_risk=99.0,
    )

    for payload in _serialize_both(path, nodes=[target], edges=[]):
        dimensions = payload["evidenceDimensions"]
        assert dimensions["reachability"]["status"] == "unavailable"
        assert dimensions["reachability"]["verdict"] is None
        assert dimensions["exploitability"]["status"] == "unavailable"
        assert dimensions["exploitability"]["verdict"] is None
        assert dimensions["impact"] == {
            "status": "unavailable",
            "category": None,
            "basis": [],
            "reasonCodes": ["impact_not_assessed"],
        }
        assert dimensions["actionability"]["actionable"] is None
        assert dimensions["completeness"]["status"] == "unavailable"
        assert payload["severity"] == "unknown"
        assert payload["relationships"] == []

    api_payload = _serialize_both(path, nodes=[target], edges=[])[1]
    assert api_payload["evidence"]["isKev"] is None
    assert api_payload["evidence"]["networkExploitable"] is None


def test_persisted_confirmed_path_without_freshness_is_not_reprojected_as_confirmed() -> None:
    target = UnifiedNode(
        id="vuln:cve",
        entity_type=EntityType.VULNERABILITY,
        label="CVE-2026-1",
        severity="critical",
    )
    path = AttackPath(
        source="agent:a",
        target=target.id,
        hops=["agent:a", target.id],
        edges=["vulnerable_to"],
        composite_risk=99.0,
        reachability="confirmed",
        reachability_basis=["legacy_structural_path"],
        hop_evidence=[
            {
                "source_node_id": "agent:a",
                "target_node_id": target.id,
                "relationship": "vulnerable_to",
                "complete": True,
                "truncated": False,
            }
        ],
        analysis={"status": "complete", "reason_codes": [], "limits": {}, "observed": {"hop_count": 1}},
    )

    for payload in _serialize_both(path, nodes=[target], edges=[]):
        dimensions = payload["evidenceDimensions"]
        assert dimensions["completeness"]["status"] == "partial"
        assert dimensions["completeness"]["reasonCodes"] == ["unknown_evidence_freshness"]
        assert dimensions["reachability"]["status"] == "unavailable"
        assert dimensions["reachability"]["verdict"] is None


def test_path_relationship_names_do_not_fabricate_edges_or_traversability() -> None:
    path = AttackPath(
        source="agent:a",
        target="vuln:cve",
        hops=["agent:a", "vuln:cve"],
        edges=["vulnerable_to"],
        reachability="confirmed",
        reachability_basis=["graph_path"],
    )

    for payload in _serialize_both(path, nodes=[], edges=[]):
        assert payload["relationships"] == []
        assert payload["edgeIds"] == []


def test_legacy_receipt_flags_cannot_claim_complete_reachability():
    path = AttackPath(
        source="a",
        target="b",
        hops=["a", "b"],
        edges=["uses"],
        composite_risk=9,
        reachability="confirmed",
        reachability_basis=["directed_provenance_backed_hops"],
        analysis={"status": "complete"},
        hop_evidence=[
            {
                "source_node_id": "unrelated",
                "target_node_id": "b",
                "relationship": "uses",
                "freshness": "fresh",
                "complete": True,
                "truncated": False,
            }
        ],
    )
    for payload in _serialize_both(path, nodes=[], edges=[]):
        assert payload["evidenceDimensions"]["completeness"]["status"] != "complete"
        assert payload["evidenceDimensions"]["reachability"]["verdict"] is None


@pytest.mark.parametrize("kind", ["missing", "reversed", "blocked", "unrelated"])
def test_receipts_require_matching_traversable_topology(kind):
    path = AttackPath(
        source="a",
        target="b",
        hops=["a", "b"],
        edges=["uses"],
        composite_risk=9,
        reachability="confirmed",
        reachability_basis=["directed_provenance_backed_hops"],
        analysis={"status": "complete"},
        hop_evidence=[
            {
                "source_node_id": "a",
                "target_node_id": "b",
                "relationship": "uses",
                "freshness": "fresh",
                "complete": True,
                "truncated": False,
                "direction": "directed",
                "traversable": True,
                "relationship_provenance": "recorded",
                "correlation_identity_status": "current",
                "source_snapshot_ids": ["scan-1"],
            }
        ],
    )
    edge = UnifiedEdge(
        source="b" if kind == "reversed" else "a",
        target="a" if kind == "reversed" else "b",
        relationship=RelationshipType.CONTAINS if kind == "unrelated" else RelationshipType.USES,
        traversable=kind != "blocked",
    )
    for payload in _serialize_both(path, nodes=[], edges=[] if kind == "missing" else [edge]):
        assert payload["evidenceDimensions"]["reachability"]["verdict"] is None


@pytest.mark.parametrize("finding_severity, expected", [("low", "low"), ("none", "none"), ("", "unknown")])
def test_exposure_severity_uses_known_findings_not_asset_priority(finding_severity, expected):
    asset = UnifiedNode(id="asset", entity_type=EntityType.CONTAINER, label="asset", severity="critical")
    finding = UnifiedNode(id="finding", entity_type=EntityType.VULNERABILITY, label="finding", severity=finding_severity)
    path = AttackPath(source="asset", target="finding", hops=["asset", "finding"], edges=["vulnerable_to"])
    for payload in _serialize_both(path, nodes=[asset, finding], edges=[]):
        assert payload["severity"] == expected


def test_legacy_confirmed_projection_is_qualified_without_mutating_receipts():
    from copy import deepcopy

    from agent_bom.api.routes.graph import _serialize_attack_path

    path = AttackPath(source="a", target="b", hops=["a", "b"], edges=["uses"], reachability="confirmed")
    original = deepcopy(path.to_dict())
    for payload in _serialize_both(path, nodes=[], edges=[]):
        assert payload["reachability"] == "unknown"
        assert payload["reachabilityBasis"]
    assert _serialize_attack_path(path, [], nodes_by_id={})["reachability"] == "unknown"
    assert path.to_dict() == original


@pytest.mark.parametrize(
    "kind, expected",
    [
        ("observed", [{"event_id": "gw_event-123", "trace_id": "trace-456"}]),
        ("blocked", [{"event_id": "gw_event-123", "trace_id": "trace-456"}]),
        ("missing", []),
        ("placeholder", []),
        ("wrong_edge", []),
        ("static", []),
        ("unsafe", []),
    ],
)
def test_runtime_references_follow_only_exact_runtime_hops(kind, expected):
    from agent_bom.graph import UnifiedGraph
    from agent_bom.graph.path_evidence import annotate_attack_path_evidence

    graph = UnifiedGraph(scan_id="scan-1")
    agent = UnifiedNode(id="agent:a", entity_type=EntityType.AGENT, label="a")
    tool = UnifiedNode(id="tool:b", entity_type=EntityType.TOOL, label="b")
    graph.add_node(agent)
    graph.add_node(tool)
    evidence = {"event_id": "gw_event-123", "trace_id": "trace-456", "prompt": "never expose", "credential": "never expose"}
    if kind == "blocked":
        evidence["blocked"] = True
    if kind == "missing":
        evidence = {}
    if kind == "placeholder":
        evidence = {"event_id": "runtime_event", "trace_id": "unknown"}
    if kind == "unsafe":
        evidence = {"event_id": "https://secret.example/token", "trace_id": "***REDACTED***"}
    relationship = RelationshipType.USES if kind == "static" else RelationshipType.INVOKED
    graph.add_edge(
        UnifiedEdge(
            source="agent:other" if kind == "wrong_edge" else agent.id, target=tool.id, relationship=relationship, evidence=evidence
        )
    )
    path = AttackPath(source=agent.id, target=tool.id, hops=[agent.id, tool.id], edges=[relationship.value])
    annotate_attack_path_evidence(path, graph)
    for payload in _serialize_both(path, nodes=[agent, tool], edges=graph.edges):
        receipt = payload["hopEvidence"][0]
        assert receipt["runtime_references"] == expected
        assert "prompt" not in receipt and "credential" not in receipt
        if kind == "blocked":
            assert receipt["runtime_observed_state"] == "blocked"
            assert receipt["runtime_outcome"] == "blocked"


def test_runtime_reference_does_not_synthesize_trace_id_from_event_id():
    from agent_bom.graph.hop_evidence import runtime_evidence_references

    assert runtime_evidence_references({"event_id": "evt-123", "trace_id": "unknown"}) == [{"event_id": "evt-123"}]


def test_static_legacy_receipt_cannot_claim_runtime_reference():
    from agent_bom.graph.hop_evidence import exposure_hop_evidence

    path = AttackPath(
        source="agent:a",
        target="tool:b",
        hops=["agent:a", "tool:b"],
        edges=["uses"],
        hop_evidence=[
            {
                "source_node_id": "agent:a",
                "target_node_id": "tool:b",
                "relationship": "uses",
                "runtime_observed_state": "not_observed",
                "runtime_references": [{"event_id": "evt-123"}],
            }
        ],
    )
    assert exposure_hop_evidence(path)[0]["runtime_references"] == []


@pytest.mark.parametrize(
    "entity_type",
    [
        EntityType.AGENT,
        EntityType.USER,
        EntityType.GROUP,
        EntityType.SERVICE_ACCOUNT,
        EntityType.DATA_STORE,
        EntityType.DATASET,
        EntityType.RESOURCE,
        EntityType.CLOUD_RESOURCE,
    ],
)
def test_exposure_refs_preserve_canonical_type_and_raw_identity(entity_type):
    node = UnifiedNode(id="node:exact", entity_type=entity_type, label="raw-reviewer_Name")
    path = AttackPath(source=node.id, target=node.id, hops=[node.id])
    for payload in _serialize_both(path, nodes=[node], edges=[]):
        for ref in [payload["source"], payload["target"], *payload["hops"]]:
            assert ref["entityType"] == entity_type.value
            assert ref["rawLabel"] == "raw-reviewer_Name"


def test_missing_exposure_node_has_no_invented_raw_identity():
    path = AttackPath(source="agent:missing", target="agent:missing", hops=["agent:missing"])
    for payload in _serialize_both(path, nodes=[], edges=[]):
        for ref in [payload["source"], payload["target"], *payload["hops"]]:
            assert ref["entityType"] == "unknown"
            assert "rawLabel" not in ref


def test_runtime_hop_references_and_node_identity_survive_sqlite_reopen(tmp_path):
    from agent_bom.api.graph_store import SQLiteGraphStore
    from agent_bom.graph import UnifiedGraph
    from agent_bom.graph.path_evidence import annotate_attack_path_evidence

    graph = UnifiedGraph(scan_id="receipt-scan", tenant_id="receipt-tenant")
    for node in [
        UnifiedNode(id="agent:a", entity_type=EntityType.AGENT, label="raw_agent-a"),
        UnifiedNode(id="data:b", entity_type=EntityType.DATA_STORE, label="raw_data-b"),
        UnifiedNode(id="identity:c", entity_type=EntityType.SERVICE_ACCOUNT, label="raw_identity-c"),
    ]:
        graph.add_node(node)
    graph.add_edge(
        UnifiedEdge(
            source="agent:a",
            target="data:b",
            relationship=RelationshipType.ACCESSED,
            evidence={"event_id": "evt-123", "trace_id": "trace-456", "blocked": True},
        )
    )
    path = AttackPath(source="agent:a", target="data:b", hops=["agent:a", "data:b"], edges=["accessed"])
    annotate_attack_path_evidence(path, graph)
    graph.attack_paths = [path]
    database = tmp_path / "receipts.db"
    SQLiteGraphStore(database).save_graph(graph)
    restored = SQLiteGraphStore(database).load_graph(tenant_id="receipt-tenant", scan_id="receipt-scan")
    assert restored is not None
    assert [(node.id, node.entity_type, node.label) for node in sorted(restored.nodes.values(), key=lambda node: node.id)] == [
        (node.id, node.entity_type, node.label) for node in sorted(graph.nodes.values(), key=lambda node: node.id)
    ]
    for payload in _serialize_both(restored.attack_paths[0], nodes=list(restored.nodes.values()), edges=restored.edges):
        assert payload["source"]["entityType"] == "agent"
        assert payload["source"]["rawLabel"] == "raw_agent-a"
        assert payload["target"]["entityType"] == "data_store"
        assert payload["hopEvidence"][0]["runtime_references"] == [{"event_id": "evt-123", "trace_id": "trace-456"}]
        assert payload["hopEvidence"][0]["runtime_observed_state"] == "blocked"
