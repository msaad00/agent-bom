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
        assert dimensions["exploitability"]["verdict"] == "exploitable"
        assert dimensions["impact"]["category"] == "code-execution"
        assert dimensions["actionability"]["actionable"] is True
        assert dimensions["completeness"]["status"] == "complete"
        assert payload["relationships"][0]["traversable"] is True


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
