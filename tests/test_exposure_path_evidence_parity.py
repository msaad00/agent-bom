"""Exposure-path surfaces preserve independent, server-authored evidence."""

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
        traversable=False,
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
        assert payload["relationships"][0]["traversable"] is False


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
