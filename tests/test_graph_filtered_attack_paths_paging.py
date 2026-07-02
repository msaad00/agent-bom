"""Filtered /graph responses keep attack paths whose hops span node pages."""

from __future__ import annotations

from agent_bom.api.routes.graph import _FILTERED_GRAPH_ATTACK_PATH_LIMIT, _filtered_graph_response
from agent_bom.graph.container import AttackPath, UnifiedGraph
from agent_bom.graph.edge import UnifiedEdge
from agent_bom.graph.node import UnifiedNode
from agent_bom.graph.types import EntityType, RelationshipType


def _graph_larger_than_page(filler: int) -> UnifiedGraph:
    """Agent on page 0, vulnerable server/package/vuln pushed onto a later page."""
    g = UnifiedGraph(scan_id="s", tenant_id="t")
    # Source agent is inserted first so it lands on page 0.
    g.add_node(UnifiedNode(id="agent:a", entity_type=EntityType.AGENT, label="agent-a"))
    # Filler nodes fill the rest of the first page (and beyond).
    for i in range(filler):
        g.add_node(UnifiedNode(id=f"pkg:filler-{i}", entity_type=EntityType.PACKAGE, label=f"filler-{i}"))
    # The rest of the kill-chain is inserted last, so it falls on a later page.
    g.add_node(UnifiedNode(id="server:fs", entity_type=EntityType.SERVER, label="fs"))
    g.add_node(UnifiedNode(id="pkg:express", entity_type=EntityType.PACKAGE, label="express"))
    g.add_node(UnifiedNode(id="vuln:CVE-1", entity_type=EntityType.VULNERABILITY, label="CVE-1", severity="critical", risk_score=9.0))
    g.add_edge(UnifiedEdge(source="agent:a", target="server:fs", relationship=RelationshipType.USES))
    g.add_edge(UnifiedEdge(source="server:fs", target="pkg:express", relationship=RelationshipType.DEPENDS_ON))
    g.add_edge(UnifiedEdge(source="pkg:express", target="vuln:CVE-1", relationship=RelationshipType.VULNERABLE_TO))
    return g


def test_filtered_response_keeps_paths_spanning_pages_with_resolved_labels():
    limit = 500
    g = _graph_larger_than_page(filler=limit + 100)

    response = _filtered_graph_response(g, offset=0, limit=limit)

    # Off-page hop nodes must not be on the returned page (regression guard).
    page_ids = {n["id"] for n in response["nodes"]}
    assert "agent:a" in page_ids
    assert "vuln:CVE-1" not in page_ids
    assert "server:fs" not in page_ids

    # Path whose source is on the page survives even though its hops span pages.
    assert response["attack_paths"], "filtered response dropped the cross-page attack path"
    path = response["attack_paths"][0]

    # Off-page hop labels are back-filled, not left as raw ids / unknown roles.
    exposure_hops = {hop["id"]: hop for hop in path["exposure_path"]["hops"]}
    assert exposure_hops["vuln:CVE-1"]["label"] == "CVE-1"
    assert exposure_hops["vuln:CVE-1"]["role"] != "unknown"
    assert exposure_hops["server:fs"]["label"] == "fs"
    assert exposure_hops["server:fs"]["role"] != "unknown"


def test_filtered_response_caps_embedded_attack_paths_for_large_pages():
    g = UnifiedGraph(scan_id="s", tenant_id="t")
    g.add_node(UnifiedNode(id="agent:a", entity_type=EntityType.AGENT, label="agent-a"))
    for i in range(_FILTERED_GRAPH_ATTACK_PATH_LIMIT + 20):
        vuln_id = f"vuln:CVE-{i}"
        g.add_node(UnifiedNode(id=vuln_id, entity_type=EntityType.VULNERABILITY, label=f"CVE-{i}", severity="critical"))
        g.attack_paths.append(
            AttackPath(
                source="agent:a",
                target=vuln_id,
                hops=["agent:a", vuln_id],
                edges=["vulnerable_to"],
                composite_risk=90.0 - (i * 0.01),
                summary=f"path {i}",
                vuln_ids=[f"CVE-{i}"],
            )
        )

    response = _filtered_graph_response(g, offset=0, limit=1)

    assert len(response["attack_paths"]) == _FILTERED_GRAPH_ATTACK_PATH_LIMIT
    assert response["attack_path_pagination"] == {
        "total": _FILTERED_GRAPH_ATTACK_PATH_LIMIT + 20,
        "limit": _FILTERED_GRAPH_ATTACK_PATH_LIMIT,
        "has_more": True,
    }
