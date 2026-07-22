"""Finding ↔ EntityType alignment and graph FK helpers."""

from __future__ import annotations

from agent_bom.finding import Asset, Finding, FindingSource, FindingType
from agent_bom.graph.asset_entity import (
    canonical_asset_type,
    entity_type_for_asset_type,
    finding_id_from_node_attributes,
    link_findings_to_graph_nodes,
    normalize_asset_type,
)
from agent_bom.graph.container import UnifiedGraph
from agent_bom.graph.edge import UnifiedEdge
from agent_bom.graph.node import UnifiedNode
from agent_bom.graph.types import EntityType, RelationshipType


def test_identity_alias_maps_to_managed_identity_without_mutating_asset_type():
    assert entity_type_for_asset_type("identity") is EntityType.MANAGED_IDENTITY
    assert canonical_asset_type("mcp_server") == EntityType.SERVER.value
    assert normalize_asset_type("MCP-Server") == "mcp_server"

    finding = Finding(
        finding_type=FindingType.CIEM_OVER_PRIVILEGE,
        source=FindingSource.GRAPH_ANALYSIS,
        asset=Asset(name="role-a", asset_type="identity", identifier="arn:aws:iam::1:role/a"),
        severity="medium",
        title="over grant",
    )
    # asset_type stays the emitted convention (stable_id safety)
    assert finding.asset.asset_type == "identity"
    assert finding.entity_type == EntityType.MANAGED_IDENTITY.value


def test_link_findings_stamps_finding_id_on_vuln_node_and_package_node_id():
    graph = UnifiedGraph(scan_id="s1", tenant_id="t1")
    pkg = UnifiedNode(id="pkg:pypi/flask@3.0.0", entity_type=EntityType.PACKAGE, label="flask")
    vuln = UnifiedNode(
        id="vuln:CVE-2026-0001",
        entity_type=EntityType.VULNERABILITY,
        label="CVE-2026-0001",
        attributes={"vulnerability_id": "CVE-2026-0001"},
    )
    graph.add_node(pkg)
    graph.add_node(vuln)
    graph.add_edge(
        UnifiedEdge(
            source=pkg.id,
            target=vuln.id,
            relationship=RelationshipType.VULNERABLE_TO,
            evidence={"source": "test"},
        )
    )

    finding = Finding(
        finding_type=FindingType.CVE,
        source=FindingSource.MCP_SCAN,
        asset=Asset(name="flask", asset_type="package", identifier="pkg:pypi/flask@3.0.0"),
        severity="high",
        title="CVE-2026-0001: flask@3.0.0",
        cve_id="CVE-2026-0001",
        id="finding-uuid-1",
    )

    linked = link_findings_to_graph_nodes([finding], graph)
    assert linked == 1
    assert finding.finding_node_id == "vuln:CVE-2026-0001"
    assert finding.node_id == "pkg:pypi/flask@3.0.0"
    assert finding_id_from_node_attributes(vuln.attributes) == "finding-uuid-1"


def test_attack_path_finding_ids_prefer_stamped_attributes():
    from agent_bom.api.routes.graph import _finding_ids_for_nodes

    nodes = {
        "vuln:CVE-1": UnifiedNode(
            id="vuln:CVE-1",
            entity_type=EntityType.VULNERABILITY,
            label="CVE-1",
            attributes={"finding_id": "fid-abc"},
        )
    }
    assert _finding_ids_for_nodes(nodes, ["vuln:CVE-1"], ["CVE-1"]) == ["fid-abc", "CVE-1"]


def test_link_report_findings_stamps_persisted_graph_nodes():
    from agent_bom.graph.asset_entity import link_report_findings_to_graph

    graph = UnifiedGraph(scan_id="s1", tenant_id="t1")
    pkg = UnifiedNode(id="pkg:pypi/flask@3.0.0", entity_type=EntityType.PACKAGE, label="flask")
    vuln = UnifiedNode(
        id="vuln:CVE-2026-0002",
        entity_type=EntityType.VULNERABILITY,
        label="CVE-2026-0002",
        attributes={"vulnerability_id": "CVE-2026-0002"},
    )
    graph.add_node(pkg)
    graph.add_node(vuln)
    graph.add_edge(
        UnifiedEdge(
            source=pkg.id,
            target=vuln.id,
            relationship=RelationshipType.VULNERABLE_TO,
            evidence={"source": "test"},
        )
    )
    report_json = {
        "findings": [
            {
                "id": "finding-persist-1",
                "finding_type": "cve",
                "source": "mcp_scan",
                "severity": "high",
                "title": "CVE-2026-0002: flask",
                "cve_id": "CVE-2026-0002",
                "asset": {"name": "flask", "asset_type": "package"},
            }
        ]
    }
    assert link_report_findings_to_graph(report_json, graph) == 1
    assert finding_id_from_node_attributes(vuln.attributes) == "finding-persist-1"


def test_toxic_finding_rehydrate_preserves_graph_fks():
    from agent_bom.graph.toxic_findings import toxic_combination_findings_from_data

    rows = [
        {
            "id": "toxic-1",
            "finding_type": "combination",
            "source": "graph_analysis",
            "severity": "critical",
            "title": "Exposed + vulnerable",
            "description": "demo",
            "asset": {"name": "web", "asset_type": "cloud_resource"},
            "node_id": "cloud_resource:web",
            "finding_node_id": "vuln:CVE-1",
            "entity_type": "cloud_resource",
        }
    ]
    findings = toxic_combination_findings_from_data(rows)
    assert len(findings) == 1
    assert findings[0].node_id == "cloud_resource:web"
    assert findings[0].finding_node_id == "vuln:CVE-1"
    assert findings[0].entity_type == "cloud_resource"
