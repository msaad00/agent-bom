"""Portable identities remain joinable and independent of ordering."""

import pytest

from agent_bom.models import Agent, AgentType, AIBOMReport, MCPServer, Package
from agent_bom.output import to_json
from agent_bom.output.graph_export import build_graph_from_scan_data
from agent_bom.output.spdx2_fmt import to_spdx2
from agent_bom.output.spdx_fmt import to_spdx
from agent_bom.package_utils import canonical_package_key


def report(packages):
    return AIBOMReport(
        scan_id="identity",
        agents=[
            Agent(
                name="test",
                agent_type=AgentType.CUSTOM,
                config_path="config",
                mcp_servers=[MCPServer(name="server", command="test", packages=packages)],
            )
        ],
    )


@pytest.mark.parametrize("export", [to_spdx2, to_spdx])
def test_spdx_package_ids_survive_inventory_reordering(export):
    a, b = Package(name="a", version="1", ecosystem="npm"), Package(name="b", version="2", ecosystem="npm")

    def ids(document):
        rows = document.get("packages", document.get("@graph", []))
        return {r["name"]: r.get("SPDXID", r.get("spdxId")) for r in rows if r.get("name") in {"a", "b"}}

    assert ids(export(report([a, b]))) == ids(export(report([b, a])))


def test_standalone_graph_exposes_canonical_join_key_and_retains_legacy_id():
    package = Package(
        name="github.com/Azure/azure-sdk-for-go", version="1.0.0", ecosystem="go", purl="pkg:golang/github.com/Azure/azure-sdk-for-go@1.0.0"
    )
    from agent_bom.graph.builder import build_unified_graph_from_report

    original_report = report([package])
    graph = build_graph_from_scan_data(to_json(original_report))
    node = next(n for n in graph.nodes if n.kind == "pkg")
    assert node.attributes["canonical_node_id"] in build_unified_graph_from_report(to_json(original_report)).nodes
    assert node.id == "pkg:go/github.com/Azure/azure-sdk-for-go@1.0.0"
    assert node.attributes["canonical_node_id"] == "pkg:" + canonical_package_key(
        package.name, package.version, package.ecosystem, package.purl
    )


def test_package_finding_uses_the_supplied_canonical_purl():
    from agent_bom.finding import blast_radius_to_finding
    from agent_bom.models import BlastRadius, Severity, Vulnerability

    package = Package(
        name="github.com/Azure/azure-sdk-for-go", version="1", ecosystem="go", purl="pkg:golang/github.com/Azure/azure-sdk-for-go@1"
    )
    finding = blast_radius_to_finding(
        BlastRadius(
            package=package,
            vulnerability=Vulnerability(id="CVE-2026-9999", summary="test", severity=Severity.HIGH),
            affected_servers=[],
            affected_agents=[],
            exposed_credentials=[],
            exposed_tools=[],
        )
    )
    assert finding.asset.identifier == package.purl
