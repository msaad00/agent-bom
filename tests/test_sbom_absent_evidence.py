"""Portable inventories preserve supplied evidence and leave omissions unknown."""

import json

import pytest

from agent_bom.sbom import parse_cyclonedx, parse_spdx


def spdx2():
    return {
        "spdxVersion": "SPDX-2.3",
        "SPDXID": "SPDXRef-DOCUMENT",
        "packages": [
            {"SPDXID": "app", "name": "server", "primaryPackagePurpose": "APPLICATION"},
            {"SPDXID": "parent", "name": "parent", "versionInfo": "1"},
            {"SPDXID": "child", "name": "child", "versionInfo": "1"},
            {"SPDXID": "orphan", "name": "orphan", "versionInfo": "1"},
        ],
        "relationships": [
            {"spdxElementId": "app", "relationshipType": "DEPENDS_ON", "relatedSpdxElement": "parent"},
            {"spdxElementId": "parent", "relationshipType": "DEPENDS_ON", "relatedSpdxElement": "child"},
        ],
    }


def test_spdx2_context_is_not_package_and_explicit_lineage_is_preserved():
    packages = {p.name: p for p in parse_spdx(spdx2())}
    assert "server" not in packages
    assert packages["parent"].is_direct is True
    assert packages["child"].is_direct is False
    assert packages["child"].parent_package == "parent"
    assert packages["orphan"].is_direct is None
    assert all(p.reachability_evidence == "declaration_only" for p in packages.values())
    assert all(p.dependency_scope == "unknown" for p in packages.values())


def test_spdx3_absent_directness_does_not_invent_runtime_evidence():
    packages = parse_spdx(
        {
            "spdxVersion": "SPDX-3.0.1",
            "elements": [{"type": "software_Package", "spdxId": "p", "name": "library", "software_packageVersion": "1"}],
        }
    )
    assert packages[0].is_direct is None
    assert packages[0].reachability_evidence == "declaration_only"


def test_cyclonedx_cvss_vector_survives_native_rating_import():
    vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    doc = {
        "bomFormat": "CycloneDX",
        "components": [{"bom-ref": "p", "type": "library", "name": "library", "version": "1"}],
        "vulnerabilities": [
            {
                "id": "CVE-2020-0001",
                "ratings": [{"score": 9.8, "severity": "critical", "method": "CVSSv31", "vector": vector}],
                "affects": [{"ref": "p"}],
            }
        ],
    }
    package = parse_cyclonedx(doc)[0]
    assert package.vulnerabilities[0].cvss_vector == vector
    assert package.vulnerabilities[0].network_exploitable is True
    assert package.is_direct is None


def test_imported_spdx_absent_completeness_stays_unknown_on_cyclonedx_export(tmp_path):
    import json

    from agent_bom.models import AIBOMReport
    from agent_bom.output.cyclonedx_fmt import to_cyclonedx
    from agent_bom.parsers.sbom_context import load_sbom_agents

    path = tmp_path / "sbom.json"
    path.write_text(json.dumps(spdx2()))
    agents, _ = load_sbom_agents(str(path))
    exported = to_cyclonedx(AIBOMReport(agents=agents))
    assert exported["compositions"][0]["aggregate"] == "unknown"


def test_shared_cyclonedx_component_has_context_specific_parent(tmp_path):
    import json

    from agent_bom.parsers.sbom_context import load_sbom_agents

    def component(ref, role=None):
        return {
            "bom-ref": ref,
            "type": "application" if role else "library",
            "name": ref,
            "version": "1",
            "properties": [{"name": "agent-bom:type", "value": role}] if role else [],
        }

    doc = {
        "bomFormat": "CycloneDX",
        "components": [
            component("agent", "ai-agent"),
            component("s1", "mcp-server"),
            component("s2", "mcp-server"),
            component("p1"),
            component("p2"),
            component("shared"),
        ],
        "dependencies": [
            {"ref": "agent", "dependsOn": ["s1", "s2"]},
            {"ref": "s1", "dependsOn": ["p1"]},
            {"ref": "s2", "dependsOn": ["p2"]},
            {"ref": "p1", "dependsOn": ["shared"]},
            {"ref": "p2", "dependsOn": ["shared"]},
        ],
    }
    path = tmp_path / "bom.json"
    path.write_text(json.dumps(doc))
    agents, _ = load_sbom_agents(str(path))
    servers = {s.name: s for a in agents for s in a.mcp_servers}
    first = next(p for p in servers["s1"].packages if p.name == "shared")
    second = next(p for p in servers["s2"].packages if p.name == "shared")
    assert first.parent_package == "p1"
    assert second.parent_package == "p2"
    assert first is not second


@pytest.mark.parametrize("format_name", ["spdx2", "spdx3"])
def test_spdx_retains_declared_agent_server_membership(tmp_path, format_name):
    from agent_bom.models import Agent, AgentType, AIBOMReport, MCPServer, Package
    from agent_bom.output.spdx2_fmt import to_spdx2
    from agent_bom.output.spdx_fmt import to_spdx
    from agent_bom.parsers.sbom_context import load_sbom_agents

    report = AIBOMReport(
        agents=[
            Agent(
                name="agent",
                agent_type=AgentType.CUSTOM,
                config_path="config",
                mcp_servers=[
                    MCPServer(name="one", command="one", packages=[Package(name="first", version="1", ecosystem="npm")]),
                    MCPServer(name="two", command="two", packages=[Package(name="second", version="2", ecosystem="npm")]),
                ],
            )
        ]
    )
    document = to_spdx2(report) if format_name == "spdx2" else to_spdx(report)
    path = tmp_path / "bom.json"
    path.write_text(json.dumps(document))
    agents, _ = load_sbom_agents(str(path))
    memberships = {s.name: {p.name for p in s.packages} for a in agents for s in a.mcp_servers}
    assert memberships == {"one": {"first"}, "two": {"second"}}


def test_cyclonedx_unassigned_inventory_is_retained_with_a_coverage_gap(tmp_path):
    from agent_bom.parsers.sbom_context import load_sbom_agents

    def context(ref, role):
        return {"bom-ref": ref, "type": "application", "name": ref, "properties": [{"name": "agent-bom:type", "value": role}]}

    document = {
        "bomFormat": "CycloneDX",
        "components": [
            context("a", "ai-agent"),
            context("s", "mcp-server"),
            {"bom-ref": "orphan", "type": "library", "name": "unassigned", "version": "1", "purl": "pkg:npm/unassigned@1"},
        ],
        "dependencies": [{"ref": "a", "dependsOn": ["s"]}],
        "compositions": [{"aggregate": "complete"}],
    }
    path = tmp_path / "bom.json"
    path.write_text(json.dumps(document))
    agents, _ = load_sbom_agents(str(path))
    assert [p.name for a in agents for s in a.mcp_servers for p in s.packages] == ["unassigned"]
    assert any(a.metadata["sbom_import"]["composition_complete"] is False for a in agents)
