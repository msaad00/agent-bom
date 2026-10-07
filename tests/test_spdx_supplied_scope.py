"""Native SPDX relationship scopes survive import and portable re-export."""

import pytest

from agent_bom.models import Agent, AgentType, AIBOMReport, MCPServer
from agent_bom.output.cyclonedx_fmt import to_cyclonedx
from agent_bom.sbom import parse_spdx


@pytest.mark.parametrize(
    "scope,relation",
    [("runtime", "RUNTIME_DEPENDENCY_OF"), ("dev", "DEV_DEPENDENCY_OF"), ("test", "TEST_DEPENDENCY_OF"), ("build", "BUILD_DEPENDENCY_OF")],
)
def test_spdx2_supplied_scope_is_preserved(scope, relation):
    document = {
        "spdxVersion": "SPDX-2.3",
        "packages": [
            {"SPDXID": "app", "name": "application", "primaryPackagePurpose": "APPLICATION"},
            {
                "SPDXID": "p",
                "name": "library",
                "versionInfo": "1.0.0",
                "externalRefs": [{"referenceType": "purl", "referenceLocator": "pkg:npm/library@1.0.0"}],
            },
        ],
        "relationships": [{"spdxElementId": "p", "relationshipType": relation, "relatedSpdxElement": "app"}],
    }
    packages = parse_spdx(document)
    assert {package.name for package in packages} == {"application", "library"}
    library = next(package for package in packages if package.name == "library")
    assert library.dependency_scope == scope
    assert library.is_direct is True
    agent = Agent(
        name="import",
        agent_type=AgentType.CUSTOM,
        config_path="bom.json",
        mcp_servers=[MCPServer(name="inventory", command="sbom", packages=packages)],
    )
    exported = to_cyclonedx(AIBOMReport(agents=[agent]))
    component = next(c for c in exported["components"] if c["name"] == "library")
    assert {p["name"]: p["value"] for p in component["properties"]}["agent-bom:dependency-scope"] == scope


def test_spdx3_lifecycle_scope_is_preserved():
    packages = parse_spdx(
        {
            "spdxVersion": "SPDX-3.0.1",
            "elements": [
                {"type": "software_Package", "spdxId": "app", "name": "application", "software_primaryPurpose": "application"},
                {"type": "software_Package", "spdxId": "p", "name": "library", "software_packageVersion": "1"},
                {"type": "LifecycleScopedRelationship", "relationshipType": "dependsOn", "from": "app", "to": ["p"], "scope": "test"},
            ],
        }
    )
    assert {package.name for package in packages} == {"application", "library"}
    assert next(package for package in packages if package.name == "library").dependency_scope == "test"


@pytest.mark.parametrize("format_name", ["spdx2", "spdx3"])
def test_supplied_scope_survives_spdx_reexport(format_name):
    from agent_bom.output.spdx2_fmt import to_spdx2
    from agent_bom.output.spdx_fmt import to_spdx

    packages = parse_spdx(
        {
            "spdxVersion": "SPDX-2.3",
            "packages": [
                {"SPDXID": "app", "name": "application", "primaryPackagePurpose": "APPLICATION"},
                {"SPDXID": "p", "name": "library", "versionInfo": "1"},
            ],
            "relationships": [{"spdxElementId": "p", "relationshipType": "TEST_DEPENDENCY_OF", "relatedSpdxElement": "app"}],
        }
    )
    report = AIBOMReport(
        agents=[
            Agent(
                name="import",
                agent_type=AgentType.CUSTOM,
                config_path="bom.json",
                mcp_servers=[MCPServer(name="inventory", command="sbom", packages=packages)],
            )
        ]
    )
    document = to_spdx2(report) if format_name == "spdx2" else to_spdx(report)
    restored = parse_spdx(document)
    assert {package.name for package in restored} == {"application", "library"}
    assert next(package for package in restored if package.name == "library").dependency_scope == "test"
