"""SBOM exports retain observed dependency paths without guessing parents."""

from __future__ import annotations

import pytest

from agent_bom.models import Agent, AgentType, AIBOMReport, MCPServer, Package
from agent_bom.output.cyclonedx_fmt import to_cyclonedx
from agent_bom.output.spdx2_fmt import to_spdx2
from agent_bom.output.spdx_fmt import to_spdx


def _report(packages: list[Package], other: list[Package] | None = None) -> AIBOMReport:
    servers = [MCPServer(name="main-server", command="node", packages=packages)]
    if other:
        servers.append(MCPServer(name="other-server", command="python", packages=other))
    return AIBOMReport(agents=[Agent(name="agent", agent_type=AgentType.CUSTOM, config_path="sample.json", mcp_servers=servers)])


def _edges(report: AIBOMReport, fmt: str) -> tuple[set[tuple[str, str]], dict]:
    if fmt == "cyclonedx":
        doc = to_cyclonedx(report)
        names = {c["bom-ref"]: c["name"] for c in doc["components"]}
        edges = {(names[d["ref"]], names[target]) for d in doc["dependencies"] for target in d["dependsOn"]}
    elif fmt == "spdx3":
        doc = to_spdx(report)
        names = {e["spdxId"]: e["name"] for e in doc["@graph"] if "name" in e}
        edges = {(names[e["from"]], names[target]) for e in doc["@graph"] if e.get("relationshipType") == "dependsOn" for target in e["to"]}
    else:
        doc = to_spdx2(report, version=fmt)
        names = {p["SPDXID"]: p["name"] for p in doc["packages"]}
        edges = {
            (names[e["spdxElementId"]], names[e["relatedSpdxElement"]])
            for e in doc["relationships"]
            if e["relationshipType"] == "DEPENDS_ON"
        }
    return edges, doc


@pytest.mark.parametrize("fmt", ["cyclonedx", "spdx3", "2.3", "2.2"])
def test_export_preserves_dependency_chain_independent_of_package_order(fmt):
    leaf = Package(name="leaf", version="1", ecosystem="npm", is_direct=False, parent_package="middle", dependency_depth=2)
    middle = Package(name="middle", version="1", ecosystem="npm", is_direct=False, parent_package="root", dependency_depth=1)
    root = Package(name="root", version="1", ecosystem="npm")
    edges, _ = _edges(_report([leaf, middle, root]), fmt)
    assert ("root", "middle") in edges
    assert ("middle", "leaf") in edges
    assert ("main-server", "root") in edges
    assert ("main-server", "middle") not in edges
    assert ("main-server", "leaf") not in edges


@pytest.mark.parametrize("fmt", ["cyclonedx", "spdx3", "2.3", "2.2"])
@pytest.mark.parametrize("case", ["missing", "ambiguous", "other-server", "other-ecosystem", "self"])
def test_export_never_guesses_unresolved_parent(fmt, case):
    child = Package(name="child", version="1", ecosystem="npm", is_direct=False, parent_package="parent")
    packages = [child]
    other = None
    if case == "ambiguous":
        packages += [Package(name="parent", version=v, ecosystem="npm") for v in ["1", "2"]]
    elif case == "other-server":
        other = [Package(name="parent", version="1", ecosystem="npm")]
    elif case == "other-ecosystem":
        packages += [Package(name="parent", version="1", ecosystem="pypi")]
    elif case == "self":
        child.parent_package = "child"
    edges, document = _edges(_report(packages, other), fmt)
    assert not any(target == "child" for _, target in edges)
    if fmt == "cyclonedx":
        assert document["compositions"][0]["aggregate"] == "incomplete"
    else:
        assert "parent-resolution=unresolved" in str(document)


@pytest.mark.parametrize("fmt", ["cyclonedx", "spdx3", "2.3", "2.2"])
def test_export_normalizes_pypi_parent_and_ignores_duplicate_observations(fmt):
    parent = Package(name="Example_Package", version="1", ecosystem="pypi")
    child = Package(name="child", version="1", ecosystem="pypi", is_direct=False, parent_package="example-package")
    edges, _ = _edges(_report([child, parent, parent]), fmt)
    assert ("Example_Package", "child") in edges


@pytest.mark.parametrize("fmt", ["cyclonedx", "spdx3", "2.3", "2.2"])
def test_export_keeps_equal_names_with_distinct_package_urls_separate(fmt):
    packages = [
        Package(name="parent", version="1", ecosystem="deb", purl=f"pkg:deb/{distro}/parent@1?arch=amd64")
        for distro in ["debian", "ubuntu"]
    ]
    packages.append(Package(name="child", version="1", ecosystem="deb", is_direct=False, parent_package="parent"))
    edges, document = _edges(_report(packages), fmt)
    assert not any(target == "child" for _, target in edges)
    if fmt == "cyclonedx":
        entries = document["components"]
    elif fmt == "spdx3":
        entries = document["@graph"]
    else:
        entries = document["packages"]
    assert len([e for e in entries if e.get("name") == "parent"]) == 2


@pytest.mark.parametrize("fmt", ["cyclonedx", "spdx3", "2.3"])
def test_dependency_hierarchy_documents_validate_against_official_schemas(fmt):
    import json
    from pathlib import Path

    from jsonschema import Draft7Validator, Draft201909Validator, Draft202012Validator
    from referencing import Registry, Resource

    packages = [
        Package(name="parent", version="1.0.0", ecosystem="npm"),
        Package(name="child", version="1.0.0", ecosystem="npm", is_direct=False, parent_package="parent"),
        Package(name="unresolved", version="1.0.0", ecosystem="npm", is_direct=False),
    ]
    _, document = _edges(_report(packages), fmt)
    fixtures = Path(__file__).parent / "fixtures"
    if fmt == "cyclonedx":
        names = ["cyclonedx-1.7.schema.json", "spdx.schema.json", "jsf-0.82.schema.json", "cryptography-defs.schema.json"]
        schemas = [json.loads((fixtures / name).read_text()) for name in names]
        registry = Registry().with_resources([(schema["$id"], Resource.from_contents(schema)) for schema in schemas])
        validator = Draft7Validator(schemas[0], registry=registry)
    else:
        filename = "spdx-3.0.1.schema.json" if fmt == "spdx3" else "spdx-2.3.schema.json"
        validator_type = Draft202012Validator if fmt == "spdx3" else Draft201909Validator
        validator = validator_type(json.loads((fixtures / filename).read_text()))
    errors = [f"{error.json_path}: {error.message}" for error in validator.iter_errors(document)]
    assert errors == []
