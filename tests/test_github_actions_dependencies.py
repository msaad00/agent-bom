"""GitHub Actions dependency inventory regressions."""

from __future__ import annotations

from agent_bom.github_actions import attach_github_action_packages, discover_github_action_packages, scan_github_actions
from agent_bom.models import Agent, AgentType, MCPServer, Package, ServerSurface


def _write_workflow(tmp_path, name: str, content: str) -> None:
    workflow_dir = tmp_path / ".github" / "workflows"
    workflow_dir.mkdir(parents=True, exist_ok=True)
    (workflow_dir / name).write_text(content, encoding="utf-8")


def test_non_ai_workflow_actions_are_inventory_dependencies(tmp_path) -> None:
    sha = "0123456789abcdef0123456789abcdef01234567"
    _write_workflow(
        tmp_path,
        "ci.yml",
        f"""name: CI
on: push
permissions: {{}}
jobs:
  test:
    uses: octo-org/automation/.github/workflows/python.yml@main
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@{sha} # v4
      - uses: actions/setup-python@v5
      - uses: ./local-action
      - uses: docker://alpine:3.20
      - run: pytest
""",
    )

    agents, warnings = scan_github_actions(str(tmp_path))
    packages = discover_github_action_packages(str(tmp_path))

    assert agents == []
    assert len(packages) == 3
    assert {(package.ecosystem, package.name, package.version) for package in packages} == {
        ("github-action", "actions/checkout", sha),
        ("github-action", "actions/setup-python", "v5"),
        ("github-action-workflow", "octo-org/automation/.github/workflows/python.yml", "main"),
    }
    assert not any("local-action" in package.name or "alpine" in package.name for package in packages)
    assert any("actions/setup-python@v5" in warning for warning in warnings)
    assert any("python.yml@main" in warning for warning in warnings)

    exact = next(package for package in packages if package.name == "actions/checkout")
    assert exact.version_source == "command_pin"
    assert exact.declared_version == sha
    assert exact.resolved_version == sha
    assert exact.version_confidence == "exact"
    assert exact.floating_reference is False
    assert exact.version_evidence == [
        {
            "type": "command_pin",
            "source_file": ".github/workflows/ci.yml",
            "line": 10,
            "parser": "github_actions",
        }
    ]

    floating = next(package for package in packages if package.name == "actions/setup-python")
    assert floating.declared_version == "v5"
    assert floating.resolved_version is None
    assert floating.version_confidence == "low"
    assert floating.floating_reference is True
    assert "mutable" in (floating.floating_reference_reason or "")


def test_duplicate_action_coordinates_preserve_each_workflow_evidence(tmp_path) -> None:
    _write_workflow(
        tmp_path,
        "build.yml",
        """name: Build
on: push
permissions: {}
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
""",
    )
    _write_workflow(
        tmp_path,
        "test.yaml",
        """name: Test
on: pull_request
permissions: {}
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
""",
    )

    packages = discover_github_action_packages(str(tmp_path))

    assert len(packages) == 1
    assert packages[0].name == "actions/checkout"
    assert packages[0].version == "v4"
    assert [item["source_file"] for item in packages[0].version_evidence] == [
        ".github/workflows/build.yml",
        ".github/workflows/test.yaml",
    ]


def test_dynamic_action_owner_is_not_invented_as_a_package(tmp_path) -> None:
    _write_workflow(
        tmp_path,
        "dynamic.yml",
        """name: Dynamic
on: push
permissions: {}
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: ${{ matrix.owner }}/action@v1
      - uses: owner/action@${{ matrix.ref }}
      - uses: -/-/!/-/!/-/!/-/!/-/!/-/!@v1
""",
    )

    packages = discover_github_action_packages(str(tmp_path))

    assert [(package.name, package.version) for package in packages] == [
        ("owner/action", "${{ matrix.ref }}"),
    ]
    assert packages[0].floating_reference is True
    assert packages[0].resolved_version is None
    assert packages[0].version_confidence == "unknown"


def test_action_dependencies_attach_to_existing_project_inventory(tmp_path) -> None:
    project_agent = Agent(
        name=f"project:{tmp_path.name}",
        agent_type=AgentType.CUSTOM,
        config_path=str(tmp_path),
        source="project",
        mcp_servers=[
            MCPServer(
                name=tmp_path.name,
                command="project",
                surface=ServerSurface.OTHER,
                packages=[Package(name="click", version="8.3.1", ecosystem="pypi")],
            )
        ],
    )
    action_package = Package(name="actions/checkout", version="v4", ecosystem="github-action")
    agents = [project_agent]

    attach_github_action_packages(agents, tmp_path, [action_package])
    attach_github_action_packages(agents, tmp_path, [action_package])

    assert len(agents) == 1
    action_server = next(server for server in project_agent.mcp_servers if server.name == "github-actions")
    assert action_server.surface == ServerSurface.OTHER
    assert action_server.packages == [action_package]


def test_action_only_repository_gets_a_project_inventory_container(tmp_path) -> None:
    action_package = Package(name="actions/checkout", version="v4", ecosystem="github-action")
    agents: list[Agent] = []

    attach_github_action_packages(agents, tmp_path, [action_package])

    assert len(agents) == 1
    assert agents[0].name == f"project:{tmp_path.name}"
    assert agents[0].source == "project"
    assert agents[0].mcp_servers[0].name == "github-actions"
    assert agents[0].mcp_servers[0].packages == [action_package]


def test_action_dependency_identity_reaches_json_sboms_and_graph(tmp_path) -> None:
    from agent_bom.graph.builder import build_unified_graph_from_report
    from agent_bom.models import AIBOMReport
    from agent_bom.output import to_cyclonedx, to_json, to_spdx

    sha = "0123456789abcdef0123456789abcdef01234567"
    _write_workflow(
        tmp_path,
        "ci.yml",
        f"""name: CI
on: push
permissions: {{}}
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@{sha}
""",
    )
    packages = discover_github_action_packages(str(tmp_path))
    agents: list[Agent] = []
    attach_github_action_packages(agents, tmp_path, packages)
    report = AIBOMReport(agents=agents, tool_version="0.102.0")

    payload = to_json(report)
    json_package = payload["agents"][0]["mcp_servers"][0]["packages"][0]
    assert json_package["ecosystem"] == "github-action"
    assert json_package["version_provenance"]["confidence"] == "exact"
    assert json_package["discovery_provenance"]["source_type"] == "local_discovery"
    assert json_package["discovery_provenance"]["collector"] == "github_actions"

    cyclonedx = to_cyclonedx(report)
    cdx_package = next(component for component in cyclonedx["components"] if component["name"] == "actions/checkout")
    cdx_properties = {item["name"]: item["value"] for item in cdx_package["properties"]}
    assert cdx_properties["agent-bom:ecosystem"] == "github-action"
    assert cdx_properties["agent-bom:discovery-provenance:source-type"] == "local_discovery"
    assert cdx_properties["agent-bom:discovery-provenance:collector"] == "github_actions"

    spdx = to_spdx(report)
    spdx_package = next(element for element in spdx["@graph"] if element.get("name") == "actions/checkout")
    spdx_statements = {annotation["statement"] for annotation in spdx_package["annotation"]}
    assert "agent-bom:ecosystem=github-action" in spdx_statements
    assert "agent-bom:discovery-provenance-source-type=local_discovery" in spdx_statements
    assert "agent-bom:discovery-provenance-collector=github_actions" in spdx_statements

    graph = build_unified_graph_from_report(payload)
    package_node = next(node for node in graph.nodes.values() if node.label == f"actions/checkout@{sha}")
    assert package_node.attributes["ecosystem"] == "github-action"
    assert package_node.attributes["version_provenance"]["confidence"] == "exact"
    assert package_node.attributes["discovery_provenance"]["collector"] == "github_actions"
