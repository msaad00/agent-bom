"""One project root is one agent, whichever discovery sources observed it."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from agent_bom.discovery.identity import consolidate_project_agents
from agent_bom.models import Agent, AgentType, MCPServer, MCPTool, Package, ServerSurface


def _project_sources(root: Path) -> list[Agent]:
    return [
        Agent(
            name=f"project:{root.name}",
            agent_type=AgentType.CUSTOM,
            config_path=str(root / ".mcp.json"),
            source="project-config",
            metadata={"project_root": str(root)},
            mcp_servers=[
                MCPServer(name="filesystem", command="npx", args=["-y", "@modelcontextprotocol/server-filesystem"]),
                MCPServer(name="github", command="npx", args=["-y", "form-data@4.0.0"], env={"GITHUB_PERSONAL_ACCESS_TOKEN": "***"}),
            ],
        ),
        Agent(
            name=f"project:{root.name}",
            agent_type=AgentType.CUSTOM,
            config_path=str(root),
            source="project",
            mcp_servers=[
                MCPServer(
                    name="app",
                    command="project",
                    surface=ServerSurface.OTHER,
                    packages=[Package(name="pyyaml", version="5.3", ecosystem="pypi")],
                )
            ],
        ),
        Agent(
            name="ai-inventory",
            agent_type=AgentType.CUSTOM,
            config_path=str(root),
            source="ai-inventory",
            mcp_servers=[MCPServer(name="ai-inventory", surface=ServerSurface.AI_INVENTORY)],
        ),
        Agent(
            name="langchain:react-agent",
            agent_type=AgentType.CUSTOM,
            config_path=str(root),
            source="python-agents",
            mcp_servers=[
                MCPServer(
                    name="langchain:react-agent",
                    command="python",
                    surface=ServerSurface.OTHER,
                    tools=[MCPTool(name="lookup", description="agent tool")],
                )
            ],
        ),
        Agent(
            name="langchain:agent:agentexecutor",
            agent_type=AgentType.CUSTOM,
            config_path=str(root),
            source="python-agents",
            mcp_servers=[MCPServer(name="langchain:agent:agentexecutor", command="python", surface=ServerSurface.OTHER)],
        ),
    ]


def _host_agent() -> Agent:
    return Agent(
        name="claude-code",
        agent_type=AgentType.CLAUDE_CODE,
        config_path="/home/user/.claude.json",
        mcp_servers=[MCPServer(name="memory", command="npx", args=["-y", "@modelcontextprotocol/server-memory"])],
    )


def test_all_sources_for_one_project_root_collapse_into_one_agent(tmp_path: Path) -> None:
    root = tmp_path / "sampleapp"
    root.mkdir()
    manifest_agent_id = _project_sources(root)[1].stable_id

    merged = consolidate_project_agents([*_project_sources(root), _host_agent()])

    assert [agent.name for agent in merged] == ["project:sampleapp", "claude-code"]
    project = merged[0]
    assert project.source == "project"
    assert project.agent_type == AgentType.CUSTOM
    # Identity continuity: the canonical id stays the manifest-rooted project id.
    assert project.stable_id == manifest_agent_id
    assert [server.name for server in project.mcp_servers] == [
        "filesystem",
        "github",
        "app",
        "ai-inventory",
        "langchain:react-agent",
        "langchain:agent:agentexecutor",
    ]
    assert project.metadata["project_root"] == str(root.resolve())
    assert project.metadata["evidence_sources"] == ["ai-inventory", "project", "project-config", "python-agents"]
    assert project.metadata["code_agents"] == ["langchain:react-agent", "langchain:agent:agentexecutor"]
    # Only real MCP servers count as MCP servers on the merged agent.
    assert sum(1 for server in project.mcp_servers if server.is_mcp_surface) == 2


def test_distinct_project_roots_stay_distinct(tmp_path: Path) -> None:
    first = tmp_path / "a"
    second = tmp_path / "b"
    first.mkdir()
    second.mkdir()

    merged = consolidate_project_agents([*_project_sources(first), *_project_sources(second)])

    assert sorted(agent.name for agent in merged) == ["project:a", "project:b"]


def test_consolidation_is_idempotent(tmp_path: Path) -> None:
    root = tmp_path / "sampleapp"
    root.mkdir()

    once = consolidate_project_agents(_project_sources(root))
    twice = consolidate_project_agents(once)

    assert [agent.stable_id for agent in twice] == [agent.stable_id for agent in once]
    assert [server.name for server in twice[0].mcp_servers] == [server.name for server in once[0].mcp_servers]


def test_single_source_agent_is_left_untouched(tmp_path: Path) -> None:
    root = tmp_path / "solo"
    root.mkdir()
    only = _project_sources(root)[3]

    merged = consolidate_project_agents([only, _host_agent()])

    assert merged[0] is only
    assert merged[0].name == "langchain:react-agent"


@pytest.mark.parametrize("identity_field", ["source_id", "device_fingerprint"])
def test_project_consolidation_preserves_explicit_agent_identities(tmp_path: Path, identity_field: str) -> None:
    members = [
        Agent(
            name="project:worker",
            agent_type=AgentType.CUSTOM,
            config_path=str(tmp_path),
            source="project",
            metadata={"project_root": str(tmp_path)},
            **{identity_field: identity},
        )
        for identity in ("worker-one", "worker-two")
    ]
    expected = [member.stable_id for member in members]

    merged = consolidate_project_agents(members)

    assert [member.stable_id for member in merged] == expected
    assert [getattr(member, identity_field) for member in merged] == ["worker-one", "worker-two"]


def test_project_root_metadata_does_not_absorb_a_host_agent(tmp_path: Path) -> None:
    host = _host_agent()
    host.metadata["project_root"] = str(tmp_path)
    members = _project_sources(tmp_path)

    merged = consolidate_project_agents([*members, host])

    assert len(merged) == 2
    assert merged[-1] is host


def _write_sample_project(root: Path) -> None:
    (root / "app").mkdir(parents=True)
    (root / ".mcp.json").write_text(
        json.dumps(
            {
                "mcpServers": {
                    "filesystem": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"]},
                    "github": {
                        "command": "npx",
                        "args": ["-y", "@modelcontextprotocol/server-github"],
                        "env": {"GITHUB_PERSONAL_ACCESS_TOKEN": "placeholder"},
                    },
                }
            }
        )
    )
    (root / "app" / "agent.py").write_text(
        "from langchain.agents import AgentExecutor, create_react_agent\n"
        "from langchain_core.tools import tool\n\n\n"
        "@tool\n"
        "def lookup(q: str) -> str:\n"
        '    """Lookup."""\n'
        "    return q\n\n\n"
        "agent = create_react_agent(llm=None, tools=[lookup], prompt=None)\n"
        "executor = AgentExecutor(agent=agent, tools=[lookup])\n"
    )
    (root / "app" / "requirements.txt").write_text("langchain==0.0.300\npyyaml==5.3\nrequests==2.19.0\n")


def test_project_scan_reports_one_agent_and_only_real_mcp_servers(tmp_path: Path, monkeypatch) -> None:
    from agent_bom.cli import main

    monkeypatch.delenv("AGENT_BOM_CONFIG", raising=False)
    root = tmp_path / "sampleapp"
    _write_sample_project(root)
    out = tmp_path / "report.json"

    result = CliRunner().invoke(
        main,
        ["scan", "-p", str(root), "--no-scan", "--offline", "--no-auto-update-db", "-f", "json", "-o", str(out)],
        catch_exceptions=False,
    )

    assert result.exit_code == 0, result.output
    report = json.loads(out.read_text())
    assert [agent["name"] for agent in report["agents"]] == ["project:sampleapp"]
    assert report["summary"]["total_agents"] == 1
    assert report["summary"]["total_mcp_servers"] == 2
    servers = {server["name"] for server in report["agents"][0]["mcp_servers"]}
    assert {"filesystem", "github", "app"} <= servers
