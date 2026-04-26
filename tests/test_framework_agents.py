from __future__ import annotations

from pathlib import Path

from agent_bom.ai_components import scan_source
from agent_bom.ai_components.framework_agents import scan_framework_agents


def test_langgraph_agent_relationships_are_not_mcp_servers(tmp_path: Path):
    app = tmp_path / "graph_agent.py"
    app.write_text(
        "import os\n"
        "from langgraph.prebuilt import create_react_agent\n"
        "from langchain_core.tools import tool\n"
        "\n"
        "@tool\n"
        "def search(query: str) -> str:\n"
        "    return query\n"
        "\n"
        "model = os.getenv('OPENAI_API_KEY')\n"
        "agent = create_react_agent('gpt-4o', [search])\n",
        encoding="utf-8",
    )

    agents = scan_framework_agents(tmp_path)

    assert len(agents) == 1
    agent = agents[0].to_dict()
    assert agent["kind"] == "framework_agent"
    assert agent["framework"] == "langgraph"
    assert agent["model_refs"] == ["gpt-4o"]
    assert agent["credential_refs"] == ["OPENAI_API_KEY"]
    assert agent["capabilities"][0]["name"] == "search"
    assert agent["provenance"]["relationship_model"] == "non-mcp-framework"


def test_autogen_and_crewai_relationships_preserve_framework_context(tmp_path: Path):
    (tmp_path / "autogen_app.py").write_text(
        "from autogen_agentchat.agents import AssistantAgent\n"
        "\n"
        "def lookup(query):\n"
        "    return query\n"
        "\n"
        "planner = AssistantAgent('planner', model='gpt-4o-mini', tools=[lookup])\n",
        encoding="utf-8",
    )
    (tmp_path / "crew_app.py").write_text(
        "from crewai import Agent\n\ndef summarize(text):\n    return text\n\nresearcher = Agent(role='Researcher', tools=[summarize])\n",
        encoding="utf-8",
    )

    payloads = [agent.to_dict() for agent in scan_framework_agents(tmp_path)]
    by_framework = {agent["framework"]: agent for agent in payloads}

    assert by_framework["autogen"]["name"] == "planner"
    assert by_framework["autogen"]["model_refs"] == ["gpt-4o-mini"]
    assert by_framework["autogen"]["capabilities"][0]["name"] == "lookup"
    assert by_framework["crewai"]["name"] == "Researcher"
    assert by_framework["crewai"]["capabilities"][0]["name"] == "summarize"


def test_ai_component_report_includes_framework_agent_relationships(tmp_path: Path):
    (tmp_path / "assistant.py").write_text(
        "from openai import OpenAI\n"
        "\n"
        "client = OpenAI()\n"
        "assistant = client.beta.assistants.create(\n"
        "    name='support-assistant',\n"
        "    model='gpt-4o',\n"
        "    tools=[{'type': 'function', 'function': {'name': 'lookup_ticket'}}],\n"
        ")\n",
        encoding="utf-8",
    )

    report = scan_source(tmp_path)
    data = report.to_dict()

    assert data["stats"]["framework_agents"] == 1
    agent = data["framework_agents"][0]
    assert agent["framework"] == "openai-assistants"
    assert agent["name"] == "support-assistant"
    assert agent["model_refs"] == ["gpt-4o"]
    assert agent["capabilities"][0]["name"] == "lookup_ticket"


def test_crewai_crew_static_topology_edges(tmp_path: Path):
    (tmp_path / "crew.py").write_text(
        "from crewai import Agent, Crew\n"
        "\n"
        "researcher = Agent(role='Researcher')\n"
        "writer = Agent(role='Writer')\n"
        "crew = Crew(agents=[researcher, writer])\n",
        encoding="utf-8",
    )

    payloads = [agent.to_dict() for agent in scan_framework_agents(tmp_path)]
    crew = next(agent for agent in payloads if agent["name"] == "crew")

    relationships = {(edge["source_name"], edge["target_name"], edge["relationship"]) for edge in crew["topology_edges"]}
    assert ("crew", "Researcher", "delegated_to") in relationships
    assert ("crew", "Writer", "delegated_to") in relationships

    researcher = next(agent for agent in payloads if agent["name"] == "Researcher")
    share_edges = {(edge["source_name"], edge["target_name"], edge["relationship"]) for edge in researcher["topology_edges"]}
    assert ("Researcher", "Writer", "shares_server") in share_edges


def test_langgraph_static_add_edge_topology(tmp_path: Path):
    (tmp_path / "graph.py").write_text(
        "from langgraph.graph import StateGraph\n"
        "\n"
        "graph = StateGraph(dict)\n"
        "graph.add_node('research', lambda s: s)\n"
        "graph.add_node('write', lambda s: s)\n"
        "graph.add_edge('research', 'write')\n",
        encoding="utf-8",
    )

    payloads = [agent.to_dict() for agent in scan_framework_agents(tmp_path)]
    research = next(agent for agent in payloads if agent["name"] == "research")

    assert research["framework"] == "langgraph"
    assert research["topology_edges"][0]["relationship"] == "delegated_to"
    assert research["topology_edges"][0]["target_name"] == "write"


def test_autogen_groupchat_static_topology_edges(tmp_path: Path):
    (tmp_path / "chat.py").write_text(
        "from autogen import AssistantAgent, UserProxyAgent, GroupChat\n"
        "\n"
        "assistant = AssistantAgent('assistant')\n"
        "user = UserProxyAgent('user')\n"
        "chat = GroupChat(agents=[assistant, user])\n",
        encoding="utf-8",
    )

    payloads = [agent.to_dict() for agent in scan_framework_agents(tmp_path)]
    chat = next(agent for agent in payloads if agent["name"] == "chat")

    relationships = {(edge["source_name"], edge["target_name"], edge["relationship"]) for edge in chat["topology_edges"]}
    assert ("chat", "assistant", "delegated_to") in relationships
    assert ("chat", "user", "delegated_to") in relationships
