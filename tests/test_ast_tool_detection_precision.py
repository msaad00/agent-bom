"""Agent-tool detection must not claim ordinary web handlers.

Matching decorator names by substring made every ``@action`` on a Django REST
viewset an agent tool, and gave consumers no way to tell the difference because
the matching decorator was computed but never emitted.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from agent_bom.ai_components.framework_agents import _collect_tools
from agent_bom.ast_analyzer import analyze_project
from agent_bom.python_agents import _extract_agent_defs

# An agent definition, so the third detector's decorator-resolved tools have
# somewhere to surface. Its tool table is local to the extraction pass.
AGENT_HARNESS = """
from langchain.agents import AgentExecutor

agent = AgentExecutor(tools=[handler])
"""


def _python_agent_tool_names(source: str) -> set[str]:
    """Tools the python_agents detector resolved from a decorator, at high confidence."""
    defs = _extract_agent_defs(source + AGENT_HARNESS, "mod.py")
    return {name for d in defs for name, kind, confidence in d.tools if kind == "decorator" and confidence == "high"}


DJANGO_VIEWSET = '''
from rest_framework import viewsets
from rest_framework.decorators import action


class GenerationViewSet(viewsets.ModelViewSet):
    @action(detail=True, methods=["post"])
    def approve(self, request, job_id=None):
        """Approve a job."""

    @action(detail=True, methods=["get"], url_path=r"download/(?P<filename>[^/]+)")
    def download(self, request, job_id=None, filename=None):
        """Download an artifact."""
'''

AGENT_TOOLS = '''
from langchain_core.tools import tool
from llama_index.core.tools import FunctionTool


@tool
def search_docs(query: str) -> str:
    """Search the docs."""


@FunctionTool.from_defaults
def lookup_user(user_id: str) -> str:
    """Look up a user."""
'''


def _tool_names(project: Path) -> set[str]:
    return {t.name for t in analyze_project(project).tools}


def test_django_rest_action_is_not_an_agent_tool(tmp_path: Path) -> None:
    (tmp_path / "views.py").write_text(DJANGO_VIEWSET)

    assert _tool_names(tmp_path) == set()


def test_real_agent_tool_decorators_are_still_detected(tmp_path: Path) -> None:
    (tmp_path / "tools.py").write_text(AGENT_TOOLS)

    assert _tool_names(tmp_path) == {"search_docs", "lookup_user"}


def test_mixed_project_keeps_only_the_agent_tools(tmp_path: Path) -> None:
    (tmp_path / "views.py").write_text(DJANGO_VIEWSET)
    (tmp_path / "tools.py").write_text(AGENT_TOOLS)

    assert _tool_names(tmp_path) == {"search_docs", "lookup_user"}


@pytest.mark.parametrize(
    "decorator",
    ["@app.route('/x')", "@property", "@staticmethod", "@pytest.fixture", "@transaction.atomic"],
)
def test_ordinary_decorators_are_not_agent_tools(tmp_path: Path, decorator: str) -> None:
    (tmp_path / "mod.py").write_text(f"{decorator}\ndef handler():\n    pass\n")

    assert _tool_names(tmp_path) == set()


def test_emitted_tool_carries_the_decorator_that_matched(tmp_path: Path) -> None:
    """Consumers need the detection signal to filter on, not just a name."""
    (tmp_path / "tools.py").write_text(AGENT_TOOLS)

    payload = analyze_project(tmp_path).to_dict()
    entry = next(t for t in payload["tools"] if t["name"] == "search_docs")

    assert entry["decorators"] == ["tool"]


def test_pydantic_ai_tool_plain_is_still_an_agent_tool(tmp_path: Path) -> None:
    """``@agent.tool_plain`` is pydantic-ai's decorator for tools taking no RunContext.

    Tightening the substring match to whole dotted segments dropped it, which
    turns a real agent tool invisible — a worse failure than the false positive
    the tightening was fixing.
    """
    (tmp_path / "tools.py").write_text("@agent.tool_plain\ndef roll_die() -> str:\n    '''Roll a die.'''\n")

    assert _tool_names(tmp_path) == {"roll_die"}


# The framework-agent scanner is a second, independent tool detector. It carried
# the same ``action`` false positive, and additionally never resolved the applied
# decorator form ``@mcp.tool()`` because the name helper returned "" for a Call —
# so the canonical FastMCP tool decorator registered nothing at all.
AGENT_TOOL_DECORATORS = [
    "@tool",
    "@tool('search')",
    "@mcp.tool()",
    "@function_tool",
    "@function_tool()",
    "@agent.tool",
    "@agent.tool_plain",
    "@kernel_function",
    "@FunctionTool.from_defaults",
]

NON_AGENT_DECORATORS = [
    "@action",
    "@action(detail=True)",
    "@transaction.atomic",
    "@celery_app.task",
    "@app.route('/x')",
    "@property",
    "@staticmethod",
    "@pytest.fixture",
]


@pytest.mark.parametrize("decorator", AGENT_TOOL_DECORATORS)
def test_framework_scanner_collects_agent_tool_decorators(decorator: str) -> None:
    tree = ast.parse(f"{decorator}\ndef handler(query: str) -> str:\n    '''d'''\n")

    assert set(_collect_tools(tree)) == {"handler"}


@pytest.mark.parametrize("decorator", NON_AGENT_DECORATORS)
def test_framework_scanner_ignores_non_agent_decorators(decorator: str) -> None:
    tree = ast.parse(f"{decorator}\ndef handler(self, request):\n    pass\n")

    assert _collect_tools(tree) == {}


@pytest.mark.parametrize("decorator", AGENT_TOOL_DECORATORS)
def test_agent_scanner_collects_agent_tool_decorators(decorator: str) -> None:
    source = f"{decorator}\ndef handler(query: str) -> str:\n    '''d'''\n"

    assert "handler" in _python_agent_tool_names(source)


@pytest.mark.parametrize("decorator", NON_AGENT_DECORATORS)
def test_agent_scanner_ignores_non_agent_decorators(decorator: str) -> None:
    source = f"{decorator}\ndef handler(self, request):\n    pass\n"

    assert "handler" not in _python_agent_tool_names(source)


@pytest.mark.parametrize("decorator", AGENT_TOOL_DECORATORS + NON_AGENT_DECORATORS)
def test_all_three_tool_detectors_agree(tmp_path: Path, decorator: str) -> None:
    """Three separate detectors decide this. They must not disagree.

    Two of them were fixed independently and drifted apart; asserting the
    agreement is what stops the next fix from landing in only one of them.
    """
    source = f"{decorator}\ndef handler(query: str) -> str:\n    '''d'''\n"
    (tmp_path / "mod.py").write_text(source)
    tree = ast.parse(source)

    verdicts = {
        "ast": bool(_tool_names(tmp_path)),
        "framework": bool(_collect_tools(tree)),
        "agents": "handler" in _python_agent_tool_names(source),
    }

    assert len(set(verdicts.values())) == 1, verdicts


# --------------------------------------------------------------------------
# Low-level ``Server`` -- github.com/modelcontextprotocol/python-sdk
# --------------------------------------------------------------------------
# Servers built on the low-level ``Server`` class declare their tools in a
# ListTools handler instead of via ``@mcp.tool()``. The tool NAME is the ``name``
# of each ``types.Tool`` returned, never the handler's own function name --
# emitting the handler name would be the same dishonesty as claiming a web
# handler. Every sample below is copied from the SDK's own examples.

# v1.x docs/low-level-server.md, from
# examples/snippets/servers/lowlevel/structured_output.py.
LOWLEVEL_V1_APPLIED_DECORATOR = '''"""Run from the repository root."""

from typing import Any

import mcp.server.stdio
import mcp.types as types
from mcp.server.lowlevel import NotificationOptions, Server
from mcp.server.models import InitializationOptions

server = Server("example-server")


@server.list_tools()
async def list_tools() -> list[types.Tool]:
    """List available tools with structured output schemas."""
    return [
        types.Tool(
            name="get_weather",
            description="Get current weather for a city",
            inputSchema={
                "type": "object",
                "properties": {"city": {"type": "string", "description": "City name"}},
                "required": ["city"],
            },
        )
    ]


@server.call_tool()
async def call_tool(name: str, arguments: dict[str, Any]) -> dict[str, Any]:
    """Handle tool calls with structured output."""
    if name == "get_weather":
        return {"temperature": 22.5, "city": arguments["city"]}
    raise ValueError(f"Unknown tool: {name}")
'''

# The same handler registered with the bare decorator. ``@server.list_tools`` is
# an ``ast.Attribute`` and ``@server.list_tools()`` an ``ast.Call``; a matcher
# that unwraps only one of them silently registers nothing for the other.
LOWLEVEL_V1_BARE_DECORATOR = """import mcp.types as types
from mcp.server.lowlevel import Server

server = Server("example-server")


@server.list_tools
async def handle_list_tools() -> list[types.Tool]:
    return [
        types.Tool(name="query_db", description="Query the database", inputSchema={}),
        types.Tool(name="fetch_url", description="Fetch a URL", inputSchema={}),
    ]
"""

# v2 examples/snippets/servers/lowlevel/structured_output.py: the handler is a
# plain function wired through the ``Server`` constructor, so there is no
# decorator at all.
LOWLEVEL_V2_CONSTRUCTOR_KWARG = '''"""Run from the repository root."""

import mcp.server.stdio
import mcp.types as types
from mcp.server import Server, ServerRequestContext


async def handle_list_tools(
    ctx: ServerRequestContext, params: types.PaginatedRequestParams | None
) -> types.ListToolsResult:
    """List available tools with structured output schemas."""
    return types.ListToolsResult(
        tools=[
            types.Tool(
                name="get_weather",
                description="Get current weather for a city",
                input_schema={"type": "object", "properties": {"city": {"type": "string"}}},
            )
        ]
    )


server = Server(
    "example-server",
    on_list_tools=handle_list_tools,
)
'''

# A plugin registry with a method named ``list_tools`` returning its own ``Tool``
# records. Nothing here is MCP, and the shape is identical.
ORDINARY_LIST_TOOLS_REGISTRY = """from dataclasses import dataclass

from .registry import registry


@dataclass
class Tool:
    name: str
    description: str


class HardwareInventory:
    @registry.list_tools
    def list_tools(self) -> list[Tool]:
        return [
            Tool(name="hammer-42", description="a claw hammer"),
            Tool(name="wrench-7", description="an adjustable wrench"),
        ]
"""

# An MCP project whose ``Tool`` is an unrelated domain record. Without a
# ListTools handler to anchor it, an ``mcp`` import alone must not turn every
# ``Tool(name=...)`` in the file into a tool.
MCP_PROJECT_ORDINARY_TOOL_RECORD = '''from dataclasses import dataclass

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("workshop")


@dataclass
class Tool:
    name: str


BENCH = [Tool(name="hammer-42"), Tool(name="wrench-7")]


@mcp.tool()
def count_tools() -> int:
    """Count the tools on the bench."""
    return len(BENCH)
'''


def test_lowlevel_applied_list_tools_decorator_declares_its_tools(tmp_path: Path) -> None:
    (tmp_path / "server.py").write_text(LOWLEVEL_V1_APPLIED_DECORATOR)

    assert _tool_names(tmp_path) == {"get_weather"}


def test_lowlevel_bare_list_tools_decorator_declares_its_tools(tmp_path: Path) -> None:
    (tmp_path / "server.py").write_text(LOWLEVEL_V1_BARE_DECORATOR)

    assert _tool_names(tmp_path) == {"query_db", "fetch_url"}


def test_lowlevel_constructor_on_list_tools_handler_declares_its_tools(tmp_path: Path) -> None:
    (tmp_path / "server.py").write_text(LOWLEVEL_V2_CONSTRUCTOR_KWARG)

    assert _tool_names(tmp_path) == {"get_weather"}


def test_lowlevel_handler_function_name_is_not_reported_as_a_tool(tmp_path: Path) -> None:
    """The handler lists tools; it is not one. Emitting its name over-reports."""
    (tmp_path / "server.py").write_text(LOWLEVEL_V1_BARE_DECORATOR)

    assert "handle_list_tools" not in _tool_names(tmp_path)


def test_lowlevel_tools_carry_the_signal_that_matched(tmp_path: Path) -> None:
    (tmp_path / "server.py").write_text(LOWLEVEL_V1_APPLIED_DECORATOR)

    entries = [t for t in analyze_project(tmp_path).to_dict()["tools"] if t["name"] == "get_weather"]

    assert [t["decorators"] for t in entries] == [["tools/list"]]


def test_ordinary_list_tools_method_without_mcp_is_not_an_agent_tool(tmp_path: Path) -> None:
    (tmp_path / "inventory.py").write_text(ORDINARY_LIST_TOOLS_REGISTRY)

    assert _tool_names(tmp_path) == set()


def test_tool_records_without_a_list_tools_handler_are_not_agent_tools(tmp_path: Path) -> None:
    (tmp_path / "workshop.py").write_text(MCP_PROJECT_ORDINARY_TOOL_RECORD)

    assert _tool_names(tmp_path) == {"count_tools"}


LANGCHAIN_REGISTERED_TOOL = """import subprocess

import requests
from langchain.agents import AgentExecutor
from langchain.tools import Tool


def fetch_url(url: str) -> str:
    return requests.get(url).text


def run_shell(command: str) -> str:
    fetch_url("https://example.invalid/audit")
    return subprocess.check_output(command, shell=True, text=True)


shell_tool = Tool(name="shell", func=run_shell, description="Run a shell command")
agent = AgentExecutor(agent=None, tools=[shell_tool])
"""


LANGCHAIN_UNREGISTERED_TOOL = """import subprocess

from langchain.tools import Tool


def run_shell(command: str) -> str:
    return subprocess.check_output(command, shell=True, text=True)


shell_tool = Tool(name="shell", func=run_shell, description="Run a shell command")
"""


def test_framework_registered_constructor_tool_is_a_code_flow_root(tmp_path: Path) -> None:
    """A framework registration, not the class name alone, makes the handler invokable."""
    (tmp_path / "app.py").write_text(LANGCHAIN_REGISTERED_TOOL)

    payload = analyze_project(tmp_path).to_dict()
    assert payload["tools"] == [
        {
            "name": "shell",
            "parameters": [{"name": "command", "type": "str", "default": None}],
            "return_type": "str",
            "description": "",
            "file": "app.py",
            "line": 12,
            "is_async": False,
            "decorators": [],
            "handler": "run_shell",
            "registration_kind": "framework_tool",
            "framework": "LangChain",
            "provenance": "python:LangChain:AgentExecutor.tools[0]:shell_tool->Tool(func=run_shell)",
        }
    ]

    flow = [finding for finding in payload["flow_findings"] if finding["entrypoint"] == "shell"]
    assert any(finding["category"] == "unguarded_tool_sink" and finding["sink"] == "subprocess.check_output" for finding in flow)
    assert any(finding["category"] == "tainted_command_execution" and finding["sink"] == "subprocess.check_output" for finding in flow)

    reach = [entry for entry in payload["dependency_symbol_reach"] if entry["entrypoint"] == "shell"]
    assert {(entry["package"], entry["symbol"]) for entry in reach} == {
        ("requests", "get"),
        ("subprocess", "check_output"),
    }
    assert all(entry["entrypoint_kind"] == "framework_tool" for entry in reach)
    assert all(entry["entrypoint_framework"] == "LangChain" for entry in reach)
    assert all(entry["entrypoint_provenance"].startswith("python:LangChain:AgentExecutor.tools") for entry in reach)


def test_unregistered_framework_tool_constructor_is_not_an_invocation_root(tmp_path: Path) -> None:
    """Importing a framework and constructing a Tool is not proof an agent can invoke it."""
    (tmp_path / "app.py").write_text(LANGCHAIN_UNREGISTERED_TOOL)

    result = analyze_project(tmp_path)

    assert result.tools == []
    assert result.flow_findings == []
    assert result.dependency_symbol_reach == []


@pytest.mark.parametrize(
    "source, expected_name, expected_handler, expected_framework",
    [
        (
            "from langchain.agents import AgentExecutor\n"
            "from langchain.tools import Tool\n\n"
            "def lookup(query: str) -> str:\n    return query\n\n"
            "agent = AgentExecutor(agent=None, tools=[Tool(name='lookup-docs', func=lookup, description='Lookup')])\n",
            "lookup-docs",
            "lookup",
            "LangChain",
        ),
        (
            "from langgraph.prebuilt import create_react_agent as make_agent\n"
            "from langchain_core.tools import StructuredTool as ST\n\n"
            "def lookup(query: str) -> str:\n    return query\n\n"
            "lookup_tool = ST.from_function(lookup, name='lookup-docs')\n"
            "agent = make_agent(None, [lookup_tool])\n",
            "lookup-docs",
            "lookup",
            "LangGraph",
        ),
    ],
)
def test_framework_registration_resolves_inline_positional_and_aliased_forms(
    tmp_path: Path,
    source: str,
    expected_name: str,
    expected_handler: str,
    expected_framework: str,
) -> None:
    (tmp_path / "app.py").write_text(source)

    tools = analyze_project(tmp_path).to_dict()["tools"]

    assert [(tool["name"], tool["handler"], tool["framework"]) for tool in tools] == [(expected_name, expected_handler, expected_framework)]


def test_framework_agent_does_not_promote_a_project_local_tool_record(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(
        "from dataclasses import dataclass\n"
        "from langchain.agents import AgentExecutor\n\n"
        "@dataclass\n"
        "class Tool:\n"
        "    name: str\n"
        "    func: object\n\n"
        "def handler(value: str) -> str:\n"
        "    return value\n\n"
        "record = Tool(name='inventory-record', func=handler)\n"
        "agent = AgentExecutor(agent=None, tools=[record])\n"
    )

    assert analyze_project(tmp_path).tools == []


LOWLEVEL_CALL_TOOL_RUNS_A_SHELL = """import subprocess
from typing import Any

import mcp.types as types
from mcp.server.lowlevel import Server

server = Server("shell-server")


@server.list_tools()
async def handle_list_tools() -> list[types.Tool]:
    return [types.Tool(name="run_command", description="Run a command", inputSchema={})]


@server.call_tool()
async def handle_call_tool(name: str, arguments: dict[str, Any]) -> list[types.TextContent]:
    output = subprocess.run(arguments["cmd"], shell=True, capture_output=True)
    return [types.TextContent(type="text", text=output.stdout.decode())]
"""


def test_lowlevel_call_tool_dispatcher_stays_a_sink_entrypoint(tmp_path: Path) -> None:
    """Dropping its tool NAME must not drop its sink analysis.

    ``@server.call_tool()`` is where a low-level server's dangerous work
    actually happens, so it stays a tool entrypoint for flow findings even
    though it is no longer emitted as a tool called "call_tool".
    """
    (tmp_path / "server.py").write_text(LOWLEVEL_CALL_TOOL_RUNS_A_SHELL)
    result = analyze_project(tmp_path)

    assert _tool_names(tmp_path) == {"run_command"}
    assert [(f.entrypoint, f.sink) for f in result.flow_findings if f.category == "unguarded_tool_sink"] == [
        ("handle_call_tool", "subprocess.run")
    ]
