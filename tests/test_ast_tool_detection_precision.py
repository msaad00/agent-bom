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


@pytest.mark.parametrize("decorator", AGENT_TOOL_DECORATORS + NON_AGENT_DECORATORS)
def test_both_tool_detectors_agree(tmp_path: Path, decorator: str) -> None:
    """The two detectors must not disagree about what an agent tool is."""
    source = f"{decorator}\ndef handler(query: str) -> str:\n    '''d'''\n"
    (tmp_path / "mod.py").write_text(source)

    assert bool(_tool_names(tmp_path)) is bool(_collect_tools(ast.parse(source)))
