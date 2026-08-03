"""The regex fallback is a fourth agent-tool detector, and it had drifted.

When a Python file fails to parse, ``python_agents._extract_agent_defs`` falls
back to ``_extract_agent_defs_regex``. That path kept its own decorator list —
``function_tool|tool|skill|action`` — so it still carried both defects the AST
detectors were fixed for: Django REST's ``@action`` was reported as an agent
tool at confidence "high", and the applied form ``@mcp.tool()`` (FastMCP's
documented decorator) registered nothing, because the pattern requires a
newline immediately after the decorator name.
"""

from __future__ import annotations

import pytest

from agent_bom.python_agents import _extract_agent_defs

# A deliberate syntax error, so ``ast.parse`` fails and the regex path runs.
# The Agent(...) call is what the regex path hangs its tool table off.
UNPARSEABLE_TAIL = "\ndef broken(:\n    pass\n"
AGENT_HARNESS = 'from crewai import Agent\n\nresearcher = Agent("researcher")\n'


def _fallback_tools(decorated: str) -> set[str]:
    source = AGENT_HARNESS + decorated + UNPARSEABLE_TAIL
    defs = _extract_agent_defs(source, "mod.py")
    assert defs, "regex fallback produced no agent definitions"
    return {name for d in defs for name, kind, _confidence in d.tools if kind == "decorator"}


@pytest.mark.parametrize(
    "decorator",
    ["@tool", "@tool('search')", "@mcp.tool()", "@function_tool", "@function_tool()", "@agent.tool", "@agent.tool_plain"],
)
def test_fallback_finds_agent_tool_decorators(decorator: str) -> None:
    assert _fallback_tools(f"\n{decorator}\ndef handler(query):\n    return query\n") == {"handler"}


@pytest.mark.parametrize("decorator", ["@action", "@action(detail=True)", "@app.route('/x')", "@celery_app.task"])
def test_fallback_ignores_web_and_task_decorators(decorator: str) -> None:
    assert _fallback_tools(f"\n{decorator}\ndef handler(self, request):\n    pass\n") == set()
