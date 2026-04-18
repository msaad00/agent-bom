"""Tests for the MCP tool-schema rule catalog.

Each rule is asserted with a representative bad schema (rule must fire,
with the expected severity + OWASP tags) and a representative clean
schema (rule must stay silent). Together this prevents the catalog
from drifting into either false-positive noise or false-negative
silence as new rules land.
"""

from __future__ import annotations

import pytest

from agent_bom.mcp_tool_rules import (
    MCPRuleFinding,
    evaluate_server_tools,
    evaluate_tool,
)
from agent_bom.models import MCPTool


def _tool(tool_name: str, description: str = "Adequate description for tool", **schema_props) -> MCPTool:
    """Build a minimal MCPTool with the given schema properties."""
    schema = {"type": "object", "properties": schema_props}
    return MCPTool(name=tool_name, description=description, input_schema=schema)


# ─── Per-rule positive + negative cases ──────────────────────────────────────


class TestShellInputRule:
    def test_fires_on_unbounded_command_string(self) -> None:
        tool = _tool("run_command", command={"type": "string"})
        rules = [f for f in evaluate_tool(tool) if f.rule_id == "MCP-TOOL-01-shell-input"]
        assert len(rules) == 1
        finding = rules[0]
        assert finding.severity == "critical"
        assert "MCP01-Untrusted-Tool-Inputs" in finding.owasp_mcp_tags
        assert "CWE-78" in finding.cwe_ids

    def test_silent_when_command_has_enum(self) -> None:
        tool = _tool("run_command", command={"type": "string", "enum": ["ls", "pwd"]})
        assert not [f for f in evaluate_tool(tool) if f.rule_id == "MCP-TOOL-01-shell-input"]

    def test_silent_when_property_unrelated(self) -> None:
        tool = _tool("greet", name={"type": "string"})
        assert not [f for f in evaluate_tool(tool) if f.rule_id == "MCP-TOOL-01-shell-input"]


class TestPathTraversalRule:
    def test_fires_on_unbounded_file_path(self) -> None:
        tool = _tool("read_file", file_path={"type": "string"})
        rules = [f for f in evaluate_tool(tool) if f.rule_id == "MCP-TOOL-02-path-traversal"]
        assert len(rules) == 1
        assert rules[0].severity == "high"
        assert "CWE-22" in rules[0].cwe_ids

    def test_silent_when_path_has_pattern(self) -> None:
        tool = _tool("read_file", file_path={"type": "string", "pattern": "^/sandbox/[a-z0-9_/.-]+$"})
        assert not [f for f in evaluate_tool(tool) if f.rule_id == "MCP-TOOL-02-path-traversal"]


class TestSSRFRule:
    def test_fires_on_unbounded_url(self) -> None:
        tool = _tool("fetch", url={"type": "string"})
        rules = [f for f in evaluate_tool(tool) if f.rule_id == "MCP-TOOL-03-ssrf"]
        assert len(rules) == 1
        assert rules[0].severity == "high"
        assert "CWE-918" in rules[0].cwe_ids

    def test_silent_when_url_has_enum(self) -> None:
        tool = _tool("fetch", url={"type": "string", "enum": ["https://api.example.com/v1"]})
        assert not [f for f in evaluate_tool(tool) if f.rule_id == "MCP-TOOL-03-ssrf"]


class TestSQLInjectionRule:
    def test_fires_on_unbounded_query(self) -> None:
        tool = _tool("run_query", query={"type": "string"})
        rules = [f for f in evaluate_tool(tool) if f.rule_id == "MCP-TOOL-04-sql-injection"]
        assert len(rules) == 1
        assert "CWE-89" in rules[0].cwe_ids

    def test_silent_on_parameterized_shape(self) -> None:
        tool = _tool(
            "run_query",
            statement_id={"type": "string", "enum": ["list_users", "list_jobs"]},
            params={"type": "object"},
        )
        assert not [f for f in evaluate_tool(tool) if f.rule_id == "MCP-TOOL-04-sql-injection"]


class TestCredentialInInputRule:
    def test_fires_on_token_input(self) -> None:
        tool = _tool("call_api", token={"type": "string"})
        rules = [f for f in evaluate_tool(tool) if f.rule_id == "MCP-TOOL-05-credential-in-input"]
        assert len(rules) == 1
        assert "MCP02-Credential-Leakage" in rules[0].owasp_mcp_tags
        assert "CWE-522" in rules[0].cwe_ids

    def test_silent_on_username(self) -> None:
        tool = _tool("call_api", username={"type": "string"})
        assert not [f for f in evaluate_tool(tool) if f.rule_id == "MCP-TOOL-05-credential-in-input"]


class TestPromptPassthroughRule:
    def test_fires_on_prompt_described_property(self) -> None:
        tool = _tool(
            "summarize",
            text={"type": "string", "description": "The system prompt to compose with the user input"},
        )
        rules = [f for f in evaluate_tool(tool) if f.rule_id == "MCP-TOOL-06-prompt-passthrough"]
        assert len(rules) == 1
        assert "LLM01-Prompt-Injection" in rules[0].owasp_tags

    def test_silent_when_description_is_neutral(self) -> None:
        tool = _tool(
            "summarize",
            text={"type": "string", "description": "Free-form English text to summarize"},
        )
        assert not [f for f in evaluate_tool(tool) if f.rule_id == "MCP-TOOL-06-prompt-passthrough"]


class TestWeakDescriptionRule:
    def test_fires_when_description_missing(self) -> None:
        tool = MCPTool(name="x", description="", input_schema={"type": "object", "properties": {}})
        rules = [f for f in evaluate_tool(tool) if f.rule_id == "MCP-TOOL-07-weak-description"]
        assert len(rules) == 1
        assert rules[0].severity == "low"

    def test_fires_on_trivial_description(self) -> None:
        tool = MCPTool(name="x", description="do x", input_schema={"type": "object", "properties": {}})
        rules = [f for f in evaluate_tool(tool) if f.rule_id == "MCP-TOOL-07-weak-description"]
        assert len(rules) == 1

    def test_silent_when_description_is_useful(self) -> None:
        tool = _tool("read_file", file_path={"type": "string", "pattern": "^/safe/"})
        assert not [f for f in evaluate_tool(tool) if f.rule_id == "MCP-TOOL-07-weak-description"]


# ─── Dispatcher invariants ────────────────────────────────────────────────────


def test_evaluate_tool_handles_missing_schema() -> None:
    tool = MCPTool(name="empty", description="A reasonable description here", input_schema=None)
    # No schema → no per-property rules fire, no crash
    findings = evaluate_tool(tool)
    assert all(f.tool_name == "empty" for f in findings)


def test_evaluate_tool_handles_non_dict_schema() -> None:
    tool = MCPTool(name="weird", description="A reasonable description here", input_schema={"type": "string"})
    findings = evaluate_tool(tool)
    # No properties dict → no per-property rules fire, no crash
    assert all(f.rule_id == "MCP-TOOL-07-weak-description" for f in findings) or findings == []


def test_evaluate_server_tools_aggregates_across_inventory() -> None:
    tools = [
        _tool("run_command", command={"type": "string"}),
        _tool("read_file", file_path={"type": "string"}),
        _tool("safe_lookup", item_id={"type": "string", "pattern": "^[a-z0-9]{8}$"}),
    ]
    findings = evaluate_server_tools(tools)
    rule_ids = {f.rule_id for f in findings}
    assert "MCP-TOOL-01-shell-input" in rule_ids
    assert "MCP-TOOL-02-path-traversal" in rule_ids
    # The clean tool contributes nothing
    by_tool = {f.tool_name for f in findings}
    assert "safe_lookup" not in by_tool


def test_findings_serialize_cleanly() -> None:
    tool = _tool("run_command", command={"type": "string"})
    findings = [f for f in evaluate_tool(tool) if isinstance(f, MCPRuleFinding)]
    assert findings
    payload = findings[0].to_dict()
    assert payload["rule_id"] == "MCP-TOOL-01-shell-input"
    assert payload["owasp_mcp_tags"] == ["MCP01-Untrusted-Tool-Inputs", "MCP04-Excessive-Capability"]


# ─── No accidental fires on the canonical demo tools ─────────────────────────


@pytest.mark.parametrize(
    "tool",
    [
        # Mirrors the curated demo tools in src/agent_bom/demo.py — they
        # are intentionally clean so they should produce no rule findings.
        _tool(
            "list_directory",
            description="List directory entries under the workspace root",
            path={"type": "string", "pattern": "^/workspace/[A-Za-z0-9_/.-]+$"},
        ),
        _tool(
            "send_message",
            description="Send a chat message to a configured Slack channel",
            channel_id={"type": "string", "pattern": "^C[A-Z0-9]{8,}$"},
            text={"type": "string", "maxLength": 2000},
        ),
    ],
)
def test_demo_clean_tools_produce_no_rule_findings(tool: MCPTool) -> None:
    assert evaluate_tool(tool) == []
