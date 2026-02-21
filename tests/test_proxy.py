"""Tests for agent_bom.proxy — MCP runtime proxy helpers."""

from __future__ import annotations

import io
import json

from agent_bom.proxy import (
    check_policy,
    extract_tool_name,
    is_tools_call,
    log_tool_call,
    parse_jsonrpc,
)

# ── parse_jsonrpc ────────────────────────────────────────────────────────────


def test_parse_jsonrpc_valid():
    """Valid JSON-RPC line returns a dict with method."""
    result = parse_jsonrpc('{"jsonrpc":"2.0","method":"tools/call","id":1}')
    assert result is not None
    assert isinstance(result, dict)
    assert result["method"] == "tools/call"
    assert result["id"] == 1


def test_parse_jsonrpc_invalid():
    """Non-JSON input returns None."""
    result = parse_jsonrpc("not json")
    assert result is None


def test_parse_jsonrpc_empty():
    """Empty string returns None."""
    result = parse_jsonrpc("")
    assert result is None


# ── is_tools_call ────────────────────────────────────────────────────────────


def test_is_tools_call_true():
    """Message with method='tools/call' is recognized."""
    msg = {"jsonrpc": "2.0", "method": "tools/call", "id": 1, "params": {"name": "read_file"}}
    assert is_tools_call(msg) is True


def test_is_tools_call_false():
    """Message with method='tools/list' is not a tools/call."""
    msg = {"jsonrpc": "2.0", "method": "tools/list", "id": 2}
    assert is_tools_call(msg) is False


# ── extract_tool_name ────────────────────────────────────────────────────────


def test_extract_tool_name():
    """Extracts params.name from a tools/call message."""
    msg = {
        "jsonrpc": "2.0",
        "method": "tools/call",
        "id": 3,
        "params": {"name": "write_file", "arguments": {"path": "/tmp/x"}},
    }
    assert extract_tool_name(msg) == "write_file"


# ── log_tool_call ────────────────────────────────────────────────────────────


def test_log_tool_call():
    """log_tool_call writes valid JSONL with 'tool' and 'policy' keys."""
    buf = io.StringIO()
    log_tool_call(buf, "read_file", {"path": "/etc/hosts"}, policy_result="allowed")

    buf.seek(0)
    line = buf.readline()
    record = json.loads(line)

    assert record["tool"] == "read_file"
    assert record["policy"] == "allowed"
    assert "ts" in record
    assert record["args"]["path"] == "/etc/hosts"


# ── check_policy ─────────────────────────────────────────────────────────────


def test_check_policy_allows():
    """Policy with no matching rules allows the tool call."""
    policy = {
        "rules": [
            {"id": "block-exec", "action": "block", "block_tools": ["exec_cmd"]},
        ],
    }
    allowed, reason = check_policy(policy, "read_file", {})
    assert allowed is True
    assert reason == ""


def test_check_policy_blocks_tool():
    """Policy with block_tools blocks a matching tool name."""
    policy = {
        "rules": [
            {"id": "block-exec", "action": "block", "block_tools": ["exec_cmd"]},
        ],
    }
    allowed, reason = check_policy(policy, "exec_cmd", {})
    assert allowed is False
    assert "exec_cmd" in reason
    assert "block-exec" in reason


def test_check_policy_blocks_arg_pattern():
    """Policy with arg_pattern blocks when argument matches regex."""
    policy = {
        "rules": [
            {
                "id": "no-etc",
                "action": "block",
                "arg_pattern": {"path": "/etc/.*"},
            },
        ],
    }
    allowed, reason = check_policy(policy, "read_file", {"path": "/etc/passwd"})
    assert allowed is False
    assert "/etc/.*" in reason


# ── CLI proxy --help ─────────────────────────────────────────────────────────


def test_proxy_cli_help():
    """'agent-bom proxy --help' mentions 'security proxy'."""
    from click.testing import CliRunner

    from agent_bom.cli import main

    runner = CliRunner()
    result = runner.invoke(main, ["proxy", "--help"])
    assert result.exit_code == 0
    assert "security proxy" in result.output
