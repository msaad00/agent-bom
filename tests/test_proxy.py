"""Tests for agent_bom.proxy — MCP runtime proxy helpers."""

from __future__ import annotations

import io
import json

from agent_bom.proxy import (
    ProxyMetrics,
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


# ── ProxyMetrics ────────────────────────────────────────────────────────────


def test_proxy_metrics_record_call():
    """record_call increments tool call counter."""
    m = ProxyMetrics()
    m.record_call("read_file")
    m.record_call("read_file")
    m.record_call("write_file")
    assert m.tool_calls["read_file"] == 2
    assert m.tool_calls["write_file"] == 1


def test_proxy_metrics_record_blocked():
    """record_blocked increments blocked counter by reason."""
    m = ProxyMetrics()
    m.record_blocked("policy")
    m.record_blocked("policy")
    m.record_blocked("undeclared")
    assert m.blocked_calls["policy"] == 2
    assert m.blocked_calls["undeclared"] == 1


def test_proxy_metrics_latency():
    """record_latency stores latency values."""
    m = ProxyMetrics()
    m.record_latency(10.5)
    m.record_latency(20.3)
    m.record_latency(15.1)
    assert len(m.latencies_ms) == 3


def test_proxy_metrics_summary():
    """summary() returns a well-structured dict."""
    m = ProxyMetrics()
    m.record_call("scan")
    m.record_call("scan")
    m.record_call("check")
    m.record_blocked("policy")
    m.record_latency(10.0)
    m.record_latency(50.0)
    m.total_messages_client_to_server = 5
    m.total_messages_server_to_client = 3

    s = m.summary()
    assert s["type"] == "proxy_summary"
    assert s["total_tool_calls"] == 3
    assert s["total_blocked"] == 1
    assert s["calls_by_tool"]["scan"] == 2
    assert s["calls_by_tool"]["check"] == 1
    assert s["blocked_by_reason"]["policy"] == 1
    assert s["latency"]["min_ms"] == 10.0
    assert s["latency"]["max_ms"] == 50.0
    assert s["latency"]["count"] == 2
    assert s["messages_client_to_server"] == 5
    assert s["messages_server_to_client"] == 3
    assert "ts" in s
    assert "uptime_seconds" in s


def test_proxy_metrics_summary_empty():
    """summary() works when no data recorded."""
    m = ProxyMetrics()
    s = m.summary()
    assert s["total_tool_calls"] == 0
    assert s["total_blocked"] == 0
    assert s["latency"] == {}
    assert s["messages_client_to_server"] == 0


# ── CLI proxy --help ─────────────────────────────────────────────────────────


def test_proxy_cli_help():
    """'agent-bom proxy --help' mentions 'security proxy'."""
    from click.testing import CliRunner

    from agent_bom.cli import main

    runner = CliRunner()
    result = runner.invoke(main, ["proxy", "--help"])
    assert result.exit_code == 0
    assert "security proxy" in result.output
