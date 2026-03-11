"""Additional tests for agent_bom.proxy helpers to improve coverage."""

from __future__ import annotations

import io
import json

from agent_bom.proxy import (
    _truncate_args,
    extract_declared_tools,
    extract_tool_arguments,
    extract_tool_name,
    is_tools_call,
    is_tools_list_response,
    log_tool_call,
    make_error_response,
    parse_jsonrpc,
)

# ---------------------------------------------------------------------------
# parse_jsonrpc
# ---------------------------------------------------------------------------


def test_parse_jsonrpc_valid():
    msg = json.dumps({"jsonrpc": "2.0", "method": "tools/call", "id": 1})
    result = parse_jsonrpc(msg)
    assert result is not None
    assert result["method"] == "tools/call"


def test_parse_jsonrpc_empty():
    assert parse_jsonrpc("") is None
    assert parse_jsonrpc("  ") is None


def test_parse_jsonrpc_invalid_json():
    assert parse_jsonrpc("not json") is None


def test_parse_jsonrpc_non_rpc():
    assert parse_jsonrpc('{"data": 123}') is None


def test_parse_jsonrpc_result():
    msg = json.dumps({"jsonrpc": "2.0", "id": 1, "result": {"tools": []}})
    result = parse_jsonrpc(msg)
    assert result is not None


def test_parse_jsonrpc_method_only():
    msg = json.dumps({"method": "notifications/initialized"})
    result = parse_jsonrpc(msg)
    assert result is not None


# ---------------------------------------------------------------------------
# is_tools_call / is_tools_list_response
# ---------------------------------------------------------------------------


def test_is_tools_call_true():
    assert is_tools_call({"method": "tools/call"}) is True


def test_is_tools_call_false():
    assert is_tools_call({"method": "tools/list"}) is False
    assert is_tools_call({}) is False


def test_is_tools_list_response_true():
    msg = {"result": {"tools": [{"name": "read_file"}]}}
    assert is_tools_list_response(msg) is True


def test_is_tools_list_response_false():
    assert is_tools_list_response({"result": "ok"}) is False
    assert is_tools_list_response({}) is False
    assert is_tools_list_response({"result": {"data": []}}) is False


# ---------------------------------------------------------------------------
# extract_tool_name / extract_tool_arguments / extract_declared_tools
# ---------------------------------------------------------------------------


def test_extract_tool_name():
    msg = {"params": {"name": "read_file", "arguments": {}}}
    assert extract_tool_name(msg) == "read_file"


def test_extract_tool_name_missing():
    assert extract_tool_name({}) is None
    assert extract_tool_name({"params": {}}) is None


def test_extract_tool_arguments():
    msg = {"params": {"name": "t", "arguments": {"path": "/tmp"}}}
    assert extract_tool_arguments(msg) == {"path": "/tmp"}


def test_extract_tool_arguments_empty():
    assert extract_tool_arguments({}) == {}
    assert extract_tool_arguments({"params": {}}) == {}


def test_extract_declared_tools():
    msg = {
        "result": {
            "tools": [
                {"name": "read_file", "description": "Read a file"},
                {"name": "write_file", "description": "Write a file"},
            ]
        }
    }
    tools = extract_declared_tools(msg)
    assert tools == ["read_file", "write_file"]


def test_extract_declared_tools_empty():
    assert extract_declared_tools({}) == []
    assert extract_declared_tools({"result": {}}) == []


def test_extract_declared_tools_non_dict():
    msg = {"result": {"tools": ["read_file"]}}
    assert extract_declared_tools(msg) == []


# ---------------------------------------------------------------------------
# make_error_response
# ---------------------------------------------------------------------------


def test_make_error_response():
    resp = make_error_response(42, -32600, "Invalid request")
    assert resp["jsonrpc"] == "2.0"
    assert resp["id"] == 42
    assert resp["error"]["code"] == -32600
    assert resp["error"]["message"] == "Invalid request"


def test_make_error_response_null_id():
    resp = make_error_response(None, -32700, "Parse error")
    assert resp["id"] is None


# ---------------------------------------------------------------------------
# _truncate_args
# ---------------------------------------------------------------------------


def test_truncate_args_short():
    args = {"a": "short", "b": 42}
    result = _truncate_args(args)
    assert result == {"a": "short", "b": 42}


def test_truncate_args_long_string():
    args = {"data": "x" * 500}
    result = _truncate_args(args, max_value_len=100)
    assert len(result["data"]) <= 120  # truncated + "..."


def test_truncate_args_nested():
    args = {"config": {"key": "value"}, "num": 42}
    result = _truncate_args(args)
    assert "config" in result


# ---------------------------------------------------------------------------
# log_tool_call
# ---------------------------------------------------------------------------


def test_log_tool_call_basic():
    buf = io.StringIO()
    log_tool_call(buf, "read_file", {"path": "/tmp"})
    buf.seek(0)
    record = json.loads(buf.readline())
    assert record["type"] == "tools/call"
    assert record["tool"] == "read_file"
    assert record["policy"] == "allowed"


def test_log_tool_call_blocked():
    buf = io.StringIO()
    log_tool_call(buf, "exec", {"cmd": "rm -rf /"}, policy_result="blocked", reason="undeclared", payload_sha256="abc123", message_id=42)
    buf.seek(0)
    record = json.loads(buf.readline())
    assert record["policy"] == "blocked"
    assert record["reason"] == "undeclared"
    assert record["payload_sha256"] == "abc123"
    assert record["message_id"] == 42


def test_log_tool_call_no_optional_fields():
    buf = io.StringIO()
    log_tool_call(buf, "test_tool", {})
    buf.seek(0)
    record = json.loads(buf.readline())
    assert "reason" not in record
    assert "payload_sha256" not in record
    assert "message_id" not in record


# ---------------------------------------------------------------------------
# ProxyMetricsServer render with latency
# ---------------------------------------------------------------------------


def test_proxy_metrics_server_render_with_latency():
    from agent_bom.proxy import ProxyMetrics, ProxyMetricsServer

    m = ProxyMetrics()
    m.record_call("tool_a")
    m.record_call("tool_b")
    m.record_latency(10.0)
    m.record_latency(50.0)
    m.total_messages_client_to_server = 10
    m.total_messages_server_to_client = 8
    m.replay_rejections = 2

    server = ProxyMetricsServer(m, port=0)
    text = server.render_metrics()
    assert "agent_bom_proxy_latency_ms" in text
    assert 'quantile="0.5"' in text
    assert "agent_bom_proxy_replay_rejections_total" in text
    assert "agent_bom_proxy_messages_total" in text
    assert "client_to_server" in text
