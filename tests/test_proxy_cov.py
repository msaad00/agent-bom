"""Tests for proxy module — coverage expansion for parsing, policy, metrics, audit."""

from __future__ import annotations

import io
import json
import os
import tempfile

import pytest

from agent_bom.proxy import (
    ProxyMetrics,
    ProxyMetricsServer,
    ReplayDetector,
    RotatingAuditLog,
    _safe_compile,
    _safe_regex_match,
    _safe_regex_search,
    _truncate_args,
    check_policy,
    compute_payload_hash,
    compute_response_hmac,
    extract_declared_tools,
    extract_tool_arguments,
    extract_tool_name,
    is_tools_call,
    is_tools_list_response,
    log_tool_call,
    make_error_response,
    parse_jsonrpc,
    set_gateway_evaluator,
)

# -- JSON-RPC parsing --


class TestParseJsonrpc:
    def test_valid_request(self):
        line = '{"jsonrpc": "2.0", "method": "tools/call", "id": 1}'
        result = parse_jsonrpc(line)
        assert result is not None
        assert result["method"] == "tools/call"

    def test_valid_response(self):
        line = '{"jsonrpc": "2.0", "result": {"tools": []}, "id": 1}'
        result = parse_jsonrpc(line)
        assert result is not None

    def test_empty_line(self):
        assert parse_jsonrpc("") is None
        assert parse_jsonrpc("   ") is None

    def test_invalid_json(self):
        assert parse_jsonrpc("not json") is None

    def test_non_dict_json(self):
        assert parse_jsonrpc("[1, 2, 3]") is None

    def test_dict_without_jsonrpc_keys(self):
        assert parse_jsonrpc('{"foo": "bar"}') is None

    def test_method_key_accepted(self):
        result = parse_jsonrpc('{"method": "ping"}')
        assert result is not None


class TestToolHelpers:
    def test_is_tools_call(self):
        assert is_tools_call({"method": "tools/call"})
        assert not is_tools_call({"method": "tools/list"})
        assert not is_tools_call({})

    def test_is_tools_list_response(self):
        assert is_tools_list_response({"result": {"tools": []}})
        assert not is_tools_list_response({"result": "ok"})
        assert not is_tools_list_response({"error": "bad"})

    def test_extract_tool_name(self):
        msg = {"params": {"name": "read_file"}}
        assert extract_tool_name(msg) == "read_file"
        assert extract_tool_name({}) is None

    def test_extract_tool_arguments(self):
        msg = {"params": {"arguments": {"path": "/tmp/test"}}}
        assert extract_tool_arguments(msg) == {"path": "/tmp/test"}
        assert extract_tool_arguments({}) == {}

    def test_extract_declared_tools(self):
        msg = {"result": {"tools": [{"name": "read"}, {"name": "write"}]}}
        assert extract_declared_tools(msg) == ["read", "write"]
        assert extract_declared_tools({}) == []

    def test_make_error_response(self):
        resp = make_error_response(1, -32600, "Invalid Request")
        assert resp["jsonrpc"] == "2.0"
        assert resp["id"] == 1
        assert resp["error"]["code"] == -32600
        assert resp["error"]["message"] == "Invalid Request"


# -- Audit logging --


class TestLogToolCall:
    def test_basic_log(self):
        buf = io.StringIO()
        log_tool_call(buf, "read_file", {"path": "/tmp"})
        buf.seek(0)
        record = json.loads(buf.read().strip())
        assert record["tool"] == "read_file"
        assert record["policy"] == "allowed"

    def test_blocked_log(self):
        buf = io.StringIO()
        log_tool_call(buf, "delete_all", {}, policy_result="blocked", reason="policy violation")
        buf.seek(0)
        record = json.loads(buf.read().strip())
        assert record["policy"] == "blocked"
        assert record["reason"] == "policy violation"

    def test_with_metadata(self):
        buf = io.StringIO()
        log_tool_call(
            buf,
            "write",
            {},
            payload_sha256="abc123",
            message_id=42,
            agent_id="agent-1",
        )
        buf.seek(0)
        record = json.loads(buf.read().strip())
        assert record["payload_sha256"] == "abc123"
        assert record["message_id"] == 42
        assert record["agent_id"] == "agent-1"


class TestTruncateArgs:
    def test_short_values_unchanged(self):
        args = {"key": "short"}
        assert _truncate_args(args) == {"key": "short"}

    def test_long_string_truncated(self):
        args = {"key": "x" * 500}
        result = _truncate_args(args)
        assert len(result["key"]) < 500
        assert "truncated" in result["key"]

    def test_non_string_unchanged(self):
        args = {"num": 42, "list": [1, 2, 3]}
        result = _truncate_args(args)
        assert result["num"] == 42


# -- Payload integrity --


class TestPayloadHashing:
    def test_deterministic_hash(self):
        payload = {"method": "tools/call", "params": {"name": "test"}}
        h1 = compute_payload_hash(payload)
        h2 = compute_payload_hash(payload)
        assert h1 == h2

    def test_different_payloads_different_hash(self):
        h1 = compute_payload_hash({"a": 1})
        h2 = compute_payload_hash({"a": 2})
        assert h1 != h2

    def test_order_independent(self):
        h1 = compute_payload_hash({"b": 2, "a": 1})
        h2 = compute_payload_hash({"a": 1, "b": 2})
        assert h1 == h2


class TestHmac:
    def test_hmac_deterministic(self):
        payload = {"result": "ok"}
        h1 = compute_response_hmac(payload, "secret")
        h2 = compute_response_hmac(payload, "secret")
        assert h1 == h2

    def test_different_key_different_hmac(self):
        payload = {"result": "ok"}
        h1 = compute_response_hmac(payload, "secret1")
        h2 = compute_response_hmac(payload, "secret2")
        assert h1 != h2


# -- Replay detector --


class TestReplayDetector:
    def test_first_message_not_replay(self):
        detector = ReplayDetector()
        msg = {"method": "tools/call", "params": {"name": "test"}, "id": 1}
        assert not detector.check(msg)

    def test_duplicate_message_is_replay(self):
        detector = ReplayDetector()
        msg = {"method": "tools/call", "params": {"name": "test"}, "id": 1}
        detector.check(msg)
        assert detector.check(msg)

    def test_different_messages_not_replay(self):
        detector = ReplayDetector()
        detector.check({"id": 1})
        assert not detector.check({"id": 2})

    def test_eviction_on_capacity(self):
        detector = ReplayDetector(max_entries=10)
        for i in range(20):
            detector.check({"id": i})
        assert detector.memory_bytes > 0


# -- Policy checking --


class TestCheckPolicy:
    def test_empty_policy_allows(self):
        allowed, reason = check_policy({}, "any_tool", {})
        assert allowed
        assert reason == ""

    def test_block_tools_blocks(self):
        policy = {"rules": [{"action": "block", "block_tools": ["dangerous_tool"]}]}
        allowed, reason = check_policy(policy, "dangerous_tool", {})
        assert not allowed
        assert "blocked" in reason.lower() or "dangerous_tool" in reason

    def test_allowlist_blocks_unlisted(self):
        policy = {"rules": [{"mode": "allowlist", "action": "block", "allow_tools": ["safe_tool"]}]}
        allowed, reason = check_policy(policy, "unsafe_tool", {})
        assert not allowed

    def test_allowlist_allows_listed(self):
        policy = {"rules": [{"mode": "allowlist", "action": "block", "allow_tools": ["safe_tool"]}]}
        allowed, reason = check_policy(policy, "safe_tool", {})
        assert allowed

    def test_tool_name_exact_match_blocks(self):
        policy = {"rules": [{"action": "fail", "tool_name": "rm_all"}]}
        allowed, reason = check_policy(policy, "rm_all", {})
        assert not allowed

    def test_tool_name_pattern_blocks(self):
        policy = {"rules": [{"action": "fail", "tool_name_pattern": "^delete_.*"}]}
        allowed, reason = check_policy(policy, "delete_file", {})
        assert not allowed

    def test_arg_pattern_blocks(self):
        policy = {"rules": [{"action": "fail", "arg_pattern": {"path": r"/etc/.*"}}]}
        allowed, reason = check_policy(policy, "read", {"path": "/etc/passwd"})
        assert not allowed

    def test_warn_action_not_enforced(self):
        policy = {"rules": [{"action": "warn", "block_tools": ["test"]}]}
        allowed, reason = check_policy(policy, "test", {})
        assert allowed

    def test_oversized_pattern_skipped(self):
        policy = {"rules": [{"action": "fail", "tool_name_pattern": "a" * 600}]}
        allowed, _ = check_policy(policy, "test", {})
        assert allowed

    def test_oversized_arg_pattern_skipped(self):
        policy = {"rules": [{"action": "fail", "arg_pattern": {"x": "a" * 600}}]}
        allowed, _ = check_policy(policy, "test", {"x": "hello"})
        assert allowed

    def test_deny_tool_classes_blocks_network_tool(self):
        policy = {"rules": [{"id": "net", "action": "block", "deny_tool_classes": ["network"]}]}
        allowed, reason = check_policy(policy, "web_fetch", {"url": "https://api.example.com"})
        assert not allowed
        assert "tool class" in reason.lower()

    def test_block_unknown_egress_allows_subdomain(self):
        policy = {
            "rules": [
                {
                    "id": "egress",
                    "action": "block",
                    "block_unknown_egress": True,
                    "allowed_hosts": ["example.com"],
                }
            ]
        }
        allowed, reason = check_policy(policy, "web_fetch", {"url": "https://api.example.com/v1"})
        assert allowed
        assert reason == ""


# -- Regex helpers --


class TestRegexHelpers:
    def test_safe_compile_caches(self):
        p1 = _safe_compile("^test$")
        p2 = _safe_compile("^test$")
        assert p1 is p2

    def test_safe_regex_match(self):
        assert _safe_regex_match("^hello", "hello world")
        assert not _safe_regex_match("^world", "hello world")

    def test_safe_regex_search(self):
        assert _safe_regex_search("world", "hello world")
        assert not _safe_regex_search("xyz", "hello world")

    def test_oversized_input_rejected(self):
        assert not _safe_regex_match("test", "x" * 20000)
        assert not _safe_regex_search("test", "x" * 20000)


# -- ProxyMetrics --


class TestProxyMetrics:
    def test_record_call(self):
        m = ProxyMetrics()
        m.record_call("read")
        m.record_call("read")
        m.record_call("write")
        assert m.tool_calls["read"] == 2
        assert m.tool_calls["write"] == 1

    def test_record_blocked(self):
        m = ProxyMetrics()
        m.record_blocked("policy")
        assert m.blocked_calls["policy"] == 1

    def test_record_latency(self):
        m = ProxyMetrics()
        m.record_latency(100.0)
        m.record_latency(200.0)
        assert len(m.latencies_ms) == 2

    def test_latency_bounded(self):
        m = ProxyMetrics()
        for i in range(15000):
            m.record_latency(float(i))
        assert len(m.latencies_ms) <= 10000

    def test_summary(self):
        m = ProxyMetrics()
        m.record_call("test")
        m.record_blocked("policy")
        m.record_latency(50.0)
        m.total_messages_client_to_server = 10
        m.total_messages_server_to_client = 8
        m.replay_rejections = 1

        summary = m.summary()
        assert summary["total_tool_calls"] == 1
        assert summary["total_blocked"] == 1
        assert "latency" in summary
        assert summary["latency"]["count"] == 1
        assert summary["messages_client_to_server"] == 10


class TestProxyMetricsServer:
    def test_render_metrics(self):
        m = ProxyMetrics()
        m.record_call("read")
        m.record_blocked("policy")
        m.record_latency(100.0)
        m.total_messages_client_to_server = 5
        m.total_messages_server_to_client = 3

        server = ProxyMetricsServer(m)
        text = server.render_metrics()
        assert "agent_bom_proxy_tool_calls_total" in text
        assert "agent_bom_proxy_blocked_total" in text
        assert "agent_bom_proxy_uptime_seconds" in text


# -- RotatingAuditLog --


class TestRotatingAuditLog:
    def test_basic_write(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False) as f:
            path = f.name

        try:
            log = RotatingAuditLog(path)
            log.write('{"test": 1}\n')
            log.flush()
            log.close()
            with open(path) as f:
                content = f.read()
            assert '{"test": 1}' in content
        finally:
            os.unlink(path)

    def test_rejects_symlink(self):
        with tempfile.NamedTemporaryFile(delete=False) as f:
            real_path = f.name
        link_path = real_path + ".link"
        try:
            os.symlink(real_path, link_path)
            with pytest.raises(ValueError, match="symlink"):
                RotatingAuditLog(link_path)
        finally:
            os.unlink(link_path)
            os.unlink(real_path)


# -- Gateway evaluator --


class TestGatewayEvaluator:
    def test_set_gateway_evaluator(self):
        def fn(agent, tool, args):
            return (True, "")

        set_gateway_evaluator(fn)
        from agent_bom.proxy import _gateway_evaluator

        assert _gateway_evaluator is fn
        # Reset
        set_gateway_evaluator(None)


# ── Unique tests from cov2 ──────────────────────────────────────────────────


class TestRotatingAuditLogRotation:
    def test_rotation(self):
        from pathlib import Path

        with tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False) as f:
            path = f.name
        os.unlink(path)

        log = RotatingAuditLog(path, max_bytes=100)
        for i in range(1001):
            log.write(f'{{"i": {i}}}\n')
        log.close()

        assert Path(path).exists()


class TestProxyMetricsSummaryNoLatency:
    def test_empty_latency(self):
        m = ProxyMetrics()
        s = m.summary()
        assert s["latency"] == {}


class TestProxyMetricsServerPort:
    def test_render_with_port(self):
        m = ProxyMetrics()
        m.record_call("read_file")
        m.record_blocked("policy")
        server = ProxyMetricsServer(m, port=0)
        text = server.render_metrics()
        assert "agent_bom_proxy_tool_calls_total" in text
        assert "agent_bom_proxy_blocked_total" in text


class TestProxyMetricsSummaryRelay:
    def test_relay_errors_in_summary(self):
        m = ProxyMetrics()
        m.record_call("tool_a")
        m.record_blocked("policy")
        m.record_latency(10.0)
        m.record_latency(20.0)
        m.total_messages_client_to_server = 5
        m.total_messages_server_to_client = 3
        m.replay_rejections = 1
        m.relay_errors = 2

        s = m.summary()
        assert s["type"] == "proxy_summary"
        assert s["replay_rejections"] == 1
        assert s["relay_errors"] == 2
        assert "p50_ms" in s["latency"]
        assert "avg_ms" in s["latency"]
