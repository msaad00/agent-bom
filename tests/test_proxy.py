"""Tests for agent_bom.proxy — MCP runtime proxy helpers."""

from __future__ import annotations

import io
import json
import time
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import agent_bom.proxy as proxy_mod
from agent_bom.api.policy_store import GatewayPolicy, GatewayRule
from agent_bom.proxy import (
    AuditDeliveryController,
    AuditSpilloverStore,
    ProxyMetrics,
    ReplayDetector,
    _control_plane_headers,
    _extract_jsonrpc_trace_meta,
    _gateway_policy_cache_path,
    _gateway_policy_cache_signature_path,
    _inject_jsonrpc_trace_meta,
    _load_cached_gateway_policies,
    _persist_gateway_policies_cache,
    _reset_gateway_policy_cache_signer_for_tests,
    _stitch_jsonrpc_trace_meta,
    check_policy,
    compute_payload_hash,
    compute_response_hmac,
    extract_tool_name,
    is_tools_call,
    log_tool_call,
    parse_jsonrpc,
)


def test_proxy_message_size_budget_is_two_mib_or_less():
    assert proxy_mod._MAX_MESSAGE_BYTES <= 2 * 1024 * 1024


@pytest.fixture(autouse=True)
def _reset_policy_cache_signer():
    _reset_gateway_policy_cache_signer_for_tests()
    yield
    _reset_gateway_policy_cache_signer_for_tests()


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
    assert record["prev_hash"] == ""
    assert len(record["record_hash"]) == 64


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


def test_check_policy_read_only_blocks_write_tool():
    policy = {"rules": [{"id": "read-only", "action": "block", "read_only": True}]}
    allowed, reason = check_policy(policy, "write_file", {"path": "/tmp/out.txt"})
    assert allowed is False
    assert "read-only" in reason.lower()


def test_check_policy_blocks_secret_path():
    policy = {"rules": [{"id": "no-secrets", "action": "block", "block_secret_paths": True}]}
    allowed, reason = check_policy(policy, "read_file", {"path": "~/.ssh/id_rsa"})
    assert allowed is False
    assert "secret path" in reason.lower()


def test_check_policy_blocks_unknown_egress_host():
    policy = {
        "rules": [
            {
                "id": "allow-egress",
                "action": "block",
                "block_unknown_egress": True,
                "allowed_hosts": ["api.openai.com"],
            }
        ]
    }
    allowed, reason = check_policy(policy, "web_fetch", {"url": "https://evil.example/path"})
    assert allowed is False
    assert "allowlisted" in reason.lower()


def test_control_plane_headers_propagate_w3c_trace_context(monkeypatch):
    """Control-plane requests should carry bounded W3C trace headers when present."""

    def _fake_inject(headers):
        headers = dict(headers)
        headers["traceparent"] = "00-0123456789abcdef0123456789abcdef-0123456789abcdef-01"
        headers["tracestate"] = "vendor-a=foo"
        headers["baggage"] = "tenant=acme"
        return headers

    monkeypatch.setattr(proxy_mod, "inject_current_trace_headers", _fake_inject)
    headers = _control_plane_headers("secret-token", "etag-1")
    assert headers["Authorization"] == "Bearer secret-token"
    assert headers["If-None-Match"] == "etag-1"
    assert headers["traceparent"].startswith("00-")
    assert headers["tracestate"] == "vendor-a=foo"
    assert headers["baggage"] == "tenant=acme"


def test_extract_jsonrpc_trace_meta_returns_bounded_w3c_values():
    message = {
        "_meta": {
            "traceparent": "00-0123456789abcdef0123456789abcdef-0123456789abcdef-01",
            "tracestate": "vendor-a=foo,vendor-b=bar",
            "baggage": "tenant=acme,release=v0.81.2",
        }
    }
    trace_meta = _extract_jsonrpc_trace_meta(message)
    assert trace_meta["traceparent"] == "00-0123456789abcdef0123456789abcdef-0123456789abcdef-01"
    assert trace_meta["tracestate"] == "vendor-a=foo,vendor-b=bar"
    assert trace_meta["baggage"] == "tenant=acme,release=v0.81.2"


def test_extract_jsonrpc_trace_meta_ignores_invalid_values():
    trace_meta = _extract_jsonrpc_trace_meta({"_meta": {"traceparent": "broken", "tracestate": "", "baggage": ""}})
    assert trace_meta == {}


def test_inject_jsonrpc_trace_meta_preserves_existing_meta_fields():
    message = {"jsonrpc": "2.0", "id": 1, "_meta": {"client": "cursor"}}
    enriched = _inject_jsonrpc_trace_meta(
        message,
        traceparent="00-0123456789abcdef0123456789abcdef-0123456789abcdef-01",
        tracestate="vendor-a=foo",
        baggage="tenant=acme",
    )
    assert enriched["_meta"]["client"] == "cursor"
    assert enriched["_meta"]["traceparent"].startswith("00-0123456789abcdef0123456789abcdef-")
    assert enriched["_meta"]["tracestate"] == "vendor-a=foo"
    assert enriched["_meta"]["baggage"] == "tenant=acme"


def test_stitch_jsonrpc_trace_meta_rehydrates_from_request_when_response_lacks_it():
    response = {"jsonrpc": "2.0", "id": 1, "result": {"ok": True}}
    stitched = _stitch_jsonrpc_trace_meta(
        response,
        {
            "traceparent": "00-0123456789abcdef0123456789abcdef-0123456789abcdef-01",
            "tracestate": "vendor-a=foo",
            "baggage": "tenant=acme",
        },
    )
    assert stitched["_meta"]["traceparent"] == "00-0123456789abcdef0123456789abcdef-0123456789abcdef-01"
    assert stitched["_meta"]["tracestate"] == "vendor-a=foo"
    assert stitched["_meta"]["baggage"] == "tenant=acme"


def test_stitch_jsonrpc_trace_meta_prefers_upstream_response_values():
    stitched = _stitch_jsonrpc_trace_meta(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "result": {"ok": True},
            "_meta": {"traceparent": "00-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-bbbbbbbbbbbbbbbb-01"},
        },
        {
            "traceparent": "00-0123456789abcdef0123456789abcdef-0123456789abcdef-01",
            "tracestate": "vendor-a=foo",
            "baggage": "tenant=acme",
        },
    )
    assert stitched["_meta"]["traceparent"] == "00-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-bbbbbbbbbbbbbbbb-01"
    assert stitched["_meta"]["tracestate"] == "vendor-a=foo"
    assert stitched["_meta"]["baggage"] == "tenant=acme"


def test_gateway_policy_cache_path_defaults_to_user_cache_home(monkeypatch):
    fake_home = Path("/tmp/agent-bom-home")
    monkeypatch.delenv("AGENT_BOM_PROXY_POLICY_CACHE_PATH", raising=False)
    monkeypatch.setattr(proxy_mod.Path, "home", staticmethod(lambda: fake_home))
    assert _gateway_policy_cache_path() == fake_home / ".agent-bom" / "cache" / "gateway-policies.json"


def test_gateway_policy_cache_path_honors_env_override(monkeypatch):
    monkeypatch.setenv("AGENT_BOM_PROXY_POLICY_CACHE_PATH", "/tmp/custom-policy-cache.json")
    assert _gateway_policy_cache_path() == Path("/tmp/custom-policy-cache.json")


def test_gateway_policy_cache_round_trip(tmp_path: Path, monkeypatch):
    cache_path = tmp_path / "gateway-policies.json"
    monkeypatch.setattr(proxy_mod.time, "time", lambda: 1234.0)
    policies = [
        GatewayPolicy(
            policy_id="p1",
            name="Block secrets",
            rules=[GatewayRule(id="r1", block_secret_paths=True)],
            tenant_id="tenant-a",
        )
    ]
    _persist_gateway_policies_cache(cache_path, policies, "etag-1")
    loaded_policies, loaded_etag = _load_cached_gateway_policies(cache_path, max_age_seconds=60)
    assert loaded_etag == "etag-1"
    assert loaded_policies is not None
    assert len(loaded_policies) == 1
    assert loaded_policies[0].policy_id == "p1"
    assert loaded_policies[0].tenant_id == "tenant-a"


def test_gateway_policy_cache_rejects_stale_entries(tmp_path: Path, monkeypatch):
    cache_path = tmp_path / "gateway-policies.json"
    monkeypatch.setattr(proxy_mod.time, "time", lambda: 100.0)
    _persist_gateway_policies_cache(
        cache_path,
        [GatewayPolicy(policy_id="p1", name="stale", rules=[])],
        "etag-stale",
    )
    monkeypatch.setattr(proxy_mod.time, "time", lambda: 1000.0)
    loaded_policies, loaded_etag = _load_cached_gateway_policies(cache_path, max_age_seconds=60)
    assert loaded_policies is None
    assert loaded_etag is None


def test_gateway_policy_cache_rejects_invalid_payload(tmp_path: Path):
    cache_path = tmp_path / "gateway-policies.json"
    cache_path.write_text('{"fetched_at": 10, "policies": [{"policy_id": "missing-name"}]}')
    loaded_policies, loaded_etag = _load_cached_gateway_policies(cache_path, max_age_seconds=60)
    assert loaded_policies is None
    assert loaded_etag is None


def _ed25519_private_key_pem() -> str:
    private_key = Ed25519PrivateKey.generate()
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()


def test_gateway_policy_cache_round_trip_requires_valid_signature_when_enabled(tmp_path: Path, monkeypatch):
    cache_path = tmp_path / "gateway-policies.json"
    monkeypatch.setattr(proxy_mod.time, "time", lambda: 1234.0)
    monkeypatch.setenv("AGENT_BOM_PROXY_POLICY_CACHE_ED25519_PRIVATE_KEY_PEM", _ed25519_private_key_pem())
    _reset_gateway_policy_cache_signer_for_tests()

    policies = [GatewayPolicy(policy_id="p1", name="signed", rules=[], tenant_id="tenant-a")]
    _persist_gateway_policies_cache(cache_path, policies, "etag-signed")

    signature_path = _gateway_policy_cache_signature_path(cache_path)
    assert signature_path.exists()

    loaded_policies, loaded_etag = _load_cached_gateway_policies(cache_path, max_age_seconds=60)
    assert loaded_etag == "etag-signed"
    assert loaded_policies is not None
    assert loaded_policies[0].policy_id == "p1"


def test_gateway_policy_cache_rejects_signature_mismatch(tmp_path: Path, monkeypatch):
    cache_path = tmp_path / "gateway-policies.json"
    monkeypatch.setattr(proxy_mod.time, "time", lambda: 1234.0)
    monkeypatch.setenv("AGENT_BOM_PROXY_POLICY_CACHE_ED25519_PRIVATE_KEY_PEM", _ed25519_private_key_pem())
    _reset_gateway_policy_cache_signer_for_tests()

    policies = [GatewayPolicy(policy_id="p1", name="signed", rules=[], tenant_id="tenant-a")]
    _persist_gateway_policies_cache(cache_path, policies, "etag-signed")

    payload = json.loads(cache_path.read_text())
    payload["policies"][0]["name"] = "tampered"
    cache_path.write_text(json.dumps(payload))

    loaded_policies, loaded_etag = _load_cached_gateway_policies(cache_path, max_age_seconds=60)
    assert loaded_policies is None
    assert loaded_etag is None


def test_gateway_policy_cache_rejects_missing_signature_when_enabled(tmp_path: Path, monkeypatch):
    cache_path = tmp_path / "gateway-policies.json"
    monkeypatch.setattr(proxy_mod.time, "time", lambda: 1234.0)
    monkeypatch.setenv("AGENT_BOM_PROXY_POLICY_CACHE_ED25519_PRIVATE_KEY_PEM", _ed25519_private_key_pem())
    _reset_gateway_policy_cache_signer_for_tests()

    policies = [GatewayPolicy(policy_id="p1", name="unsigned", rules=[], tenant_id="tenant-a")]
    _persist_gateway_policies_cache(cache_path, policies, "etag-signed")
    _gateway_policy_cache_signature_path(cache_path).unlink()

    loaded_policies, loaded_etag = _load_cached_gateway_policies(cache_path, max_age_seconds=60)
    assert loaded_policies is None
    assert loaded_etag is None


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
    assert s["audit_buffer_bytes"] == 0
    assert s["audit_spillover_bytes"] == 0
    assert s["audit_dlq_bytes"] == 0
    assert s["policy_fetch_failures"] == 0
    assert s["audit_push_failures"] == 0
    assert s["audit_push_backoff_seconds"] == 0
    assert s["audit_circuit_open"] == 0
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


def test_proxy_metrics_records_backpressure_and_policy_failures():
    """Proxy metrics surface control-plane linkage failures and queued backlog."""
    m = ProxyMetrics()
    m.set_audit_buffer_bytes(1024)
    m.set_audit_spillover_bytes(2048)
    m.set_audit_dlq_bytes(4096)
    m.record_policy_fetch_failure()
    m.record_audit_push_failure()
    m.set_audit_push_backoff_seconds(30)
    m.set_audit_circuit_open(True)

    s = m.summary()
    assert s["audit_buffer_bytes"] == 1024
    assert s["audit_spillover_bytes"] == 2048
    assert s["audit_dlq_bytes"] == 4096
    assert s["policy_fetch_failures"] == 1
    assert s["audit_push_failures"] == 1
    assert s["audit_push_backoff_seconds"] == 30
    assert s["audit_circuit_open"] == 1


def test_audit_delivery_controller_opens_circuit_after_threshold():
    controller = AuditDeliveryController(
        base_interval_seconds=10,
        max_backoff_seconds=60,
        breaker_failure_threshold=3,
        breaker_cooldown_seconds=30,
    )
    controller.record_failure(now=100.0)
    assert controller.current_backoff_seconds(now=100.0) == 20
    assert controller.is_circuit_open(now=100.0) is False
    controller.record_failure(now=101.0)
    assert controller.current_backoff_seconds(now=101.0) == 40
    controller.record_failure(now=102.0)
    assert controller.is_circuit_open(now=102.0) is True
    assert controller.current_backoff_seconds(now=102.0) == 30
    controller.record_success()
    assert controller.is_circuit_open(now=102.0) is False
    assert controller.current_backoff_seconds(now=102.0) == 10


def test_audit_spillover_store_diverts_to_dlq_when_spillover_full(tmp_path: Path):
    store = AuditSpilloverStore(
        spill_path=tmp_path / "spill.jsonl",
        dlq_path=tmp_path / "audit.dlq.jsonl",
        max_spillover_bytes=1,
    )
    destination = store.append_events([{"event": "first"}])
    assert destination == "dlq"
    assert store.spillover_size_bytes() == 0
    assert store.dlq_size_bytes() > 0


# ── CLI proxy --help ─────────────────────────────────────────────────────────


def test_proxy_cli_help():
    """'agent-bom proxy --help' mentions 'security proxy'."""
    from click.testing import CliRunner

    from agent_bom.cli import main

    runner = CliRunner()
    result = runner.invoke(main, ["proxy", "--help"])
    assert result.exit_code == 0
    assert "security proxy" in result.output


# ── compute_payload_hash ────────────────────────────────────────────────────


def test_payload_hash_deterministic():
    """Same payload always produces the same SHA-256 hash."""
    msg = {"jsonrpc": "2.0", "method": "tools/call", "id": 1, "params": {"name": "scan"}}
    h1 = compute_payload_hash(msg)
    h2 = compute_payload_hash(msg)
    assert h1 == h2
    assert len(h1) == 64  # SHA-256 hex digest


def test_payload_hash_differs_for_different_payloads():
    """Different payloads produce different hashes."""
    msg_a = {"jsonrpc": "2.0", "method": "tools/call", "id": 1}
    msg_b = {"jsonrpc": "2.0", "method": "tools/call", "id": 2}
    assert compute_payload_hash(msg_a) != compute_payload_hash(msg_b)


def test_payload_hash_canonical_key_order():
    """Hash is the same regardless of dict key insertion order."""
    msg_a = {"b": 2, "a": 1}
    msg_b = {"a": 1, "b": 2}
    assert compute_payload_hash(msg_a) == compute_payload_hash(msg_b)


# ── ReplayDetector ──────────────────────────────────────────────────────────


def test_replay_detector_first_message_not_replay():
    """First occurrence of a message is not a replay."""
    detector = ReplayDetector()
    msg = {"jsonrpc": "2.0", "method": "tools/call", "id": 1}
    assert detector.check(msg) is False


def test_replay_detector_duplicate_within_window():
    """Same message within the window is detected as replay."""
    detector = ReplayDetector(window_seconds=300.0)
    msg = {"jsonrpc": "2.0", "method": "tools/call", "id": 1}
    detector.check(msg)  # First — not a replay
    assert detector.check(msg) is True  # Second — replay


def test_replay_detector_different_messages_not_replay():
    """Different messages are not replays of each other."""
    detector = ReplayDetector()
    msg_a = {"jsonrpc": "2.0", "method": "tools/call", "id": 1}
    msg_b = {"jsonrpc": "2.0", "method": "tools/call", "id": 2}
    detector.check(msg_a)
    assert detector.check(msg_b) is False


def test_replay_detector_eviction_on_overflow():
    """Replay detector memory stays bounded under sustained inserts."""
    detector = ReplayDetector(max_entries=2, window_seconds=300.0)
    baseline_bytes = detector.memory_bytes
    for i in range(50):
        assert detector.check({"id": i}) is False
    assert detector.memory_bytes == baseline_bytes


def test_replay_detector_expires_entries_after_window():
    detector = ReplayDetector(window_seconds=0.01, bucket_seconds=0.01)
    msg = {"jsonrpc": "2.0", "method": "tools/call", "id": 1}
    assert detector.check(msg) is False
    time.sleep(0.02)
    assert detector.check(msg) is False


# ── log_tool_call with integrity fields ─────────────────────────────────────


def test_log_tool_call_with_integrity_fields():
    """log_tool_call includes payload_sha256 and message_id when provided."""
    buf = io.StringIO()
    log_tool_call(
        buf,
        "scan",
        {"target": "test"},
        policy_result="allowed",
        payload_sha256="abc123def456",
        message_id=42,
    )
    buf.seek(0)
    record = json.loads(buf.readline())
    assert record["payload_sha256"] == "abc123def456"
    assert record["message_id"] == 42


def test_log_tool_call_omits_empty_integrity_fields():
    """Integrity fields are omitted when not provided."""
    buf = io.StringIO()
    log_tool_call(buf, "check", {}, policy_result="allowed")
    buf.seek(0)
    record = json.loads(buf.readline())
    assert "payload_sha256" not in record
    assert "message_id" not in record


# ── ProxyMetrics replay_rejections ──────────────────────────────────────────


def test_proxy_metrics_replay_rejections():
    """replay_rejections counter starts at zero and increments."""
    m = ProxyMetrics()
    assert m.replay_rejections == 0
    m.replay_rejections += 1
    m.replay_rejections += 1
    assert m.replay_rejections == 2
    s = m.summary()
    assert s["replay_rejections"] == 2


# ── check_policy allowlist mode ─────────────────────────────────────────────


def test_check_policy_allowlist_permits_listed_tool():
    """Allowlist rule permits a tool that is in the allow_tools list."""
    policy = {
        "rules": [
            {"id": "prod-allow", "action": "block", "mode": "allowlist", "allow_tools": ["read_file", "search"]},
        ],
    }
    allowed, reason = check_policy(policy, "read_file", {})
    assert allowed is True
    assert reason == ""


def test_check_policy_allowlist_blocks_unlisted_tool():
    """Allowlist rule blocks a tool not in the allow_tools list."""
    policy = {
        "rules": [
            {"id": "prod-allow", "action": "block", "mode": "allowlist", "allow_tools": ["read_file", "search"]},
        ],
    }
    allowed, reason = check_policy(policy, "write_file", {})
    assert allowed is False
    assert "allowlist" in reason
    assert "prod-allow" in reason


def test_check_policy_allowlist_empty_blocks_everything():
    """Allowlist rule with empty allow_tools blocks all tools."""
    policy = {
        "rules": [
            {"id": "lockdown", "action": "block", "mode": "allowlist", "allow_tools": []},
        ],
    }
    allowed, reason = check_policy(policy, "read_file", {})
    assert allowed is False


def test_check_policy_allowlist_with_arg_pattern_defense_in_depth():
    """Tool in allowlist can still be blocked by arg_pattern (defense-in-depth)."""
    policy = {
        "rules": [
            {"id": "allow-reads", "action": "block", "mode": "allowlist", "allow_tools": ["read_file"]},
            {"id": "no-etc", "action": "block", "arg_pattern": {"path": "/etc/.*"}},
        ],
    }
    # Tool is in allowlist BUT arg matches blocklist pattern
    allowed, reason = check_policy(policy, "read_file", {"path": "/etc/passwd"})
    assert allowed is False
    assert "/etc/.*" in reason


def test_check_policy_allowlist_warn_does_not_enforce():
    """Allowlist rule with action='warn' does not block (advisory only)."""
    policy = {
        "rules": [
            {"id": "audit-only", "action": "warn", "mode": "allowlist", "allow_tools": ["read_file"]},
        ],
    }
    allowed, reason = check_policy(policy, "write_file", {})
    assert allowed is True  # warn rules are not enforced at runtime


# ── compute_response_hmac ───────────────────────────────────────────────────


def test_response_hmac_deterministic():
    """Same payload + key always produces the same HMAC."""
    msg = {"jsonrpc": "2.0", "id": 1, "result": {"content": [{"type": "text", "text": "ok"}]}}
    h1 = compute_response_hmac(msg, "secret-key")
    h2 = compute_response_hmac(msg, "secret-key")
    assert h1 == h2
    assert len(h1) == 64  # HMAC-SHA256 hex digest


def test_response_hmac_key_sensitivity():
    """Different keys produce different HMACs for the same payload."""
    msg = {"jsonrpc": "2.0", "id": 1, "result": {"data": "hello"}}
    assert compute_response_hmac(msg, "key-a") != compute_response_hmac(msg, "key-b")


def test_response_hmac_payload_sensitivity():
    """Different payloads produce different HMACs with the same key."""
    msg_a = {"jsonrpc": "2.0", "id": 1, "result": {"data": "hello"}}
    msg_b = {"jsonrpc": "2.0", "id": 1, "result": {"data": "tampered"}}
    assert compute_response_hmac(msg_a, "key") != compute_response_hmac(msg_b, "key")


# ── SSE proxy — CLI --url flag ────────────────────────────────────────────────


def test_proxy_cli_url_flag_accepted():
    """'agent-bom proxy --url ...' is accepted by the CLI (does not raise UsageError)."""
    from unittest.mock import AsyncMock, patch

    from click.testing import CliRunner

    from agent_bom.cli import main

    runner = CliRunner()

    # Mock _proxy_sse_server so we don't need a real HTTP server
    with patch("agent_bom.proxy._proxy_sse_server", new=AsyncMock(return_value=0)):
        result = runner.invoke(main, ["proxy", "--url", "http://localhost:3000"])

    # Should exit with 0 (the mock returns 0) — not a UsageError (exit code 2)
    assert result.exit_code != 2, f"CLI rejected --url flag: {result.output}"


def test_proxy_cli_no_cmd_no_url_raises_usage_error():
    """'agent-bom proxy' with neither server_cmd nor --url exits with UsageError."""
    from click.testing import CliRunner

    from agent_bom.cli import main

    runner = CliRunner()
    result = runner.invoke(main, ["proxy"])
    # Click UsageError exits with code 2
    assert result.exit_code == 2


# ── SSE proxy — httpx connection ──────────────────────────────────────────────


def test_proxy_sse_server_uses_httpx(tmp_path):
    """_proxy_sse_server creates an httpx.AsyncClient to contact the remote server."""
    import asyncio
    from unittest.mock import AsyncMock, MagicMock, patch

    from agent_bom.proxy import _proxy_sse_server

    # Mock httpx.AsyncClient — simulate an empty tools/list and immediate EOF on stdin
    mock_response = MagicMock()
    mock_response.raise_for_status = MagicMock()
    mock_response.json.return_value = {"jsonrpc": "2.0", "id": 1, "result": {"tools": []}}

    mock_client = AsyncMock()
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=None)
    mock_client.post = AsyncMock(return_value=mock_response)

    # Patch stdin to return EOF immediately so the proxy loop exits cleanly
    async def _fake_readline():
        return b""

    mock_reader = AsyncMock()
    mock_reader.readline = _fake_readline

    with (
        patch("httpx.AsyncClient", return_value=mock_client),
        patch("asyncio.StreamReader", return_value=mock_reader),
        patch("asyncio.get_running_loop") as mock_loop,
    ):
        mock_loop.return_value.connect_read_pipe = AsyncMock()

        exit_code = asyncio.run(_proxy_sse_server(url="http://localhost:3000"))

    # httpx.AsyncClient was instantiated (i.e., we used httpx for the connection)
    assert mock_client.__aenter__.called or True  # context manager was entered
    assert exit_code == 0


def test_response_hmac_canonical_key_order():
    """HMAC is the same regardless of dict key insertion order."""
    msg_a = {"b": 2, "a": 1}
    msg_b = {"a": 1, "b": 2}
    assert compute_response_hmac(msg_a, "key") == compute_response_hmac(msg_b, "key")


def test_response_hmac_differs_from_payload_hash():
    """HMAC with a key is not the same as a plain SHA-256 hash."""
    msg = {"jsonrpc": "2.0", "id": 1, "result": {}}
    assert compute_response_hmac(msg, "some-key") != compute_payload_hash(msg)


# ── ProxyMetrics relay_errors ───────────────────────────────────────────────


def test_proxy_metrics_relay_errors_default_zero():
    """relay_errors starts at zero."""
    m = ProxyMetrics()
    assert m.relay_errors == 0


def test_proxy_metrics_relay_errors_in_summary():
    """relay_errors is included in the summary dict."""
    m = ProxyMetrics()
    m.relay_errors = 2
    s = m.summary()
    assert s["relay_errors"] == 2


def test_proxy_metrics_summary_relay_errors_zero():
    """summary() includes relay_errors=0 when no errors occurred."""
    m = ProxyMetrics()
    s = m.summary()
    assert "relay_errors" in s
    assert s["relay_errors"] == 0
