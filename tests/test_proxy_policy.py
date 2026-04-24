"""Tests for agent_bom.proxy policy and integrity features to improve coverage."""

from __future__ import annotations

from unittest.mock import MagicMock

from agent_bom.proxy import (
    ReplayDetector,
    check_policy,
    compute_payload_hash,
    compute_response_hmac,
    set_gateway_evaluator,
)
from agent_bom.proxy_policy import summarize_policy_bundle

# ---------------------------------------------------------------------------
# compute_payload_hash
# ---------------------------------------------------------------------------


def test_compute_payload_hash_deterministic():
    payload = {"method": "tools/call", "id": 1}
    h1 = compute_payload_hash(payload)
    h2 = compute_payload_hash(payload)
    assert h1 == h2
    assert len(h1) == 64  # SHA-256 hex


def test_compute_payload_hash_order_independent():
    h1 = compute_payload_hash({"a": 1, "b": 2})
    h2 = compute_payload_hash({"b": 2, "a": 1})
    assert h1 == h2


def test_compute_payload_hash_different_payloads():
    h1 = compute_payload_hash({"x": 1})
    h2 = compute_payload_hash({"x": 2})
    assert h1 != h2


# ---------------------------------------------------------------------------
# compute_response_hmac
# ---------------------------------------------------------------------------


def test_compute_response_hmac():
    payload = {"result": {"tools": []}}
    mac = compute_response_hmac(payload, "secret-key")
    assert len(mac) == 64


def test_compute_response_hmac_different_keys():
    payload = {"result": "ok"}
    mac1 = compute_response_hmac(payload, "key1")
    mac2 = compute_response_hmac(payload, "key2")
    assert mac1 != mac2


def test_compute_response_hmac_deterministic():
    payload = {"id": 1, "result": "ok"}
    mac1 = compute_response_hmac(payload, "key")
    mac2 = compute_response_hmac(payload, "key")
    assert mac1 == mac2


# ---------------------------------------------------------------------------
# ReplayDetector
# ---------------------------------------------------------------------------


def test_replay_detector_first_message():
    rd = ReplayDetector()
    assert rd.check({"method": "tools/call", "id": 1}) is False


def test_replay_detector_duplicate():
    rd = ReplayDetector()
    msg = {"method": "tools/call", "id": 1}
    rd.check(msg)
    assert rd.check(msg) is True


def test_replay_detector_different_messages():
    rd = ReplayDetector()
    rd.check({"id": 1})
    assert rd.check({"id": 2}) is False


def test_replay_detector_eviction():
    """When max_entries is reached, detector evicts oldest entries."""
    rd = ReplayDetector(max_entries=5, window_seconds=300)
    for i in range(10):
        rd.check({"id": i})
    # Should still work after evictions
    assert rd.check({"id": 999}) is False


# ---------------------------------------------------------------------------
# check_policy
# ---------------------------------------------------------------------------


def test_check_policy_empty_rules():
    allowed, reason = check_policy({"rules": []}, "read_file", {})
    assert allowed is True
    assert reason == ""


def test_check_policy_no_rules_key():
    allowed, reason = check_policy({}, "read_file", {})
    assert allowed is True


def test_check_policy_block_tool():
    policy = {"rules": [{"id": "r1", "action": "block", "block_tools": ["exec"]}]}
    allowed, reason = check_policy(policy, "exec", {})
    assert allowed is False
    assert "blocked" in reason.lower()


def test_check_policy_block_tool_not_matched():
    policy = {"rules": [{"id": "r1", "action": "block", "block_tools": ["exec"]}]}
    allowed, reason = check_policy(policy, "read_file", {})
    assert allowed is True


def test_check_policy_tool_name_match():
    policy = {"rules": [{"id": "r1", "action": "fail", "tool_name": "dangerous_tool"}]}
    allowed, reason = check_policy(policy, "dangerous_tool", {})
    assert allowed is False


def test_check_policy_tool_name_pattern():
    policy = {"rules": [{"id": "r1", "action": "block", "tool_name_pattern": "^exec.*"}]}
    allowed, reason = check_policy(policy, "exec_cmd", {})
    assert allowed is False


def test_check_policy_tool_name_pattern_no_match():
    policy = {"rules": [{"id": "r1", "action": "block", "tool_name_pattern": "^exec.*"}]}
    allowed, reason = check_policy(policy, "read_file", {})
    assert allowed is True


def test_check_policy_arg_pattern():
    policy = {
        "rules": [
            {
                "id": "r1",
                "action": "block",
                "arg_pattern": {"path": "/etc/passwd"},
            }
        ]
    }
    allowed, reason = check_policy(policy, "read_file", {"path": "/etc/passwd"})
    assert allowed is False


def test_check_policy_arg_pattern_no_match():
    policy = {
        "rules": [
            {
                "id": "r1",
                "action": "block",
                "arg_pattern": {"path": "/etc/passwd"},
            }
        ]
    }
    allowed, reason = check_policy(policy, "read_file", {"path": "/tmp/safe"})
    assert allowed is True


def test_check_policy_warn_action_not_blocking():
    """Warn action should not block."""
    policy = {"rules": [{"id": "r1", "action": "warn", "block_tools": ["exec"]}]}
    allowed, reason = check_policy(policy, "exec", {})
    assert allowed is True


def test_check_policy_allowlist_mode():
    """Allowlist mode blocks tools not in the list."""
    policy = {"rules": [{"id": "r1", "mode": "allowlist", "action": "block", "allow_tools": ["read_file"]}]}
    allowed, reason = check_policy(policy, "exec", {})
    assert allowed is False
    assert "allowlist" in reason.lower()


def test_check_policy_allowlist_mode_allowed():
    """Tool in allowlist is allowed."""
    policy = {"rules": [{"id": "r1", "mode": "allowlist", "action": "block", "allow_tools": ["read_file"]}]}
    allowed, reason = check_policy(policy, "read_file", {})
    assert allowed is True


def test_check_policy_oversized_pattern():
    """Oversized patterns should be skipped."""
    policy = {"rules": [{"id": "r1", "action": "block", "tool_name_pattern": "x" * 600}]}
    allowed, reason = check_policy(policy, "test", {})
    assert allowed is True


def test_check_policy_oversized_arg_pattern():
    policy = {"rules": [{"id": "r1", "action": "block", "arg_pattern": {"cmd": "x" * 600}}]}
    allowed, reason = check_policy(policy, "exec", {"cmd": "ls"})
    assert allowed is True


def test_check_policy_read_only_allows_read_tool():
    policy = {"rules": [{"id": "r1", "action": "block", "read_only": True}]}
    allowed, reason = check_policy(policy, "read_file", {"path": "/tmp/demo.txt"})
    assert allowed is True
    assert reason == ""


def test_check_policy_read_only_blocks_execute_tool():
    policy = {"rules": [{"id": "r1", "action": "block", "read_only": True}]}
    allowed, reason = check_policy(policy, "exec_shell", {"cmd": "ls"})
    assert allowed is False
    assert "read-only" in reason.lower()


def test_check_policy_blocks_secret_env_path():
    policy = {"rules": [{"id": "r1", "action": "block", "block_secret_paths": True}]}
    allowed, reason = check_policy(policy, "read_file", {"path": "/workspace/.env"})
    assert allowed is False
    assert "secret path" in reason.lower()


def test_check_policy_blocks_non_allowlisted_host():
    policy = {
        "rules": [
            {
                "id": "r1",
                "action": "block",
                "block_unknown_egress": True,
                "allowed_hosts": ["api.openai.com"],
            }
        ]
    }
    allowed, reason = check_policy(policy, "web_fetch", {"endpoint": "https://evil.example/api"})
    assert allowed is False
    assert "allowlisted" in reason.lower()


def test_summarize_policy_bundle_disabled():
    summary = summarize_policy_bundle({})
    assert summary["rollout_mode"] == "disabled"
    assert summary["blocks_requests"] is False
    assert summary["total_rules"] == 0


def test_summarize_policy_bundle_advisory_only():
    summary = summarize_policy_bundle(
        {
            "rules": [
                {"id": "warn-exec", "action": "warn", "deny_tool_classes": ["execute"]},
                {"id": "warn-secret", "block_secret_paths": True},
            ]
        }
    )
    assert summary["rollout_mode"] == "advisory_only"
    assert summary["advisory_only"] is True
    assert summary["blocking_rules"] == 0
    assert summary["advisory_rules"] == 2
    assert summary["denied_tool_classes"] == ["execute"]
    assert summary["protects_secret_paths"] is True


def test_summarize_policy_bundle_default_deny():
    summary = summarize_policy_bundle(
        {
            "rules": [
                {"id": "allow-read", "mode": "allowlist", "action": "block", "allow_tools": ["read_file"]},
                {"id": "no-egress", "action": "block", "block_unknown_egress": True, "allowed_hosts": ["api.openai.com"]},
            ]
        }
    )
    assert summary["rollout_mode"] == "default_deny"
    assert summary["blocks_requests"] is True
    assert summary["default_deny"] is True
    assert summary["allowlist_rules"] == 1
    assert summary["default_deny_rules"] == 1
    assert summary["restricts_unknown_egress"] is True


# ---------------------------------------------------------------------------
# set_gateway_evaluator
# ---------------------------------------------------------------------------


def test_set_gateway_evaluator():
    fn = MagicMock(return_value=(True, ""))
    set_gateway_evaluator(fn)
    # Just verify it doesn't crash; the evaluator is module-level state
