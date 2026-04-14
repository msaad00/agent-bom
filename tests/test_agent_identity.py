"""Tests for agent_identity — JWT/opaque token extraction and validation."""

from __future__ import annotations

import base64
import io
import json
import time

from agent_bom.agent_identity import (
    ANONYMOUS,
    check_identity,
    extract_identity_token,
    resolve_agent_id,
)
from agent_bom.proxy import log_tool_call

# ─── Helpers ─────────────────────────────────────────────────────────────────


def _make_jwt(payload: dict, header: dict | None = None) -> str:
    """Build a fake (unsigned) JWT with the given payload."""
    h = header or {"alg": "HS256", "typ": "JWT"}

    def _b64(d: dict) -> str:
        return base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b"=").decode()

    return f"{_b64(h)}.{_b64(payload)}.fakesig"


def _msg_with_identity(token: str) -> dict:
    """Build a minimal tools/call message carrying the given identity token."""
    return {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": "read_file",
            "arguments": {"path": "/tmp/x"},
            "_meta": {"agent_identity": token},
        },
    }


# ─── extract_identity_token ───────────────────────────────────────────────────


def test_extract_token_present():
    msg = _msg_with_identity("mytoken")
    assert extract_identity_token(msg) == "mytoken"


def test_extract_token_missing_meta():
    msg = {"method": "tools/call", "params": {"name": "x", "arguments": {}}}
    assert extract_identity_token(msg) is None


def test_extract_token_missing_field():
    msg = {"method": "tools/call", "params": {"name": "x", "arguments": {}, "_meta": {}}}
    assert extract_identity_token(msg) is None


def test_extract_token_empty_string():
    msg = _msg_with_identity("   ")
    assert extract_identity_token(msg) is None


def test_extract_token_no_params():
    assert extract_identity_token({"method": "tools/call"}) is None


# ─── resolve_agent_id — JWT ───────────────────────────────────────────────────


def test_resolve_jwt_sub_claim():
    token = _make_jwt({"sub": "agent-alice", "iat": int(time.time())})
    agent_id, err = resolve_agent_id(token, {})
    assert agent_id == "agent-alice"
    assert err is None


def test_resolve_jwt_agent_id_claim_fallback():
    token = _make_jwt({"agent_id": "bot-42"})
    agent_id, err = resolve_agent_id(token, {})
    assert agent_id == "bot-42"
    assert err is None


def test_resolve_jwt_name_claim_fallback():
    token = _make_jwt({"name": "pipeline-runner"})
    agent_id, err = resolve_agent_id(token, {})
    assert agent_id == "pipeline-runner"
    assert err is None


def test_resolve_jwt_expired():
    token = _make_jwt({"sub": "agent-bob", "exp": int(time.time()) - 100})
    agent_id, err = resolve_agent_id(token, {})
    assert agent_id == ANONYMOUS
    assert err is not None
    assert "expired" in err.lower()


def test_resolve_jwt_future_exp_ok():
    token = _make_jwt({"sub": "agent-carl", "exp": int(time.time()) + 3600})
    agent_id, err = resolve_agent_id(token, {})
    assert agent_id == "agent-carl"
    assert err is None


def test_resolve_jwt_no_identity_claim():
    token = _make_jwt({"iss": "example.com"})
    agent_id, err = resolve_agent_id(token, {})
    assert agent_id == ANONYMOUS
    assert err is not None


def test_resolve_jwt_malformed_payload():
    # Two dots but garbled base64
    token = "aaa.!!!.bbb"
    agent_id, err = resolve_agent_id(token, {})
    assert agent_id == ANONYMOUS
    assert err is not None


def test_resolve_jwt_invalid_exp_type():
    token = _make_jwt({"sub": "x", "exp": "not-a-number"})
    agent_id, err = resolve_agent_id(token, {})
    assert agent_id == ANONYMOUS
    assert err is not None


# ─── resolve_agent_id — opaque token ─────────────────────────────────────────


def test_resolve_opaque_token_in_policy():
    policy = {"agent_tokens": {"secret-token-123": "my-agent"}}
    agent_id, err = resolve_agent_id("secret-token-123", policy)
    assert agent_id == "my-agent"
    assert err is None


def test_resolve_opaque_token_not_in_policy():
    policy = {"agent_tokens": {"other-token": "other-agent"}}
    agent_id, err = resolve_agent_id("unknown-token", policy)
    assert agent_id == ANONYMOUS
    assert err is not None


def test_resolve_opaque_no_policy():
    agent_id, err = resolve_agent_id("some-token", {})
    assert agent_id == ANONYMOUS
    assert err is not None


def test_resolve_opaque_empty_value_in_policy():
    policy = {"agent_tokens": {"tok": ""}}
    agent_id, err = resolve_agent_id("tok", policy)
    assert agent_id == ANONYMOUS
    assert err is not None


# ─── check_identity — full flow ───────────────────────────────────────────────


def test_check_identity_no_token_no_requirement():
    msg = {"method": "tools/call", "params": {"name": "x", "arguments": {}}}
    agent_id, block = check_identity(msg, {})
    assert agent_id == ANONYMOUS
    assert block is None


def test_check_identity_no_token_required_blocks():
    msg = {"method": "tools/call", "params": {"name": "x", "arguments": {}}}
    policy = {"require_agent_identity": True}
    agent_id, block = check_identity(msg, policy)
    assert agent_id == ANONYMOUS
    assert block is not None
    assert "required" in block.lower()


def test_check_identity_valid_jwt_passes():
    token = _make_jwt({"sub": "agent-diana"})
    msg = _msg_with_identity(token)
    agent_id, block = check_identity(msg, {})
    assert agent_id == "agent-diana"
    assert block is None


def test_check_identity_valid_jwt_required_passes():
    token = _make_jwt({"sub": "agent-diana"})
    msg = _msg_with_identity(token)
    policy = {"require_agent_identity": True}
    agent_id, block = check_identity(msg, policy)
    assert agent_id == "agent-diana"
    assert block is None


def test_check_identity_expired_jwt_required_blocks():
    token = _make_jwt({"sub": "agent-x", "exp": int(time.time()) - 60})
    msg = _msg_with_identity(token)
    policy = {"require_agent_identity": True}
    agent_id, block = check_identity(msg, policy)
    assert agent_id == ANONYMOUS
    assert block is not None


def test_check_identity_expired_jwt_not_required_anonymous():
    token = _make_jwt({"sub": "agent-x", "exp": int(time.time()) - 60})
    msg = _msg_with_identity(token)
    agent_id, block = check_identity(msg, {})
    assert agent_id == ANONYMOUS
    assert block is None  # expired but not required → warn, don't block


def test_check_identity_opaque_token_resolves():
    msg = _msg_with_identity("tok-abc")
    policy = {"agent_tokens": {"tok-abc": "pipeline-bot"}}
    agent_id, block = check_identity(msg, policy)
    assert agent_id == "pipeline-bot"
    assert block is None


def test_check_identity_unknown_token_not_required():
    msg = _msg_with_identity("unknown-tok")
    agent_id, block = check_identity(msg, {})
    assert agent_id == ANONYMOUS
    assert block is None


def test_check_identity_unknown_token_required_blocks():
    msg = _msg_with_identity("unknown-tok")
    policy = {"require_agent_identity": True}
    agent_id, block = check_identity(msg, policy)
    assert block is not None


# ─── log_tool_call carries agent_id ──────────────────────────────────────────


def test_log_tool_call_agent_id_written():
    buf = io.StringIO()
    log_tool_call(buf, "read_file", {"path": "/x"}, agent_id="agent-eve")
    buf.seek(0)
    record = json.loads(buf.readline())
    assert record["agent_id"] == "agent-eve"
    assert record["event_relationships"]["actor"]["id"] == "agent-eve"
    assert record["event_relationships"]["actor"]["role"] == "caller"


def test_log_tool_call_anonymous_default():
    buf = io.StringIO()
    log_tool_call(buf, "list_tools", {})
    buf.seek(0)
    record = json.loads(buf.readline())
    assert record["agent_id"] == ANONYMOUS
    assert "actor" not in record["event_relationships"]


def test_log_tool_call_blocked_carries_agent_id():
    buf = io.StringIO()
    log_tool_call(buf, "exec", {}, policy_result="blocked", reason="policy", agent_id="bad-bot")
    buf.seek(0)
    record = json.loads(buf.readline())
    assert record["agent_id"] == "bad-bot"
    assert record["policy"] == "blocked"
    assert record["event_relationships"]["actor"]["id"] == "bad-bot"
