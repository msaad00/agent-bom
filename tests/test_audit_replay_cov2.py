"""Tests for agent_bom.audit_replay to improve coverage."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

from agent_bom.audit_replay import (
    AlertEntry,
    AuditLog,
    RelayErrorEntry,
    ResponseHMACEntry,
    SummaryEntry,
    ToolCallEntry,
    _policy_style,
    _severity_style,
    display_json,
    display_rich,
    parse_audit_log,
    replay,
    verify_hmac_entries,
)

# ---------------------------------------------------------------------------
# parse_audit_log
# ---------------------------------------------------------------------------


def _write_jsonl(lines: list[dict]) -> Path:
    """Write JSONL lines to a temp file and return path."""
    tmp = tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False)
    for line in lines:
        tmp.write(json.dumps(line) + "\n")
    tmp.flush()
    return Path(tmp.name)


def test_parse_empty_log():
    path = _write_jsonl([])
    log = parse_audit_log(path)
    assert len(log.tool_calls) == 0
    assert log.summary is None


def test_parse_tool_call_entry():
    path = _write_jsonl(
        [
            {
                "type": "tools/call",
                "ts": "2025-01-01T00:00:00Z",
                "tool": "read_file",
                "policy": "allowed",
                "reason": "",
                "agent_id": "a1",
                "args": {"path": "/tmp"},
                "payload_sha256": "abc123",
                "message_id": 42,
            }
        ]
    )
    log = parse_audit_log(path)
    assert len(log.tool_calls) == 1
    tc = log.tool_calls[0]
    assert tc.tool == "read_file"
    assert tc.policy == "allowed"
    assert tc.message_id == 42


def test_parse_relay_error():
    path = _write_jsonl([{"type": "relay_error", "ts": "2025-01-01T00:00:00Z", "error": "connection lost", "error_type": "timeout"}])
    log = parse_audit_log(path)
    assert len(log.relay_errors) == 1
    assert log.relay_errors[0].error == "connection lost"


def test_parse_response_hmac():
    path = _write_jsonl([{"type": "response_hmac", "ts": "2025-01-01T00:00:00Z", "id": 42, "hmac_sha256": "deadbeef" * 8}])
    log = parse_audit_log(path)
    assert len(log.hmac_entries) == 1
    assert log.hmac_entries[0].message_id == 42


def test_parse_proxy_summary():
    path = _write_jsonl(
        [
            {
                "type": "proxy_summary",
                "ts": "2025-01-01T00:00:00Z",
                "uptime_seconds": 120.0,
                "total_tool_calls": 50,
                "total_blocked": 3,
                "calls_by_tool": {"read": 30, "write": 20},
                "blocked_by_reason": {"policy": 3},
                "latency": {"p50_ms": 10, "p95_ms": 50, "avg_ms": 15},
                "replay_rejections": 1,
                "relay_errors": 0,
                "runtime_alerts": 2,
            }
        ]
    )
    log = parse_audit_log(path)
    assert log.summary is not None
    assert log.summary.total_tool_calls == 50
    assert log.summary.replay_rejections == 1


def test_parse_alert_entry():
    path = _write_jsonl(
        [{"ts": "2025-01-01T00:00:00Z", "severity": "high", "detector": "cred_leak", "message": "API key found", "tool": "read_file"}]
    )
    log = parse_audit_log(path)
    assert len(log.alerts) == 1
    assert log.alerts[0].detector == "cred_leak"


def test_parse_unknown_entry():
    path = _write_jsonl([{"type": "custom_event", "data": 123}])
    log = parse_audit_log(path)
    assert len(log.unknown) == 1


def test_parse_invalid_json_line():
    tmp = tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False)
    tmp.write("not valid json\n")
    tmp.write(json.dumps({"type": "tools/call", "tool": "x"}) + "\n")
    tmp.flush()
    log = parse_audit_log(Path(tmp.name))
    assert len(log.tool_calls) == 1


def test_parse_blank_lines():
    tmp = tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False)
    tmp.write("\n\n")
    tmp.flush()
    log = parse_audit_log(Path(tmp.name))
    assert len(log.tool_calls) == 0


# ---------------------------------------------------------------------------
# verify_hmac_entries
# ---------------------------------------------------------------------------


def test_verify_hmac_match():
    import hashlib
    import hmac as hmac_mod

    sign_key = "secret123"
    payload_hash = "abc123"
    expected_hmac = hmac_mod.new(sign_key.encode(), payload_hash.encode(), hashlib.sha256).hexdigest()

    log = AuditLog(
        tool_calls=[
            ToolCallEntry(ts="", tool="t", policy="allowed", reason="", agent_id="", args={}, payload_sha256=payload_hash, message_id=1)
        ],
        hmac_entries=[ResponseHMACEntry(ts="", message_id=1, hmac_sha256=expected_hmac)],
    )
    verified, failed = verify_hmac_entries(log, sign_key)
    assert verified == 1
    assert failed == 0


def test_verify_hmac_mismatch():
    log = AuditLog(
        tool_calls=[ToolCallEntry(ts="", tool="t", policy="allowed", reason="", agent_id="", args={}, payload_sha256="abc", message_id=1)],
        hmac_entries=[ResponseHMACEntry(ts="", message_id=1, hmac_sha256="wrong" * 16)],
    )
    verified, failed = verify_hmac_entries(log, "secret")
    assert verified == 0
    assert failed == 1


def test_verify_hmac_no_matching_call():
    log = AuditLog(
        tool_calls=[],
        hmac_entries=[ResponseHMACEntry(ts="", message_id=99, hmac_sha256="x" * 64)],
    )
    verified, failed = verify_hmac_entries(log, "key")
    assert verified == 0
    assert failed == 0


# ---------------------------------------------------------------------------
# display_json
# ---------------------------------------------------------------------------


def test_display_json_empty(capsys):
    log = AuditLog()
    code = display_json(log)
    assert code == 0
    out = json.loads(capsys.readouterr().out)
    assert out["tool_calls"] == 0


def test_display_json_with_blocked(capsys):
    log = AuditLog(
        tool_calls=[
            ToolCallEntry(ts="", tool="t", policy="blocked", reason="policy", agent_id="", args={}, payload_sha256="", message_id=None)
        ],
    )
    code = display_json(log)
    assert code == 1
    out = json.loads(capsys.readouterr().out)
    assert out["blocked"] == 1


def test_display_json_with_relay_errors(capsys):
    log = AuditLog(
        relay_errors=[RelayErrorEntry(ts="", error="err", error_type="io")],
    )
    code = display_json(log)
    assert code == 1


def test_display_json_with_summary(capsys):
    log = AuditLog(
        summary=SummaryEntry(
            ts="",
            uptime_seconds=10.0,
            total_tool_calls=5,
            total_blocked=0,
            calls_by_tool={},
            blocked_by_reason={},
            latency={},
            replay_rejections=0,
            relay_errors=0,
            runtime_alerts=0,
        )
    )
    code = display_json(log)
    assert code == 0
    out = json.loads(capsys.readouterr().out)
    assert out["summary"]["total_tool_calls"] == 5


# ---------------------------------------------------------------------------
# display_rich
# ---------------------------------------------------------------------------


def test_display_rich_empty():
    log = AuditLog()
    code = display_rich(log)
    assert code == 0


def test_display_rich_with_blocked_calls():
    log = AuditLog(
        summary=SummaryEntry(
            ts="",
            uptime_seconds=5.0,
            total_tool_calls=3,
            total_blocked=1,
            calls_by_tool={"read": 3},
            blocked_by_reason={"policy": 1},
            latency={"p50_ms": 10, "p95_ms": 50, "avg_ms": 15},
            replay_rejections=2,
            relay_errors=1,
            runtime_alerts=1,
        ),
        tool_calls=[
            ToolCallEntry(
                ts="2025-01-01T00:00:00Z",
                tool="read_file",
                policy="blocked",
                reason="undeclared",
                agent_id="agent1",
                args={"path": "/etc"},
                payload_sha256="hash",
                message_id=1,
            )
        ],
    )
    code = display_rich(log, blocked_only=True)
    assert code == 1


def test_display_rich_alerts_only():
    log = AuditLog(
        alerts=[
            AlertEntry(
                ts="2025-01-01T00:00:00Z",
                detector="cred_leak",
                severity="high",
                message="Key found",
                tool="read_file",
                raw={},
            )
        ],
    )
    code = display_rich(log, alerts_only=True)
    assert code == 0


def test_display_rich_with_tool_filter():
    log = AuditLog(
        tool_calls=[
            ToolCallEntry(ts="", tool="read_file", policy="allowed", reason="", agent_id="", args={}, payload_sha256="", message_id=None),
            ToolCallEntry(ts="", tool="write_file", policy="allowed", reason="", agent_id="", args={}, payload_sha256="", message_id=None),
        ],
        alerts=[AlertEntry(ts="", detector="d", severity="low", message="m", tool="write_file", raw={})],
    )
    code = display_rich(log, tool_filter="read")
    assert code == 0


def test_display_rich_relay_errors():
    log = AuditLog(
        relay_errors=[RelayErrorEntry(ts="2025-01-01T00:00:00Z", error="timeout", error_type="io")],
    )
    code = display_rich(log)
    assert code == 1


def test_display_rich_hmac_entries():
    log = AuditLog(
        hmac_entries=[ResponseHMACEntry(ts="", message_id=1, hmac_sha256="x" * 64)],
    )
    code = display_rich(log)
    assert code == 0


# ---------------------------------------------------------------------------
# _severity_style / _policy_style
# ---------------------------------------------------------------------------


def test_severity_style():
    assert "red" in _severity_style("critical")
    assert "red" in _severity_style("high")
    assert "yellow" in _severity_style("medium")
    assert "dim" in _severity_style("low")
    assert _severity_style("unknown") == "white"


def test_policy_style():
    assert "red" in _policy_style("blocked")
    assert "green" in _policy_style("allowed")


# ---------------------------------------------------------------------------
# replay (entry point)
# ---------------------------------------------------------------------------


def test_replay_missing_file():
    code = replay("/nonexistent/file.jsonl")
    assert code == 2


def test_replay_clean_log():
    path = _write_jsonl([{"type": "tools/call", "tool": "read", "policy": "allowed"}])
    code = replay(str(path))
    assert code == 0


def test_replay_as_json(capsys):
    path = _write_jsonl([{"type": "tools/call", "tool": "read", "policy": "blocked", "reason": "test"}])
    code = replay(str(path), as_json=True)
    assert code == 1
