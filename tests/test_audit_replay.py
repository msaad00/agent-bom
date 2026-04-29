"""Tests for agent_bom.audit_replay — audit log parser and viewer."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

from agent_bom.audit_integrity import compute_audit_record_mac
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
    verify_hash_chain,
    verify_hmac_entries,
)

# ── Helpers ──────────────────────────────────────────────────────────────────


def _write_log(entries: list[dict]) -> Path:
    """Write a list of dicts as JSONL to a temp file, return path."""
    tmp = tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False)
    for e in entries:
        tmp.write(json.dumps(e) + "\n")
    tmp.close()
    return Path(tmp.name)


def _chained(entries: list[dict]) -> list[dict]:
    chained: list[dict] = []
    prev_hash = ""
    for entry in entries:
        payload = dict(entry)
        payload["prev_hash"] = prev_hash
        payload["record_hash_algorithm"] = "aes-cmac-128"
        digest_payload = {k: v for k, v in payload.items() if k not in {"prev_hash", "record_hash"}}
        payload["record_hash"] = compute_audit_record_mac(digest_payload, prev_hash)
        prev_hash = payload["record_hash"]
        chained.append(payload)
    return chained


TOOL_CALL = {
    "ts": "2026-03-09T10:00:00.000000+00:00",
    "type": "tools/call",
    "tool": "read_file",
    "policy": "allowed",
    "reason": "",
    "agent_id": "claude",
    "args": {"path": "/tmp/test.txt"},
    "payload_sha256": "abc123",
    "message_id": 1,
}

BLOCKED_CALL = {
    "ts": "2026-03-09T10:00:01.000000+00:00",
    "type": "tools/call",
    "tool": "delete_file",
    "policy": "blocked",
    "reason": "policy:no-delete",
    "agent_id": "claude",
    "args": {},
    "payload_sha256": "def456",
    "message_id": 2,
}

ALERT = {
    "ts": "2026-03-09T10:00:02.000000+00:00",
    "type": "tool_drift",
    "detector": "ToolDrift",
    "severity": "high",
    "message": "New tool appeared: delete_all",
    "tool": "delete_all",
}

RELAY_ERROR = {
    "ts": "2026-03-09T10:00:03.000000+00:00",
    "type": "relay_error",
    "error": "Connection reset by peer",
    "error_type": "ConnectionResetError",
}

RESPONSE_HMAC = {
    "ts": "2026-03-09T10:00:01.100000+00:00",
    "type": "response_hmac",
    "id": 1,
    "hmac_sha256": "a" * 64,
}

PROXY_SUMMARY = {
    "ts": "2026-03-09T10:05:00.000000+00:00",
    "type": "proxy_summary",
    "uptime_seconds": 300.5,
    "total_tool_calls": 42,
    "total_blocked": 3,
    "calls_by_tool": {"read_file": 30, "write_file": 12},
    "blocked_by_reason": {"policy": 3},
    "latency": {"min_ms": 5.0, "max_ms": 200.0, "avg_ms": 25.0, "p50_ms": 20.0, "p95_ms": 150.0, "count": 42},
    "messages_client_to_server": 50,
    "messages_server_to_client": 48,
    "replay_rejections": 0,
    "relay_errors": 0,
    "runtime_alerts": 1,
    "runtime_alerts_by_severity": {"critical": 1},
    "runtime_alerts_by_detector": {"ToolDrift": 1},
    "blocked_runtime_alerts": 0,
    "latest_runtime_alert_at": "2026-03-09T10:00:02.000000+00:00",
}


# ── parse_audit_log ──────────────────────────────────────────────────────────


def test_parse_empty_log():
    p = _write_log([])
    log = parse_audit_log(p)
    assert log.tool_calls == []
    assert log.alerts == []
    assert log.relay_errors == []
    assert log.summary is None


def test_parse_tool_calls():
    p = _write_log([TOOL_CALL, BLOCKED_CALL])
    log = parse_audit_log(p)
    assert len(log.tool_calls) == 2
    assert log.tool_calls[0].tool == "read_file"
    assert log.tool_calls[0].policy == "allowed"
    assert log.tool_calls[1].tool == "delete_file"
    assert log.tool_calls[1].policy == "blocked"
    assert log.tool_calls[1].reason == "policy:no-delete"


def test_parse_alert_entry():
    p = _write_log([ALERT])
    log = parse_audit_log(p)
    assert len(log.alerts) == 1
    a = log.alerts[0]
    assert a.detector == "ToolDrift"
    assert a.severity == "high"
    assert "New tool" in a.message


def test_parse_relay_error():
    p = _write_log([RELAY_ERROR])
    log = parse_audit_log(p)
    assert len(log.relay_errors) == 1
    e = log.relay_errors[0]
    assert e.error_type == "ConnectionResetError"
    assert "reset" in e.error.lower()


def test_parse_response_hmac():
    p = _write_log([RESPONSE_HMAC])
    log = parse_audit_log(p)
    assert len(log.hmac_entries) == 1
    assert log.hmac_entries[0].message_id == 1
    assert len(log.hmac_entries[0].hmac_sha256) == 64


def test_parse_proxy_summary():
    p = _write_log([PROXY_SUMMARY])
    log = parse_audit_log(p)
    assert log.summary is not None
    s = log.summary
    assert s.total_tool_calls == 42
    assert s.total_blocked == 3
    assert s.uptime_seconds == 300.5
    assert s.latency["p95_ms"] == 150.0
    assert s.runtime_alerts_by_severity["critical"] == 1
    assert s.latest_runtime_alert_at == "2026-03-09T10:00:02.000000+00:00"


def test_parse_full_log():
    p = _write_log([TOOL_CALL, BLOCKED_CALL, ALERT, RELAY_ERROR, RESPONSE_HMAC, PROXY_SUMMARY])
    log = parse_audit_log(p)
    assert len(log.tool_calls) == 2
    assert len(log.alerts) == 1
    assert len(log.relay_errors) == 1
    assert len(log.hmac_entries) == 1
    assert log.summary is not None


def test_parse_ignores_invalid_json_lines():
    tmp = tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False)
    tmp.write(
        '{"type": "tools/call", "tool": "ok", "policy": "allowed", "ts": "", "reason": "",'
        ' "agent_id": "", "args": {}, "payload_sha256": "", "message_id": 1}\n'
    )
    tmp.write("not valid json\n")
    tmp.write("\n")
    tmp.write(
        '{"type": "proxy_summary", "uptime_seconds": 1.0, "total_tool_calls": 1, "total_blocked": 0,'
        ' "calls_by_tool": {}, "blocked_by_reason": {}, "latency": {},'
        ' "replay_rejections": 0, "relay_errors": 0, "runtime_alerts": 0, "ts": ""}\n'
    )
    tmp.close()
    log = parse_audit_log(Path(tmp.name))
    assert len(log.tool_calls) == 1
    assert log.summary is not None


# ── display_json ─────────────────────────────────────────────────────────────


def test_display_json_clean_log(capsys):
    p = _write_log([TOOL_CALL, PROXY_SUMMARY])
    log = parse_audit_log(p)
    exit_code = display_json(log)
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert data["tool_calls"] == 1
    assert data["blocked"] == 0
    assert exit_code == 0


def test_display_json_with_blocked(capsys):
    p = _write_log([BLOCKED_CALL])
    log = parse_audit_log(p)
    exit_code = display_json(log)
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert data["blocked"] == 1
    assert exit_code == 1


def test_display_json_with_relay_error(capsys):
    p = _write_log([RELAY_ERROR])
    log = parse_audit_log(p)
    exit_code = display_json(log)
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert data["relay_errors"] == 1
    assert exit_code == 1


def test_display_json_alert_details(capsys):
    p = _write_log([ALERT])
    log = parse_audit_log(p)
    display_json(log)
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert len(data["alert_details"]) == 1
    assert data["alert_details"][0]["severity"] == "high"
    assert data["alert_details"][0]["detector"] == "ToolDrift"


# ── replay() function ─────────────────────────────────────────────────────────


def test_replay_clean_returns_0():
    p = _write_log([TOOL_CALL, PROXY_SUMMARY])
    code = replay(str(p), as_json=True)
    assert code == 0


def test_replay_blocked_returns_1():
    p = _write_log([BLOCKED_CALL])
    code = replay(str(p), as_json=True)
    assert code == 1


def test_replay_relay_error_returns_1():
    p = _write_log([RELAY_ERROR])
    code = replay(str(p), as_json=True)
    assert code == 1


def test_replay_nonexistent_file_returns_2():
    code = replay("/nonexistent/audit.jsonl")
    assert code == 2


def test_replay_blocked_only_filter(capsys):
    p = _write_log([TOOL_CALL, BLOCKED_CALL])
    replay(str(p), blocked_only=True, as_json=True)
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    # blocked_only doesn't filter the JSON output count — that shows all
    assert data["blocked"] == 1


def test_replay_json_output_structure(capsys):
    p = _write_log([TOOL_CALL, BLOCKED_CALL, ALERT, PROXY_SUMMARY])
    replay(str(p), as_json=True)
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert "tool_calls" in data
    assert "blocked" in data
    assert "alerts" in data
    assert "relay_errors" in data
    assert "summary" in data
    assert "alert_details" in data


def test_replay_json_includes_chain_verification_when_requested(capsys):
    p = _write_log(_chained([TOOL_CALL]))
    replay(str(p), verify_chain=True, as_json=True)
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert data["chain_verification"] == {"verified": 1, "tampered": 0}


# ── verify_hmac_entries ───────────────────────────────────────────────────────


def test_verify_hmac_no_entries():
    log = AuditLog()
    verified, failed = verify_hmac_entries(log, "secret")
    assert verified == 0
    assert failed == 0


def test_verify_hmac_no_matching_tool_call():
    """HMAC entry with no matching tool call is skipped."""
    log = AuditLog(hmac_entries=[ResponseHMACEntry(ts="", message_id=99, hmac_sha256="a" * 64)])
    verified, failed = verify_hmac_entries(log, "secret")
    assert verified == 0
    assert failed == 0


# ── AuditLog dataclass ────────────────────────────────────────────────────────


def test_audit_log_default_empty():
    log = AuditLog()
    assert log.tool_calls == []
    assert log.alerts == []
    assert log.relay_errors == []
    assert log.hmac_entries == []
    assert log.summary is None
    assert log.unknown == []


def test_summary_entry_fields():
    s = SummaryEntry(
        ts="2026-01-01T00:00:00Z",
        uptime_seconds=100.0,
        total_tool_calls=10,
        total_blocked=2,
        calls_by_tool={"scan": 10},
        blocked_by_reason={"policy": 2},
        latency={"avg_ms": 15.0},
        replay_rejections=0,
        relay_errors=0,
        runtime_alerts=1,
    )
    assert s.total_tool_calls == 10
    assert s.calls_by_tool["scan"] == 10


def test_tool_call_entry_fields():
    tc = ToolCallEntry(
        ts="2026-01-01T00:00:00Z",
        tool="scan",
        policy="allowed",
        reason="",
        agent_id="claude",
        args={"target": "langchain"},
        payload_sha256="abc",
        message_id=1,
    )
    assert tc.tool == "scan"
    assert tc.policy == "allowed"


# ── Unique tests from cov2 ──────────────────────────────────────────────────


def test_parse_unknown_entry():
    p = _write_log([{"type": "custom_event", "data": 123}])
    log = parse_audit_log(p)
    assert len(log.unknown) == 1


def test_parse_blank_lines():
    tmp = tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False)
    tmp.write("\n\n")
    tmp.close()
    log = parse_audit_log(Path(tmp.name))
    assert len(log.tool_calls) == 0


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


def test_verify_hmac_rejects_short_hmac():
    log = AuditLog(
        tool_calls=[ToolCallEntry(ts="", tool="t", policy="allowed", reason="", agent_id="", args={}, payload_sha256="abc", message_id=1)],
        hmac_entries=[ResponseHMACEntry(ts="", message_id=1, hmac_sha256="deadbeef")],
    )
    verified, failed = verify_hmac_entries(log, "secret")
    assert verified == 0
    assert failed == 1


def test_verify_hash_chain_passes_for_valid_records():
    p = _write_log(_chained([TOOL_CALL, BLOCKED_CALL]))
    verified, tampered = verify_hash_chain(p)
    assert verified == 2
    assert tampered == 0


def test_verify_hash_chain_detects_tamper():
    entries = _chained([TOOL_CALL, BLOCKED_CALL])
    entries[1]["tool"] = "tampered_tool"
    p = _write_log(entries)
    verified, tampered = verify_hash_chain(p)
    assert verified == 1
    assert tampered == 1


def test_display_json_empty(capsys):
    log = AuditLog()
    code = display_json(log)
    assert code == 0
    out = json.loads(capsys.readouterr().out)
    assert out["tool_calls"] == 0


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


def test_severity_style():
    assert "red" in _severity_style("critical")
    assert "red" in _severity_style("high")
    assert "yellow" in _severity_style("medium")
    assert "dim" in _severity_style("low")
    assert _severity_style("unknown") == "white"


def test_policy_style():
    assert "red" in _policy_style("blocked")
    assert "green" in _policy_style("allowed")


def test_replay_clean_log_rich():
    p = _write_log([{"type": "tools/call", "tool": "read", "policy": "allowed"}])
    code = replay(str(p))
    assert code == 0


def test_replay_as_json_blocked(capsys):
    p = _write_log([{"type": "tools/call", "tool": "read", "policy": "blocked", "reason": "test"}])
    code = replay(str(p), as_json=True)
    assert code == 1
