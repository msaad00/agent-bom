"""Tests for agent_bom.watch — config watch + alerting module."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

from agent_bom.watch import (
    Alert,
    ConfigChangeHandler,
    ConsoleAlertSink,
    FileAlertSink,
    WebhookAlertSink,
)

# ── 1. Alert dataclass — auto-generated timestamp ─────────────────────────


def test_alert_dataclass():
    """Create an Alert with default fields; timestamp should be auto-generated."""
    alert = Alert(alert_type="config_changed", summary="something changed")

    assert alert.timestamp != ""
    # ISO format contains "T" separator and a timezone offset or "Z"
    assert "T" in alert.timestamp
    assert alert.alert_type == "config_changed"
    assert alert.severity == "info"  # default
    assert alert.summary == "something changed"
    assert alert.details == {}
    assert alert.config_path == ""


# ── 2. Alert with explicit custom fields ───────────────────────────────────


def test_alert_custom_fields():
    """Create an Alert with every field set explicitly; values must be preserved."""
    alert = Alert(
        timestamp="2025-01-15T12:00:00+00:00",
        alert_type="new_vulnerability",
        severity="critical",
        summary="CVE-2025-9999 found",
        details={"cve": "CVE-2025-9999", "package": "foo@1.0.0"},
        config_path="/home/user/.config/claude/config.json",
    )

    assert alert.timestamp == "2025-01-15T12:00:00+00:00"
    assert alert.alert_type == "new_vulnerability"
    assert alert.severity == "critical"
    assert alert.summary == "CVE-2025-9999 found"
    assert alert.details["cve"] == "CVE-2025-9999"
    assert alert.config_path == "/home/user/.config/claude/config.json"


# ── 3. ConsoleAlertSink — should not raise ─────────────────────────────────


def test_console_sink():
    """ConsoleAlertSink.send() should complete without raising."""
    sink = ConsoleAlertSink()
    alert = Alert(
        alert_type="config_changed",
        severity="high",
        summary="Test alert for console sink",
        details={"key": "value"},
    )

    # Must not raise
    sink.send(alert)


# ── 4. FileAlertSink — appends JSONL lines ────────────────────────────────


def test_file_sink_appends():
    """FileAlertSink should append each alert as a valid JSON line."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False) as f:
        tmp_path = f.name

    sink = FileAlertSink(tmp_path)

    alert1 = Alert(
        alert_type="config_changed",
        severity="info",
        summary="First alert",
    )
    alert2 = Alert(
        alert_type="new_vulnerability",
        severity="critical",
        summary="Second alert",
        details={"cve": "CVE-2025-0001"},
    )

    sink.send(alert1)
    sink.send(alert2)

    lines = Path(tmp_path).read_text().strip().splitlines()
    assert len(lines) == 2

    parsed_1 = json.loads(lines[0])
    parsed_2 = json.loads(lines[1])

    assert parsed_1["summary"] == "First alert"
    assert parsed_1["alert_type"] == "config_changed"

    assert parsed_2["summary"] == "Second alert"
    assert parsed_2["severity"] == "critical"
    assert parsed_2["details"]["cve"] == "CVE-2025-0001"

    # Cleanup
    Path(tmp_path).unlink(missing_ok=True)


# ── 5. ConfigChangeHandler debounce ────────────────────────────────────────


def test_config_change_handler_debounce():
    """Two rapid on_modified calls should only trigger _scan_and_alert once."""
    sinks: list = []
    handler = ConfigChangeHandler(alert_sinks=sinks, debounce_seconds=1.0)

    with patch.object(handler, "_scan_and_alert") as mock_scan:
        handler.on_modified("/fake/config.json")
        handler.on_modified("/fake/config.json")  # within debounce window

        assert mock_scan.call_count == 1
        mock_scan.assert_called_once_with("/fake/config.json")


# ── 6. CLI watch --help ───────────────────────────────────────────────────


def test_watch_cli_help():
    """``agent-bom watch --help`` should mention 'Watch MCP configs'."""
    from click.testing import CliRunner

    from agent_bom.cli import main

    runner = CliRunner()
    result = runner.invoke(main, ["watch", "--help"])

    assert result.exit_code == 0
    assert "Watch MCP configs" in result.output


# ── 7. WebhookAlertSink — successful delivery ────────────────────────────


def test_webhook_sink_success():
    """WebhookAlertSink should POST alert payload and succeed on 200."""
    alert = Alert(
        alert_type="new_vulnerability",
        severity="critical",
        summary="CVE-2025-9999 found",
        config_path="/tmp/config.json",
        details={"cve": "CVE-2025-9999"},
    )

    mock_response = MagicMock()
    mock_response.status_code = 200

    with patch("httpx.post", return_value=mock_response) as mock_post:
        sink = WebhookAlertSink("https://hooks.slack.com/test", retries=0)
        sink.send(alert)

        mock_post.assert_called_once()
        call_kwargs = mock_post.call_args
        payload = call_kwargs.kwargs.get("json") or call_kwargs[1].get("json")
        assert payload["text"] == "[CRITICAL] CVE-2025-9999 found"
        assert payload["alert_type"] == "new_vulnerability"
        assert payload["severity"] == "critical"
        assert payload["config_path"] == "/tmp/config.json"
        assert payload["details"]["cve"] == "CVE-2025-9999"
        assert "timestamp" in payload


# ── 8. WebhookAlertSink — retry on 5xx ───────────────────────────────────


def test_webhook_sink_retries_on_server_error():
    """WebhookAlertSink should retry on 5xx responses."""
    alert = Alert(alert_type="config_changed", severity="info", summary="Test")

    fail_resp = MagicMock()
    fail_resp.status_code = 502
    ok_resp = MagicMock()
    ok_resp.status_code = 200

    with patch("httpx.post", side_effect=[fail_resp, ok_resp]) as mock_post:
        with patch("time.sleep"):  # Skip actual sleep
            sink = WebhookAlertSink("https://hooks.example.com/test", retries=2)
            sink.send(alert)

            assert mock_post.call_count == 2


# ── 9. WebhookAlertSink — no retry on 4xx ────────────────────────────────


def test_webhook_sink_no_retry_on_client_error():
    """WebhookAlertSink should not retry on 4xx (client error)."""
    alert = Alert(alert_type="config_changed", severity="info", summary="Test")

    resp_403 = MagicMock()
    resp_403.status_code = 403

    with patch("httpx.post", return_value=resp_403) as mock_post:
        sink = WebhookAlertSink("https://hooks.example.com/test", retries=2)
        sink.send(alert)

        # Should NOT retry — 4xx is not transient
        assert mock_post.call_count == 1


# ── 10. WebhookAlertSink — retry on network error ────────────────────────


def test_webhook_sink_retries_on_network_error():
    """WebhookAlertSink should retry on connection/timeout errors."""
    import httpx

    alert = Alert(alert_type="config_changed", severity="info", summary="Test")

    ok_resp = MagicMock()
    ok_resp.status_code = 200

    with patch("httpx.post", side_effect=[httpx.ConnectError("fail"), ok_resp]) as mock_post:
        with patch("time.sleep"):
            sink = WebhookAlertSink("https://hooks.example.com/test", retries=2)
            sink.send(alert)

            assert mock_post.call_count == 2


# ── 11. WebhookAlertSink — exhausted retries ─────────────────────────────


def test_webhook_sink_exhausted_retries():
    """WebhookAlertSink should log warning after exhausting retries."""
    import httpx

    alert = Alert(alert_type="config_changed", severity="info", summary="Test")

    with patch("httpx.post", side_effect=httpx.ConnectError("fail")) as mock_post:
        with patch("time.sleep"):
            sink = WebhookAlertSink("https://hooks.example.com/test", retries=1)
            # Should not raise
            sink.send(alert)

            # 1 initial + 1 retry = 2 calls
            assert mock_post.call_count == 2


# ── 12. WebhookAlertSink — payload format ────────────────────────────────


def test_webhook_payload_format():
    """Webhook payload should be Slack-compatible with text field."""
    alert = Alert(
        alert_type="new_vulnerability",
        severity="high",
        summary="3 new vulnerabilities detected",
        config_path="/home/user/.config/claude/config.json",
        details={"new_findings": 3, "resolved_findings": 1},
    )

    captured_payload = {}

    def capture_post(url, json=None, timeout=None):
        captured_payload.update(json)
        resp = MagicMock()
        resp.status_code = 200
        return resp

    with patch("httpx.post", side_effect=capture_post):
        sink = WebhookAlertSink("https://hooks.slack.com/test")
        sink.send(alert)

    assert captured_payload["text"] == "[HIGH] 3 new vulnerabilities detected"
    assert captured_payload["severity"] == "high"
    assert captured_payload["alert_type"] == "new_vulnerability"
    assert captured_payload["details"]["new_findings"] == 3
    assert captured_payload["details"]["resolved_findings"] == 1
    assert captured_payload["config_path"] == "/home/user/.config/claude/config.json"


# ── 13. ConfigChangeHandler process_diff generates alerts ─────────────────


def test_config_change_handler_process_diff():
    """_process_diff should generate alerts from diff summary."""
    collected: list[Alert] = []

    class CollectorSink:
        def send(self, alert: Alert) -> None:
            collected.append(alert)

    handler = ConfigChangeHandler(alert_sinks=[CollectorSink()])

    diff = {
        "summary": {"new_findings": 2, "resolved_findings": 1, "new_packages": 3},
        "new": [
            {"severity": "high", "id": "CVE-2025-0001"},
            {"severity": "critical", "id": "CVE-2025-0002"},
        ],
    }

    handler._process_diff(diff, "/tmp/config.json")

    assert len(collected) == 2  # vulnerability alert + new packages alert

    vuln_alert = collected[0]
    assert vuln_alert.alert_type == "new_vulnerability"
    assert vuln_alert.severity == "critical"  # max of high + critical
    assert "2 new" in vuln_alert.summary

    pkg_alert = collected[1]
    assert pkg_alert.alert_type == "config_changed"
    assert "3 new package" in pkg_alert.summary
