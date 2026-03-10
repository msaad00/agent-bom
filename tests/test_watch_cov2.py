"""Tests for agent_bom.watch to improve coverage."""

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
    discover_config_dirs,
    discover_config_paths,
)

# ---------------------------------------------------------------------------
# Alert model
# ---------------------------------------------------------------------------


def test_alert_auto_timestamp():
    a = Alert(alert_type="test", severity="info", summary="hello")
    assert a.timestamp != ""
    assert "T" in a.timestamp  # ISO format


def test_alert_custom_timestamp():
    a = Alert(timestamp="2025-01-01T00:00:00Z")
    assert a.timestamp == "2025-01-01T00:00:00Z"


# ---------------------------------------------------------------------------
# ConsoleAlertSink
# ---------------------------------------------------------------------------


def test_console_alert_sink():
    sink = ConsoleAlertSink()
    alert = Alert(alert_type="new_vulnerability", severity="critical", summary="Critical vuln found", details={"cve": "CVE-2025-0001"})
    # Should not raise
    sink.send(alert)


def test_console_alert_sink_all_severities():
    sink = ConsoleAlertSink()
    for sev in ("critical", "high", "medium", "low", "info", "unknown"):
        alert = Alert(severity=sev, summary=f"test {sev}")
        sink.send(alert)


# ---------------------------------------------------------------------------
# FileAlertSink
# ---------------------------------------------------------------------------


def test_file_alert_sink():
    with tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False) as f:
        path = f.name

    sink = FileAlertSink(path)
    alert = Alert(alert_type="config_changed", severity="info", summary="Changed")
    sink.send(alert)

    lines = Path(path).read_text().strip().splitlines()
    assert len(lines) == 1
    data = json.loads(lines[0])
    assert data["alert_type"] == "config_changed"


# ---------------------------------------------------------------------------
# WebhookAlertSink
# ---------------------------------------------------------------------------


def test_webhook_alert_sink_success():
    mock_resp = MagicMock()
    mock_resp.status_code = 200

    with patch("httpx.post", return_value=mock_resp) as mock_post:
        sink = WebhookAlertSink("https://hooks.example.com/test")
        alert = Alert(severity="high", summary="test")
        sink.send(alert)
        mock_post.assert_called_once()


def test_webhook_alert_sink_retry_on_5xx():
    mock_resp_500 = MagicMock()
    mock_resp_500.status_code = 500
    mock_resp_200 = MagicMock()
    mock_resp_200.status_code = 200

    with patch("httpx.post", side_effect=[mock_resp_500, mock_resp_200]) as mock_post:
        sink = WebhookAlertSink("https://hooks.example.com/test", retries=2, timeout=1.0)
        alert = Alert(severity="info", summary="retry test")
        sink.send(alert)
        assert mock_post.call_count == 2


def test_webhook_alert_sink_network_error():
    with patch("httpx.post", side_effect=Exception("connection refused")):
        sink = WebhookAlertSink("https://hooks.example.com/test", retries=1, timeout=1.0)
        alert = Alert(severity="low", summary="fail test")
        # Should not raise
        sink.send(alert)


def test_webhook_alert_sink_4xx_no_retry():
    mock_resp = MagicMock()
    mock_resp.status_code = 403

    with patch("httpx.post", return_value=mock_resp) as mock_post:
        sink = WebhookAlertSink("https://hooks.example.com/test", retries=2)
        alert = Alert(severity="info", summary="forbidden")
        sink.send(alert)
        assert mock_post.call_count == 1


# ---------------------------------------------------------------------------
# ConfigChangeHandler
# ---------------------------------------------------------------------------


def test_handler_debounce():
    sinks = [MagicMock()]
    handler = ConfigChangeHandler(sinks, debounce_seconds=10.0)
    # First call should proceed
    with patch.object(handler, "_scan_and_alert") as mock_scan:
        handler.on_modified("/test/config.json")
        assert mock_scan.call_count == 1
        # Second call within debounce should be skipped
        handler.on_modified("/test/config.json")
        assert mock_scan.call_count == 1


def test_handler_process_diff_new_findings():
    sink = MagicMock()
    handler = ConfigChangeHandler([sink])
    diff = {
        "summary": {"new_findings": 3, "resolved_findings": 1, "new_packages": 0},
        "new": [
            {"severity": "high"},
            {"severity": "medium"},
            {"severity": "low"},
        ],
    }
    handler._process_diff(diff, "/test/config.json")
    sink.send.assert_called_once()
    alert = sink.send.call_args[0][0]
    assert alert.alert_type == "new_vulnerability"
    assert alert.severity == "high"


def test_handler_process_diff_critical():
    sink = MagicMock()
    handler = ConfigChangeHandler([sink])
    diff = {
        "summary": {"new_findings": 1, "new_packages": 0},
        "new": [{"severity": "critical"}],
    }
    handler._process_diff(diff, "/test")
    alert = sink.send.call_args[0][0]
    assert alert.severity == "critical"


def test_handler_process_diff_new_packages():
    sink = MagicMock()
    handler = ConfigChangeHandler([sink])
    diff = {
        "summary": {"new_findings": 0, "new_packages": 5},
        "new": [],
    }
    handler._process_diff(diff, "/test")
    sink.send.assert_called_once()
    alert = sink.send.call_args[0][0]
    assert alert.alert_type == "config_changed"


def test_handler_send_alert_sink_failure():
    failing_sink = MagicMock()
    failing_sink.send.side_effect = Exception("sink error")
    handler = ConfigChangeHandler([failing_sink])
    alert = Alert(severity="info", summary="test")
    # Should not raise
    handler._send_alert(alert)


# ---------------------------------------------------------------------------
# discover_config_paths / discover_config_dirs
# ---------------------------------------------------------------------------


def test_discover_config_paths():
    paths = discover_config_paths()
    assert isinstance(paths, list)


def test_discover_config_dirs():
    dirs = discover_config_dirs()
    assert isinstance(dirs, list)
