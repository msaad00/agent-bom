"""Tests for watch module — coverage expansion for alert sinks and config change handling."""

from __future__ import annotations

import json
import os
import tempfile
from unittest.mock import MagicMock, patch

from agent_bom.watch import (
    Alert,
    ConfigChangeHandler,
    ConsoleAlertSink,
    FileAlertSink,
    WebhookAlertSink,
    _log_value,
    discover_config_dirs,
    discover_config_paths,
)


class TestAlert:
    def test_defaults(self):
        alert = Alert()
        assert alert.severity == "info"
        assert alert.timestamp

    def test_custom_alert(self):
        alert = Alert(
            alert_type="new_vulnerability",
            severity="critical",
            summary="Critical CVE found",
            config_path="/path/to/config",
        )
        assert alert.severity == "critical"
        assert alert.summary == "Critical CVE found"


def test_log_value_strips_ansi_and_control_characters():
    cleaned = _log_value("server\x1b[31m-red\x1b[0m\r\nnext\tline")
    assert "\x1b" not in cleaned
    assert "\n" not in cleaned
    assert "\r" not in cleaned
    assert "\t" not in cleaned
    assert "server-red next line" == cleaned


class TestConsoleAlertSink:
    def test_send(self):
        sink = ConsoleAlertSink()
        alert = Alert(alert_type="test", severity="high", summary="Test alert")
        sink.send(alert)

    def test_send_with_details(self):
        sink = ConsoleAlertSink()
        alert = Alert(
            alert_type="test",
            severity="critical",
            summary="Test alert",
            details={"key": "value"},
        )
        sink.send(alert)

    def test_send_all_severities(self):
        sink = ConsoleAlertSink()
        for sev in ("critical", "high", "medium", "low", "info"):
            alert = Alert(severity=sev, summary=f"{sev} alert")
            sink.send(alert)


class TestFileAlertSink:
    def test_writes_to_file(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False) as f:
            path = f.name
        try:
            sink = FileAlertSink(path)
            alert = Alert(alert_type="test", severity="info", summary="Test")
            sink.send(alert)
            with open(path) as f:
                line = f.read().strip()
            data = json.loads(line)
            assert data["severity"] == "info"
            assert data["summary"] == "Test"
        finally:
            os.unlink(path)


class TestWebhookAlertSink:
    def test_successful_send(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        with (
            patch("httpx.post", return_value=mock_resp),
            patch("agent_bom.security.validate_url", return_value=None),
        ):
            sink = WebhookAlertSink("https://hooks.slack.com/test")
            alert = Alert(alert_type="test", severity="high", summary="Alert!")
            sink.send(alert)

    def test_retry_on_5xx(self):
        mock_resp_500 = MagicMock()
        mock_resp_500.status_code = 500
        mock_resp_200 = MagicMock()
        mock_resp_200.status_code = 200
        with (
            patch("httpx.post", side_effect=[mock_resp_500, mock_resp_200]),
            patch("agent_bom.security.validate_url", return_value=None),
        ):
            sink = WebhookAlertSink("https://hooks.slack.com/test", retries=1)
            alert = Alert(alert_type="test", severity="high", summary="Alert!")
            sink.send(alert)

    def test_exception_handling(self):
        with (
            patch("httpx.post", side_effect=ConnectionError("refused")),
            patch("agent_bom.security.validate_url", return_value=None),
        ):
            sink = WebhookAlertSink("https://hooks.slack.com/test", retries=0)
            alert = Alert(alert_type="test", severity="high", summary="Alert!")
            sink.send(alert)


class TestConfigChangeHandler:
    def test_debounce(self):
        handler = ConfigChangeHandler(alert_sinks=[], debounce_seconds=10.0)
        handler._last_trigger["/path/to/config.json"] = 9999999999.0
        handler.on_modified("/path/to/config.json")

    def test_process_diff_with_findings(self):
        mock_sink = MagicMock()
        handler = ConfigChangeHandler(alert_sinks=[mock_sink])
        diff = {
            "summary": {"new_findings": 3, "resolved_findings": 1},
            "new": [
                {"severity": "high"},
                {"severity": "medium"},
                {"severity": "critical"},
            ],
        }
        handler._process_diff(diff, "/path/to/config")
        assert mock_sink.send.called

    def test_process_diff_with_new_packages(self):
        mock_sink = MagicMock()
        handler = ConfigChangeHandler(alert_sinks=[mock_sink])
        diff = {
            "summary": {"new_findings": 0, "new_packages": 5},
            "new": [],
        }
        handler._process_diff(diff, "/path/to/config")
        assert mock_sink.send.called

    def test_process_diff_no_changes(self):
        mock_sink = MagicMock()
        handler = ConfigChangeHandler(alert_sinks=[mock_sink])
        diff = {"summary": {"new_findings": 0, "new_packages": 0}, "new": []}
        handler._process_diff(diff, "/path/to/config")
        assert not mock_sink.send.called

    def test_send_alert_handles_sink_error(self):
        mock_sink = MagicMock()
        mock_sink.send.side_effect = RuntimeError("sink error")
        handler = ConfigChangeHandler(alert_sinks=[mock_sink])
        alert = Alert(severity="info", summary="test")
        handler._send_alert(alert)

    def test_process_diff_severity_levels(self):
        mock_sink = MagicMock()
        handler = ConfigChangeHandler(alert_sinks=[mock_sink])

        diff = {
            "summary": {"new_findings": 1},
            "new": [{"severity": "medium"}],
        }
        handler._process_diff(diff, "/config")
        call_args = mock_sink.send.call_args[0][0]
        assert call_args.severity == "medium"


# ── Unique tests from cov2 ──────────────────────────────────────────────────


class TestAlertTimestamps:
    def test_auto_timestamp(self):
        a = Alert(alert_type="test", severity="info", summary="hello")
        assert a.timestamp != ""
        assert "T" in a.timestamp

    def test_custom_timestamp(self):
        a = Alert(timestamp="2025-01-01T00:00:00Z")
        assert a.timestamp == "2025-01-01T00:00:00Z"


class TestConsoleAlertSinkExtraSeverities:
    def test_unknown_severity(self):
        sink = ConsoleAlertSink()
        alert = Alert(severity="unknown", summary="test unknown")
        sink.send(alert)


class TestWebhookAlertSink4xx:
    def test_4xx_no_retry(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 403

        with (
            patch("httpx.post", return_value=mock_resp) as mock_post,
            patch("agent_bom.security.validate_url", return_value=None),
        ):
            sink = WebhookAlertSink("https://hooks.example.com/test", retries=2)
            alert = Alert(severity="info", summary="forbidden")
            sink.send(alert)
            assert mock_post.call_count == 1


class TestHandlerDebounceWithScanAndAlert:
    def test_debounce_skips_second_call(self):
        sinks = [MagicMock()]
        handler = ConfigChangeHandler(sinks, debounce_seconds=10.0)
        with patch.object(handler, "_scan_and_alert") as mock_scan:
            handler.on_modified("/test/config.json")
            assert mock_scan.call_count == 1
            handler.on_modified("/test/config.json")
            assert mock_scan.call_count == 1


class TestHandlerProcessDiffCritical:
    def test_critical_severity(self):
        sink = MagicMock()
        handler = ConfigChangeHandler([sink])
        diff = {
            "summary": {"new_findings": 1, "new_packages": 0},
            "new": [{"severity": "critical"}],
        }
        handler._process_diff(diff, "/test")
        alert = sink.send.call_args[0][0]
        assert alert.severity == "critical"


class TestHandlerProcessDiffNewPackages:
    def test_new_packages_config_changed(self):
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


class TestDiscoverHelpers:
    def test_discover_config_paths(self):
        paths = discover_config_paths()
        assert isinstance(paths, list)

    def test_discover_config_dirs(self):
        dirs = discover_config_dirs()
        assert isinstance(dirs, list)
