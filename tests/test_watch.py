"""Tests for agent_bom.watch — config watch + alerting module."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path
from unittest.mock import patch

from agent_bom.watch import (
    Alert,
    ConfigChangeHandler,
    ConsoleAlertSink,
    FileAlertSink,
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
