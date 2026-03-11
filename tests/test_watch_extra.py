"""Additional tests for agent_bom.watch to cover scan_and_alert path."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from agent_bom.watch import ConfigChangeHandler

# ---------------------------------------------------------------------------
# ConfigChangeHandler._scan_and_alert
# ---------------------------------------------------------------------------


def test_scan_and_alert_first_scan():
    """First scan should generate an 'initial scan' info alert."""
    sink = MagicMock()
    handler = ConfigChangeHandler([sink], debounce_seconds=0)

    # Mock all the scan pipeline
    from agent_bom.models import Agent, AgentType, MCPServer, TransportType

    mock_agent = Agent(
        name="test",
        agent_type=AgentType.CUSTOM,
        config_path="/test",
        mcp_servers=[MCPServer(name="srv", command="echo", transport=TransportType.STDIO)],
    )

    with (
        patch("agent_bom.discovery.discover_all", return_value=[mock_agent]),
        patch("agent_bom.parsers.extract_packages", return_value=[]),
        patch("agent_bom.output.to_json", return_value={"agents": []}),
        patch("time.sleep"),
    ):
        handler._scan_and_alert("/test/config.json")

    sink.send.assert_called_once()
    alert = sink.send.call_args[0][0]
    assert alert.alert_type == "config_changed"
    assert "Initial scan" in alert.summary


def test_scan_and_alert_with_diff():
    """Second scan should generate diff-based alerts."""
    sink = MagicMock()
    handler = ConfigChangeHandler([sink], debounce_seconds=0)
    handler._last_scan = {"agents": []}  # Simulate previous scan

    from agent_bom.models import Agent, AgentType, MCPServer, TransportType

    mock_agent = Agent(
        name="test",
        agent_type=AgentType.CUSTOM,
        config_path="/test",
        mcp_servers=[MCPServer(name="srv", command="echo", transport=TransportType.STDIO)],
    )

    diff_result = {"summary": {"new_findings": 2, "new_packages": 1}, "new": [{"severity": "medium"}, {"severity": "low"}]}

    with (
        patch("agent_bom.discovery.discover_all", return_value=[mock_agent]),
        patch("agent_bom.parsers.extract_packages", return_value=[]),
        patch("agent_bom.output.to_json", return_value={"agents": []}),
        patch("agent_bom.history.diff_reports", return_value=diff_result),
        patch("time.sleep"),
    ):
        handler._scan_and_alert("/test/config.json")

    # Should generate 2 alerts: new_vulnerability + config_changed
    assert sink.send.call_count == 2


def test_scan_and_alert_exception():
    """Scan failures should be logged, not raised."""
    sink = MagicMock()
    handler = ConfigChangeHandler([sink], debounce_seconds=0)

    with patch("agent_bom.discovery.discover_all", side_effect=RuntimeError("scan failed")), patch("time.sleep"):
        # Should not raise
        handler._scan_and_alert("/test/config.json")

    # No alert sent on failure
    sink.send.assert_not_called()


# ---------------------------------------------------------------------------
# _process_diff edge cases
# ---------------------------------------------------------------------------


def test_process_diff_no_new_findings():
    """When there are no new findings and no new packages, no alerts."""
    sink = MagicMock()
    handler = ConfigChangeHandler([sink])
    diff = {"summary": {"new_findings": 0, "new_packages": 0}, "new": []}
    handler._process_diff(diff, "/test")
    sink.send.assert_not_called()


def test_process_diff_medium_severity():
    """Medium severity should be used when no high/critical."""
    sink = MagicMock()
    handler = ConfigChangeHandler([sink])
    diff = {
        "summary": {"new_findings": 1, "new_packages": 0},
        "new": [{"severity": "medium"}],
    }
    handler._process_diff(diff, "/test")
    alert = sink.send.call_args[0][0]
    assert alert.severity == "medium"


def test_process_diff_low_severity():
    """Low severity when only low findings."""
    sink = MagicMock()
    handler = ConfigChangeHandler([sink])
    diff = {
        "summary": {"new_findings": 1, "new_packages": 0},
        "new": [{"severity": "low"}],
    }
    handler._process_diff(diff, "/test")
    alert = sink.send.call_args[0][0]
    assert alert.severity == "low"
