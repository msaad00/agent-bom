"""Tests for the --auto-update-db / AGENT_BOM_AUTO_UPDATE_DB scan flag."""

from __future__ import annotations

from unittest.mock import patch

from click.testing import CliRunner

from agent_bom.cli.scan import scan


def _invoke(*args):
    """Invoke the scan CLI via CliRunner."""
    runner = CliRunner()
    return runner.invoke(scan, list(args), catch_exceptions=False)


def test_auto_update_db_flag_triggers_sync_when_stale():
    """When DB freshness is >7 days, sync_db() must be called once."""
    with (
        patch("agent_bom.db.schema.db_freshness_days", return_value=10) as mock_fresh,
        patch("agent_bom.db.sync.sync_db") as mock_sync,
        patch("agent_bom.cli.scan.discover_all", return_value=[]),
        patch("agent_bom.cli.scan.scan_agents_sync", return_value=[]),
    ):
        result = _invoke("--auto-update-db", "--no-scan")
        mock_fresh.assert_called_once()
        mock_sync.assert_called_once()
        assert result.exit_code == 0


def test_auto_update_db_skips_when_fresh():
    """When DB freshness is <=7 days, sync_db() must NOT be called."""
    with (
        patch("agent_bom.db.schema.db_freshness_days", return_value=3) as mock_fresh,
        patch("agent_bom.db.sync.sync_db") as mock_sync,
        patch("agent_bom.cli.scan.discover_all", return_value=[]),
        patch("agent_bom.cli.scan.scan_agents_sync", return_value=[]),
    ):
        result = _invoke("--auto-update-db", "--no-scan")
        mock_fresh.assert_called_once()
        mock_sync.assert_not_called()
        assert result.exit_code == 0


def test_auto_update_db_off_by_default():
    """Without --auto-update-db, sync_db() must never be called."""
    with (
        patch("agent_bom.db.schema.db_freshness_days") as mock_fresh,
        patch("agent_bom.db.sync.sync_db") as mock_sync,
        patch("agent_bom.cli.scan.discover_all", return_value=[]),
        patch("agent_bom.cli.scan.scan_agents_sync", return_value=[]),
    ):
        result = _invoke("--no-scan")
        mock_fresh.assert_not_called()
        mock_sync.assert_not_called()
        assert result.exit_code == 0


def test_auto_update_db_handles_sync_failure():
    """When sync_db() raises, the scan should continue without crashing."""
    with (
        patch("agent_bom.db.schema.db_freshness_days", return_value=None),
        patch("agent_bom.db.sync.sync_db", side_effect=RuntimeError("network error")),
        patch("agent_bom.cli.scan.discover_all", return_value=[]),
        patch("agent_bom.cli.scan.scan_agents_sync", return_value=[]),
    ):
        result = _invoke("--auto-update-db", "--no-scan")
        # Scan must not crash — exit code 0 (no findings)
        assert result.exit_code == 0
