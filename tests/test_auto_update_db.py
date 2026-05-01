"""Tests for the --auto-update-db / AGENT_BOM_AUTO_UPDATE_DB scan flag."""

from __future__ import annotations

from unittest.mock import patch

from click.testing import CliRunner

from agent_bom.cli.agents import scan


def _invoke(*args):
    """Invoke the scan CLI via CliRunner."""
    runner = CliRunner()
    return runner.invoke(scan, list(args), catch_exceptions=False)


def test_auto_update_db_flag_triggers_sync_when_stale():
    """When DB freshness is >7 days, sync_db() must be called."""
    with (
        patch("agent_bom.db.schema.db_freshness_days", return_value=10) as mock_fresh,
        patch("agent_bom.db.sync.sync_db") as mock_sync,
        patch("agent_bom.cli.agents.discover_all", return_value=[]),
        patch("agent_bom.cli.agents.scan_agents_sync", return_value=[]),
    ):
        result = _invoke("--auto-update-db", "--demo")
        assert mock_fresh.call_count >= 1
        assert mock_sync.call_count >= 1
        assert result.exit_code == 0


def test_auto_update_db_skips_when_fresh():
    """When DB freshness is <=7 days, sync_db() must NOT be called."""
    with (
        patch("agent_bom.db.schema.db_freshness_days", return_value=3) as mock_fresh,
        patch("agent_bom.db.sync.sync_db") as mock_sync,
        patch("agent_bom.cli.agents.discover_all", return_value=[]),
        patch("agent_bom.cli.agents.scan_agents_sync", return_value=[]),
    ):
        result = _invoke("--auto-update-db", "--demo")
        assert mock_fresh.call_count >= 1
        mock_sync.assert_not_called()
        assert result.exit_code == 0


def test_auto_update_db_opt_out():
    """With --no-auto-update-db, sync_db() must never be called."""
    with (
        patch("agent_bom.db.schema.db_freshness_days") as mock_fresh,
        patch("agent_bom.db.sync.sync_db") as mock_sync,
        patch("agent_bom.cli.agents.discover_all", return_value=[]),
        patch("agent_bom.cli.agents.scan_agents_sync", return_value=[]),
    ):
        result = _invoke("--no-auto-update-db", "--no-scan")
        mock_fresh.assert_not_called()
        mock_sync.assert_not_called()
        assert result.exit_code == 0


def test_auto_update_db_on_by_default():
    """Default behavior: auto-update-db is ON, sync_db() called when stale (not with --no-scan)."""
    with (
        patch("agent_bom.db.schema.db_freshness_days", return_value=10) as mock_fresh,
        patch("agent_bom.db.sync.sync_db") as mock_sync,
        patch("agent_bom.cli.agents.discover_all", return_value=[]),
        patch("agent_bom.cli.agents.scan_agents_sync", return_value=[]),
    ):
        result = _invoke("--demo")
        assert mock_fresh.call_count >= 1
        assert mock_sync.call_count >= 1
        assert result.exit_code == 0


def test_no_scan_skips_db_refresh():
    """--no-scan must skip DB refresh entirely — no network calls."""
    with (
        patch("agent_bom.db.schema.db_freshness_days") as mock_fresh,
        patch("agent_bom.db.sync.sync_db") as mock_sync,
        patch("agent_bom.cli.agents.discover_all", return_value=[]),
        patch("agent_bom.cli.agents.scan_agents_sync", return_value=[]),
    ):
        result = _invoke("--no-scan")
        mock_fresh.assert_not_called()
        mock_sync.assert_not_called()
        assert result.exit_code == 0


def test_dry_run_skips_db_refresh():
    """--dry-run must show the access plan without refreshing the vuln DB."""
    with (
        patch("agent_bom.db.schema.db_freshness_days") as mock_fresh,
        patch("agent_bom.db.sync.sync_db") as mock_sync,
        patch("agent_bom.cli.agents.discover_all", return_value=[]),
        patch("agent_bom.cli.agents.scan_agents_sync", return_value=[]),
    ):
        result = _invoke("--dry-run", "--db-source", "osv")
        mock_fresh.assert_not_called()
        mock_sync.assert_not_called()
        assert result.exit_code == 0


def test_auto_update_db_handles_sync_failure():
    """When sync_db() raises, the scan should continue without crashing."""
    with (
        patch("agent_bom.db.schema.db_freshness_days", return_value=None),
        patch("agent_bom.db.sync.sync_db", side_effect=RuntimeError("network error")),
        patch("agent_bom.cli.agents.discover_all", return_value=[]),
        patch("agent_bom.cli.agents.scan_agents_sync", return_value=[]),
    ):
        result = _invoke("--auto-update-db", "--demo")
        # Scan must not crash — exit code 0 (no findings)
        assert result.exit_code == 0
