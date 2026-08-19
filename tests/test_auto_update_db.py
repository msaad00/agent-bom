"""Tests for the --auto-update-db / AGENT_BOM_AUTO_UPDATE_DB scan flag."""

from __future__ import annotations

from unittest.mock import patch

from click.testing import CliRunner

from agent_bom.cli.agents import scan
from agent_bom.vuln_freshness import VulnDataFreshness


def _invoke(*args):
    """Invoke the scan CLI via CliRunner."""
    runner = CliRunner()
    return runner.invoke(scan, list(args), catch_exceptions=False)


def _freshness(*, mode="local", stale=False, danger=False):
    return VulnDataFreshness(
        mode=mode,
        sources=["OSV", "GHSA"],
        last_updated="2026-06-01T00:00:00+00:00",
        age_hours=48 if stale else 1,
        record_count=1000,
        stale=stale,
        danger=danger,
        max_age_hours=24,
    )


def test_auto_update_db_flag_triggers_sync_when_aging(tmp_path):
    """When DB freshness misses the daily target, sync_db() must be called."""
    with (
        patch("agent_bom.vuln_freshness.compute_freshness", return_value=_freshness(stale=True)),
        patch("agent_bom.db.sync.sync_db") as mock_sync,
        patch("agent_bom.cli.agents.discover_all", return_value=[]),
        patch("agent_bom.cli.agents.scan_agents_sync", return_value=[]),
    ):
        result = _invoke("--auto-update-db", str(tmp_path))
        assert mock_sync.call_count >= 1
        assert result.exit_code == 0


def test_auto_update_db_skips_when_fresh(tmp_path):
    """When DB freshness is inside the daily target, sync_db() must NOT be called."""
    with (
        patch("agent_bom.vuln_freshness.compute_freshness", return_value=_freshness(stale=False)),
        patch("agent_bom.db.sync.sync_db") as mock_sync,
        patch("agent_bom.cli.agents.discover_all", return_value=[]),
        patch("agent_bom.cli.agents.scan_agents_sync", return_value=[]),
    ):
        result = _invoke("--auto-update-db", str(tmp_path))
        mock_sync.assert_not_called()
        assert result.exit_code == 0


def test_demo_skips_db_refresh_when_ambient_cache_is_stale():
    """The versioned demo evidence must not depend on an ambient DB refresh."""
    with (
        patch("agent_bom.vuln_freshness.compute_freshness", return_value=_freshness(stale=True)),
        patch("agent_bom.db.sync.sync_db") as mock_sync,
        patch("agent_bom.cli.agents.discover_all", return_value=[]),
        patch("agent_bom.cli.agents.scan_agents_sync", return_value=[]),
    ):
        result = _invoke("--auto-update-db", "--demo")
        mock_sync.assert_not_called()
        assert result.exit_code == 0


def test_auto_update_db_opt_out():
    """With --no-auto-update-db, sync_db() must never be called."""
    with (
        patch("agent_bom.vuln_freshness.compute_freshness", return_value=_freshness(stale=True)),
        patch("agent_bom.db.sync.sync_db") as mock_sync,
        patch("agent_bom.cli.agents.discover_all", return_value=[]),
        patch("agent_bom.cli.agents.scan_agents_sync", return_value=[]),
    ):
        result = _invoke("--no-auto-update-db", "--no-scan")
        mock_sync.assert_not_called()
        assert result.exit_code == 0


def test_default_scan_does_not_block_on_full_db_refresh(tmp_path):
    """Default online scans use cached data plus targeted lookups without a bulk sync."""
    with (
        patch("agent_bom.vuln_freshness.compute_freshness", return_value=_freshness(stale=True)),
        patch("agent_bom.db.sync.sync_db") as mock_sync,
        patch("agent_bom.cli.agents.discover_all", return_value=[]),
        patch("agent_bom.cli.agents.scan_agents_sync", return_value=[]),
    ):
        result = _invoke(str(tmp_path))
        mock_sync.assert_not_called()
        assert result.exit_code == 0


def test_explicit_db_refresh_is_included_in_timing_breakdown(tmp_path):
    """An explicitly requested bulk refresh must be visible in scan profiling."""
    import time

    def _slow_sync(*, sources=None):
        del sources
        time.sleep(0.11)

    with (
        patch("agent_bom.vuln_freshness.compute_freshness", return_value=_freshness(stale=True)),
        patch("agent_bom.db.sync.sync_db", side_effect=_slow_sync),
        patch("agent_bom.cli.agents.discover_all", return_value=[]),
        patch("agent_bom.cli.agents.scan_agents_sync", return_value=[]),
    ):
        result = _invoke("--auto-update-db", "--format", "console", str(tmp_path))
        assert result.exit_code == 0
        assert "db refresh:" in result.output


def test_offline_skips_db_refresh():
    """--offline must never trigger a network refresh even when the cache is stale."""
    with (
        patch("agent_bom.vuln_freshness.compute_freshness", return_value=_freshness(mode="offline", stale=True)),
        patch("agent_bom.db.sync.sync_db") as mock_sync,
        patch("agent_bom.cli.agents.discover_all", return_value=[]),
        patch("agent_bom.cli.agents.scan_agents_sync", return_value=[]),
    ):
        result = _invoke("--offline", "--demo")
        mock_sync.assert_not_called()
        assert result.exit_code == 0


def test_no_scan_skips_db_refresh():
    """--no-scan must skip DB refresh entirely — no network calls."""
    with (
        patch("agent_bom.db.sync.sync_db") as mock_sync,
        patch("agent_bom.cli.agents.discover_all", return_value=[]),
        patch("agent_bom.cli.agents.scan_agents_sync", return_value=[]),
    ):
        result = _invoke("--no-scan")
        mock_sync.assert_not_called()
        assert result.exit_code == 0


def test_dry_run_skips_db_refresh():
    """--dry-run must show the access plan without refreshing the vuln DB."""
    with (
        patch("agent_bom.db.sync.sync_db") as mock_sync,
        patch("agent_bom.cli.agents.discover_all", return_value=[]),
        patch("agent_bom.cli.agents.scan_agents_sync", return_value=[]),
    ):
        result = _invoke("--dry-run", "--db-source", "osv")
        mock_sync.assert_not_called()
        assert result.exit_code == 0


def test_auto_update_db_handles_sync_failure(tmp_path):
    """When sync_db() raises, the scan should continue without crashing."""
    with (
        patch("agent_bom.vuln_freshness.compute_freshness", return_value=_freshness(mode="live", stale=False)),
        patch("agent_bom.db.sync.sync_db", side_effect=RuntimeError("network error")),
        patch("agent_bom.cli.agents.discover_all", return_value=[]),
        patch("agent_bom.cli.agents.scan_agents_sync", return_value=[]),
    ):
        result = _invoke("--auto-update-db", str(tmp_path))
        # Scan must not crash — exit code 0 (no findings)
        assert result.exit_code == 0
