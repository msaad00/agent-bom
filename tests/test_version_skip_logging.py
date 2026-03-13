"""Tests for version-skip warning logs in OSV batch queries."""

from __future__ import annotations

import logging
from unittest.mock import patch

import pytest

from agent_bom.models import Package


@pytest.fixture()
def _no_scan_cache():
    """Disable ScanCache so tests don't need SQLite."""
    with patch("agent_bom.scanners._get_scan_cache", return_value=None):
        yield


@pytest.mark.asyncio()
@pytest.mark.usefixtures("_no_scan_cache")
async def test_unknown_version_logs_warning(caplog: pytest.LogCaptureFixture) -> None:
    """A package with version 'unknown' should emit a warning log."""
    packages = [Package(name="requests", version="unknown", ecosystem="pypi")]
    with caplog.at_level(logging.WARNING, logger="agent_bom.scanners"):
        from agent_bom.scanners import query_osv_batch

        await query_osv_batch(packages)

    assert any("Skipping package" in rec.message and "'unknown'" in rec.message for rec in caplog.records), (
        f"Expected warning about 'unknown' version, got: {[r.message for r in caplog.records]}"
    )


@pytest.mark.asyncio()
@pytest.mark.usefixtures("_no_scan_cache")
async def test_latest_version_logs_warning(caplog: pytest.LogCaptureFixture) -> None:
    """A package with version 'latest' should emit a warning log."""
    packages = [Package(name="express", version="latest", ecosystem="npm")]
    with caplog.at_level(logging.WARNING, logger="agent_bom.scanners"):
        from agent_bom.scanners import query_osv_batch

        await query_osv_batch(packages)

    assert any("Skipping package" in rec.message and "'latest'" in rec.message for rec in caplog.records), (
        f"Expected warning about 'latest' version, got: {[r.message for r in caplog.records]}"
    )


@pytest.mark.asyncio()
@pytest.mark.usefixtures("_no_scan_cache")
async def test_skip_count_accurate(caplog: pytest.LogCaptureFixture) -> None:
    """Skip count in summary log should match number of skipped packages."""
    packages = [
        Package(name="requests", version="unknown", ecosystem="pypi"),
        Package(name="flask", version="latest", ecosystem="pypi"),
        Package(name="express", version="unknown", ecosystem="npm"),
    ]
    with caplog.at_level(logging.INFO, logger="agent_bom.scanners"):
        from agent_bom.scanners import query_osv_batch

        await query_osv_batch(packages)

    summary = [r for r in caplog.records if "skipped" in r.message and "Scan complete" in r.message]
    assert len(summary) == 1, f"Expected 1 summary log, got {len(summary)}: {[r.message for r in caplog.records]}"
    assert "3 skipped" in summary[0].message


def test_validate_version_debug_log(caplog: pytest.LogCaptureFixture) -> None:
    """validate_version should emit debug log for unknown/latest."""
    from agent_bom.version_utils import validate_version

    with caplog.at_level(logging.DEBUG, logger="agent_bom.version_utils"):
        result = validate_version("unknown", "pypi")

    assert result is False
    assert any("Invalid version" in r.message and "'unknown'" in r.message for r in caplog.records)
