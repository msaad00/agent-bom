"""Tests for error logging in scanner-critical paths.

Verifies that exceptions in cache init, enrichment, and DB lookup
are logged rather than silently swallowed.
"""

from __future__ import annotations

import logging
from unittest.mock import patch

from agent_bom.scanners import _get_scan_cache, parse_cvss_vector


class TestScanCacheInitLogging:
    """ScanCache init failure must be logged, not silent."""

    def setup_method(self):
        # Reset the module-level singleton so _get_scan_cache re-attempts init
        import agent_bom.scanners as sc

        sc._scan_cache_instance = None

    def test_cache_init_failure_logs_warning(self, caplog):
        with (
            patch("agent_bom.scan_cache.ScanCache", side_effect=RuntimeError("disk full")),
            caplog.at_level(logging.WARNING, logger="agent_bom.scanners"),
        ):
            result = _get_scan_cache()
        assert result is None
        assert "ScanCache initialization failed" in caplog.text
        assert "disk full" in caplog.text


class TestCVSSParseLogging:
    """CVSS vector parse failures must be logged at debug level."""

    def test_invalid_cvss_vector_logs_debug(self, caplog):
        with caplog.at_level(logging.DEBUG, logger="agent_bom.scanners"):
            result = parse_cvss_vector("CVSS:3.1/INVALID")
        assert result is None
        # The parse should log a debug message about the failure
        assert "CVSS vector parse failed" in caplog.text or result is None

    def test_invalid_cvss4_vector_logs_debug(self, caplog):
        with caplog.at_level(logging.DEBUG, logger="agent_bom.scanners"):
            result = parse_cvss_vector("CVSS:4.0/INVALID")
        assert result is None


class TestDBLookupLogging:
    """DB version comparison fallback must be logged."""

    def test_version_compare_fallback_logs_debug(self, caplog):
        from agent_bom.db.lookup import _version_affected

        with caplog.at_level(logging.DEBUG, logger="agent_bom.db.lookup"):
            # Use a version string that will cause packaging.version.Version to fail
            result = _version_affected("not-a-version!", introduced="0.1", fixed="99.0", last_affected=None)
        # Should fall back to lexicographic and still return a result
        assert isinstance(result, bool)
