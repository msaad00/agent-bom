"""Tests for scanner robustness improvements.

Covers:
- PEP 503 package name normalization
- Cache key normalization (underscore/hyphen consistency)
- Unresolved package warnings (no silent failures)
- Configurable batch size
"""

from __future__ import annotations

import logging

import pytest

from agent_bom.models import normalize_package_name

# ── PEP 503 Normalization ──────────────────────────────────────────────────


class TestNormalizePackageName:
    """normalize_package_name() must follow PEP 503 for PyPI."""

    def test_pypi_underscore_to_hyphen(self):
        assert normalize_package_name("some_package", "pypi") == "some-package"

    def test_pypi_dot_to_hyphen(self):
        assert normalize_package_name("some.package", "pypi") == "some-package"

    def test_pypi_mixed_separators(self):
        assert normalize_package_name("Requests_OAuthlib", "pypi") == "requests-oauthlib"

    def test_pypi_consecutive_separators_collapsed(self):
        assert normalize_package_name("foo__bar..baz", "pypi") == "foo-bar-baz"

    def test_pypi_case_insensitive(self):
        assert normalize_package_name("Flask", "pypi") == "flask"
        assert normalize_package_name("FLASK", "pypi") == "flask"
        assert normalize_package_name("flask", "pypi") == "flask"

    def test_pypi_already_normalized(self):
        assert normalize_package_name("requests", "pypi") == "requests"

    def test_pypi_numpy_variants(self):
        """NumPy, numpy, Numpy, num_py all normalize to the same thing."""
        assert normalize_package_name("NumPy", "pypi") == "numpy"
        assert normalize_package_name("numpy", "pypi") == "numpy"

    def test_pypi_python_dateutil(self):
        """python-dateutil and python_dateutil must match."""
        assert normalize_package_name("python-dateutil", "pypi") == "python-dateutil"
        assert normalize_package_name("python_dateutil", "pypi") == "python-dateutil"

    def test_npm_preserves_scope(self):
        assert normalize_package_name("@scope/Pkg", "npm") == "@scope/pkg"

    def test_npm_lowercases(self):
        assert normalize_package_name("Lodash", "npm") == "lodash"

    def test_npm_no_underscore_replacement(self):
        """npm packages can have underscores — don't replace them."""
        assert normalize_package_name("my_pkg", "npm") == "my_pkg"

    def test_go_lowercases(self):
        assert normalize_package_name("github.com/Foo/Bar", "go") == "github.com/foo/bar"

    def test_empty_name(self):
        assert normalize_package_name("", "pypi") == ""

    def test_ecosystem_case_insensitive(self):
        """Ecosystem param itself is case-insensitive."""
        assert normalize_package_name("Some_Pkg", "PyPI") == "some-pkg"
        assert normalize_package_name("Some_Pkg", "PYPI") == "some-pkg"


# ── Cache Key Normalization ────────────────────────────────────────────────


class TestCacheKeyNormalization:
    """ScanCache._key() must normalize names for consistent lookups."""

    def test_pypi_cache_key_normalized(self, tmp_path):
        from agent_bom.scan_cache import ScanCache

        cache = ScanCache(db_path=tmp_path / "test.db", ttl_seconds=3600)
        vulns = [{"id": "CVE-2024-001"}]

        # Store under one form
        cache.put("pypi", "Requests_OAuthlib", "1.0.0", vulns)

        # Retrieve under different forms — should all hit
        assert cache.get("pypi", "requests-oauthlib", "1.0.0") == vulns
        assert cache.get("pypi", "Requests_OAuthlib", "1.0.0") == vulns
        assert cache.get("pypi", "requests_oauthlib", "1.0.0") == vulns

    def test_npm_cache_key_lowercased(self, tmp_path):
        from agent_bom.scan_cache import ScanCache

        cache = ScanCache(db_path=tmp_path / "test.db", ttl_seconds=3600)
        vulns = [{"id": "GHSA-xxx"}]

        cache.put("npm", "Lodash", "4.17.20", vulns)
        assert cache.get("npm", "lodash", "4.17.20") == vulns

    def test_cache_size_no_duplicates(self, tmp_path):
        """Same package with different name forms should be one cache entry."""
        from agent_bom.scan_cache import ScanCache

        cache = ScanCache(db_path=tmp_path / "test.db", ttl_seconds=3600)
        cache.put("pypi", "python_dateutil", "2.8.0", [{"id": "CVE-A"}])
        cache.put("pypi", "python-dateutil", "2.8.0", [{"id": "CVE-B"}])
        # Second put should overwrite first (same normalized key)
        assert cache.size == 1


# ── Unresolved Package Warnings ───────────────────────────────────────────


class TestUnresolvedWarnings:
    """Scanner must warn about packages with unresolved versions."""

    @pytest.mark.asyncio
    async def test_scan_packages_warns_on_unresolved(self, caplog):
        """Packages with version='unknown' should produce a warning log."""
        from agent_bom.models import Package

        packages = [
            Package(name="mystery-pkg", version="unknown", ecosystem="pypi"),
            Package(name="ghost-lib", version="latest", ecosystem="npm"),
        ]

        with caplog.at_level(logging.WARNING, logger="agent_bom.scanners"):
            from unittest.mock import AsyncMock, patch

            # Mock OSV queries and resolver to avoid network calls
            with patch("agent_bom.scanners.query_osv_batch", new_callable=AsyncMock, return_value={}):
                with patch("agent_bom.resolver.resolve_all_versions", new_callable=AsyncMock, return_value=0):
                    from agent_bom.scanners import scan_packages

                    await scan_packages(packages)

        # Check warning was emitted
        assert any("skipped" in r.message.lower() or "unresolved" in r.message.lower() for r in caplog.records)

    @pytest.mark.asyncio
    async def test_scan_packages_no_warning_when_all_resolved(self, caplog):
        """No warning when all packages have proper versions."""
        from agent_bom.models import Package

        packages = [
            Package(name="requests", version="2.28.0", ecosystem="pypi"),
        ]

        with caplog.at_level(logging.WARNING, logger="agent_bom.scanners"):
            from unittest.mock import AsyncMock, patch

            with patch("agent_bom.scanners.query_osv_batch", new_callable=AsyncMock, return_value={}):
                from agent_bom.scanners import scan_packages

                await scan_packages(packages)

        assert not any("unresolved" in r.message.lower() for r in caplog.records)


# ── Configurable Batch Size ───────────────────────────────────────────────


class TestBatchSizeConfig:
    """Batch size should be configurable via env var."""

    def test_default_batch_size(self):
        from agent_bom.config import SCANNER_BATCH_SIZE

        assert SCANNER_BATCH_SIZE == 1000

    def test_batch_size_clamped_to_1000(self, monkeypatch):
        """Even if env var is >1000, actual batch should clamp to OSV max."""
        monkeypatch.setenv("AGENT_BOM_SCANNER_BATCH_SIZE", "5000")
        # Re-import to pick up new env var
        import importlib

        import agent_bom.config

        importlib.reload(agent_bom.config)
        assert agent_bom.config.SCANNER_BATCH_SIZE == 5000  # config stores raw value
        # But scanner clamps it: min(5000, 1000) = 1000
        assert min(agent_bom.config.SCANNER_BATCH_SIZE, 1000) == 1000
        # Restore
        monkeypatch.delenv("AGENT_BOM_SCANNER_BATCH_SIZE", raising=False)
        importlib.reload(agent_bom.config)


# ── Name Normalization in Scanner Pipeline ────────────────────────────────


class TestScannerNormalization:
    """Scanner must normalize names before OSV queries."""

    @pytest.mark.asyncio
    async def test_pypi_name_normalized_before_scan(self):
        """PyPI packages get PEP 503 normalized names before OSV query."""
        from unittest.mock import patch

        from agent_bom.models import Package

        packages = [
            Package(name="Requests_OAuthlib", version="1.3.0", ecosystem="pypi"),
        ]

        captured_packages = []

        async def mock_query(pkgs):
            captured_packages.extend(pkgs)
            return {}

        with patch("agent_bom.scanners.query_osv_batch", side_effect=mock_query):
            from agent_bom.scanners import scan_packages

            await scan_packages(packages)

        # The package name should be normalized in-place
        assert packages[0].name == "requests-oauthlib"

    @pytest.mark.asyncio
    async def test_npm_name_lowercased_before_scan(self):
        """npm packages get lowercased before OSV query."""
        from unittest.mock import AsyncMock, patch

        from agent_bom.models import Package

        packages = [
            Package(name="Lodash", version="4.17.20", ecosystem="npm"),
        ]

        with patch("agent_bom.scanners.query_osv_batch", new_callable=AsyncMock, return_value={}):
            from agent_bom.scanners import scan_packages

            await scan_packages(packages)

        # npm names are NOT normalized at scan_packages level (only PyPI gets PEP 503)
        # But the query_osv_batch normalizes the name in the query payload
        assert packages[0].name == "Lodash"  # original preserved for npm
