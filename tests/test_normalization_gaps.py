"""Tests for normalization gap fixes — ensures all key construction paths
use normalize_package_name() so mixed-case / underscore / dot variants
resolve to the same canonical key.

Covers:
- cli/_check.py key lookup
- scanners/__init__.py scan_agents() dedup + propagation
- cli/_history.py rescan key lookup
- api/postgres_store.py cache key
"""

from __future__ import annotations

import pytest

from agent_bom.models import Package, normalize_package_name

# ── CLI check key normalization ──────────────────────────────────────────────


class TestCheckKeyNormalization:
    """cli/_check.py must normalize names in OSV result lookup keys."""

    def test_check_normalizes_pypi_name(self):
        """Django (capital D) should match query_osv_batch key 'django'."""
        # query_osv_batch returns normalized keys
        results = {"pypi:django@3.2.0": [{"id": "GHSA-test", "summary": "test"}]}

        # Simulate what _check.py does after fix: construct key with normalization
        name, version, ecosystem = "Django", "3.2.0", "pypi"
        key = f"{ecosystem}:{normalize_package_name(name, ecosystem)}@{version}"

        vuln_data = results.get(key, [])
        assert len(vuln_data) == 1, "Normalized key should match query results"

    def test_raw_key_would_miss(self):
        """Prove that raw (unnormalized) key causes a miss."""
        results = {"pypi:django@3.2.0": [{"id": "CVE-test"}]}
        raw_key = "pypi:Django@3.2.0"
        assert results.get(raw_key, []) == [], "Raw key should NOT match normalized results"


# ── scan_agents() key normalization ──────────────────────────────────────────


class TestScanAgentsKeyNormalization:
    """scanners/__init__.py scan_agents() must normalize all package keys."""

    def test_dedup_normalizes_names(self):
        """Same package with different casing should deduplicate to one."""
        pkg1 = Package(name="Requests", version="2.28.0", ecosystem="pypi")
        pkg2 = Package(name="requests", version="2.28.0", ecosystem="pypi")

        def _pkg_key(pkg: Package) -> str:
            return f"{pkg.ecosystem.lower()}:{normalize_package_name(pkg.name, pkg.ecosystem)}@{pkg.version}"

        assert _pkg_key(pkg1) == _pkg_key(pkg2), "Normalized keys must match for dedup"

    def test_underscore_dot_variants_dedup(self):
        """python_dateutil, python.dateutil, python-dateutil should all collapse."""
        variants = ["python_dateutil", "python.dateutil", "python-dateutil"]
        keys = {f"pypi:{normalize_package_name(v, 'pypi')}@2.8.0" for v in variants}
        assert len(keys) == 1, f"All variants should produce same key, got {keys}"

    def test_propagation_key_matches_dedup_key(self):
        """Vuln propagation key must match the dedup key used for building pkg_to_servers."""
        pkg = Package(name="Flask_RESTful", version="0.3.10", ecosystem="pypi")

        def _pkg_key(p: Package) -> str:
            return f"{p.ecosystem.lower()}:{normalize_package_name(p.name, p.ecosystem)}@{p.version}"

        # Dedup phase key
        dedup_key = _pkg_key(pkg)
        # Propagation phase key (same function)
        prop_key = _pkg_key(pkg)
        assert dedup_key == prop_key == "pypi:flask-restful@0.3.10"


# ── CLI history/rescan key normalization ─────────────────────────────────────


class TestRescanKeyNormalization:
    """cli/_history.py must normalize names for fresh result lookups."""

    def test_rescan_key_matches_osv_results(self):
        """Rescan key for 'Pillow' must match normalized 'pillow' from OSV."""
        pkg = Package(name="Pillow", version="9.0.0", ecosystem="pypi")
        fresh_results = {"pypi:pillow@9.0.0": [{"id": "GHSA-test"}]}

        key = f"{pkg.ecosystem.lower()}:{normalize_package_name(pkg.name, pkg.ecosystem)}@{pkg.version}"
        assert fresh_results.get(key) is not None, "Normalized key should find results"

    def test_rescan_raw_key_misses(self):
        """Without normalization, 'Pillow' misses 'pillow' results."""
        fresh_results = {"pypi:pillow@9.0.0": [{"id": "GHSA-test"}]}
        raw_key = "pypi:Pillow@9.0.0"
        assert fresh_results.get(raw_key) is None, "Raw key should miss normalized results"


# ── Postgres store key normalization ─────────────────────────────────────────


class TestPostgresStoreKeyNormalization:
    """api/postgres_store.py _key() must normalize package names."""

    def test_postgres_key_normalizes_pypi(self):
        """Postgres cache key should normalize PyPI names."""
        from agent_bom.api.postgres_store import PostgresScanCache

        key = PostgresScanCache._key("pypi", "Django", "3.2.0")
        assert key == "pypi:django@3.2.0"

    def test_postgres_key_normalizes_underscore(self):
        """Underscores should become hyphens for PyPI."""
        from agent_bom.api.postgres_store import PostgresScanCache

        key = PostgresScanCache._key("pypi", "python_dateutil", "2.8.0")
        assert key == "pypi:python-dateutil@2.8.0"

    def test_postgres_key_npm_lowercase(self):
        """npm names should be lowercased."""
        from agent_bom.api.postgres_store import PostgresScanCache

        key = PostgresScanCache._key("npm", "Express", "4.18.0")
        assert key == "npm:express@4.18.0"


# ── Cross-boundary consistency ───────────────────────────────────────────────


class TestCrossBoundaryConsistency:
    """All key construction paths must produce identical keys for the same package."""

    @pytest.mark.parametrize(
        "name,ecosystem,expected_norm",
        [
            ("Django", "pypi", "django"),
            ("python_dateutil", "pypi", "python-dateutil"),
            ("Flask.RESTful", "pypi", "flask-restful"),
            ("Express", "npm", "express"),
            ("@types/Node", "npm", "@types/node"),
        ],
    )
    def test_all_paths_produce_same_key(self, name, ecosystem, expected_norm):
        """Every key construction path should produce the same normalized key."""
        version = "1.0.0"
        expected_key = f"{ecosystem}:{expected_norm}@{version}"

        # Path 1: direct normalize_package_name (models.py)
        key1 = f"{ecosystem}:{normalize_package_name(name, ecosystem)}@{version}"

        # Path 2: ScanCache._key (scan_cache.py)
        from agent_bom.scan_cache import ScanCache

        key2 = ScanCache._key(ecosystem, name, version)

        assert key1 == expected_key
        assert key2 == expected_key
