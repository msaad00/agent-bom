"""Tests for agent_bom.scan_cache — SQLite-backed OSV scan cache."""

from __future__ import annotations

import time

import pytest

from agent_bom.scan_cache import ScanCache


@pytest.fixture()
def cache(tmp_path):
    """Provide a ScanCache backed by a temp SQLite DB."""
    return ScanCache(db_path=tmp_path / "test_cache.db", ttl_seconds=3600)


class TestScanCacheBasics:
    """Core get/put/clear/size operations."""

    def test_put_and_get(self, cache: ScanCache):
        vulns = [{"id": "GHSA-1234", "summary": "test vuln"}]
        cache.put("npm", "lodash", "4.17.20", vulns)
        result = cache.get("npm", "lodash", "4.17.20")
        assert result == vulns

    def test_cache_miss(self, cache: ScanCache):
        assert cache.get("npm", "nonexistent", "1.0.0") is None

    def test_empty_vuln_list_cached(self, cache: ScanCache):
        """Caching [] (no vulns) is valid — avoids re-querying clean packages."""
        cache.put("pypi", "safe-pkg", "1.0.0", [])
        result = cache.get("pypi", "safe-pkg", "1.0.0")
        assert result == []

    def test_overwrite(self, cache: ScanCache):
        cache.put("npm", "pkg", "1.0", [{"id": "old"}])
        cache.put("npm", "pkg", "1.0", [{"id": "new"}])
        result = cache.get("npm", "pkg", "1.0")
        assert result == [{"id": "new"}]

    def test_size(self, cache: ScanCache):
        assert cache.size == 0
        cache.put("npm", "a", "1.0", [])
        cache.put("npm", "b", "1.0", [])
        assert cache.size == 2

    def test_clear(self, cache: ScanCache):
        cache.put("npm", "a", "1.0", [])
        cache.put("npm", "b", "1.0", [])
        cache.clear()
        assert cache.size == 0


class TestScanCacheTTL:
    """TTL expiration behaviour."""

    def test_expired_entry_returns_none(self, tmp_path):
        cache = ScanCache(db_path=tmp_path / "ttl.db", ttl_seconds=1)
        cache.put("npm", "pkg", "1.0", [{"id": "CVE-1"}])

        # Manually backdate the cached_at timestamp
        cache._conn.execute(
            "UPDATE osv_cache SET cached_at = ? WHERE cache_key = ?",
            (time.time() - 10, "npm:pkg@1.0"),
        )
        cache._conn.commit()

        assert cache.get("npm", "pkg", "1.0") is None

    def test_cleanup_expired(self, tmp_path):
        cache = ScanCache(db_path=tmp_path / "cleanup.db", ttl_seconds=1)
        cache.put("npm", "old", "1.0", [])
        cache.put("npm", "new", "1.0", [])

        # Backdate only one entry
        cache._conn.execute(
            "UPDATE osv_cache SET cached_at = ? WHERE cache_key = ?",
            (time.time() - 10, "npm:old@1.0"),
        )
        cache._conn.commit()

        removed = cache.cleanup_expired()
        assert removed == 1
        assert cache.size == 1


class TestScanCacheMaxEntries:
    """LRU eviction enforces the max_entries cap."""

    def test_eviction_on_put(self, tmp_path):
        """Oldest entry is evicted when limit is exceeded via put()."""
        cache = ScanCache(db_path=tmp_path / "max.db", ttl_seconds=3600, max_entries=3)
        cache.put("npm", "a", "1.0", [])
        cache.put("npm", "b", "1.0", [])
        cache.put("npm", "c", "1.0", [])
        assert cache.size == 3

        # Adding a 4th should evict the oldest (a)
        cache.put("npm", "d", "1.0", [])
        assert cache.size == 3
        assert cache.get("npm", "a", "1.0") is None  # evicted
        assert cache.get("npm", "d", "1.0") == []  # present

    def test_eviction_on_put_many(self, tmp_path):
        """put_many() also triggers eviction when limit is exceeded."""
        cache = ScanCache(db_path=tmp_path / "many.db", ttl_seconds=3600, max_entries=5)
        for i in range(5):
            cache.put("npm", f"pkg{i}", "1.0", [])
        assert cache.size == 5

        cache.put_many([("npm", "extra1", "1.0", []), ("npm", "extra2", "1.0", [])])
        assert cache.size == 5  # cap enforced

    def test_unlimited_when_zero(self, tmp_path):
        """max_entries=0 disables eviction (unbounded mode)."""
        cache = ScanCache(db_path=tmp_path / "unlimited.db", ttl_seconds=3600, max_entries=0)
        for i in range(20):
            cache.put("npm", f"pkg{i}", "1.0", [])
        assert cache.size == 20

    def test_default_max_entries_from_config(self, tmp_path):
        """Default max_entries is read from SCAN_CACHE_MAX_ENTRIES config."""
        from agent_bom.config import SCAN_CACHE_MAX_ENTRIES

        cache = ScanCache(db_path=tmp_path / "cfg.db")
        assert cache._max_entries == SCAN_CACHE_MAX_ENTRIES
