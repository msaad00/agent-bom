"""Tests for enrichment persistent caching (NVD + EPSS)."""

from __future__ import annotations

import json
import time

import pytest

import agent_bom.enrichment as enrichment


@pytest.fixture(autouse=True)
def _reset_enrichment_cache(tmp_path, monkeypatch):
    """Reset module-level caches and redirect to tmp dir."""
    monkeypatch.setattr(enrichment, "_ENRICHMENT_CACHE_DIR", tmp_path)
    monkeypatch.setattr(enrichment, "_nvd_file_cache", {})
    monkeypatch.setattr(enrichment, "_epss_file_cache", {})
    monkeypatch.setattr(enrichment, "_enrichment_cache_loaded", False)


class TestNVDCache:
    def test_nvd_cache_stores_and_loads(self, tmp_path):
        """NVD data stored via _save persists and loads via _load."""
        enrichment._nvd_file_cache["CVE-2025-1234"] = {
            "id": "CVE-2025-1234",
            "published": "2025-01-01",
            "_cached_at": time.time(),
        }
        enrichment._save_enrichment_cache()

        # Verify file exists
        cache_file = tmp_path / "nvd_cache.json"
        assert cache_file.exists()

        # Reset and reload
        enrichment._nvd_file_cache.clear()
        enrichment._enrichment_cache_loaded = False
        enrichment._load_enrichment_cache()

        assert "CVE-2025-1234" in enrichment._nvd_file_cache

    def test_nvd_cache_ttl_expiry(self, tmp_path):
        """Expired NVD cache entries are dropped on load."""
        # Write entry with old timestamp
        cache_file = tmp_path / "nvd_cache.json"
        cache_file.write_text(
            json.dumps(
                {
                    "CVE-OLD": {"id": "CVE-OLD", "_cached_at": time.time() - 999_999},
                    "CVE-FRESH": {"id": "CVE-FRESH", "_cached_at": time.time()},
                }
            )
        )

        enrichment._load_enrichment_cache()

        assert "CVE-OLD" not in enrichment._nvd_file_cache
        assert "CVE-FRESH" in enrichment._nvd_file_cache


class TestEPSSCache:
    def test_epss_cache_stores_and_loads(self, tmp_path):
        """EPSS data stored via _save persists and loads via _load."""
        enrichment._epss_file_cache["CVE-2025-5678"] = {
            "score": 0.42,
            "percentile": 0.85,
            "_cached_at": time.time(),
        }
        enrichment._save_enrichment_cache()

        cache_file = tmp_path / "epss_cache.json"
        assert cache_file.exists()

        enrichment._epss_file_cache.clear()
        enrichment._enrichment_cache_loaded = False
        enrichment._load_enrichment_cache()

        assert "CVE-2025-5678" in enrichment._epss_file_cache
        assert enrichment._epss_file_cache["CVE-2025-5678"]["score"] == 0.42

    def test_epss_cache_ttl_expiry(self, tmp_path):
        """Expired EPSS cache entries are dropped on load."""
        cache_file = tmp_path / "epss_cache.json"
        cache_file.write_text(
            json.dumps(
                {
                    "CVE-STALE": {"score": 0.1, "_cached_at": time.time() - 999_999},
                }
            )
        )

        enrichment._load_enrichment_cache()
        assert "CVE-STALE" not in enrichment._epss_file_cache


class TestSaveCacheIdempotent:
    def test_save_creates_cache_dir(self, tmp_path):
        """_save_enrichment_cache creates the cache dir if missing."""
        sub = tmp_path / "nested" / "dir"
        enrichment._ENRICHMENT_CACHE_DIR = sub
        enrichment._nvd_file_cache["CVE-X"] = {"_cached_at": time.time()}
        enrichment._save_enrichment_cache()
        assert (sub / "nvd_cache.json").exists()
