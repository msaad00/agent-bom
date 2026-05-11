"""Tests for enrichment persistent caching (NVD + EPSS)."""

from __future__ import annotations

import json
import time

import pytest

import agent_bom.enrichment as enrichment
from agent_bom.models import Severity, Vulnerability


@pytest.fixture(autouse=True)
def _reset_enrichment_cache(tmp_path, monkeypatch):
    """Reset module-level caches and redirect to tmp dir."""
    monkeypatch.setattr(enrichment, "_ENRICHMENT_CACHE_DIR", tmp_path)
    monkeypatch.setattr(enrichment, "_nvd_file_cache", {})
    monkeypatch.setattr(enrichment, "_epss_file_cache", {})
    monkeypatch.setattr(enrichment, "_enrichment_cache_loaded", False)
    monkeypatch.setattr(enrichment, "_KEV_CACHE_FILE", tmp_path / "kev_cache.json")
    monkeypatch.setattr(enrichment, "_kev_cache", None)
    monkeypatch.setattr(enrichment, "_kev_cache_time", None)


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


@pytest.mark.asyncio
async def test_offline_enrichment_joins_epss_and_kev_caches(tmp_path, monkeypatch):
    now = time.time()
    (tmp_path / "epss_cache.json").write_text(
        json.dumps(
            {
                "CVE-2025-9999": {
                    "score": 0.81,
                    "percentile": 96.0,
                    "date": "2026-05-10",
                    "_cached_at": now - 999_999,
                }
            }
        )
    )
    (tmp_path / "kev_cache.json").write_text(
        json.dumps(
            {
                "_cached_at": now - 999_999,
                "data": {
                    "CVE-2025-9999": {
                        "date_added": "2026-05-01",
                        "due_date": "2026-05-22",
                    }
                },
            }
        )
    )

    async def _no_network(*_args, **_kwargs):
        raise AssertionError("offline cache join must not perform network requests")

    monkeypatch.setattr(enrichment, "request_with_retry", _no_network)

    vuln = Vulnerability(id="CVE-2025-9999", summary="cached", severity=Severity.HIGH)
    enriched = await enrichment.enrich_vulnerabilities([vuln], offline=True)

    assert enriched == 1
    assert vuln.epss_score == 0.81
    assert vuln.epss_percentile == 96.0
    assert vuln.exploitability == "HIGH"
    assert vuln.is_kev is True
    assert vuln.kev_date_added == "2026-05-01"
    assert vuln.kev_due_date == "2026-05-22"
