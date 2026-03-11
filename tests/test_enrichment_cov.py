"""Tests for enrichment module — coverage expansion for NVD, EPSS, KEV."""

from __future__ import annotations

import time
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from agent_bom.enrichment import (
    _evict_oldest,
    calculate_exploitability,
    extract_cve_ids,
    fetch_cisa_kev_catalog,
    fetch_epss_scores,
    fetch_nvd_data,
)
from agent_bom.models import Vulnerability


class TestEvictOldest:
    def test_no_eviction_under_limit(self):
        cache = {"a": {"_cached_at": 1}, "b": {"_cached_at": 2}}
        _evict_oldest(cache, 10)
        assert len(cache) == 2

    def test_eviction_over_limit(self):
        cache = {str(i): {"_cached_at": i} for i in range(20)}
        _evict_oldest(cache, 10)
        assert len(cache) == 10

    def test_evicts_oldest_entries(self):
        cache = {
            "old": {"_cached_at": 100},
            "new": {"_cached_at": 999},
        }
        _evict_oldest(cache, 1)
        assert "new" in cache
        assert "old" not in cache


class TestExtractCveIds:
    def test_primary_cve_ids(self):
        from agent_bom.models import Severity

        vulns = [
            Vulnerability(id="CVE-2024-1234", summary="test", severity=Severity.HIGH),
            Vulnerability(id="GHSA-abc", summary="test", severity=Severity.MEDIUM),
        ]
        cve_ids = extract_cve_ids(vulns)
        assert "CVE-2024-1234" in cve_ids
        assert "GHSA-abc" not in cve_ids

    def test_cve_from_aliases(self):
        from agent_bom.models import Severity

        vuln = Vulnerability(id="GHSA-xyz", summary="test", severity=Severity.HIGH, aliases=["CVE-2024-5678"])
        cve_ids = extract_cve_ids([vuln])
        assert "CVE-2024-5678" in cve_ids

    def test_empty_list(self):
        assert extract_cve_ids([]) == []


class TestCalculateExploitability:
    def test_none_score(self):
        assert calculate_exploitability(None) is None

    def test_high_score(self):
        result = calculate_exploitability(0.95)
        assert result == "HIGH"

    def test_medium_score(self):
        result = calculate_exploitability(0.5)
        assert result == "MEDIUM"

    def test_low_score(self):
        result = calculate_exploitability(0.01)
        assert result == "LOW"


class TestFetchNvdData:
    @pytest.mark.asyncio
    async def test_successful_fetch(self):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"vulnerabilities": [{"cve": {"id": "CVE-2024-1234", "weaknesses": []}}]}
        client = AsyncMock()
        with (
            patch("agent_bom.enrichment.request_with_retry", return_value=mock_response),
            patch("agent_bom.enrichment._load_enrichment_cache"),
            patch("agent_bom.enrichment._nvd_file_cache", {}),
        ):
            result = await fetch_nvd_data("CVE-2024-1234", client)
            assert result is not None
            assert result["id"] == "CVE-2024-1234"

    @pytest.mark.asyncio
    async def test_cache_hit(self):
        cached = {"id": "CVE-2024-1234", "_cached_at": time.time()}
        client = AsyncMock()
        with (
            patch("agent_bom.enrichment._load_enrichment_cache"),
            patch("agent_bom.enrichment._nvd_file_cache", {"CVE-2024-1234": cached}),
        ):
            result = await fetch_nvd_data("CVE-2024-1234", client)
            assert result is not None

    @pytest.mark.asyncio
    async def test_with_api_key(self):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"vulnerabilities": [{"cve": {"id": "CVE-2024-1234"}}]}
        client = AsyncMock()
        with (
            patch("agent_bom.enrichment.request_with_retry", return_value=mock_response),
            patch("agent_bom.enrichment._load_enrichment_cache"),
            patch("agent_bom.enrichment._nvd_file_cache", {}),
        ):
            result = await fetch_nvd_data("CVE-2024-1234", client, api_key="test-key")
            assert result is not None

    @pytest.mark.asyncio
    async def test_failed_response(self):
        mock_response = MagicMock()
        mock_response.status_code = 404
        client = AsyncMock()
        with (
            patch("agent_bom.enrichment.request_with_retry", return_value=mock_response),
            patch("agent_bom.enrichment._load_enrichment_cache"),
            patch("agent_bom.enrichment._nvd_file_cache", {}),
        ):
            result = await fetch_nvd_data("CVE-2024-9999", client)
            assert result is None

    @pytest.mark.asyncio
    async def test_no_vulnerabilities(self):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"vulnerabilities": []}
        client = AsyncMock()
        with (
            patch("agent_bom.enrichment.request_with_retry", return_value=mock_response),
            patch("agent_bom.enrichment._load_enrichment_cache"),
            patch("agent_bom.enrichment._nvd_file_cache", {}),
        ):
            result = await fetch_nvd_data("CVE-2024-9999", client)
            assert result is None


class TestFetchEpssScores:
    @pytest.mark.asyncio
    async def test_empty_cve_list(self):
        client = AsyncMock()
        result = await fetch_epss_scores([], client)
        assert result == {}

    @pytest.mark.asyncio
    async def test_all_cached(self):
        cached = {"CVE-2024-1234": {"score": 0.5, "percentile": 0.8, "_cached_at": time.time()}}
        client = AsyncMock()
        with (
            patch("agent_bom.enrichment._load_enrichment_cache"),
            patch("agent_bom.enrichment._epss_file_cache", cached),
        ):
            result = await fetch_epss_scores(["CVE-2024-1234"], client)
            assert "CVE-2024-1234" in result

    @pytest.mark.asyncio
    async def test_successful_batch_fetch(self):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "data": [
                {"cve": "CVE-2024-1234", "epss": "0.5", "percentile": "0.8", "date": "2024-01-01"},
                {"cve": "CVE-2024-5678", "epss": "0.1", "percentile": "0.3", "date": "2024-01-01"},
            ]
        }
        client = AsyncMock()
        with (
            patch("agent_bom.enrichment.request_with_retry", return_value=mock_response),
            patch("agent_bom.enrichment._load_enrichment_cache"),
            patch("agent_bom.enrichment._epss_file_cache", {}),
        ):
            result = await fetch_epss_scores(["CVE-2024-1234", "CVE-2024-5678"], client)
            assert "CVE-2024-1234" in result
            assert result["CVE-2024-1234"]["score"] == 0.5

    @pytest.mark.asyncio
    async def test_failed_response(self):
        mock_response = MagicMock()
        mock_response.status_code = 500
        client = AsyncMock()
        with (
            patch("agent_bom.enrichment.request_with_retry", return_value=mock_response),
            patch("agent_bom.enrichment._load_enrichment_cache"),
            patch("agent_bom.enrichment._epss_file_cache", {}),
        ):
            result = await fetch_epss_scores(["CVE-2024-1234"], client)
            assert result == {}


class TestFetchCisaKev:
    @pytest.mark.asyncio
    async def test_successful_fetch(self):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "vulnerabilities": [
                {
                    "cveID": "CVE-2024-1234",
                    "dateAdded": "2024-01-01",
                    "dueDate": "2024-02-01",
                    "shortDescription": "Test vuln",
                    "requiredAction": "Update",
                    "vendorProject": "TestVendor",
                    "product": "TestProduct",
                }
            ]
        }
        client = AsyncMock()
        with (
            patch("agent_bom.enrichment.request_with_retry", return_value=mock_response),
            patch("agent_bom.enrichment._kev_cache", None),
            patch("agent_bom.enrichment._kev_cache_time", None),
            patch("agent_bom.enrichment._KEV_CACHE_FILE") as mock_cache_file,
        ):
            mock_cache_file.exists.return_value = False
            mock_cache_file.parent.mkdir.return_value = None
            result = await fetch_cisa_kev_catalog(client)
            assert "CVE-2024-1234" in result

    @pytest.mark.asyncio
    async def test_in_memory_cache_hit(self):
        from datetime import datetime, timezone

        client = AsyncMock()
        cached_data = {"CVE-2024-1234": {"date_added": "2024-01-01"}}
        with (
            patch("agent_bom.enrichment._kev_cache", cached_data),
            patch("agent_bom.enrichment._kev_cache_time", datetime.now(timezone.utc)),
        ):
            result = await fetch_cisa_kev_catalog(client)
            assert result == cached_data
