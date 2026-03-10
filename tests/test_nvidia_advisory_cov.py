"""Tests for NVIDIA advisory module — coverage expansion for async functions."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from agent_bom.models import Package, Severity
from agent_bom.scanners.nvidia_advisory import (
    _extract_fixed_version,
    _normalise,
    _parse_csaf_severity,
    check_nvidia_advisories,
    extract_vulns_from_csaf,
    fetch_nvidia_advisory_index,
    fetch_nvidia_csaf,
)


class TestNormalise:
    def test_lowercase(self):
        assert _normalise("Torch") == "torch"

    def test_hyphen_to_underscore(self):
        assert _normalise("flash-attn") == "flash_attn"


class TestParseCsafSeverity:
    def test_critical_score(self):
        scores = [{"cvss_v3": {"baseScore": 9.5}}]
        sev, score = _parse_csaf_severity(scores)
        assert sev == Severity.CRITICAL
        assert score == 9.5

    def test_high_score(self):
        scores = [{"cvss_v3": {"baseScore": 7.5}}]
        sev, score = _parse_csaf_severity(scores)
        assert sev == Severity.HIGH

    def test_medium_score(self):
        scores = [{"cvss_v3": {"baseScore": 5.0}}]
        sev, score = _parse_csaf_severity(scores)
        assert sev == Severity.MEDIUM

    def test_low_score(self):
        scores = [{"cvss_v3": {"baseScore": 2.0}}]
        sev, score = _parse_csaf_severity(scores)
        assert sev == Severity.LOW

    def test_no_scores(self):
        sev, score = _parse_csaf_severity([])
        assert sev == Severity.MEDIUM
        assert score is None

    def test_cvss_v4_fallback(self):
        scores = [{"cvss_v4": {"baseScore": 8.0}}]
        sev, score = _parse_csaf_severity(scores)
        assert sev == Severity.HIGH
        assert score == 8.0


class TestExtractFixedVersion:
    def test_with_fixed_products(self):
        vuln = {"product_status": {"fixed": ["CUDA Toolkit 12.9 Update 1"]}}
        result = _extract_fixed_version(vuln)
        assert result is not None
        assert "12.9" in result

    def test_no_fixed(self):
        vuln = {"product_status": {"affected": ["some product"]}}
        result = _extract_fixed_version(vuln)
        assert result is None

    def test_empty_fixed(self):
        vuln = {"product_status": {"fixed": []}}
        result = _extract_fixed_version(vuln)
        assert result is None


class TestExtractVulnsFromCsaf:
    def test_basic_extraction(self):
        csaf = {
            "vulnerabilities": [
                {
                    "cve": "CVE-2025-0001",
                    "scores": [{"cvss_v3": {"baseScore": 9.0}}],
                    "notes": [{"category": "description", "text": "A critical vulnerability"}],
                    "cwe": {"id": "CWE-119"},
                    "product_status": {"fixed": ["CUDA 12.9"]},
                    "references": [{"url": "https://nvidia.com/advisory/1"}],
                }
            ]
        }
        vulns = extract_vulns_from_csaf(csaf)
        assert len(vulns) == 1
        assert vulns[0].id == "CVE-2025-0001"
        assert vulns[0].severity == Severity.CRITICAL
        assert "CWE-119" in vulns[0].cwe_ids
        assert len(vulns[0].references) == 1

    def test_no_cve_skipped(self):
        csaf = {"vulnerabilities": [{"scores": []}]}
        vulns = extract_vulns_from_csaf(csaf)
        assert len(vulns) == 0

    def test_no_vulnerabilities_key(self):
        csaf = {"document": {"title": "Empty"}}
        vulns = extract_vulns_from_csaf(csaf)
        assert len(vulns) == 0

    def test_missing_notes_uses_default_summary(self):
        csaf = {
            "vulnerabilities": [
                {
                    "cve": "CVE-2025-0002",
                    "scores": [],
                    "notes": [],
                    "product_status": {},
                    "references": [],
                }
            ]
        }
        vulns = extract_vulns_from_csaf(csaf)
        assert "CVE-2025-0002" in vulns[0].summary


class TestFetchNvidiaAdvisoryIndex:
    @pytest.mark.asyncio
    async def test_successful_fetch(self):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = [
            {"name": "CVE-2025-001", "path": "2025/CVE-2025-001", "type": "dir"},
            {"name": "README.md", "path": "2025/README.md", "type": "file"},
        ]
        with patch("agent_bom.scanners.nvidia_advisory.request_with_retry", return_value=mock_response):
            client = AsyncMock()
            result = await fetch_nvidia_advisory_index(years=["2025"], client=client)
            assert len(result) == 1
            assert result[0]["id"] == "CVE-2025-001"

    @pytest.mark.asyncio
    async def test_no_client_creates_one(self):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = []
        with (
            patch("agent_bom.scanners.nvidia_advisory.request_with_retry", return_value=mock_response),
            patch("agent_bom.scanners.nvidia_advisory.httpx.AsyncClient") as mock_client_cls,
        ):
            mock_client = AsyncMock()
            mock_client_cls.return_value = mock_client
            result = await fetch_nvidia_advisory_index(years=["2025"])
            assert result == []

    @pytest.mark.asyncio
    async def test_failed_response(self):
        mock_response = MagicMock()
        mock_response.status_code = 404
        with patch("agent_bom.scanners.nvidia_advisory.request_with_retry", return_value=mock_response):
            client = AsyncMock()
            result = await fetch_nvidia_advisory_index(years=["2025"], client=client)
            assert result == []


class TestFetchNvidiaCsaf:
    @pytest.mark.asyncio
    async def test_successful_fetch(self):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"document": {"title": "Test"}}
        with patch("agent_bom.scanners.nvidia_advisory.request_with_retry", return_value=mock_response):
            client = AsyncMock()
            result = await fetch_nvidia_csaf("https://example.com/advisory.json", client)
            assert result == {"document": {"title": "Test"}}

    @pytest.mark.asyncio
    async def test_failed_fetch(self):
        with patch("agent_bom.scanners.nvidia_advisory.request_with_retry", return_value=None):
            client = AsyncMock()
            result = await fetch_nvidia_csaf("https://example.com/bad.json", client)
            assert result is None

    @pytest.mark.asyncio
    async def test_json_parse_error(self):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.side_effect = ValueError("bad json")
        with patch("agent_bom.scanners.nvidia_advisory.request_with_retry", return_value=mock_response):
            client = AsyncMock()
            result = await fetch_nvidia_csaf("https://example.com/bad.json", client)
            assert result is None


class TestCheckNvidiaAdvisories:
    @pytest.mark.asyncio
    async def test_no_nvidia_packages(self):
        pkgs = [Package(name="requests", version="2.31.0", ecosystem="pypi")]
        result = await check_nvidia_advisories(pkgs)
        assert result == 0

    @pytest.mark.asyncio
    async def test_nvidia_packages_with_advisory(self):
        pkgs = [Package(name="torch", version="2.0.0", ecosystem="pypi")]
        mock_index = [{"id": "CVE-2025-001", "path": "2025/CVE-2025-001", "url": "https://example.com/adv.json"}]
        mock_csaf = {
            "document": {"title": "NVIDIA CUDA Toolkit Security Update"},
            "product_tree": {"branches": []},
            "vulnerabilities": [
                {
                    "cve": "CVE-2025-0001",
                    "scores": [{"cvss_v3": {"baseScore": 9.0}}],
                    "notes": [{"category": "description", "text": "Critical vuln"}],
                    "cwe": {},
                    "product_status": {},
                    "references": [],
                }
            ],
        }
        with (
            patch("agent_bom.scanners.nvidia_advisory.create_client"),
            patch("agent_bom.scanners.nvidia_advisory.fetch_nvidia_advisory_index", return_value=mock_index),
            patch("agent_bom.scanners.nvidia_advisory.fetch_nvidia_csaf", return_value=mock_csaf),
        ):
            result = await check_nvidia_advisories(pkgs)
            assert result >= 1
            assert any(v.id == "CVE-2025-0001" for v in pkgs[0].vulnerabilities)

    @pytest.mark.asyncio
    async def test_no_advisories_found(self):
        pkgs = [Package(name="torch", version="2.0.0", ecosystem="pypi")]
        with (
            patch("agent_bom.scanners.nvidia_advisory.create_client"),
            patch("agent_bom.scanners.nvidia_advisory.fetch_nvidia_advisory_index", return_value=[]),
        ):
            result = await check_nvidia_advisories(pkgs)
            assert result == 0

    @pytest.mark.asyncio
    async def test_max_advisories_limit(self):
        pkgs = [Package(name="torch", version="2.0.0", ecosystem="pypi")]
        mock_index = [
            {"id": f"CVE-2025-{i:04d}", "path": f"2025/CVE-2025-{i:04d}", "url": f"https://example.com/adv{i}.json"} for i in range(30)
        ]
        mock_csaf = {
            "document": {"title": "Unrelated Advisory"},
            "product_tree": {"branches": []},
            "vulnerabilities": [],
        }
        with (
            patch("agent_bom.scanners.nvidia_advisory.create_client"),
            patch("agent_bom.scanners.nvidia_advisory.fetch_nvidia_advisory_index", return_value=mock_index),
            patch("agent_bom.scanners.nvidia_advisory.fetch_nvidia_csaf", return_value=mock_csaf),
        ):
            result = await check_nvidia_advisories(pkgs, max_advisories=5)
            assert result == 0
