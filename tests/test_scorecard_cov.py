"""Tests for scorecard module — coverage expansion for async functions."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from agent_bom.scorecard import (
    enrich_packages_with_scorecard,
    enrich_packages_with_scorecard_stats,
    extract_github_repo,
    extract_github_repo_from_purl,
    fetch_scorecard,
)


class TestExtractGithubRepo:
    def test_basic_url(self):
        assert extract_github_repo("https://github.com/owner/repo") == "owner/repo"

    def test_url_with_git_suffix(self):
        assert extract_github_repo("https://github.com/owner/repo.git") == "owner/repo"

    def test_url_with_path(self):
        assert extract_github_repo("https://github.com/owner/repo/tree/main") == "owner/repo"

    def test_non_github_url(self):
        assert extract_github_repo("https://gitlab.com/owner/repo") is None

    def test_empty_string(self):
        assert extract_github_repo("") is None


class TestExtractGithubRepoFromPurl:
    def test_none_purl(self):
        assert extract_github_repo_from_purl("") is None

    def test_purl_with_github(self):
        result = extract_github_repo_from_purl("pkg:npm/express?vcs_url=https://github.com/expressjs/express")
        assert result == "expressjs/express"


class TestFetchScorecard:
    @pytest.mark.asyncio
    async def test_successful_fetch(self):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "score": 7.5,
            "date": "2024-01-01",
            "repo": {"name": "expressjs/express"},
            "checks": [
                {"name": "Code-Review", "score": 8},
                {"name": "Maintained", "score": 10},
            ],
        }
        with (
            patch("agent_bom.scorecard.create_client"),
            patch("agent_bom.scorecard.request_with_retry", return_value=mock_response),
            patch("agent_bom.scorecard._scorecard_cache", {}),
        ):
            result = await fetch_scorecard("expressjs/express")
            assert result is not None
            assert result["score"] == 7.5
            assert "Code-Review" in result["checks"]

    @pytest.mark.asyncio
    async def test_cache_hit(self):
        cached = {"score": 7.5, "checks": {}}
        with patch("agent_bom.scorecard._scorecard_cache", {"expressjs/express": cached}):
            result = await fetch_scorecard("expressjs/express")
            assert result == cached

    @pytest.mark.asyncio
    async def test_cache_none_hit(self):
        with patch("agent_bom.scorecard._scorecard_cache", {"bad/repo": None}):
            result = await fetch_scorecard("bad/repo")
            assert result is None

    @pytest.mark.asyncio
    async def test_failed_response(self):
        mock_response = MagicMock()
        mock_response.status_code = 404
        with (
            patch("agent_bom.scorecard.create_client"),
            patch("agent_bom.scorecard.request_with_retry", return_value=mock_response),
            patch("agent_bom.scorecard._scorecard_cache", {}),
        ):
            result = await fetch_scorecard("nonexistent/repo")
            assert result is None

    @pytest.mark.asyncio
    async def test_invalid_repo_format(self):
        result = await fetch_scorecard("invalid//repo")
        assert result is None

    @pytest.mark.asyncio
    async def test_ssrf_prevention(self):
        result = await fetch_scorecard("../../../etc/passwd")
        assert result is None

    @pytest.mark.asyncio
    async def test_json_parse_error(self):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.side_effect = ValueError("bad json")
        with (
            patch("agent_bom.scorecard.create_client"),
            patch("agent_bom.scorecard.request_with_retry", return_value=mock_response),
            patch("agent_bom.scorecard._scorecard_cache", {}),
        ):
            result = await fetch_scorecard("owner/repo")
            assert result is None


class TestEnrichPackagesWithScorecard:
    @pytest.mark.asyncio
    async def test_enriches_packages_with_repo(self):
        from agent_bom.models import Package

        pkg = Package(name="express", version="4.18.2", ecosystem="npm")
        pkg.source_repo = "https://github.com/expressjs/express"

        scorecard_data = {"score": 7.5, "checks": {"Code-Review": 8}}
        with patch("agent_bom.scorecard.fetch_scorecard", return_value=scorecard_data):
            count = await enrich_packages_with_scorecard([pkg])
            assert count == 1
            assert pkg.scorecard_score == 7.5

    @pytest.mark.asyncio
    async def test_skips_packages_without_repo(self):
        from agent_bom.models import Package

        pkg = Package(name="mylib", version="1.0.0", ecosystem="pypi")
        with patch("agent_bom.scorecard.fetch_scorecard") as mock_fetch:
            count = await enrich_packages_with_scorecard([pkg])
            assert count == 0
            mock_fetch.assert_not_called()

    @pytest.mark.asyncio
    async def test_scorecard_returns_none(self):
        from agent_bom.models import Package

        pkg = Package(name="express", version="4.18.2", ecosystem="npm")
        pkg.source_repo = "https://github.com/expressjs/express"
        with patch("agent_bom.scorecard.fetch_scorecard", return_value=None):
            count = await enrich_packages_with_scorecard([pkg])
            assert count == 0

    @pytest.mark.asyncio
    async def test_stats_uses_repository_url_and_sets_enriched_state(self):
        from agent_bom.models import Package

        pkg = Package(name="express", version="4.18.2", ecosystem="npm", repository_url="https://github.com/expressjs/express")
        with patch("agent_bom.scorecard.fetch_scorecard", return_value={"score": 7.5, "checks": {"Maintained": 10}}):
            stats = await enrich_packages_with_scorecard_stats([pkg])
            assert stats.eligible_packages == 1
            assert stats.enriched_packages == 1
            assert pkg.scorecard_lookup_state == "enriched"
            assert pkg.scorecard_repo == "expressjs/express"

    @pytest.mark.asyncio
    async def test_stats_marks_unresolved_when_repo_missing(self):
        from agent_bom.models import Package

        pkg = Package(name="pkg", version="1.0.0", ecosystem="pypi")
        stats = await enrich_packages_with_scorecard_stats([pkg])
        assert stats.eligible_packages == 0
        assert stats.unresolved_packages == 1
        assert pkg.scorecard_lookup_state == "unresolved"

    @pytest.mark.asyncio
    async def test_stats_marks_failed_when_lookup_fails(self):
        from agent_bom.models import Package

        pkg = Package(name="express", version="4.18.2", ecosystem="npm", homepage="https://github.com/expressjs/express")
        with patch("agent_bom.scorecard.fetch_scorecard", return_value=None):
            stats = await enrich_packages_with_scorecard_stats([pkg])
            assert stats.eligible_packages == 1
            assert stats.failed_packages == 1
            assert pkg.scorecard_lookup_state == "failed"

    @pytest.mark.asyncio
    async def test_rate_limit_sets_reason_and_cooldown(self):
        from agent_bom.models import Package

        pkg1 = Package(name="express", version="4.18.2", ecosystem="npm", homepage="https://github.com/expressjs/express")
        pkg2 = Package(name="next", version="16.2.1", ecosystem="npm", homepage="https://github.com/vercel/next.js")
        mock_response = MagicMock()
        mock_response.status_code = 429
        mock_response.headers = {"Retry-After": "7"}

        with (
            patch("agent_bom.scorecard.create_client"),
            patch("agent_bom.scorecard.request_with_retry", return_value=mock_response) as mock_request,
            patch("agent_bom.scorecard._scorecard_cache", {}),
            patch("agent_bom.scorecard._scorecard_reason_cache", {}),
            patch("agent_bom.scorecard._scorecard_cooldown_until", 0.0),
            patch("agent_bom.scorecard.time.monotonic", return_value=100.0),
        ):
            stats = await enrich_packages_with_scorecard_stats([pkg1, pkg2])

        assert stats.failed_packages == 2
        assert mock_request.call_count == 1
        assert pkg1.scorecard_lookup_reason == "scorecard_rate_limited"
        assert pkg2.scorecard_lookup_reason == "scorecard_service_unavailable"
