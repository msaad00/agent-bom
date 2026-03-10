"""Tests for http_client module — coverage expansion for retry logic."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import httpx
import pytest

from agent_bom.http_client import (
    _safe_url,
    _sanitize_for_log,
    create_client,
    request_with_retry,
)


class TestSanitizeForLog:
    def test_strips_newlines(self):
        assert _sanitize_for_log("line1\nline2") == "line1\\nline2"

    def test_strips_carriage_returns(self):
        assert _sanitize_for_log("line1\rline2") == "line1\\rline2"

    def test_plain_string(self):
        assert _sanitize_for_log("hello") == "hello"


class TestSafeUrl:
    def test_strips_query_params(self):
        result = _safe_url("https://api.example.com/path?apiKey=secret&token=abc")
        assert "secret" not in result
        assert "token" not in result
        assert "example.com" in result

    def test_strips_userinfo(self):
        result = _safe_url("https://user:pass@api.example.com/path")
        assert "pass" not in result

    def test_basic_url(self):
        result = _safe_url("https://api.example.com/v1/data")
        assert "api.example.com" in result
        assert "/v1/data" in result

    def test_invalid_url(self):
        result = _safe_url("")
        assert isinstance(result, str)


class TestCreateClient:
    def test_creates_client(self):
        client = create_client(timeout=10.0)
        assert isinstance(client, httpx.AsyncClient)

    def test_default_timeout(self):
        client = create_client()
        assert isinstance(client, httpx.AsyncClient)


class TestRequestWithRetry:
    @pytest.mark.asyncio
    async def test_success_on_first_try(self):
        mock_response = MagicMock()
        mock_response.status_code = 200
        client = AsyncMock()
        client.request.return_value = mock_response
        result = await request_with_retry(client, "GET", "https://example.com")
        assert result.status_code == 200

    @pytest.mark.asyncio
    async def test_retries_on_429(self):
        mock_429 = MagicMock()
        mock_429.status_code = 429
        mock_429.headers = {"Retry-After": "0.01"}
        mock_200 = MagicMock()
        mock_200.status_code = 200
        client = AsyncMock()
        client.request.side_effect = [mock_429, mock_200]
        result = await request_with_retry(client, "GET", "https://example.com", max_retries=2)
        assert result.status_code == 200

    @pytest.mark.asyncio
    async def test_retries_on_500(self):
        mock_500 = MagicMock()
        mock_500.status_code = 500
        mock_500.headers = {}
        mock_200 = MagicMock()
        mock_200.status_code = 200
        client = AsyncMock()
        client.request.side_effect = [mock_500, mock_200]
        result = await request_with_retry(client, "GET", "https://example.com", max_retries=2)
        assert result.status_code == 200

    @pytest.mark.asyncio
    async def test_exhausted_retries_returns_last_response(self):
        mock_503 = MagicMock()
        mock_503.status_code = 503
        mock_503.headers = {}
        client = AsyncMock()
        client.request.return_value = mock_503
        result = await request_with_retry(client, "GET", "https://example.com", max_retries=1)
        assert result.status_code == 503

    @pytest.mark.asyncio
    async def test_timeout_exception_retries(self):
        mock_200 = MagicMock()
        mock_200.status_code = 200
        client = AsyncMock()
        client.request.side_effect = [httpx.TimeoutException("timeout"), mock_200]
        result = await request_with_retry(client, "GET", "https://example.com", max_retries=2)
        assert result.status_code == 200

    @pytest.mark.asyncio
    async def test_timeout_exhausted_returns_none(self):
        client = AsyncMock()
        client.request.side_effect = httpx.TimeoutException("timeout")
        result = await request_with_retry(client, "GET", "https://example.com", max_retries=0)
        assert result is None

    @pytest.mark.asyncio
    async def test_http_error_retries(self):
        mock_200 = MagicMock()
        mock_200.status_code = 200
        client = AsyncMock()
        client.request.side_effect = [httpx.HTTPError("error"), mock_200]
        result = await request_with_retry(client, "GET", "https://example.com", max_retries=2)
        assert result.status_code == 200

    @pytest.mark.asyncio
    async def test_http_error_exhausted_returns_none(self):
        client = AsyncMock()
        client.request.side_effect = httpx.HTTPError("error")
        result = await request_with_retry(client, "GET", "https://example.com", max_retries=0)
        assert result is None

    @pytest.mark.asyncio
    async def test_retry_after_header_invalid(self):
        mock_429 = MagicMock()
        mock_429.status_code = 429
        mock_429.headers = {"Retry-After": "not-a-number"}
        mock_200 = MagicMock()
        mock_200.status_code = 200
        client = AsyncMock()
        client.request.side_effect = [mock_429, mock_200]
        result = await request_with_retry(client, "GET", "https://example.com", max_retries=2)
        assert result.status_code == 200
