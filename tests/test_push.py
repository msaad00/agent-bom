"""Tests for hybrid push-to-dashboard."""

import asyncio
from unittest.mock import AsyncMock, patch

import pytest

from agent_bom.push import (
    _looks_like_secret,
    _push_async,
    _push_retry_delay,
    generate_source_id,
    push_results,
    sanitize_results,
)

# ─── generate_source_id ──────────────────────────────────────────────────────


class TestGenerateSourceId:
    def test_env_override_takes_priority(self, monkeypatch):
        monkeypatch.setenv("AGENT_BOM_PUSH_SOURCE_ID", "device-acme-001")
        assert generate_source_id() == "device-acme-001"

    def test_stable(self):
        """Same machine produces same source_id."""
        id1 = generate_source_id()
        id2 = generate_source_id()
        assert id1 == id2

    def test_length(self):
        """source_id is 12 hex characters."""
        sid = generate_source_id()
        assert len(sid) == 12
        assert all(c in "0123456789abcdef" for c in sid)

    def test_different_hostname(self):
        """Different hostname produces different ID."""
        with patch("agent_bom.push.platform") as mock_platform:
            mock_platform.node.return_value = "host-a"
            id_a = generate_source_id()

        with patch("agent_bom.push.platform") as mock_platform:
            mock_platform.node.return_value = "host-b"
            id_b = generate_source_id()

        assert id_a != id_b


# ─── sanitize_results ────────────────────────────────────────────────────────


class TestSanitizeResults:
    def test_strips_config_path(self):
        results = {"agents": [{"name": "agent-1", "config_path": "/home/user/.config/mcp.json"}]}
        sanitized = sanitize_results(results)
        assert "config_path" not in sanitized["agents"][0]

    def test_redacts_secrets_in_metadata(self):
        results = {
            "agents": [
                {
                    "name": "agent-1",
                    "metadata": {
                        "api_token": "sk-abc123",
                        "api_key": "key-xyz",
                        "display_name": "My Bot",
                    },
                }
            ]
        }
        sanitized = sanitize_results(results)
        meta = sanitized["agents"][0]["metadata"]
        assert meta["api_token"] == "***REDACTED***"
        assert meta["api_key"] == "***REDACTED***"
        assert meta["display_name"] == "My Bot"

    def test_redacts_nested_secret_fields(self):
        results = {
            "agents": [
                {
                    "name": "agent-1",
                    "metadata": {
                        "nested": {
                            "api_key": "key-xyz",
                            "safe": "visible",
                        },
                        "tools": [{"auth_token": "tok-123", "name": "search"}],
                    },
                }
            ]
        }
        sanitized = sanitize_results(results)
        meta = sanitized["agents"][0]["metadata"]
        assert meta["nested"]["api_key"] == "***REDACTED***"
        assert meta["nested"]["safe"] == "visible"
        assert meta["tools"][0]["auth_token"] == "***REDACTED***"
        assert meta["tools"][0]["name"] == "search"

    def test_adds_source_id(self):
        results = {"agents": []}
        sanitized = sanitize_results(results)
        assert "source_id" in sanitized
        assert len(sanitized["source_id"]) == 12

    def test_adds_idempotency_key(self):
        results = {"agents": []}
        sanitized = sanitize_results(results)
        assert "idempotency_key" in sanitized
        assert len(sanitized["idempotency_key"]) >= 32

    def test_does_not_mutate_original(self):
        results = {"agents": [{"name": "a", "config_path": "/x"}]}
        sanitize_results(results)
        assert results["agents"][0]["config_path"] == "/x"

    def test_empty_agents(self):
        results = {"agents": []}
        sanitized = sanitize_results(results)
        assert sanitized["agents"] == []
        assert "source_id" in sanitized

    def test_no_agents_key(self):
        results = {"summary": "ok"}
        sanitized = sanitize_results(results)
        assert sanitized["summary"] == "ok"
        assert "source_id" in sanitized

    def test_adds_endpoint_identity_metadata_from_env(self, monkeypatch):
        monkeypatch.setenv("AGENT_BOM_PUSH_SOURCE_ID", "device-acme-001")
        monkeypatch.setenv("AGENT_BOM_PUSH_ENROLLMENT_NAME", "corp-laptop-rollout")
        monkeypatch.setenv("AGENT_BOM_PUSH_OWNER", "platform-security")
        monkeypatch.setenv("AGENT_BOM_PUSH_ENVIRONMENT", "production")
        monkeypatch.setenv("AGENT_BOM_PUSH_MDM_PROVIDER", "jamf")
        monkeypatch.setenv("AGENT_BOM_PUSH_TAGS", "developer-endpoint, mdm")
        results = {"agents": [{"name": "cursor"}]}
        sanitized = sanitize_results(results)
        agent = sanitized["agents"][0]
        assert agent["source_id"] == "device-acme-001"
        assert agent["enrollment_name"] == "corp-laptop-rollout"
        assert agent["owner"] == "platform-security"
        assert agent["environment"] == "production"
        assert agent["mdm_provider"] == "jamf"
        assert agent["tags"] == ["developer-endpoint", "mdm"]


# ─── _looks_like_secret ──────────────────────────────────────────────────────


class TestLooksLikeSecret:
    def test_token_key(self):
        assert _looks_like_secret("api_token") is True

    def test_password_key(self):
        assert _looks_like_secret("db_password") is True

    def test_safe_key(self):
        assert _looks_like_secret("display_name") is False

    def test_case_insensitive(self):
        assert _looks_like_secret("API_KEY") is True


# ─── push_results ─────────────────────────────────────────────────────────────


class TestPushResults:
    def test_push_success(self):
        mock_resp = AsyncMock()
        mock_resp.status_code = 200

        mock_client = AsyncMock()
        mock_client.post = AsyncMock(return_value=mock_resp)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with (
            patch("agent_bom.http_client.create_client", return_value=mock_client),
            patch("agent_bom.security.validate_url", return_value=None),
        ):
            result = push_results("https://dashboard.example.com/v1/results/push", {"agents": []})
        assert result is True

    def test_push_failure(self):
        """A 500 is retryable; the final result is False after max attempts."""
        mock_resp = AsyncMock()
        mock_resp.status_code = 500
        mock_resp.text = "Internal server error"

        mock_client = AsyncMock()
        mock_client.post = AsyncMock(return_value=mock_resp)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with (
            patch("agent_bom.http_client.create_client", return_value=mock_client),
            patch("agent_bom.push.asyncio.sleep", new=AsyncMock()),
            patch("agent_bom.security.validate_url", return_value=None),
        ):
            result = push_results("https://dashboard.example.com/v1/results/push", {"agents": []})
        assert result is False
        # 3 retry attempts by default
        assert mock_client.post.call_count == 3

    def test_push_with_api_key(self):
        mock_resp = AsyncMock()
        mock_resp.status_code = 200

        mock_client = AsyncMock()
        mock_client.post = AsyncMock(return_value=mock_resp)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with (
            patch("agent_bom.http_client.create_client", return_value=mock_client),
            patch("agent_bom.security.validate_url", return_value=None),
        ):
            result = push_results(
                "https://dashboard.example.com/v1/results/push",
                {"agents": []},
                api_key="test-key-123",
            )
        assert result is True
        # Verify Authorization header was passed
        call_kwargs = mock_client.post.call_args
        headers = call_kwargs.kwargs.get("headers", {})
        assert headers.get("Authorization") == "Bearer test-key-123"

    def test_push_network_error(self):
        """Network errors retry up to max attempts then return False."""
        mock_client = AsyncMock()
        mock_client.post = AsyncMock(side_effect=OSError("Connection refused"))
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with (
            patch("agent_bom.http_client.create_client", return_value=mock_client),
            patch("agent_bom.push.asyncio.sleep", new=AsyncMock()),
            patch("agent_bom.security.validate_url", return_value=None),
        ):
            result = push_results("https://unreachable.example.com/push", {"agents": []})
        assert result is False
        assert mock_client.post.call_count == 3


# ─── push retry contract ──────────────────────────────────────────────────────


class TestPushRetry:
    def test_retryable_status_then_success(self):
        """503 then 200 ⇒ single retry, final True."""
        resp_fail = AsyncMock(status_code=503)
        resp_fail.text = "Service unavailable"
        resp_ok = AsyncMock(status_code=200)

        mock_client = AsyncMock()
        mock_client.post = AsyncMock(side_effect=[resp_fail, resp_ok])
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with (
            patch("agent_bom.http_client.create_client", return_value=mock_client),
            patch("agent_bom.push.asyncio.sleep", new=AsyncMock()),
            patch("agent_bom.security.validate_url", return_value=None),
        ):
            result = asyncio.run(_push_async("https://dashboard.example.com/push", {"agents": []}, max_attempts=3))
        assert result is True
        assert mock_client.post.call_count == 2

    def test_non_retryable_status_short_circuits(self):
        """4xx that isn't 408/425/429 returns False without retrying."""
        resp = AsyncMock(status_code=400)
        resp.text = "Bad request"

        mock_client = AsyncMock()
        mock_client.post = AsyncMock(return_value=resp)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with (
            patch("agent_bom.http_client.create_client", return_value=mock_client),
            patch("agent_bom.push.asyncio.sleep", new=AsyncMock()),
            patch("agent_bom.security.validate_url", return_value=None),
        ):
            result = asyncio.run(_push_async("https://dashboard.example.com/push", {"agents": []}, max_attempts=3))
        assert result is False
        assert mock_client.post.call_count == 1

    def test_429_is_retryable(self):
        resp_429 = AsyncMock(status_code=429)
        resp_429.text = "rate limited"
        resp_ok = AsyncMock(status_code=200)

        mock_client = AsyncMock()
        mock_client.post = AsyncMock(side_effect=[resp_429, resp_ok])
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with (
            patch("agent_bom.http_client.create_client", return_value=mock_client),
            patch("agent_bom.push.asyncio.sleep", new=AsyncMock()),
            patch("agent_bom.security.validate_url", return_value=None),
        ):
            result = asyncio.run(_push_async("https://dashboard.example.com/push", {"agents": []}, max_attempts=3))
        assert result is True
        assert mock_client.post.call_count == 2

    @pytest.mark.parametrize(
        "attempt,expected_floor,cap",
        [
            (1, 1.0, 30.0),
            (2, 2.0, 30.0),
            (3, 4.0, 30.0),
            (10, 30.0, 30.0),  # capped
        ],
    )
    def test_retry_delay_exponential_and_capped(self, attempt, expected_floor, cap):
        delay = _push_retry_delay(attempt, base=1.0, cap=cap)
        assert expected_floor <= delay <= cap + 0.01
