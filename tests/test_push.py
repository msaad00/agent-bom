"""Tests for hybrid push-to-dashboard."""

from unittest.mock import AsyncMock, patch

from agent_bom.push import (
    _looks_like_secret,
    generate_source_id,
    push_results,
    sanitize_results,
)

# ─── generate_source_id ──────────────────────────────────────────────────────


class TestGenerateSourceId:
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

    def test_adds_source_id(self):
        results = {"agents": []}
        sanitized = sanitize_results(results)
        assert "source_id" in sanitized
        assert len(sanitized["source_id"]) == 12

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

        with patch("agent_bom.http_client.create_client", return_value=mock_client):
            result = push_results("https://dashboard.example.com/v1/results/push", {"agents": []})
        assert result is True

    def test_push_failure(self):
        mock_resp = AsyncMock()
        mock_resp.status_code = 500
        mock_resp.text = "Internal server error"

        mock_client = AsyncMock()
        mock_client.post = AsyncMock(return_value=mock_resp)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("agent_bom.http_client.create_client", return_value=mock_client):
            result = push_results("https://dashboard.example.com/v1/results/push", {"agents": []})
        assert result is False

    def test_push_with_api_key(self):
        mock_resp = AsyncMock()
        mock_resp.status_code = 200

        mock_client = AsyncMock()
        mock_client.post = AsyncMock(return_value=mock_resp)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("agent_bom.http_client.create_client", return_value=mock_client):
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
        mock_client = AsyncMock()
        mock_client.post = AsyncMock(side_effect=Exception("Connection refused"))
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("agent_bom.http_client.create_client", return_value=mock_client):
            result = push_results("https://unreachable.example.com/push", {"agents": []})
        assert result is False
