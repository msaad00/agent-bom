"""Tests for Glama.ai registry integration."""

import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from agent_bom.glama import (
    GlamaSearchResult,
    GlamaServer,
    GlamaSyncResult,
    _parse_server,
    search_glama,
    sync_from_glama,
)


class TestParseServer:
    def test_basic_parse(self):
        raw = {
            "id": "abc123",
            "name": "TestServer",
            "namespace": "owner",
            "slug": "test-server",
            "description": "A test MCP server",
            "repository": {"url": "https://github.com/owner/test-server"},
            "spdxLicense": {"name": "MIT License"},
            "tools": [{"name": "read"}, {"name": "write"}],
            "attributes": ["security"],
            "url": "https://glama.ai/mcp/servers/abc123",
        }
        s = _parse_server(raw)
        assert s.id == "abc123"
        assert s.name == "TestServer"
        assert s.namespace == "owner"
        assert s.slug == "test-server"
        assert s.repository_url == "https://github.com/owner/test-server"
        assert s.license == "MIT License"
        assert len(s.tools) == 2

    def test_minimal_parse(self):
        raw = {"id": "x", "name": "Minimal"}
        s = _parse_server(raw)
        assert s.id == "x"
        assert s.name == "Minimal"
        assert s.namespace == ""
        assert s.tools == []
        assert s.license == ""

    def test_null_fields(self):
        raw = {
            "id": "y",
            "name": "Nulls",
            "repository": None,
            "spdxLicense": None,
            "tools": None,
            "attributes": None,
        }
        s = _parse_server(raw)
        assert s.repository_url == ""
        assert s.license == ""
        assert s.tools == []
        assert s.attributes == []


class TestDataclasses:
    def test_glama_server_defaults(self):
        s = GlamaServer(id="1", name="Test")
        assert s.namespace == ""
        assert s.tools == []

    def test_glama_search_result_defaults(self):
        r = GlamaSearchResult()
        assert r.servers == []
        assert r.has_next_page is False

    def test_glama_sync_result_defaults(self):
        r = GlamaSyncResult()
        assert r.added == 0
        assert r.skipped == 0
        assert r.total_fetched == 0


@pytest.mark.asyncio
async def test_search_glama_api_failure():
    """Test search_glama handles API failure gracefully."""
    mock_resp = MagicMock()
    mock_resp.status_code = 500

    with patch("agent_bom.glama.create_client") as mock_client:
        mock_ctx = AsyncMock()
        mock_ctx.__aenter__ = AsyncMock(return_value=mock_ctx)
        mock_ctx.__aexit__ = AsyncMock(return_value=False)
        mock_client.return_value = mock_ctx

        with patch("agent_bom.glama.request_with_retry", return_value=mock_resp):
            result = await search_glama(query="test")
            assert result.total_fetched == 0
            assert result.servers == []


@pytest.mark.asyncio
async def test_search_glama_success():
    """Test search_glama parses response correctly."""
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "pageInfo": {"hasNextPage": True, "endCursor": "abc"},
        "servers": [
            {
                "id": "s1",
                "name": "Server1",
                "namespace": "ns",
                "slug": "server1",
                "description": "Test",
                "repository": {"url": "https://github.com/ns/server1"},
                "spdxLicense": {"name": "Apache-2.0"},
                "tools": [{"name": "scan"}],
                "attributes": [],
                "url": "https://glama.ai/mcp/servers/s1",
            }
        ],
    }

    with patch("agent_bom.glama.create_client") as mock_client:
        mock_ctx = AsyncMock()
        mock_ctx.__aenter__ = AsyncMock(return_value=mock_ctx)
        mock_ctx.__aexit__ = AsyncMock(return_value=False)
        mock_client.return_value = mock_ctx

        with patch("agent_bom.glama.request_with_retry", return_value=mock_resp):
            result = await search_glama(query="server1", limit=5)
            assert result.total_fetched == 1
            assert result.has_next_page is True
            assert result.end_cursor == "abc"
            assert result.servers[0].name == "Server1"


@pytest.mark.asyncio
async def test_sync_from_glama_empty_registry():
    """Test sync_from_glama with empty local registry."""
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "pageInfo": {"hasNextPage": False},
        "servers": [
            {
                "id": "s1",
                "name": "NewServer",
                "namespace": "org",
                "slug": "new-server",
                "description": "Brand new",
                "repository": {"url": "https://github.com/org/new-server"},
                "spdxLicense": {"name": "MIT"},
                "tools": [],
                "attributes": [],
                "url": "https://glama.ai/mcp/servers/s1",
            }
        ],
    }

    with (
        patch("agent_bom.glama._REGISTRY_PATH") as mock_path,
        patch("agent_bom.glama.create_client") as mock_client,
        patch("agent_bom.glama.request_with_retry", return_value=mock_resp),
    ):
        mock_path.read_text.return_value = json.dumps({"servers": {}})
        mock_path.write_text = MagicMock()

        mock_ctx = AsyncMock()
        mock_ctx.__aenter__ = AsyncMock(return_value=mock_ctx)
        mock_ctx.__aexit__ = AsyncMock(return_value=False)
        mock_client.return_value = mock_ctx

        result = await sync_from_glama(max_pages=1, dry_run=True)
        assert result.added == 1
        assert result.total_fetched == 1
        assert result.details[0]["server"] == "org/new-server"


@pytest.mark.asyncio
async def test_sync_from_glama_skips_existing():
    """Test sync_from_glama skips servers already in registry."""
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "pageInfo": {"hasNextPage": False},
        "servers": [
            {
                "id": "s1",
                "name": "ExistingServer",
                "namespace": "org",
                "slug": "existing",
                "description": "Already known",
                "repository": {},
                "tools": [],
                "attributes": [],
                "url": "",
            }
        ],
    }

    with (
        patch("agent_bom.glama._REGISTRY_PATH") as mock_path,
        patch("agent_bom.glama.create_client") as mock_client,
        patch("agent_bom.glama.request_with_retry", return_value=mock_resp),
    ):
        mock_path.read_text.return_value = json.dumps({"servers": {"org/existing": {"package": "org/existing", "ecosystem": "npm"}}})

        mock_ctx = AsyncMock()
        mock_ctx.__aenter__ = AsyncMock(return_value=mock_ctx)
        mock_ctx.__aexit__ = AsyncMock(return_value=False)
        mock_client.return_value = mock_ctx

        result = await sync_from_glama(max_pages=1, dry_run=True)
        assert result.added == 0
        assert result.skipped == 1
