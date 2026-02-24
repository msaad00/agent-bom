"""Tests for registry expansion and Official MCP Registry sync with auto-classification."""

import json
from unittest.mock import AsyncMock, MagicMock, patch

import httpx

from agent_bom.mcp_official_registry import (
    sync_from_official_registry_sync,
)


def _make_response(data, status=200):
    resp = MagicMock(spec=httpx.Response)
    resp.status_code = status
    resp.json.return_value = data
    return resp


def _mock_server_entry(name, desc="", version="1.0.0", tools=None, creds=None):
    return {
        "server": {
            "name": name,
            "description": desc,
            "version": version,
            "repository": {"url": f"https://github.com/{name}"},
            "packages": [],
            "tools": tools or [],
            "credential_env_vars": creds or [],
        },
        "_meta": {"status": "active"},
    }


class TestSyncAutoClassification:
    """Verify that sync_from_official_registry uses classify_risk_level and _infer_category."""

    @patch("agent_bom.mcp_official_registry.request_with_retry")
    @patch("agent_bom.mcp_official_registry.create_client")
    @patch("agent_bom.mcp_official_registry._REGISTRY_PATH")
    def test_new_entries_get_auto_enriched_flag(self, mock_path, mock_client, mock_request):
        """Auto-enriched entries should have auto_enriched=True."""
        mock_path.read_text.return_value = json.dumps({"servers": {}})
        mock_path.write_text = MagicMock()

        mock_client.return_value.__aenter__ = AsyncMock()
        mock_client.return_value.__aexit__ = AsyncMock()

        api_response = {
            "servers": [_mock_server_entry("test/new-server", "A test server")],
            "metadata": {"count": 1, "nextCursor": None},
        }
        mock_request.return_value = _make_response(api_response)

        result = sync_from_official_registry_sync(max_pages=1, page_size=10)

        assert result.added == 1
        assert result.total_fetched == 1

        # Check written data
        written = json.loads(mock_path.write_text.call_args[0][0])
        entry = written["servers"]["test/new-server"]
        assert entry["auto_enriched"] is True
        assert entry["verified"] is True

    @patch("agent_bom.mcp_official_registry.request_with_retry")
    @patch("agent_bom.mcp_official_registry.create_client")
    @patch("agent_bom.mcp_official_registry._REGISTRY_PATH")
    def test_risk_level_classification(self, mock_path, mock_client, mock_request):
        """Entries with dangerous tools + creds should get high risk."""
        mock_path.read_text.return_value = json.dumps({"servers": {}})
        mock_path.write_text = MagicMock()

        mock_client.return_value.__aenter__ = AsyncMock()
        mock_client.return_value.__aexit__ = AsyncMock()

        api_response = {
            "servers": [
                _mock_server_entry(
                    "test/dangerous-server",
                    "File management",
                    tools=["delete_file", "exec_command"],
                    creds=["API_KEY"],
                ),
            ],
            "metadata": {"count": 1, "nextCursor": None},
        }
        mock_request.return_value = _make_response(api_response)

        result = sync_from_official_registry_sync(max_pages=1, page_size=10)

        written = json.loads(mock_path.write_text.call_args[0][0])
        entry = written["servers"]["test/dangerous-server"]
        assert entry["risk_level"] == "high"

    @patch("agent_bom.mcp_official_registry.request_with_retry")
    @patch("agent_bom.mcp_official_registry.create_client")
    @patch("agent_bom.mcp_official_registry._REGISTRY_PATH")
    def test_category_inference(self, mock_path, mock_client, mock_request):
        """Category should be inferred from name/description."""
        mock_path.read_text.return_value = json.dumps({"servers": {}})
        mock_path.write_text = MagicMock()

        mock_client.return_value.__aenter__ = AsyncMock()
        mock_client.return_value.__aexit__ = AsyncMock()

        api_response = {
            "servers": [
                _mock_server_entry("github-actions", "GitHub CI/CD integration"),
                _mock_server_entry("postgres-query", "PostgreSQL database tools"),
            ],
            "metadata": {"count": 2, "nextCursor": None},
        }
        mock_request.return_value = _make_response(api_response)

        result = sync_from_official_registry_sync(max_pages=1, page_size=10)

        written = json.loads(mock_path.write_text.call_args[0][0])
        assert written["servers"]["github-actions"]["category"] == "developer-tools"
        assert written["servers"]["postgres-query"]["category"] == "database"

    @patch("agent_bom.mcp_official_registry.request_with_retry")
    @patch("agent_bom.mcp_official_registry.create_client")
    @patch("agent_bom.mcp_official_registry._REGISTRY_PATH")
    def test_skip_existing_entries(self, mock_path, mock_client, mock_request):
        """Existing entries should be skipped."""
        existing = {"servers": {"existing/server": {"package": "existing/server"}}}
        mock_path.read_text.return_value = json.dumps(existing)
        mock_path.write_text = MagicMock()

        mock_client.return_value.__aenter__ = AsyncMock()
        mock_client.return_value.__aexit__ = AsyncMock()

        api_response = {
            "servers": [_mock_server_entry("existing/server", "Already here")],
            "metadata": {"count": 1, "nextCursor": None},
        }
        mock_request.return_value = _make_response(api_response)

        result = sync_from_official_registry_sync(max_pages=1, page_size=10)

        assert result.added == 0
        assert result.skipped == 1
        mock_path.write_text.assert_not_called()

    @patch("agent_bom.mcp_official_registry.request_with_retry")
    @patch("agent_bom.mcp_official_registry.create_client")
    @patch("agent_bom.mcp_official_registry._REGISTRY_PATH")
    def test_dry_run_no_write(self, mock_path, mock_client, mock_request):
        """Dry run should not write to registry."""
        mock_path.read_text.return_value = json.dumps({"servers": {}})
        mock_path.write_text = MagicMock()

        mock_client.return_value.__aenter__ = AsyncMock()
        mock_client.return_value.__aexit__ = AsyncMock()

        api_response = {
            "servers": [_mock_server_entry("test/new-server")],
            "metadata": {"count": 1, "nextCursor": None},
        }
        mock_request.return_value = _make_response(api_response)

        result = sync_from_official_registry_sync(max_pages=1, page_size=10, dry_run=True)

        assert result.added == 1
        mock_path.write_text.assert_not_called()

    @patch("agent_bom.mcp_official_registry.request_with_retry")
    @patch("agent_bom.mcp_official_registry.create_client")
    @patch("agent_bom.mcp_official_registry._REGISTRY_PATH")
    def test_low_risk_read_only_no_creds(self, mock_path, mock_client, mock_request):
        """Read-only tools with no creds should be low risk."""
        mock_path.read_text.return_value = json.dumps({"servers": {}})
        mock_path.write_text = MagicMock()

        mock_client.return_value.__aenter__ = AsyncMock()
        mock_client.return_value.__aexit__ = AsyncMock()

        api_response = {
            "servers": [
                _mock_server_entry("test/reader", "Read data", tools=["get_data", "list_items"]),
            ],
            "metadata": {"count": 1, "nextCursor": None},
        }
        mock_request.return_value = _make_response(api_response)

        result = sync_from_official_registry_sync(max_pages=1, page_size=10)

        written = json.loads(mock_path.write_text.call_args[0][0])
        assert written["servers"]["test/reader"]["risk_level"] == "low"

    @patch("agent_bom.mcp_official_registry.request_with_retry")
    @patch("agent_bom.mcp_official_registry.create_client")
    @patch("agent_bom.mcp_official_registry._REGISTRY_PATH")
    def test_pagination(self, mock_path, mock_client, mock_request):
        """Pagination via nextCursor should fetch multiple pages."""
        mock_path.read_text.return_value = json.dumps({"servers": {}})
        mock_path.write_text = MagicMock()

        mock_client.return_value.__aenter__ = AsyncMock()
        mock_client.return_value.__aexit__ = AsyncMock()

        page1 = {
            "servers": [_mock_server_entry("server/one")],
            "metadata": {"count": 2, "nextCursor": "cursor_abc"},
        }
        page2 = {
            "servers": [_mock_server_entry("server/two")],
            "metadata": {"count": 2, "nextCursor": None},
        }
        mock_request.side_effect = [_make_response(page1), _make_response(page2)]

        result = sync_from_official_registry_sync(max_pages=5, page_size=1)

        assert result.added == 2
        assert result.total_fetched == 2

    @patch("agent_bom.mcp_official_registry.request_with_retry")
    @patch("agent_bom.mcp_official_registry.create_client")
    @patch("agent_bom.mcp_official_registry._REGISTRY_PATH")
    def test_api_failure_graceful(self, mock_path, mock_client, mock_request):
        """API returning None should stop gracefully."""
        mock_path.read_text.return_value = json.dumps({"servers": {}})

        mock_client.return_value.__aenter__ = AsyncMock()
        mock_client.return_value.__aexit__ = AsyncMock()

        mock_request.return_value = None

        result = sync_from_official_registry_sync(max_pages=1, page_size=10)

        assert result.added == 0
        assert result.total_fetched == 0
