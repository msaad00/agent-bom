"""Tests for Official MCP Registry integration."""

import json
from unittest.mock import AsyncMock, MagicMock, patch

import httpx

from agent_bom.mcp_official_registry import (
    OfficialRegistrySearchResult,
    OfficialRegistryServer,
    official_registry_lookup_sync,
    search_official_registry_sync,
    sync_from_official_registry_sync,
)
from agent_bom.models import MCPServer, TransportType

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _mock_search_response(servers, count=None, next_cursor=None):
    return {
        "servers": [
            {"server": s, "_meta": {"status": "active"}}
            for s in servers
        ],
        "metadata": {
            "count": count or len(servers),
            "nextCursor": next_cursor,
        },
    }


def _mock_server(name="io.github.test/server", desc="A test server", version="1.0.0"):
    return {
        "name": name,
        "description": desc,
        "version": version,
        "repository": {"url": f"https://github.com/{name}"},
        "packages": [],
    }


def _make_response(data, status=200):
    resp = MagicMock(spec=httpx.Response)
    resp.status_code = status
    resp.json.return_value = data
    return resp


# ---------------------------------------------------------------------------
# search_official_registry
# ---------------------------------------------------------------------------


@patch("agent_bom.mcp_official_registry.request_with_retry")
@patch("agent_bom.mcp_official_registry.create_client")
def test_search_success(mock_client_factory, mock_request):
    """Successful search returns servers."""
    mock_client = AsyncMock()
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)
    mock_client_factory.return_value = mock_client

    servers = [_mock_server(), _mock_server("io.github.other/server", "Other Server", "2.0.0")]
    mock_request.return_value = _make_response(_mock_search_response(servers, count=2))

    result = search_official_registry_sync("test")
    assert result.error is None
    assert len(result.servers) == 2
    assert result.total_count == 2
    assert result.servers[0].qualified_name == "io.github.test/server"


@patch("agent_bom.mcp_official_registry.request_with_retry")
@patch("agent_bom.mcp_official_registry.create_client")
def test_search_empty(mock_client_factory, mock_request):
    """Search with no results returns empty list."""
    mock_client = AsyncMock()
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)
    mock_client_factory.return_value = mock_client

    mock_request.return_value = _make_response(_mock_search_response([], count=0))

    result = search_official_registry_sync("nonexistent-xyz")
    assert result.error is None
    assert len(result.servers) == 0
    assert result.total_count == 0


@patch("agent_bom.mcp_official_registry.request_with_retry")
@patch("agent_bom.mcp_official_registry.create_client")
def test_search_unreachable(mock_client_factory, mock_request):
    """None response returns unreachable error."""
    mock_client = AsyncMock()
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)
    mock_client_factory.return_value = mock_client

    mock_request.return_value = None

    result = search_official_registry_sync("test")
    assert result.error is not None
    assert "unreachable" in result.error


@patch("agent_bom.mcp_official_registry.request_with_retry")
@patch("agent_bom.mcp_official_registry.create_client")
def test_search_api_error(mock_client_factory, mock_request):
    """Non-200 response returns error."""
    mock_client = AsyncMock()
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)
    mock_client_factory.return_value = mock_client

    mock_request.return_value = _make_response({}, status=500)

    result = search_official_registry_sync("test")
    assert result.error is not None
    assert "500" in result.error


@patch("agent_bom.mcp_official_registry.request_with_retry")
@patch("agent_bom.mcp_official_registry.create_client")
def test_search_pagination(mock_client_factory, mock_request):
    """Search returns next_cursor for pagination."""
    mock_client = AsyncMock()
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)
    mock_client_factory.return_value = mock_client

    servers = [_mock_server()]
    mock_request.return_value = _make_response(
        _mock_search_response(servers, count=100, next_cursor="abc123")
    )

    result = search_official_registry_sync("test", limit=10)
    assert result.next_cursor == "abc123"
    assert result.total_count == 100


# ---------------------------------------------------------------------------
# official_registry_lookup
# ---------------------------------------------------------------------------


@patch("agent_bom.mcp_official_registry.search_official_registry")
def test_lookup_found(mock_search):
    """Lookup resolves a server from the registry."""
    mock_search.return_value = OfficialRegistrySearchResult(
        servers=[OfficialRegistryServer(
            qualified_name="io.github.test/filesystem",
            description="Filesystem server",
            version="1.2.0",
        )],
        total_count=1,
    )

    server = MCPServer(name="filesystem", command="npx", args=[], env={}, transport=TransportType.STDIO, packages=[])
    result = official_registry_lookup_sync(server)
    assert len(result) == 1
    assert result[0].name == "io.github.test/filesystem"
    assert result[0].ecosystem == "mcp-registry"
    assert result[0].resolved_from_registry is True


@patch("agent_bom.mcp_official_registry.search_official_registry")
def test_lookup_not_found(mock_search):
    """Lookup for nonexistent server returns empty."""
    mock_search.return_value = OfficialRegistrySearchResult(servers=[], total_count=0)

    server = MCPServer(name="nonexistent-xyz", command="npx", args=[], env={}, transport=TransportType.STDIO, packages=[])
    result = official_registry_lookup_sync(server)
    assert result == []


# ---------------------------------------------------------------------------
# sync_from_official_registry
# ---------------------------------------------------------------------------


@patch("agent_bom.mcp_official_registry.request_with_retry")
@patch("agent_bom.mcp_official_registry.create_client")
def test_sync_dry_run(mock_client_factory, mock_request, tmp_path):
    """Dry run adds nothing to registry file."""
    mock_client = AsyncMock()
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)
    mock_client_factory.return_value = mock_client

    servers = [_mock_server("new/server-1"), _mock_server("new/server-2")]
    mock_request.return_value = _make_response(
        _mock_search_response(servers, count=2)
    )

    reg_file = tmp_path / "mcp_registry.json"
    reg_file.write_text(json.dumps({"servers": {}}))

    with patch("agent_bom.mcp_official_registry._REGISTRY_PATH", reg_file):
        result = sync_from_official_registry_sync(max_pages=1, dry_run=True)
        assert result.added == 2
        assert result.total_fetched == 2

        data = json.loads(reg_file.read_text())
        assert len(data["servers"]) == 0


@patch("agent_bom.mcp_official_registry.request_with_retry")
@patch("agent_bom.mcp_official_registry.create_client")
def test_sync_adds_new(mock_client_factory, mock_request, tmp_path):
    """Sync adds new servers to registry."""
    mock_client = AsyncMock()
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)
    mock_client_factory.return_value = mock_client

    servers = [_mock_server("new/server")]
    mock_request.return_value = _make_response(
        _mock_search_response(servers, count=1)
    )

    reg_file = tmp_path / "mcp_registry.json"
    reg_file.write_text(json.dumps({"servers": {}}))

    with patch("agent_bom.mcp_official_registry._REGISTRY_PATH", reg_file):
        result = sync_from_official_registry_sync(max_pages=1, dry_run=False)
        assert result.added == 1

        data = json.loads(reg_file.read_text())
        assert "new/server" in data["servers"]


@patch("agent_bom.mcp_official_registry.request_with_retry")
@patch("agent_bom.mcp_official_registry.create_client")
def test_sync_skips_existing(mock_client_factory, mock_request, tmp_path):
    """Sync skips servers already in local registry."""
    mock_client = AsyncMock()
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)
    mock_client_factory.return_value = mock_client

    servers = [_mock_server("existing/server"), _mock_server("new/server")]
    mock_request.return_value = _make_response(
        _mock_search_response(servers, count=2)
    )

    reg_file = tmp_path / "mcp_registry.json"
    reg_file.write_text(json.dumps({
        "servers": {
            "existing/server": {"package": "existing/server", "ecosystem": "npm"},
        },
    }))

    with patch("agent_bom.mcp_official_registry._REGISTRY_PATH", reg_file):
        result = sync_from_official_registry_sync(max_pages=1, dry_run=False)
        assert result.added == 1
        assert result.skipped == 1


# ---------------------------------------------------------------------------
# CLI integration
# ---------------------------------------------------------------------------


def test_cli_scan_mcp_registry_flag():
    """CLI scan command should accept --mcp-registry flag."""
    from click.testing import CliRunner

    from agent_bom.cli import main

    runner = CliRunner()
    result = runner.invoke(main, ["scan", "--help"])
    assert result.exit_code == 0
    assert "--mcp-registry" in result.output


def test_cli_registry_mcp_sync_exists():
    """CLI should have 'registry mcp-sync' subcommand."""
    from click.testing import CliRunner

    from agent_bom.cli import main

    runner = CliRunner()
    result = runner.invoke(main, ["registry", "mcp-sync", "--help"])
    assert result.exit_code == 0
    assert "Official MCP Registry" in result.output
    assert "--dry-run" in result.output
