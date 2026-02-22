"""Tests for Smithery.ai registry integration."""

import json
from unittest.mock import AsyncMock, MagicMock, patch

import httpx

from agent_bom.models import MCPServer, TransportType
from agent_bom.smithery import (
    SmitherySearchResult,
    SmitheryServer,
    search_smithery_sync,
    smithery_lookup_sync,
    sync_from_smithery_sync,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _mock_search_response(servers, total_count=None, page=1, total_pages=1):
    """Create a mock Smithery search API response."""
    return {
        "servers": servers,
        "pagination": {
            "currentPage": page,
            "pageSize": 50,
            "totalPages": total_pages,
            "totalCount": total_count or len(servers),
        },
    }


def _mock_server_entry(
    qn="exa/exa-search",
    display="Exa Search",
    verified=True,
    use_count=5000,
    remote=True,
):
    return {
        "qualifiedName": qn,
        "displayName": display,
        "description": "A test MCP server",
        "verified": verified,
        "useCount": use_count,
        "remote": remote,
        "isDeployed": remote,
        "homepage": f"https://smithery.ai/server/{qn}",
    }


def _make_response(data, status=200):
    """Create a mock httpx.Response."""
    resp = MagicMock(spec=httpx.Response)
    resp.status_code = status
    resp.json.return_value = data
    return resp


# ---------------------------------------------------------------------------
# search_smithery
# ---------------------------------------------------------------------------


def test_search_no_api_key():
    """Search without API key returns error."""
    with patch.dict("os.environ", {}, clear=True):
        with patch("agent_bom.smithery._get_token", return_value=None):
            result = search_smithery_sync("test")
            assert result.error is not None
            assert "API key" in result.error


@patch("agent_bom.smithery.request_with_retry")
@patch("agent_bom.smithery.create_client")
def test_search_success(mock_client_factory, mock_request):
    """Successful search returns servers."""
    mock_client = AsyncMock()
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)
    mock_client_factory.return_value = mock_client

    servers = [_mock_server_entry(), _mock_server_entry("brave/brave-search", "Brave Search")]
    mock_request.return_value = _make_response(_mock_search_response(servers, total_count=2))

    with patch("agent_bom.smithery._get_token", return_value="test-key"):
        result = search_smithery_sync("search")
        assert result.error is None
        assert len(result.servers) == 2
        assert result.total_count == 2
        assert result.servers[0].display_name == "Exa Search"
        assert result.servers[0].verified is True


@patch("agent_bom.smithery.request_with_retry")
@patch("agent_bom.smithery.create_client")
def test_search_unauthorized(mock_client_factory, mock_request):
    """401 response returns auth error."""
    mock_client = AsyncMock()
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)
    mock_client_factory.return_value = mock_client

    mock_request.return_value = _make_response({}, status=401)

    with patch("agent_bom.smithery._get_token", return_value="bad-key"):
        result = search_smithery_sync("test")
        assert result.error is not None
        assert "Invalid" in result.error


@patch("agent_bom.smithery.request_with_retry")
@patch("agent_bom.smithery.create_client")
def test_search_api_unreachable(mock_client_factory, mock_request):
    """None response returns unreachable error."""
    mock_client = AsyncMock()
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)
    mock_client_factory.return_value = mock_client

    mock_request.return_value = None

    with patch("agent_bom.smithery._get_token", return_value="test-key"):
        result = search_smithery_sync("test")
        assert result.error is not None
        assert "unreachable" in result.error


# ---------------------------------------------------------------------------
# smithery_lookup (registry fallback)
# ---------------------------------------------------------------------------


@patch("agent_bom.smithery.search_smithery")
def test_lookup_no_token(mock_search):
    """Lookup without token returns empty."""
    with patch("agent_bom.smithery._get_token", return_value=None):
        server = MCPServer(name="test-server", command="npx", args=[], env={}, transport=TransportType.STDIO, packages=[])
        result = smithery_lookup_sync(server)
        assert result == []
        mock_search.assert_not_called()


@patch("agent_bom.smithery.search_smithery")
def test_lookup_found(mock_search):
    """Lookup resolves a server from Smithery."""
    mock_search.return_value = SmitherySearchResult(
        servers=[SmitheryServer(
            qualified_name="exa/exa-search",
            display_name="Exa Search",
            verified=True,
            use_count=5000,
            remote=True,
        )],
        total_count=1,
    )

    with patch("agent_bom.smithery._get_token", return_value="test-key"):
        server = MCPServer(name="exa-search", command="npx", args=[], env={}, transport=TransportType.STDIO, packages=[])
        result = smithery_lookup_sync(server, token="test-key")
        assert len(result) == 1
        assert result[0].name == "exa/exa-search"
        assert result[0].ecosystem == "smithery"
        assert result[0].resolved_from_registry is True


@patch("agent_bom.smithery.search_smithery")
def test_lookup_unverified_risk(mock_search):
    """Unverified server gets high risk level."""
    mock_search.return_value = SmitherySearchResult(
        servers=[SmitheryServer(
            qualified_name="unknown/risky-server",
            display_name="Risky Server",
            verified=False,
            use_count=10,
        )],
        total_count=1,
    )

    with patch("agent_bom.smithery._get_token", return_value="test-key"):
        server = MCPServer(name="risky-server", command="npx", args=[], env={}, transport=TransportType.STDIO, packages=[])
        result = smithery_lookup_sync(server, token="test-key")
        assert len(result) == 1
        assert result[0].auto_risk_level == "high"


@patch("agent_bom.smithery.search_smithery")
def test_lookup_popular_verified_low_risk(mock_search):
    """Popular verified server gets low risk level."""
    mock_search.return_value = SmitherySearchResult(
        servers=[SmitheryServer(
            qualified_name="official/safe-server",
            display_name="Safe Server",
            verified=True,
            use_count=5000,
        )],
        total_count=1,
    )

    with patch("agent_bom.smithery._get_token", return_value="test-key"):
        server = MCPServer(name="safe-server", command="npx", args=[], env={}, transport=TransportType.STDIO, packages=[])
        result = smithery_lookup_sync(server, token="test-key")
        assert len(result) == 1
        assert result[0].auto_risk_level == "low"


@patch("agent_bom.smithery.search_smithery")
def test_lookup_not_found(mock_search):
    """Lookup for nonexistent server returns empty."""
    mock_search.return_value = SmitherySearchResult(servers=[], total_count=0)

    with patch("agent_bom.smithery._get_token", return_value="test-key"):
        server = MCPServer(name="nonexistent-xyz", command="npx", args=[], env={}, transport=TransportType.STDIO, packages=[])
        result = smithery_lookup_sync(server, token="test-key")
        assert result == []


# ---------------------------------------------------------------------------
# sync_from_smithery
# ---------------------------------------------------------------------------


@patch("agent_bom.smithery.request_with_retry")
@patch("agent_bom.smithery.create_client")
def test_sync_dry_run(mock_client_factory, mock_request, tmp_path):
    """Dry run sync adds nothing to registry file."""
    mock_client = AsyncMock()
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)
    mock_client_factory.return_value = mock_client

    servers = [
        _mock_server_entry("new/server-1", "New Server 1"),
        _mock_server_entry("new/server-2", "New Server 2"),
    ]
    mock_request.return_value = _make_response(
        _mock_search_response(servers, total_count=2, total_pages=1)
    )

    # Use a temp registry file
    reg_file = tmp_path / "mcp_registry.json"
    reg_file.write_text(json.dumps({"servers": {}}))

    with (
        patch("agent_bom.smithery._get_token", return_value="test-key"),
        patch("agent_bom.smithery._REGISTRY_PATH", reg_file),
    ):
        result = sync_from_smithery_sync(token="test-key", max_pages=1, dry_run=True)
        assert result.added == 2
        assert result.total_fetched == 2

        # File should be unchanged (dry run)
        data = json.loads(reg_file.read_text())
        assert len(data["servers"]) == 0


@patch("agent_bom.smithery.request_with_retry")
@patch("agent_bom.smithery.create_client")
def test_sync_skips_existing(mock_client_factory, mock_request, tmp_path):
    """Sync skips servers already in local registry."""
    mock_client = AsyncMock()
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)
    mock_client_factory.return_value = mock_client

    servers = [
        _mock_server_entry("existing/server", "Existing Server"),
        _mock_server_entry("new/server", "New Server"),
    ]
    mock_request.return_value = _make_response(
        _mock_search_response(servers, total_count=2, total_pages=1)
    )

    reg_file = tmp_path / "mcp_registry.json"
    reg_file.write_text(json.dumps({
        "servers": {
            "existing/server": {"package": "existing/server", "ecosystem": "npm"},
        },
    }))

    with (
        patch("agent_bom.smithery._get_token", return_value="test-key"),
        patch("agent_bom.smithery._REGISTRY_PATH", reg_file),
    ):
        result = sync_from_smithery_sync(token="test-key", max_pages=1, dry_run=False)
        assert result.added == 1
        assert result.skipped == 1


def test_sync_no_token():
    """Sync without token returns empty result."""
    with patch("agent_bom.smithery._get_token", return_value=None):
        result = sync_from_smithery_sync(token=None)
        assert result.added == 0
        assert result.total_fetched == 0


# ---------------------------------------------------------------------------
# CLI integration
# ---------------------------------------------------------------------------


def test_cli_scan_smithery_flags():
    """CLI scan command should accept --smithery and --smithery-token flags."""
    from click.testing import CliRunner

    from agent_bom.cli import main

    runner = CliRunner()
    result = runner.invoke(main, ["scan", "--help"])
    assert result.exit_code == 0
    assert "--smithery" in result.output
    assert "--smithery-token" in result.output


def test_cli_registry_smithery_sync_exists():
    """CLI should have 'registry smithery-sync' subcommand."""
    from click.testing import CliRunner

    from agent_bom.cli import main

    runner = CliRunner()
    result = runner.invoke(main, ["registry", "smithery-sync", "--help"])
    assert result.exit_code == 0
    assert "Smithery" in result.output
    assert "--token" in result.output
    assert "--dry-run" in result.output


def test_cli_registry_smithery_sync_no_key():
    """smithery-sync without API key should fail with helpful error."""
    from click.testing import CliRunner

    from agent_bom.cli import main

    runner = CliRunner()
    with patch.dict("os.environ", {}, clear=False):
        # Remove SMITHERY_API_KEY if set
        import os
        env = dict(os.environ)
        env.pop("SMITHERY_API_KEY", None)
        result = runner.invoke(main, ["registry", "smithery-sync"], env=env)
        assert result.exit_code != 0
