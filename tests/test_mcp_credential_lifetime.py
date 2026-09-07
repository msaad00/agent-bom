"""Static MCP credentials have bounded absolute lifetimes, not renewable boot TTLs."""

import asyncio
from datetime import datetime, timedelta, timezone
from unittest.mock import Mock

import pytest
from click.testing import CliRunner

from agent_bom import mcp_server
from agent_bom.cli import main

NOW = datetime(2030, 1, 1, tzinfo=timezone.utc)


@pytest.fixture
def clock(monkeypatch):
    class Clock(datetime):
        current = NOW

        @classmethod
        def now(cls, tz=None):
            return cls.current.astimezone(tz) if tz else cls.current.replace(tzinfo=None)

    monkeypatch.setattr(mcp_server, "datetime", Clock)
    return Clock


def deadline(seconds=1800):
    return (NOW + timedelta(seconds=seconds)).isoformat()


@pytest.mark.parametrize(
    "value", [None, "", " ", "bad", "2030-01-01T00:30:00", deadline(-1), deadline(0), deadline(3601), "9999-12-31T23:59:59-12:00"]
)
@pytest.mark.parametrize("operator", [False, True])
def test_configured_credential_requires_bounded_deadline(clock, value, operator):
    kwargs = {"token_expires_at": deadline()}
    if operator:
        kwargs.update(operator_token="operator-fixture", operator_token_expires_at=value)
    else:
        kwargs["token_expires_at"] = value
    with pytest.raises(ValueError, match="AGENT_BOM_MCP_.*TOKEN_EXPIRES_AT"):
        mcp_server._StaticBearerTokenVerifier("read-fixture", **kwargs)


@pytest.mark.parametrize("value", [deadline(3600), "2030-01-01T00:30:00Z", "2029-12-31T19:30:00-05:00"])
def test_timezone_aware_bounded_deadlines_preserve_scopes(clock, value):
    verifier = mcp_server._StaticBearerTokenVerifier("read-fixture", token_expires_at=value)
    access = asyncio.run(verifier.verify_token("read-fixture"))
    assert access is not None and access.expires_at is not None
    assert access.scopes == ["read"]


def test_expiry_is_independent_and_does_not_extend_on_restart(clock, monkeypatch):
    kwargs = dict(token_expires_at=deadline(60), operator_token="operator-fixture", operator_token_expires_at=deadline(120))
    verifier = mcp_server._StaticBearerTokenVerifier("read-fixture", **kwargs)
    access = asyncio.run(verifier.verify_token("operator-fixture"))
    assert access is not None and "admin" in access.scopes
    clock.current = NOW + timedelta(seconds=60)
    monkeypatch.setenv("AGENT_BOM_MCP_BEARER_TOKEN_EXPIRES_AT", deadline(3600))
    assert asyncio.run(verifier.verify_token("read-fixture")) is None
    assert asyncio.run(verifier.verify_token("operator-fixture")) is not None
    with pytest.raises(ValueError):
        mcp_server._StaticBearerTokenVerifier("read-fixture", **kwargs)
    clock.current = NOW + timedelta(seconds=120)
    assert asyncio.run(verifier.verify_token("operator-fixture")) is None


@pytest.mark.parametrize("transport", ["sse", "streamable-http"])
def test_remote_cli_rejects_missing_expiry_before_startup(monkeypatch, transport):
    monkeypatch.delenv("AGENT_BOM_MCP_BEARER_TOKEN_EXPIRES_AT", raising=False)
    from mcp.server.fastmcp import FastMCP

    run = Mock()
    monkeypatch.setattr(FastMCP, "run", run)
    result = CliRunner().invoke(main, ["mcp", "server", "--transport", transport, "--bearer-token", "synthetic-private-value"])
    assert result.exit_code != 0
    assert "AGENT_BOM_MCP_BEARER_TOKEN_EXPIRES_AT" in result.output
    assert "synthetic-private-value" not in result.output
    run.assert_not_called()


def test_stdio_does_not_construct_http_auth_from_inherited_credentials(monkeypatch):
    monkeypatch.setenv("AGENT_BOM_MCP_BEARER_TOKEN", "synthetic-private-value")
    monkeypatch.setenv("AGENT_BOM_MCP_BEARER_TOKEN_EXPIRES_AT", "2020-01-01T00:00:00Z")
    server = Mock()
    create = Mock(return_value=server)
    monkeypatch.setattr(mcp_server, "create_mcp_server", create)
    result = CliRunner().invoke(main, ["mcp", "server"])
    assert result.exit_code == 0, result.output
    assert create.call_args.kwargs["bearer_token"] is None
    server.run.assert_called_once_with(transport="stdio")


def test_real_stdio_wire_ignores_expired_http_credentials(tmp_path):
    import os
    import sys
    from pathlib import Path

    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client

    async def probe():
        env = {
            **os.environ,
            "PYTHONPATH": str(Path(__file__).resolve().parents[1] / "src"),
            "AGENT_BOM_STATE_DIR": str(tmp_path),
            "AGENT_BOM_MCP_BEARER_TOKEN": "synthetic-stdio-unused",
            "AGENT_BOM_MCP_BEARER_TOKEN_EXPIRES_AT": "2020-01-01T00:00:00Z",
            "AGENT_BOM_MCP_OPERATOR_TOKEN": "synthetic-stdio-operator-unused",
            "AGENT_BOM_MCP_OPERATOR_TOKEN_EXPIRES_AT": "malformed",
        }
        params = StdioServerParameters(
            command=sys.executable, args=["-c", "from agent_bom.cli import main; main()", "mcp", "server"], env=env
        )
        async with stdio_client(params) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                assert len((await session.list_tools()).tools) == 8

    asyncio.run(probe())
