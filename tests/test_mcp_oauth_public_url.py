"""A 401 must point clients at a URL they can actually reach.

`AuthSettings` is advertised, not internal: an unauthenticated request answers
with `WWW-Authenticate: Bearer ... resource_metadata="<issuer>/.well-known/
oauth-protected-resource"`, and an OAuth client follows that URL to learn how to
authenticate.

It was derived from the socket the process binds. Behind any proxy that is
`http://0.0.0.0:8080` — an address no client can route to — so discovery hung
instead of failing fast. The hosted server reported `AUTH TIMED OUT` after five
minutes rather than a clean rejection, and the registry listing stayed frozen on
a months-old build.
"""

from __future__ import annotations

import pytest

from agent_bom.mcp_server_factory import _public_base_url

_ENV = "AGENT_BOM_MCP_PUBLIC_URL"


def test_bind_address_is_used_when_no_public_url_is_set(monkeypatch: pytest.MonkeyPatch) -> None:
    """Local runs are unchanged — there the bind address IS the public one."""
    monkeypatch.delenv(_ENV, raising=False)

    assert _public_base_url("127.0.0.1", 8000) == "http://127.0.0.1:8000"


def test_public_url_overrides_the_bind_address(monkeypatch: pytest.MonkeyPatch) -> None:
    """Behind a proxy the bind address is unroutable and must not be advertised."""
    monkeypatch.setenv(_ENV, "https://agent-bom-mcp.up.railway.app")

    assert _public_base_url("0.0.0.0", 8080) == "https://agent-bom-mcp.up.railway.app"


def test_trailing_slash_is_normalised(monkeypatch: pytest.MonkeyPatch) -> None:
    """`<issuer>/.well-known/...` must not become `<issuer>//.well-known/...`."""
    monkeypatch.setenv(_ENV, "https://agent-bom-mcp.up.railway.app/")

    assert _public_base_url("0.0.0.0", 8080) == "https://agent-bom-mcp.up.railway.app"


@pytest.mark.parametrize("value", ["", "   "])
def test_blank_env_falls_back_rather_than_advertising_nothing(monkeypatch: pytest.MonkeyPatch, value: str) -> None:
    """An unset-but-present variable must not produce an empty issuer.

    A blank issuer would advertise `/.well-known/oauth-protected-resource` with
    no host, which is worse than the bind address: it cannot even be diagnosed
    from the response.
    """
    monkeypatch.setenv(_ENV, value)

    assert _public_base_url("0.0.0.0", 8080) == "http://0.0.0.0:8080"


def test_auth_settings_carry_the_public_url(monkeypatch: pytest.MonkeyPatch) -> None:
    """End-to-end: the value reaches the settings a client is told to follow."""
    monkeypatch.setenv(_ENV, "https://mcp.example.test")

    server = __import__("agent_bom.mcp_server_factory", fromlist=["create_fastmcp_server"]).create_fastmcp_server(
        host="0.0.0.0",
        port=8080,
        bearer_token="test-token",
        version="0.0.0-test",
        token_verifier_factory=lambda token: object(),
    )

    settings = server.settings.auth
    assert settings is not None
    assert str(settings.resource_server_url).rstrip("/") == "https://mcp.example.test"
    assert str(settings.issuer_url).rstrip("/") == "https://mcp.example.test"
