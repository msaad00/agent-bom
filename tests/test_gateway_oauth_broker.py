"""Gateway runtime-broker integration tests.

Covers the broker capabilities wired into the gateway relay:
  * OAuth 2.1 AS endpoints mounted on the gateway app (metadata discovery).
  * AS-issued access tokens authenticating as the caller identity.
  * A2A inline mutual-auth enforcement (deny weak / unauthenticated edges).
  * Per-tool-call OAuth scope mapping (scope-denied tool call).
  * DLP redaction + block on tool arguments and results.
"""

from __future__ import annotations

import base64
import hashlib
import secrets
from typing import Any

from starlette.testclient import TestClient

from agent_bom.api.oauth_as import OAuthAuthorizationServer, OAuthSigningKey
from agent_bom.gateway_server import GatewaySettings, create_gateway_app
from agent_bom.gateway_upstreams import UpstreamConfig, UpstreamRegistry


def _registry() -> UpstreamRegistry:
    return UpstreamRegistry([UpstreamConfig(name="filesystem", url="http://fs.local:8100")])


def _echo_caller(result: dict[str, Any] | None = None):
    captured: dict[str, Any] = {}

    async def _caller(upstream: UpstreamConfig, message: dict[str, Any], extra_headers: dict[str, str]) -> dict[str, Any]:
        captured["message"] = message
        return {"jsonrpc": "2.0", "id": message.get("id"), "result": result if result is not None else {"ok": True}}

    return _caller, captured


def _tools_call(name: str, arguments: dict[str, Any], *, identity: str | None = None) -> dict[str, Any]:
    meta = {"agent_identity": identity} if identity else {}
    params: dict[str, Any] = {"name": name, "arguments": arguments}
    if meta:
        params["_meta"] = meta
    return {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": params}


def _server() -> OAuthAuthorizationServer:
    return OAuthAuthorizationServer(issuer="https://gw.example", signing_key=OAuthSigningKey())


def _issue_token(server: OAuthAuthorizationServer, *, scope: str = "", subject: str = "agent-x") -> str:
    reg = server.register_client(
        {
            "redirect_uris": ["https://app.example/cb"],
            "grant_types": ["authorization_code", "client_credentials"],
            "token_endpoint_auth_method": "client_secret_post",
            "scope": scope,
            "subject": subject,
        }
    )
    tokens = server.token(
        {
            "grant_type": "client_credentials",
            "client_id": reg["client_id"],
            "client_secret": reg["client_secret"],
            "scope": scope,
        }
    )
    return tokens["access_token"]


# ── AS mounted on the gateway ─────────────────────────────────────────────────


def test_gateway_mounts_oauth_as_metadata() -> None:
    settings = GatewaySettings(registry=_registry(), policy={}, oauth_as=_server())
    client = TestClient(create_gateway_app(settings))
    resp = client.get("/.well-known/oauth-authorization-server")
    assert resp.status_code == 200
    assert resp.json()["code_challenge_methods_supported"] == ["S256"]
    assert client.get("/oauth/jwks.json").json()["keys"]


def test_gateway_healthz_reports_broker_posture() -> None:
    settings = GatewaySettings(
        registry=_registry(),
        policy={},
        oauth_as=_server(),
        a2a_mutual_auth_enforcement_mode="enforce",
        tool_scope_map={"fs.read": ["tools:read"]},
        dlp_enabled=True,
        dlp_mode="enforce",
    )
    client = TestClient(create_gateway_app(settings))
    broker = client.get("/healthz").json()["broker_runtime"]
    assert broker == {
        "oauth_as_enabled": True,
        "oidc_discovery_shim_enabled": False,
        "a2a_mutual_auth_enforcement_mode": "enforce",
        "tool_scope_mapped_tools": 1,
        "dlp_enabled": True,
        "dlp_mode": "enforce",
    }


def test_as_token_authenticates_as_caller_identity() -> None:
    server = _server()
    token = _issue_token(server, scope="tools:read", subject="billing-agent")
    caller, captured = _echo_caller()
    settings = GatewaySettings(registry=_registry(), policy={}, oauth_as=server, upstream_caller=caller)
    client = TestClient(create_gateway_app(settings))
    # Standard MCP client presents the AS token in the Authorization header.
    resp = client.post(
        "/mcp/filesystem",
        json=_tools_call("fs.read", {"path": "/tmp/x"}),
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 200
    assert "error" not in resp.json()
    assert captured["message"]["params"]["name"] == "fs.read"


# ── A2A inline mutual-auth enforcement ────────────────────────────────────────


def test_a2a_enforce_denies_anonymous_edge() -> None:
    caller, _ = _echo_caller()
    settings = GatewaySettings(
        registry=_registry(),
        policy={},
        upstream_caller=caller,
        a2a_mutual_auth_enforcement_mode="enforce",
        # Loopback transport posture permits an anonymous caller; A2A mutual-auth
        # enforcement is independent and still rejects the unauthenticated edge.
        listener_host="127.0.0.1",
    )
    client = TestClient(create_gateway_app(settings))
    resp = client.post("/mcp/filesystem", json=_tools_call("fs.read", {"path": "/tmp/x"}))
    assert resp.status_code == 200
    body = resp.json()
    assert body["error"]["data"]["policy_source"] == "a2a_mutual_auth"


def test_a2a_enforce_allows_verified_as_token() -> None:
    server = _server()
    token = _issue_token(server, subject="verified-agent")
    caller, _ = _echo_caller()
    settings = GatewaySettings(
        registry=_registry(),
        policy={},
        oauth_as=server,
        upstream_caller=caller,
        a2a_mutual_auth_enforcement_mode="enforce",
        listener_host="127.0.0.1",
    )
    client = TestClient(create_gateway_app(settings))
    resp = client.post(
        "/mcp/filesystem",
        json=_tools_call("fs.read", {"path": "/tmp/x"}),
        headers={"Authorization": f"Bearer {token}"},
    )
    assert "error" not in resp.json()


def test_a2a_enforce_denies_unverified_opaque_token() -> None:
    # An opaque policy.agent_tokens identity authenticates but is NOT mutual auth.
    caller, _ = _echo_caller()
    settings = GatewaySettings(
        registry=_registry(),
        policy={"agent_tokens": {"opaque-shared": "agent-7"}},
        upstream_caller=caller,
        a2a_mutual_auth_enforcement_mode="enforce",
        listener_host="127.0.0.1",
    )
    client = TestClient(create_gateway_app(settings))
    resp = client.post("/mcp/filesystem", json=_tools_call("fs.read", {"path": "/x"}, identity="opaque-shared"))
    body = resp.json()
    assert body["error"]["data"]["policy_source"] == "a2a_mutual_auth"


# ── Per-tool-call OAuth scope mapping ─────────────────────────────────────────


def test_scope_mapped_tool_denied_without_scope() -> None:
    server = _server()
    token = _issue_token(server, scope="tools:read", subject="reader")
    caller, _ = _echo_caller()
    settings = GatewaySettings(
        registry=_registry(),
        policy={},
        oauth_as=server,
        upstream_caller=caller,
        tool_scope_map={"fs.write": ["tools:write"]},
    )
    client = TestClient(create_gateway_app(settings))
    resp = client.post(
        "/mcp/filesystem",
        json=_tools_call("fs.write", {"path": "/x", "data": "y"}),
        headers={"Authorization": f"Bearer {token}"},
    )
    body = resp.json()
    assert body["error"]["data"]["policy_source"] == "oauth_scope"


def test_scope_mapped_tool_allowed_with_scope() -> None:
    server = _server()
    token = _issue_token(server, scope="tools:read tools:write", subject="writer")
    caller, captured = _echo_caller()
    settings = GatewaySettings(
        registry=_registry(),
        policy={},
        oauth_as=server,
        upstream_caller=caller,
        tool_scope_map={"fs.write": ["tools:write"]},
    )
    client = TestClient(create_gateway_app(settings))
    resp = client.post(
        "/mcp/filesystem",
        json=_tools_call("fs.write", {"path": "/x", "data": "y"}),
        headers={"Authorization": f"Bearer {token}"},
    )
    assert "error" not in resp.json()
    assert captured["message"]["params"]["name"] == "fs.write"


# ── DLP ───────────────────────────────────────────────────────────────────────


def test_dlp_blocks_secret_in_arguments() -> None:
    caller, _ = _echo_caller()
    settings = GatewaySettings(
        registry=_registry(),
        policy={},
        upstream_caller=caller,
        dlp_enabled=True,
        dlp_mode="enforce",
        listener_host="127.0.0.1",
    )
    client = TestClient(create_gateway_app(settings))
    # AWS secret-access-key style value trips the secrets scanner.
    resp = client.post(
        "/mcp/filesystem",
        json=_tools_call("fs.write", {"body": "password=SuperSecretValue12345"}),
    )
    body = resp.json()
    assert body["error"]["data"]["policy_source"] == "dlp"


def test_dlp_redacts_pii_in_result() -> None:
    caller, _ = _echo_caller(result={"content": "reach me at jdoe@example.com please"})
    settings = GatewaySettings(
        registry=_registry(),
        policy={},
        upstream_caller=caller,
        dlp_enabled=True,
        dlp_mode="enforce",
        dlp_pii_action="redact",
        listener_host="127.0.0.1",
    )
    client = TestClient(create_gateway_app(settings))
    resp = client.post("/mcp/filesystem", json=_tools_call("fs.read", {"path": "/x"}))
    body = resp.json()
    assert "jdoe@example.com" not in body["result"]["content"]
    assert "[REDACTED:email]" in body["result"]["content"]


def test_dlp_audit_mode_does_not_block() -> None:
    caller, _ = _echo_caller()
    audits: list[dict[str, Any]] = []

    async def _sink(event: dict[str, Any]) -> None:
        audits.append(event)

    settings = GatewaySettings(
        registry=_registry(),
        policy={},
        upstream_caller=caller,
        audit_sink=_sink,
        dlp_enabled=True,
        dlp_mode="audit",
        listener_host="127.0.0.1",
    )
    client = TestClient(create_gateway_app(settings))
    resp = client.post(
        "/mcp/filesystem",
        json=_tools_call("fs.write", {"body": "password=SuperSecretValue12345"}),
    )
    assert "error" not in resp.json()
    assert any(e.get("action") == "gateway.dlp_arguments" for e in audits)


def _pkce_pair() -> tuple[str, str]:
    verifier = secrets.token_urlsafe(48)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    return verifier, challenge


def test_full_pkce_flow_then_relay_through_gateway() -> None:
    server = _server()
    caller, captured = _echo_caller()
    settings = GatewaySettings(
        registry=_registry(),
        policy={},
        oauth_as=server,
        upstream_caller=caller,
        tool_scope_map={"fs.read": ["tools:read"]},
    )
    client = TestClient(create_gateway_app(settings))
    reg = client.post(
        "/oauth/register",
        json={"redirect_uris": ["https://app.example/cb"], "scope": "tools:read"},
    ).json()
    verifier, challenge = _pkce_pair()
    authorize = client.get(
        "/oauth/authorize",
        params={
            "response_type": "code",
            "client_id": reg["client_id"],
            "redirect_uri": "https://app.example/cb",
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "scope": "tools:read",
        },
        follow_redirects=False,
    )
    code = authorize.headers["location"].split("code=")[1].split("&")[0]
    token = client.post(
        "/oauth/token",
        data={
            "grant_type": "authorization_code",
            "code": code,
            "client_id": reg["client_id"],
            "code_verifier": verifier,
        },
    ).json()["access_token"]
    resp = client.post(
        "/mcp/filesystem",
        json=_tools_call("fs.read", {"path": "/x"}),
        headers={"Authorization": f"Bearer {token}"},
    )
    assert "error" not in resp.json()
    assert captured["message"]["params"]["name"] == "fs.read"
