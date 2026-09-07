"""Gateway issuer rejection, bearer relay, A2A denial, and DLP contracts."""

from __future__ import annotations

from typing import Any

import pytest
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


# ── AS mounted on the gateway ─────────────────────────────────────────────────


def test_gateway_healthz_reports_broker_posture() -> None:
    settings = GatewaySettings(
        registry=_registry(),
        policy={},
        a2a_mutual_auth_enforcement_mode="enforce",
        tool_scope_map={"fs.read": ["tools:read"]},
        dlp_enabled=True,
        dlp_mode="enforce",
    )
    client = TestClient(create_gateway_app(settings))
    broker = client.get("/healthz").json()["broker_runtime"]
    assert broker == {
        "oauth_as_enabled": False,
        "oidc_discovery_shim_enabled": False,
        "a2a_mutual_auth_enforcement_mode": "enforce",
        "tool_scope_mapped_tools": 1,
        "dlp_enabled": True,
        "dlp_mode": "enforce",
    }


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


# Modern token formats that must be blocked end-to-end through the relay.
def _sample(*parts: str) -> str:
    return "".join(parts)


def _token_body(length: int, alphabet: str = "Ab3dEf4gH5jK") -> str:
    return (alphabet * ((length // len(alphabet)) + 1))[:length]


def _jwt_sample() -> str:
    return _sample("eyJ", _token_body(18), ".", _token_body(14), ".", _token_body(20))


_MODERN_SECRET_SAMPLES = [
    ("openai_project_key", _sample("sk-", "proj-", _token_body(50))),
    ("anthropic_api_key", _sample("sk-", "ant-", "api03-", _token_body(36))),
    ("github_fine_grained_pat", _sample("github_", "pat_", _token_body(24, "Ab3dEf4gH5_jK"))),
    ("jwt", _jwt_sample()),
    ("bearer_opaque", _sample("Authorization: ", "Bearer ", _token_body(24))),
    ("aws_secret_access_key", _sample("aws_", "secret_", "access_", "key=", _token_body(40, "Ab3dEf4gH5jK/Lm7N"))),
]


@pytest.mark.parametrize("case_id,sample", _MODERN_SECRET_SAMPLES, ids=[c[0] for c in _MODERN_SECRET_SAMPLES])
def test_dlp_blocks_modern_secret_in_arguments(case_id: str, sample: str) -> None:
    caller, captured = _echo_caller()
    settings = GatewaySettings(
        registry=_registry(),
        policy={},
        upstream_caller=caller,
        dlp_enabled=True,
        dlp_mode="enforce",
        listener_host="127.0.0.1",
    )
    client = TestClient(create_gateway_app(settings))
    resp = client.post("/mcp/filesystem", json=_tools_call("fs.write", {"body": sample}))
    body = resp.json()
    assert body["error"]["data"]["policy_source"] == "dlp", case_id
    # Blocked before reaching upstream — secret never forwarded in cleartext.
    assert "message" not in captured, f"{case_id} secret forwarded upstream"


@pytest.mark.parametrize("case_id,sample", _MODERN_SECRET_SAMPLES, ids=[c[0] for c in _MODERN_SECRET_SAMPLES])
def test_dlp_blocks_modern_secret_in_result(case_id: str, sample: str) -> None:
    caller, _ = _echo_caller(result={"content": f"leaked value {sample}"})
    settings = GatewaySettings(
        registry=_registry(),
        policy={},
        upstream_caller=caller,
        dlp_enabled=True,
        dlp_mode="enforce",
        listener_host="127.0.0.1",
    )
    client = TestClient(create_gateway_app(settings))
    resp = client.post("/mcp/filesystem", json=_tools_call("fs.read", {"path": "/x"}))
    body = resp.json()
    # Response carrying the secret is blocked, not echoed verbatim to the client.
    assert body.get("error", {}).get("data", {}).get("policy_source") == "dlp", case_id
    assert sample not in resp.text, f"{case_id} secret echoed to client"


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


def test_gateway_durably_admits_after_argument_redaction_and_before_result_redaction() -> None:
    caller, captured = _echo_caller(result={"content": "owner@example.com"})
    audits: list[dict[str, Any]] = []

    async def _sink(event: dict[str, Any]) -> None:
        audits.append(event)

    settings = GatewaySettings(
        registry=_registry(),
        policy={},
        upstream_caller=caller,
        audit_sink=_sink,
        dlp_enabled=True,
        dlp_mode="enforce",
        dlp_pii_action="redact",
        listener_host="127.0.0.1",
    )
    response = TestClient(create_gateway_app(settings)).post(
        "/mcp/filesystem",
        json=_tools_call("fs.lookup", {"email": "requester@example.com"}),
    )

    assert response.status_code == 200
    assert "requester@example.com" not in repr(captured["message"])
    assert "owner@example.com" not in response.text
    typed = [event for event in audits if event.get("event_type")]
    assert [event["event_type"] for event in typed] == [
        "gateway.dlp.arguments_redacted",
        "gateway.tool_call.allowed",
        "gateway.dlp.result_redacted",
    ]
    assert all(event["decision"] == "allow" for event in typed)
    assert all(event["tenant_id"] == "default" for event in typed)
    assert all(event["agent_id"] == "anonymous" for event in typed)
    assert all(event["profile_id"] == "" for event in typed)
    assert all(event["upstream"] == "filesystem" for event in typed)
    assert all(event["tool"] == "fs.lookup" for event in typed)
    assert [event["policy_source"] for event in typed] == ["dlp", "file", "dlp"]
    assert [event.get("data_action", "") for event in typed] == ["pii_redacted", "", "pii_redacted"]


def test_gateway_emits_typed_sensitive_result_block_without_secret() -> None:
    secret = "password=SuperSecretValue12345"
    caller, _ = _echo_caller(result={"content": secret})
    audits: list[dict[str, Any]] = []

    async def _sink(event: dict[str, Any]) -> None:
        audits.append(event)

    settings = GatewaySettings(
        registry=_registry(),
        policy={},
        upstream_caller=caller,
        audit_sink=_sink,
        dlp_enabled=True,
        dlp_mode="enforce",
        listener_host="127.0.0.1",
    )
    response = TestClient(create_gateway_app(settings)).post(
        "/mcp/filesystem",
        json=_tools_call("fs.read", {"path": "/safe"}),
    )

    assert response.json()["error"]["data"]["policy_source"] == "dlp"
    blocked = [event for event in audits if event.get("event_type") == "gateway.dlp.result_blocked"]
    assert len(blocked) == 1
    assert blocked[0]["decision"] == "deny"
    assert blocked[0]["upstream"] == "filesystem"
    assert blocked[0]["tool"] == "fs.read"
    assert blocked[0]["data_action"] == "sensitive_result_blocked"
    assert secret not in repr(blocked[0])


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


def test_gateway_refuses_embedded_issuer_before_opening_routes() -> None:
    settings = GatewaySettings(registry=_registry(), policy={}, oauth_as=_server())
    with pytest.raises(ValueError, match="trusted client authorization"):
        create_gateway_app(settings)


def test_gateway_bearer_relay_still_works_without_issuer(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("AGENT_BOM_STATE_DIR", str(tmp_path))
    caller, captured = _echo_caller()
    settings = GatewaySettings(registry=_registry(), policy={}, bearer_token="configured-token", upstream_caller=caller)
    client = TestClient(create_gateway_app(settings))
    for path in ("/oauth/register", "/oauth/token"):
        assert client.post(path, json={}).status_code == 404
    assert client.get("/oauth/authorize").status_code == 404
    message = _tools_call("fs.read", {})
    assert client.post("/mcp/filesystem", json=message).status_code == 401
    response = client.post("/mcp/filesystem", json=message, headers={"Authorization": "Bearer configured-token"})
    assert response.status_code == 200
    assert "error" not in response.json()
    assert captured["message"]["params"]["name"] == "fs.read"


@pytest.mark.parametrize("env_enabled", [False, True])
def test_gateway_cli_refuses_embedded_issuer_before_loading_upstreams(monkeypatch, env_enabled):
    from click.testing import CliRunner

    from agent_bom.cli._gateway import gateway_group

    monkeypatch.setenv("AGENT_BOM_GATEWAY_ENABLE_OAUTH_AS", "1" if env_enabled else "0")
    result = CliRunner().invoke(gateway_group, ["serve", *([] if env_enabled else ["--enable-oauth-as"])])
    assert result.exit_code != 0
    assert "trusted client authorization" in result.output


@pytest.mark.parametrize("scopes,allowed", [({"tools:read"}, False), ({"tools:read", "tools:write"}, True)])
def test_external_identity_scope_mapping_remains_enforced(monkeypatch, tmp_path, scopes, allowed):
    monkeypatch.setenv("AGENT_BOM_STATE_DIR", str(tmp_path))
    # Cryptographic external-IdP verification has its own OIDC/JWKS tests;
    # this contract exercises the relay after that trusted boundary resolves.
    monkeypatch.setattr("agent_bom.gateway_server.check_caller_identity", lambda message, policy: ("external-agent", True, None))
    monkeypatch.setattr("agent_bom.gateway_server.identity_token_scopes", lambda token: scopes)
    caller, captured = _echo_caller()
    settings = GatewaySettings(
        registry=_registry(),
        policy={"oidc_issuer": "https://idp.example"},
        bearer_token="configured-token",
        upstream_caller=caller,
        tool_scope_map={"fs.write": ["tools:write"]},
        a2a_mutual_auth_enforcement_mode="enforce",
    )
    client = TestClient(create_gateway_app(settings))
    response = client.post(
        "/mcp/filesystem",
        json=_tools_call("fs.write", {}, identity="verified-external-token"),
        headers={"Authorization": "Bearer configured-token"},
    )
    if allowed:
        assert "error" not in response.json()
        assert captured["message"]["params"]["name"] == "fs.write"
    else:
        assert response.json()["error"]["data"]["policy_source"] == "oauth_scope"
        assert not captured
