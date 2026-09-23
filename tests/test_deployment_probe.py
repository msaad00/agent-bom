"""Tests for CI deployment health probe helpers."""

from __future__ import annotations

import urllib.error

import pytest

from agent_bom.deployment_probe import (
    fetch_health,
    main,
    resolve_health_url,
    resolve_server_card_url,
    validate_health_payload,
    validate_server_card_release,
)


@pytest.mark.parametrize(
    "initial_payload",
    [
        b'{"serverInfo":{"version":"0.103.2"},"tools":[]}',
        b'{"serverInfo":{"version":"0.104.0"},"tools":[]}',
        b'{"serverInfo":{"version":"0.104.0"},"tools":[{"name":"scan"}]}',
    ],
)
def test_server_card_cli_retries_until_exact_release_contract(monkeypatch, capsys, initial_payload):
    replies = iter([initial_payload, b'{"serverInfo":{"version":"0.104.0"},"tools":[{"name":"scan","inputSchema":{"type":"object"}}]}'])
    delays = []
    monkeypatch.setattr("agent_bom.deployment_probe.urllib.request.urlopen", lambda *_args, **_kwargs: _Response(next(replies)))
    monkeypatch.setattr("agent_bom.deployment_probe.time.sleep", delays.append)

    assert (
        main(["--server-card", "--expected-version", "0.104.0", "--expected-tool-count", "1", "--attempts", "2", "--backoff-seconds", "3"])
        == 0
    )
    captured = capsys.readouterr()
    assert '"version":"0.104.0"' in captured.out
    assert delays == [3]


def test_server_card_cli_still_fails_when_release_never_arrives(monkeypatch, capsys):
    calls = []

    def old_release(*_args, **_kwargs):
        calls.append(True)
        return _Response(b'{"serverInfo":{"version":"0.103.2"},"tools":[]}')

    monkeypatch.setattr("agent_bom.deployment_probe.urllib.request.urlopen", old_release)

    assert (
        main(["--server-card", "--expected-version", "0.104.0", "--expected-tool-count", "1", "--attempts", "3", "--backoff-seconds", "0"])
        == 1
    )
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "version mismatch" in captured.err
    assert len(calls) == 3


def test_server_card_network_and_contract_errors_share_attempt_budget(monkeypatch, capsys):
    calls = []

    def changing_failure(*_args, **_kwargs):
        calls.append(True)
        if len(calls) == 1:
            raise urllib.error.URLError("temporarily unavailable")
        return _Response(b'{"serverInfo":{"version":"0.103.2"},"tools":[]}')

    monkeypatch.setattr("agent_bom.deployment_probe.urllib.request.urlopen", changing_failure)

    assert main(["--server-card", "--expected-version", "0.104.0", "--expected-tool-count", "1", "--attempts", "2"]) == 1
    assert len(calls) == 2
    assert "version mismatch" in capsys.readouterr().err


class _Response:
    def __init__(self, body: bytes) -> None:
        self._body = body

    def read(self) -> bytes:
        return self._body

    def __enter__(self) -> "_Response":
        return self

    def __exit__(self, exc_type, exc, tb) -> bool:
        return False


def test_resolve_health_url_accepts_root_base_url():
    assert resolve_health_url("https://agent-bom-mcp.up.railway.app") == "https://agent-bom-mcp.up.railway.app/health"
    assert resolve_health_url("https://agent-bom-mcp.up.railway.app/") == "https://agent-bom-mcp.up.railway.app/health"


def test_resolve_health_url_strips_mcp_suffix():
    assert resolve_health_url("https://agent-bom-mcp.up.railway.app/mcp") == "https://agent-bom-mcp.up.railway.app/health"
    assert resolve_health_url("https://agent-bom-mcp.up.railway.app/nested/mcp") == "https://agent-bom-mcp.up.railway.app/nested/health"


def test_resolve_server_card_url_uses_public_well_known_route():
    expected = "https://agent-bom-mcp.up.railway.app/.well-known/mcp/server-card.json"
    assert resolve_server_card_url("https://agent-bom-mcp.up.railway.app") == expected
    assert resolve_server_card_url("https://agent-bom-mcp.up.railway.app/mcp") == expected


def test_fetch_health_retries_normalized_url(monkeypatch):
    calls: list[str] = []

    def fake_urlopen(request, timeout):
        calls.append(request.full_url)
        if len(calls) == 1:
            raise urllib.error.URLError("temporary failure")
        assert timeout == 12
        return _Response(b'{"version":"0.76.0","tool_count":0}')

    monkeypatch.setattr("agent_bom.deployment_probe.urllib.request.urlopen", fake_urlopen)
    monkeypatch.setattr("agent_bom.deployment_probe.time.sleep", lambda *_args: None)

    url, payload = fetch_health(
        "https://agent-bom-mcp.up.railway.app/mcp",
        bearer_token="secret",
        attempts=2,
        backoff_seconds=5,
        timeout=12,
    )

    assert url == "https://agent-bom-mcp.up.railway.app/health"
    assert payload["version"] == "0.76.0"
    assert calls == [
        "https://agent-bom-mcp.up.railway.app/health",
        "https://agent-bom-mcp.up.railway.app/health",
    ]


def test_validate_health_payload_rejects_auth_required_for_public_registry():
    with pytest.raises(ValueError, match="requires auth"):
        validate_health_payload({"version": "0.76.0", "auth_required": True}, forbid_auth_required=True)


def test_validate_health_payload_allows_public_surface():
    payload = validate_health_payload({"version": "0.76.0", "auth_required": False}, forbid_auth_required=True)
    assert payload["version"] == "0.76.0"


def test_validate_server_card_release_requires_exact_version_tools_and_schemas():
    payload = {
        "serverInfo": {"version": "0.100.0"},
        "tools": [
            {"name": "scan", "inputSchema": {"type": "object"}},
            {"name": "generate_sbom", "inputSchema": {"type": "object"}},
        ],
    }

    validated = validate_server_card_release(payload, expected_version="0.100.0", expected_tool_count=2)
    assert validated is payload

    with pytest.raises(ValueError, match="version mismatch"):
        validate_server_card_release(payload, expected_version="0.101.0", expected_tool_count=2)
    with pytest.raises(ValueError, match="tool count mismatch"):
        validate_server_card_release(payload, expected_version="0.100.0", expected_tool_count=3)

    payload["tools"][1].pop("inputSchema")
    with pytest.raises(ValueError, match="tool schema"):
        validate_server_card_release(payload, expected_version="0.100.0", expected_tool_count=2)


@pytest.mark.parametrize("sse", [False, True])
@pytest.mark.parametrize("anonymous_status", [401, 403])
def test_authenticated_initialize_accepts_json_and_event_stream(monkeypatch, sse, anonymous_status):
    import io
    import json
    from email.message import Message
    from types import SimpleNamespace

    from agent_bom.deployment_probe import verify_mcp_auth

    payload = json.dumps(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "protocolVersion": "2025-03-26",
                "capabilities": {},
                "serverInfo": {"version": "0.105.0"},
            },
        }
    )
    response = io.BytesIO((f"event: message\ndata: {payload}\n\n" if sse else payload).encode())
    response.headers = Message()
    response.headers["Content-Type"] = "text/event-stream" if sse else "application/json"
    calls = []

    def open_request(request, **kwargs):
        calls.append(request)
        if not request.get_header("Authorization"):
            raise urllib.error.HTTPError(request.full_url, anonymous_status, "fixture", {}, None)
        return response

    monkeypatch.setattr("agent_bom.deployment_probe.urllib.request.build_opener", lambda *args: SimpleNamespace(open=open_request))
    verify_mcp_auth("https://example.com/mcp", bearer_token="fixture-read-token", expected_version="0.105.0", timeout=1)
    assert calls[0].full_url == "https://example.com/mcp"
    assert calls[0].get_method() == "POST"
    assert calls[0].get_header("Authorization") == "Bearer fixture-read-token"
    assert json.loads(calls[0].data)["method"] == "initialize"
    assert len(calls) == 2
    assert calls[1].get_header("Authorization") is None


def test_expired_authenticated_access_cannot_pass_public_card_gate(monkeypatch, capsys):
    from types import SimpleNamespace

    def denied(*args, **kwargs):
        raise urllib.error.HTTPError("https://secret.example/credential", 401, "token=private-token", {}, None)

    monkeypatch.setattr("agent_bom.deployment_probe.urllib.request.build_opener", lambda *args: SimpleNamespace(open=denied))
    monkeypatch.setattr(
        "agent_bom.deployment_probe.fetch_server_card", lambda *args, **kwargs: pytest.fail("public metadata cannot override auth failure")
    )
    result = main(
        [
            "--server-card",
            "--require-mcp-auth",
            "--bearer-token",
            "private-token",
            "--expected-version",
            "0.105.0",
            "--expected-tool-count",
            "8",
        ]
    )
    assert result == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "Authenticated MCP initialize failed" in captured.err
    assert "private-token" not in captured.err
    assert "secret.example" not in captured.err


def test_authenticated_probe_requires_credential_and_safe_origin(monkeypatch):
    from agent_bom.deployment_probe import verify_mcp_auth

    monkeypatch.setattr("agent_bom.deployment_probe.urllib.request.build_opener", lambda *args: pytest.fail("must reject before network"))
    for url, token in [
        ("https://example.com", None),
        ("http://example.com", "read-token"),
        ("https://user:password@example.com", "read-token"),
    ]:
        with pytest.raises(ValueError):
            verify_mcp_auth(url, bearer_token=token, expected_version="0.105.0", timeout=1)


def test_authenticated_probe_does_not_forward_bearer_on_redirect():
    from agent_bom.deployment_probe import _NoAuthRedirect

    with pytest.raises(ValueError, match="does not follow redirects"):
        _NoAuthRedirect().redirect_request(None, None, 302, "Found", {}, "https://other.example/mcp")


def test_deployment_freshness_requires_mcp_auth_not_only_public_metadata():
    from pathlib import Path

    workflow = (Path(__file__).resolve().parents[1] / ".github/workflows/deployment-freshness.yml").read_text()
    railway = workflow.split("- name: Check Railway deployment", 1)[1].split("- name: Check Smithery", 1)[0]
    assert "--server-card --require-mcp-auth" in railway
    assert railway.index("--require-mcp-auth") < railway.index('echo "probe_failed=false"')


@pytest.mark.parametrize(
    "payload",
    [
        {"jsonrpc": "2.0", "id": 1, "error": {"message": "credential=private-response"}},
        {"jsonrpc": "2.0", "id": 2, "result": {"protocolVersion": "2025-03-26", "capabilities": {}, "serverInfo": {"version": "0.105.0"}}},
        {"jsonrpc": "2.0", "id": 1, "result": {"protocolVersion": "2025-03-26", "capabilities": {}, "serverInfo": {"version": "0.104.0"}}},
        [],
    ],
)
def test_authenticated_probe_rejects_invalid_success_bodies_without_leaking(monkeypatch, capsys, payload):
    import io
    import json
    from email.message import Message
    from types import SimpleNamespace

    response = io.BytesIO(json.dumps(payload).encode())
    response.headers = Message()
    response.headers["Content-Type"] = "application/json"
    monkeypatch.setattr(
        "agent_bom.deployment_probe.urllib.request.build_opener", lambda *args: SimpleNamespace(open=lambda *a, **k: response)
    )
    assert main(["--require-mcp-auth", "--bearer-token", "fixture-token", "--expected-version", "0.105.0"]) == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "private-response" not in captured.err
    assert "Authenticated MCP initialize failed" in captured.err


@pytest.mark.parametrize("anonymous_status", [200, 404, 500])
def test_authenticated_probe_rejects_unprotected_or_unverifiable_endpoint(monkeypatch, anonymous_status):
    import io
    import json
    from email.message import Message
    from types import SimpleNamespace

    from agent_bom.deployment_probe import verify_mcp_auth

    calls = []

    def open_request(request, **kwargs):
        calls.append(request)
        if not request.get_header("Authorization") and anonymous_status != 200:
            raise urllib.error.HTTPError(request.full_url, anonymous_status, "fixture", {}, None)
        response = io.BytesIO(
            json.dumps(
                {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "result": {
                        "protocolVersion": "2025-03-26",
                        "capabilities": {},
                        "serverInfo": {"version": "0.105.0"},
                    },
                }
            ).encode()
        )
        response.headers = Message()
        response.headers["Content-Type"] = "application/json"
        return response

    monkeypatch.setattr("agent_bom.deployment_probe.urllib.request.build_opener", lambda *args: SimpleNamespace(open=open_request))
    with pytest.raises(RuntimeError, match="Authenticated MCP initialize failed"):
        verify_mcp_auth("https://example.com", bearer_token="fixture-token", expected_version="0.105.0", timeout=1)
    assert len(calls) == 2
    assert calls[1].get_header("Authorization") is None
