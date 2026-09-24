"""Probe credentials are freshly issued, bounded and never sent to redirects."""

import importlib.util
import json
from pathlib import Path
from unittest.mock import MagicMock

import pytest

spec = importlib.util.spec_from_file_location("probe_with_oauth", Path(__file__).parents[1] / "scripts/deploy/probe_with_oauth.py")
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)


@pytest.fixture
def environment():
    return {
        "MCP_PROBE_OAUTH_" + k: v
        for k, v in dict(
            ISSUER="https://id.example/realms/mcp",
            TOKEN_URL="https://id.example/realms/mcp/token",
            CLIENT_ID="probe",
            CLIENT_SECRET="private-test-value",
            AUDIENCE="https://mcp.example/mcp",
        ).items()
    }


def test_fresh_token_replaces_static_credential_without_inheriting_client_secret(monkeypatch, environment):
    opener = MagicMock()
    opener.open.return_value.__enter__.return_value.read.return_value = json.dumps(
        dict(access_token="fresh-token", token_type="Bearer", expires_in=300)
    ).encode()
    monkeypatch.setattr(probe.urllib.request, "build_opener", lambda *handlers: opener)
    environment["RAILWAY_MCP_BEARER_TOKEN"] = "stale-token"
    result = probe.probe_environment(environment)
    assert result["AGENT_BOM_DEPLOYMENT_BEARER_TOKEN"] == "fresh-token"
    assert "MCP_PROBE_OAUTH_CLIENT_SECRET" not in result
    request = opener.open.call_args.args[0]
    assert request.full_url == environment["MCP_PROBE_OAUTH_TOKEN_URL"]
    assert b"grant_type=client_credentials" in request.data
    assert b"scope=read" in request.data


@pytest.mark.parametrize(
    "change", [{"CLIENT_SECRET": ""}, {"TOKEN_URL": "https://other.example/token"}, {"TOKEN_URL": "http://id.example/token"}]
)
def test_bad_configuration_never_requests_a_token(monkeypatch, environment, change):
    opener = MagicMock()
    monkeypatch.setattr(probe.urllib.request, "build_opener", opener)
    environment.update({"MCP_PROBE_OAUTH_" + k: v for k, v in change.items()})
    with pytest.raises(ValueError):
        probe.probe_environment(environment)
    opener.assert_not_called()


@pytest.mark.parametrize("reply", [{"expires_in": 7200}, {"expires_in": True}, {"access_token": "bad\ntoken"}, {"token_type": "other"}])
def test_bad_token_response_fails_closed(monkeypatch, environment, reply):
    opener = MagicMock()
    body = dict(access_token="fresh-token", token_type="Bearer", expires_in=300)
    body.update(reply)
    opener.open.return_value.__enter__.return_value.read.return_value = json.dumps(body).encode()
    monkeypatch.setattr(probe.urllib.request, "build_opener", lambda *handlers: opener)
    with pytest.raises(ValueError):
        probe.probe_environment(environment)


def test_redirect_rejected():
    with pytest.raises(ValueError):
        probe.NoRedirect().redirect_request(None, None, 302, None, None, "https://other.example")


def test_static_mode_preserved():
    assert probe.probe_environment({"RAILWAY_MCP_BEARER_TOKEN": "existing"})["AGENT_BOM_DEPLOYMENT_BEARER_TOKEN"] == "existing"
