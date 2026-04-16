"""Tests for CI deployment health probe helpers."""

from __future__ import annotations

import urllib.error

import pytest

from agent_bom.deployment_probe import fetch_health, resolve_health_url, validate_health_payload


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
