"""Tests for JWKS signature verification in agent_identity."""

from __future__ import annotations

import base64
import json
import time
from unittest.mock import MagicMock, patch

from agent_bom.agent_identity import (
    ANONYMOUS,
    _fetch_jwks,
    _resolve_jwks_uri,
    _verify_jwt_signature,
    check_identity,
    resolve_agent_id,
)

# ─── Helpers ─────────────────────────────────────────────────────────────────


def _b64(d: dict) -> str:
    return base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b"=").decode()


def _make_jwt(payload: dict, header: dict | None = None) -> str:
    h = header or {"alg": "RS256", "typ": "JWT", "kid": "test-key"}
    return f"{_b64(h)}.{_b64(payload)}.fakesig"


def _mock_jwks_response(keys: list[dict]) -> MagicMock:
    mock = MagicMock()
    mock.status_code = 200
    mock.json.return_value = {"keys": keys}
    mock.raise_for_status = MagicMock()
    return mock


# ─── _resolve_jwks_uri ────────────────────────────────────────────────────────


def test_resolve_jwks_uri_direct():
    policy = {"jwks_uri": "https://example.com/.well-known/jwks.json"}
    assert _resolve_jwks_uri(policy) == "https://example.com/.well-known/jwks.json"


def test_resolve_jwks_uri_none_when_empty():
    assert _resolve_jwks_uri({}) is None


def test_resolve_jwks_uri_from_oidc_issuer():
    discovery = {"jwks_uri": "https://idp.example.com/jwks"}
    mock_resp = MagicMock()
    mock_resp.json.return_value = discovery
    mock_resp.raise_for_status = MagicMock()
    with patch("httpx.get", return_value=mock_resp):
        result = _resolve_jwks_uri({"oidc_issuer": "https://idp.example.com"})
    assert result == "https://idp.example.com/jwks"


def test_resolve_jwks_uri_oidc_network_failure():
    import httpx

    with patch("httpx.get", side_effect=httpx.ConnectError("timeout")):
        result = _resolve_jwks_uri({"oidc_issuer": "https://idp.example.com"})
    assert result is None


# ─── _fetch_jwks ──────────────────────────────────────────────────────────────


def test_fetch_jwks_success():
    keys = [{"kty": "RSA", "kid": "k1", "n": "abc", "e": "AQAB"}]
    mock_resp = _mock_jwks_response(keys)
    with patch("httpx.get", return_value=mock_resp):
        result = _fetch_jwks("https://example.com/jwks")
    assert result == {"keys": keys}


def test_fetch_jwks_network_error_returns_none():
    import httpx

    with patch("httpx.get", side_effect=httpx.ConnectError("down")):
        result = _fetch_jwks("https://unreachable.example.com/jwks")
    assert result is None


def test_fetch_jwks_cached(monkeypatch):
    """Second call with same URI should NOT make a second HTTP request."""
    import agent_bom.agent_identity as mod

    # Pre-populate cache
    mod._jwks_cache["https://cached.example.com/jwks"] = ({"keys": []}, time.time())
    with patch("httpx.get") as mock_get:
        _fetch_jwks("https://cached.example.com/jwks")
        mock_get.assert_not_called()


# ─── _verify_jwt_signature ───────────────────────────────────────────────────


def test_verify_jwt_none_algorithm_rejected():
    token = _make_jwt({"sub": "x"}, header={"alg": "none", "typ": "JWT"})
    verified, err = _verify_jwt_signature(token, "https://example.com/jwks")
    assert not verified
    assert err is not None
    assert "none" in err.lower() or "not accepted" in err.lower()


def test_verify_jwt_unknown_algorithm_rejected():
    token = _make_jwt({"sub": "x"}, header={"alg": "HS256", "typ": "JWT"})
    verified, err = _verify_jwt_signature(token, "https://example.com/jwks")
    assert not verified


def test_verify_jwt_no_matching_kid():
    keys = [{"kty": "RSA", "kid": "different-kid", "n": "x", "e": "AQAB"}]
    mock_resp = _mock_jwks_response(keys)
    with patch("httpx.get", return_value=mock_resp):
        token = _make_jwt({"sub": "agent"}, header={"alg": "RS256", "kid": "missing-kid"})
        verified, err = _verify_jwt_signature(token, "https://example.com/jwks")
    assert not verified
    assert "kid" in (err or "").lower() or "key" in (err or "").lower()


def test_verify_jwt_jwks_unreachable():
    import httpx

    token = _make_jwt({"sub": "x"})
    with patch("httpx.get", side_effect=httpx.ConnectError("down")):
        verified, err = _verify_jwt_signature(token, "https://down.example.com/jwks")
    assert not verified
    assert "unreachable" in (err or "").lower()


def test_verify_jwt_pyjwt_not_available(monkeypatch):
    """When PyJWT is not installed, returns (False, reason)."""
    import builtins

    real_import = builtins.__import__

    def mock_import(name, *args, **kwargs):
        if name == "jwt":
            raise ImportError("No module named 'jwt'")
        return real_import(name, *args, **kwargs)

    token = _make_jwt({"sub": "x"})
    with patch("builtins.__import__", side_effect=mock_import):
        verified, err = _verify_jwt_signature(token, "https://example.com/jwks")
    assert not verified
    assert err is not None


# ─── resolve_agent_id with jwks_uri in policy ─────────────────────────────────


def test_resolve_agent_id_no_jwks_skips_verification():
    """Without jwks_uri, signature is not verified — existing behavior preserved."""
    token = _make_jwt({"sub": "agent-alice", "iat": int(time.time())})
    agent_id, err = resolve_agent_id(token, {})
    assert agent_id == "agent-alice"
    assert err is None


def test_resolve_agent_id_jwks_blocks_on_invalid_signature():
    """With jwks_uri configured and invalid signature, returns ANONYMOUS."""
    import httpx

    token = _make_jwt({"sub": "agent-bad"})
    with patch("httpx.get", side_effect=httpx.ConnectError("unreachable")):
        agent_id, err = resolve_agent_id(token, {"jwks_uri": "https://idp.example.com/jwks"})
    assert agent_id == ANONYMOUS
    assert err is not None
    assert "signature" in err.lower() or "unreachable" in err.lower()


def test_resolve_agent_id_expired_still_blocked_with_jwks():
    token = _make_jwt({"sub": "agent-x", "exp": int(time.time()) - 60})
    # Expiry is checked before signature — should fail on expiry first
    agent_id, err = resolve_agent_id(token, {"jwks_uri": "https://idp.example.com/jwks"})
    assert agent_id == ANONYMOUS
    assert "expired" in (err or "").lower()


# ─── check_identity integration ──────────────────────────────────────────────


def test_check_identity_jwks_required_blocks_on_no_jwks_key():
    """require_agent_identity + jwks_uri + invalid token → blocked."""
    import httpx

    def _msg(token):
        return {
            "method": "tools/call",
            "params": {"name": "x", "arguments": {}, "_meta": {"agent_identity": token}},
        }

    token = _make_jwt({"sub": "agent-z"})
    policy = {"require_agent_identity": True, "jwks_uri": "https://idp.example.com/jwks"}
    with patch("httpx.get", side_effect=httpx.ConnectError("down")):
        agent_id, block = check_identity(_msg(token), policy)
    assert block is not None


def test_check_identity_no_jwks_configured_passes_as_before():
    """Without jwks_uri, identity check passes for well-formed JWT — no regression."""

    def _msg(token):
        return {
            "method": "tools/call",
            "params": {"name": "x", "arguments": {}, "_meta": {"agent_identity": token}},
        }

    token = _make_jwt({"sub": "agent-ok"})
    agent_id, block = check_identity(_msg(token), {})
    assert agent_id == "agent-ok"
    assert block is None
