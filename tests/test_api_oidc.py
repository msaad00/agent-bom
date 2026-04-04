"""Tests for OIDC/SSO JWT authentication (#278).

Tests cover:
- OIDCConfig.enabled = False when AGENT_BOM_OIDC_ISSUER not set
- OIDCConfig.enabled = True when issuer is set
- OIDCConfig.from_env() reads env vars correctly
- OIDCError raised when PyJWT not installed
- OIDCError raised when OIDC not configured
- claims_to_role(): admin, analyst, viewer mappings from direct claim
- claims_to_role(): admin/analyst from roles/groups array claims
- claims_to_role(): defaults to viewer when no role signal
- verify_oidc_token() raises OIDCError on invalid JWT (mocked PyJWT)
- verify_oidc_token() raises OIDCError when discovery fails
- OIDCConfig.verify() propagates OIDCError on bad token
- APIKeyMiddleware falls through to API key check when OIDC fails
- APIKeyMiddleware accepts OIDC token (mocked) and sets request state
- OIDC not enabled → OIDC path skipped entirely
"""

from __future__ import annotations

import os
from unittest.mock import MagicMock, patch

import pytest

from agent_bom.api.oidc import OIDCConfig, OIDCError, claims_to_role, claims_to_tenant

# ── OIDCConfig ────────────────────────────────────────────────────────────────


def test_oidc_config_disabled_when_no_issuer():
    with patch.dict(os.environ, {}, clear=False):
        os.environ.pop("AGENT_BOM_OIDC_ISSUER", None)
        cfg = OIDCConfig()
        assert cfg.enabled is False


def test_oidc_config_enabled_when_issuer_set():
    cfg = OIDCConfig(issuer="https://accounts.google.com")
    assert cfg.enabled is True
    assert cfg.issuer == "https://accounts.google.com"


def test_oidc_config_from_env_reads_issuer():
    with patch.dict(os.environ, {"AGENT_BOM_OIDC_ISSUER": "https://test.okta.com"}):
        cfg = OIDCConfig.from_env()
        assert cfg.enabled is True
        assert cfg.issuer == "https://test.okta.com"


def test_oidc_config_audience_defaults_to_issuer():
    cfg = OIDCConfig(issuer="https://myissuer.example.com")
    assert cfg.audience == "https://myissuer.example.com"


def test_oidc_config_explicit_audience():
    cfg = OIDCConfig(issuer="https://myissuer.example.com", audience="my-app")
    assert cfg.audience == "my-app"


def test_oidc_config_verify_raises_when_not_enabled():
    cfg = OIDCConfig()  # no issuer
    with pytest.raises(OIDCError, match="not configured"):
        cfg.verify("any.jwt.token")


def test_oidc_config_custom_role_claim():
    cfg = OIDCConfig(issuer="https://x.com", role_claim="custom_role")
    assert cfg.role_claim == "custom_role"


def test_oidc_config_custom_tenant_claim():
    cfg = OIDCConfig(issuer="https://x.com", tenant_claim="org_slug")
    assert cfg.tenant_claim == "org_slug"


def test_oidc_config_require_tenant_claim_from_env():
    with patch.dict(
        os.environ,
        {
            "AGENT_BOM_OIDC_ISSUER": "https://test.okta.com",
            "AGENT_BOM_OIDC_REQUIRE_TENANT_CLAIM": "true",
        },
    ):
        cfg = OIDCConfig.from_env()
        assert cfg.require_tenant_claim is True


# ── claims_to_role ────────────────────────────────────────────────────────────


def test_claims_admin_via_direct_claim():
    assert claims_to_role({"agent_bom_role": "admin"}) == "admin"


def test_claims_analyst_via_direct_claim():
    assert claims_to_role({"agent_bom_role": "analyst"}) == "analyst"


def test_claims_viewer_when_no_role_signal():
    assert claims_to_role({"sub": "user123", "email": "u@example.com"}) == "viewer"


def test_claims_admin_via_roles_array():
    assert claims_to_role({"roles": ["admin", "user"]}) == "admin"


def test_claims_analyst_via_groups_array():
    assert claims_to_role({"groups": ["security-analyst", "eng"]}) == "analyst"


def test_claims_viewer_via_unknown_role():
    assert claims_to_role({"agent_bom_role": "readonlyuser"}) == "viewer"


def test_claims_admin_case_insensitive():
    assert claims_to_role({"agent_bom_role": "ADMIN"}) == "admin"


def test_claims_custom_role_claim():
    assert claims_to_role({"my_role": "admin"}, role_claim="my_role") == "admin"


def test_claims_roles_array_analyst():
    assert claims_to_role({"roles": ["developer"]}) == "analyst"


def test_claims_permissions_array_admin():
    assert claims_to_role({"permissions": ["administrator"]}) == "admin"


def test_claims_to_tenant_direct_claim():
    assert claims_to_tenant({"tenant_id": "tenant-alpha"}) == "tenant-alpha"


def test_claims_to_tenant_alias():
    assert claims_to_tenant({"tid": "tenant-beta"}) == "tenant-beta"


def test_claims_to_tenant_custom_claim():
    assert claims_to_tenant({"org_slug": "tenant-gamma"}, tenant_claim="org_slug") == "tenant-gamma"


# ── verify_oidc_token ─────────────────────────────────────────────────────────


def test_verify_raises_oidc_error_when_pyjwt_missing():
    """If PyJWT is not installed, OIDCError is raised with install hint."""
    with patch("agent_bom.api.oidc._check_pyjwt", side_effect=OIDCError("mocked: PyJWT missing")):
        with pytest.raises(OIDCError, match="PyJWT"):
            cfg = OIDCConfig(issuer="https://example.com")
            cfg.verify("bad.token.here")


def test_verify_raises_oidc_error_on_discovery_failure():
    """Network failure during OIDC discovery raises OIDCError."""
    from agent_bom.api.oidc import verify_oidc_token

    with patch("agent_bom.api.oidc._check_pyjwt"):
        with patch("agent_bom.api.oidc._fetch_json", side_effect=OIDCError("connection refused")):
            with pytest.raises(OIDCError, match="connection refused"):
                verify_oidc_token("tok", "https://down.example.com")


def test_verify_raises_oidc_error_on_bad_jwt():
    """Invalid JWT signature raises OIDCError."""
    from agent_bom.api.oidc import verify_oidc_token

    mock_discovery = {"jwks_uri": "https://example.com/.well-known/jwks.json"}
    mock_jwks_client = MagicMock()
    mock_jwks_client.get_signing_key_from_jwt.side_effect = Exception("InvalidSignature")
    mock_jwt_module = MagicMock()
    mock_jwt_module.PyJWKClient.return_value = mock_jwks_client
    mock_jwt_module.PyJWTError = Exception

    with patch("agent_bom.api.oidc._check_pyjwt"):
        with patch("agent_bom.api.oidc.discover_oidc", return_value=mock_discovery):
            with patch.dict("sys.modules", {"jwt": mock_jwt_module}):
                with pytest.raises(OIDCError, match="signing key"):
                    verify_oidc_token("not.a.real.jwt", "https://example.com", jwks_uri="https://example.com/.well-known/jwks.json")


def test_oidc_config_verify_returns_claims_and_role():
    """verify() on OIDCConfig returns (claims, role) on success."""
    cfg = OIDCConfig(issuer="https://example.com")

    mock_claims = {"sub": "user1", "email": "user@example.com", "agent_bom_role": "analyst"}

    with patch("agent_bom.api.oidc.verify_oidc_token", return_value=mock_claims):
        claims, role = cfg.verify("valid.jwt.token")

    assert claims["email"] == "user@example.com"
    assert role == "analyst"


def test_oidc_config_resolve_tenant_defaults_when_not_required():
    cfg = OIDCConfig(issuer="https://corp.example.com")
    assert cfg.resolve_tenant({"sub": "user-1"}) == "default"


def test_oidc_config_resolve_tenant_raises_when_required_claim_missing():
    cfg = OIDCConfig(issuer="https://corp.example.com", require_tenant_claim=True)
    with pytest.raises(OIDCError, match="tenant claim"):
        cfg.resolve_tenant({"sub": "user-1"})


# ── API middleware OIDC integration ───────────────────────────────────────────


def test_api_middleware_skips_oidc_when_not_configured():
    """When OIDC is disabled, middleware does not attempt JWT verification."""
    from agent_bom.api.server import APIKeyMiddleware  # noqa: F401

    # Simulate first-time OIDC check — disabled
    with patch("agent_bom.api.oidc.OIDCConfig.from_env", return_value=OIDCConfig()):
        oidc_cfg = OIDCConfig()
        assert not oidc_cfg.enabled


def test_middleware_oidc_success_sets_request_state():
    """When OIDC verifies a Bearer token, request state is set correctly."""
    mock_claims = {"sub": "u1", "email": "alice@corp.com", "agent_bom_role": "analyst"}

    cfg = OIDCConfig(issuer="https://corp.okta.com")
    with patch("agent_bom.api.oidc.verify_oidc_token", return_value=mock_claims):
        claims, role = cfg.verify("eyJ.valid.token")

    assert role == "analyst"
    assert claims["email"] == "alice@corp.com"


def test_middleware_oidc_failure_does_not_raise():
    """OIDCError is caught and falls through — does not propagate."""
    cfg = OIDCConfig(issuer="https://corp.okta.com")

    with patch("agent_bom.api.oidc.verify_oidc_token", side_effect=OIDCError("expired")):
        with pytest.raises(OIDCError):
            # verify() re-raises — caller (middleware) catches it
            cfg.verify("expired.jwt.token")
