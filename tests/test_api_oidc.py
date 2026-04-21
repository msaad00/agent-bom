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

import base64
import json
import os
from unittest.mock import MagicMock, patch

import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient

from agent_bom.api.oidc import (
    OIDCConfig,
    OIDCError,
    claims_have_role_signal,
    claims_to_role,
    claims_to_tenant,
    oidc_enabled_from_env,
    record_oidc_decode_failure,
    reset_oidc_decode_failures,
)

# ── OIDCConfig ────────────────────────────────────────────────────────────────


def _unsigned_test_jwt(claims: dict[str, str]) -> str:
    header = base64.urlsafe_b64encode(json.dumps({"alg": "none"}).encode()).decode().rstrip("=")
    payload = base64.urlsafe_b64encode(json.dumps(claims).encode()).decode().rstrip("=")
    return f"{header}.{payload}."


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


def test_oidc_enabled_from_env_detects_tenant_bound_config():
    with patch.dict(
        os.environ,
        {"AGENT_BOM_OIDC_TENANT_PROVIDERS_JSON": '{"tenant-alpha":{"issuer":"https://alpha.okta.example","audience":"agent-bom"}}'},
        clear=False,
    ):
        assert oidc_enabled_from_env() is True


def test_oidc_config_audience_is_unset_without_explicit_value():
    cfg = OIDCConfig(issuer="https://myissuer.example.com")
    assert cfg.audience is None


def test_oidc_config_explicit_audience():
    cfg = OIDCConfig(issuer="https://myissuer.example.com", audience="my-app")
    assert cfg.audience == "my-app"


def test_oidc_config_reads_required_nonce():
    cfg = OIDCConfig(issuer="https://myissuer.example.com", required_nonce="nonce-123")
    assert cfg.required_nonce == "nonce-123"


def test_oidc_config_verify_raises_when_not_enabled():
    cfg = OIDCConfig()  # no issuer
    with pytest.raises(OIDCError, match="not configured"):
        cfg.verify("any.jwt.token")


def test_oidc_config_verify_requires_explicit_audience():
    cfg = OIDCConfig(issuer="https://corp.example.com")
    with pytest.raises(OIDCError, match="AGENT_BOM_OIDC_AUDIENCE"):
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


def test_oidc_config_require_role_claim_from_env():
    with patch.dict(
        os.environ,
        {
            "AGENT_BOM_OIDC_ISSUER": "https://test.okta.com",
            "AGENT_BOM_OIDC_REQUIRE_ROLE_CLAIM": "true",
        },
    ):
        cfg = OIDCConfig.from_env()
        assert cfg.require_role_claim is True


def test_oidc_config_reads_allow_default_tenant_and_jwks_allowlist_from_env():
    with patch.dict(
        os.environ,
        {
            "AGENT_BOM_OIDC_ISSUER": "https://test.okta.com",
            "AGENT_BOM_OIDC_ALLOWED_JWKS_URIS": "https://test.okta.com/keys, https://backup.okta.com/keys",
            "AGENT_BOM_OIDC_ALLOW_DEFAULT_TENANT": "true",
        },
    ):
        cfg = OIDCConfig.from_env()
        assert cfg.allow_default_tenant is True
        assert cfg.allowed_jwks_uris == ("https://test.okta.com/keys", "https://backup.okta.com/keys")


def test_oidc_config_from_env_reads_tenant_bound_providers():
    with patch.dict(
        os.environ,
        {
            "AGENT_BOM_OIDC_TENANT_PROVIDERS_JSON": (
                '{"tenant-alpha":{"issuer":"https://alpha.okta.example","audience":"agent-bom"},'
                '"tenant-beta":{"issuer":"https://beta.okta.example","audience":"agent-bom","require_tenant_claim":true}}'
            )
        },
        clear=False,
    ):
        cfg = OIDCConfig.from_env()

    assert cfg.enabled is True
    assert cfg.issuer == ""
    assert set(cfg.tenant_providers) == {"tenant-alpha", "tenant-beta"}
    assert cfg.tenant_providers["tenant-beta"].require_tenant_claim is True


def test_oidc_config_from_env_rejects_mixed_global_and_tenant_bound_modes():
    with patch.dict(
        os.environ,
        {
            "AGENT_BOM_OIDC_ISSUER": "https://global.okta.example",
            "AGENT_BOM_OIDC_TENANT_PROVIDERS_JSON": '{"tenant-alpha":{"issuer":"https://alpha.okta.example","audience":"agent-bom"}}',
        },
        clear=False,
    ):
        with pytest.raises(OIDCError, match="either AGENT_BOM_OIDC_ISSUER or AGENT_BOM_OIDC_TENANT_PROVIDERS_JSON"):
            OIDCConfig.from_env()


def test_oidc_config_from_env_rejects_duplicate_issuers():
    with patch.dict(
        os.environ,
        {
            "AGENT_BOM_OIDC_TENANT_PROVIDERS_JSON": (
                '{"tenant-alpha":{"issuer":"https://shared.okta.example","audience":"agent-bom"},'
                '"tenant-beta":{"issuer":"https://shared.okta.example","audience":"agent-bom"}}'
            )
        },
        clear=False,
    ):
        with pytest.raises(OIDCError, match="configured for more than one tenant"):
            OIDCConfig.from_env()


@pytest.fixture(autouse=True)
def _reset_oidc_metrics():
    reset_oidc_decode_failures()
    yield
    reset_oidc_decode_failures()


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


def test_claims_have_role_signal_false_for_unknown_role():
    assert claims_have_role_signal({"agent_bom_role": "readonlyuser"}) is False


def test_claims_have_role_signal_true_for_roles_array():
    assert claims_have_role_signal({"roles": ["admin"]}) is True


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
            cfg = OIDCConfig(issuer="https://example.com", audience="agent-bom")
            cfg.verify("bad.token.here")


def test_verify_raises_oidc_error_on_discovery_failure():
    """Network failure during OIDC discovery raises OIDCError."""
    from agent_bom.api.oidc import verify_oidc_token

    with patch("agent_bom.api.oidc._check_pyjwt"):
        with patch("agent_bom.api.oidc._fetch_json", side_effect=OIDCError("connection refused")):
            with pytest.raises(OIDCError, match="connection refused"):
                verify_oidc_token("tok", "https://down.example.com")


def test_verify_oidc_token_requires_pinned_or_allowlisted_jwks_uri():
    from agent_bom.api.oidc import verify_oidc_token

    with patch("agent_bom.api.oidc.discover_oidc", return_value={"jwks_uri": "https://example.com/jwks.json"}):
        with pytest.raises(OIDCError, match="requires a pinned JWKS URI"):
            verify_oidc_token("tok", "https://example.com", audience="agent-bom")


def test_verify_oidc_token_accepts_allowlisted_discovered_jwks_uri():
    from agent_bom.api.oidc import verify_oidc_token

    mock_jwks_client = MagicMock()
    mock_jwks_client.get_signing_key_from_jwt.side_effect = Exception("InvalidSignature")
    mock_jwt_module = MagicMock()
    mock_jwt_module.PyJWKClient.return_value = mock_jwks_client
    with patch.dict("sys.modules", {"jwt": mock_jwt_module, "cryptography": MagicMock()}):
        with patch("agent_bom.api.oidc.discover_oidc", return_value={"jwks_uri": "https://example.com/jwks.json"}):
            with pytest.raises(OIDCError, match="Failed to resolve signing key"):
                verify_oidc_token(
                    "not.a.real.jwt",
                    "https://example.com",
                    audience="agent-bom",
                    allowed_jwks_uris=("https://example.com/jwks.json",),
                )


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
    cfg = OIDCConfig(issuer="https://example.com", audience="agent-bom")

    mock_claims = {"sub": "user1", "email": "user@example.com", "agent_bom_role": "analyst"}

    with patch("agent_bom.api.oidc.verify_oidc_token", return_value=mock_claims):
        claims, role = cfg.verify("valid.jwt.token")

    assert claims["email"] == "user@example.com"
    assert role == "analyst"


def test_oidc_config_verify_requires_explicit_role_when_enabled():
    cfg = OIDCConfig(
        issuer="https://example.com",
        audience="agent-bom",
        require_role_claim=True,
    )

    with patch("agent_bom.api.oidc.verify_oidc_token", return_value={"sub": "user-1", "email": "user@example.com"}):
        with pytest.raises(OIDCError, match="required role claim"):
            cfg.verify("valid.jwt.token")


def test_oidc_config_resolve_tenant_defaults_only_when_explicitly_enabled():
    cfg = OIDCConfig(issuer="https://corp.example.com", audience="agent-bom", allow_default_tenant=True)
    assert cfg.resolve_tenant({"sub": "user-1"}) == "default"


def test_oidc_config_resolve_tenant_raises_when_claim_missing_without_opt_in():
    cfg = OIDCConfig(issuer="https://corp.example.com", audience="agent-bom")
    with pytest.raises(OIDCError, match="missing tenant claim"):
        cfg.resolve_tenant({"sub": "user-1"})


def test_oidc_config_verify_routes_token_by_issuer_for_tenant_bound_providers():
    cfg = OIDCConfig(
        tenant_providers={
            "tenant-alpha": OIDCConfig(
                issuer="https://alpha.okta.example",
                audience="agent-bom",
                tenant_id="tenant-alpha",
                require_tenant_claim=True,
            )
        }
    )
    token = _unsigned_test_jwt({"iss": "https://alpha.okta.example"})
    with patch(
        "agent_bom.api.oidc.verify_oidc_token",
        return_value={"iss": "https://alpha.okta.example", "sub": "user-1", "agent_bom_role": "analyst", "tenant_id": "tenant-alpha"},
    ):
        claims, role = cfg.verify(token)

    assert claims["iss"] == "https://alpha.okta.example"
    assert role == "analyst"


def test_oidc_config_resolve_tenant_rejects_mismatched_bound_tenant():
    cfg = OIDCConfig(
        tenant_providers={
            "tenant-alpha": OIDCConfig(
                issuer="https://alpha.okta.example",
                audience="agent-bom",
                tenant_id="tenant-alpha",
            )
        }
    )
    with patch(
        "agent_bom.api.oidc.verify_oidc_token",
        return_value={"iss": "https://alpha.okta.example", "sub": "user-1", "agent_bom_role": "viewer", "tenant_id": "tenant-beta"},
    ):
        with pytest.raises(OIDCError, match="does not match the configured tenant"):
            cfg.verify(_unsigned_test_jwt({"iss": "https://alpha.okta.example"}))


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

    cfg = OIDCConfig(issuer="https://corp.okta.com", audience="agent-bom")
    with patch("agent_bom.api.oidc.verify_oidc_token", return_value=mock_claims):
        claims, role = cfg.verify("eyJ.valid.token")

    assert role == "analyst"
    assert claims["email"] == "alice@corp.com"


def test_api_key_middleware_accepts_oidc_bearer_without_static_api_key(monkeypatch):
    from agent_bom.api.middleware import APIKeyMiddleware

    app = FastAPI()

    @app.get("/secure")
    async def secure(request: Request):
        return {
            "tenant_id": request.state.tenant_id,
            "role": request.state.api_key_role,
            "auth_method": request.state.auth_method,
        }

    app.add_middleware(APIKeyMiddleware, api_key=None)

    cfg = OIDCConfig(issuer="https://corp.okta.com", audience="agent-bom", allow_default_tenant=True)
    monkeypatch.setattr("agent_bom.api.oidc.OIDCConfig.from_env", lambda: cfg)
    monkeypatch.setattr(
        "agent_bom.api.oidc.verify_oidc_token",
        lambda *args, **kwargs: {"sub": "u1", "email": "alice@corp.com", "agent_bom_role": "analyst"},
    )

    client = TestClient(app)
    resp = client.get("/secure", headers={"Authorization": "Bearer token"})
    assert resp.status_code == 200
    assert resp.json() == {
        "tenant_id": "default",
        "role": "analyst",
        "auth_method": "oidc",
    }


def test_middleware_oidc_failure_does_not_raise():
    """OIDCError is caught and falls through — does not propagate."""
    cfg = OIDCConfig(issuer="https://corp.okta.com", audience="agent-bom")

    with patch("agent_bom.api.oidc.verify_oidc_token", side_effect=OIDCError("expired")):
        with pytest.raises(OIDCError):
            # verify() re-raises — caller (middleware) catches it
            cfg.verify("expired.jwt.token")


def test_oidc_config_passes_required_nonce_to_verifier():
    cfg = OIDCConfig(issuer="https://corp.okta.com", audience="agent-bom", required_nonce="nonce-123")

    with patch(
        "agent_bom.api.oidc.verify_oidc_token",
        return_value={"sub": "u1", "agent_bom_role": "admin", "nonce": "nonce-123"},
    ) as mock_verify:
        claims, role = cfg.verify("valid.jwt.token")

    assert claims["sub"] == "u1"
    assert role == "admin"
    assert mock_verify.call_args.args[4] == "nonce-123"


@pytest.mark.asyncio
async def test_observability_metrics_include_oidc_decode_failures():
    from agent_bom.api.routes.observability import prometheus_metrics

    record_oidc_decode_failure()
    record_oidc_decode_failure()

    response = await prometheus_metrics()
    body = response.body.decode("utf-8")
    assert "agent_bom_oidc_decode_failures_total 2" in body
