"""Single-source-of-truth auth posture (PR2 of #4274).

One derived ``AuthPosture`` is the sole place the effective credential sources,
anonymous state, listener scope, trusted-proxy usability and OIDC status are
computed. The CLI serve gate, ``/health`` posture, and the middleware runtime
status all read that one derivation — no bespoke re-derivation.
"""

import logging

import pytest

from agent_bom.api.middleware import (
    AuthPosture,
    AuthPostureError,
    apply_auth_posture,
    configure_auth_runtime,
    derive_auth_posture,
    get_auth_posture,
    get_auth_runtime_status,
    validate_auth_posture,
)

_CREDENTIAL_ENV = (
    "AGENT_BOM_API_KEY",
    "AGENT_BOM_API_KEYS",
    "AGENT_BOM_OIDC_ISSUER",
    "AGENT_BOM_OIDC_AUDIENCE",
    "AGENT_BOM_OIDC_TENANT_PROVIDERS_JSON",
    "AGENT_BOM_TRUST_PROXY_AUTH",
    "AGENT_BOM_TRUST_PROXY_AUTH_SECRET",
    "AGENT_BOM_SCIM_BEARER_TOKEN",
    "AGENT_BOM_SAML_IDP_ENTITY_ID",
    "AGENT_BOM_SAML_SP_ENTITY_ID",
    "AGENT_BOM_ALLOW_UNAUTHENTICATED_API",
)


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    for name in _CREDENTIAL_ENV:
        monkeypatch.delenv(name, raising=False)
    yield


# ── derive_auth_posture: the one derivation ─────────────────────────────────


def test_derive_posture_empty_when_nothing_configured():
    posture = derive_auth_posture(api_key_configured=False, allow_unauthenticated=False, listener_host="127.0.0.1")
    assert isinstance(posture, AuthPosture)
    assert posture.sources == ()
    assert posture.auth_configured is False
    assert posture.programmatic_auth_configured is False
    assert posture.anonymous_allowed is False
    assert posture.listener_loopback is True


def test_derive_posture_sources_in_resolver_precedence(monkeypatch):
    monkeypatch.setenv("AGENT_BOM_OIDC_ISSUER", "https://corp.okta.com")
    monkeypatch.setenv("AGENT_BOM_OIDC_AUDIENCE", "agent-bom")
    posture = derive_auth_posture(api_key_configured=True, allow_unauthenticated=False, listener_host="0.0.0.0")
    # Resolver precedence: scim > trusted_proxy > oidc_bearer > api_key > ...
    assert posture.oidc_bearer is True
    assert posture.api_key is True
    assert posture.sources == ("oidc_bearer", "api_key")
    assert posture.auth_configured is True
    assert posture.listener_loopback is False


def test_derive_posture_flags_invalid_oidc_config(monkeypatch):
    # Both single-issuer and tenant-bound modes set is a contradiction the code
    # already rejects at verify/build time — surface it as posture state.
    monkeypatch.setenv("AGENT_BOM_OIDC_ISSUER", "https://corp.okta.com")
    monkeypatch.setenv(
        "AGENT_BOM_OIDC_TENANT_PROVIDERS_JSON",
        '{"tenant-a":{"issuer":"https://a.example","audience":"agent-bom"}}',
    )
    posture = derive_auth_posture(api_key_configured=False, allow_unauthenticated=False, listener_host="127.0.0.1")
    assert posture.oidc_config_invalid is True
    assert posture.oidc_config_error


def test_validate_auth_posture_raises_on_invalid_oidc(monkeypatch):
    monkeypatch.setenv("AGENT_BOM_OIDC_ISSUER", "https://corp.okta.com")
    monkeypatch.setenv(
        "AGENT_BOM_OIDC_TENANT_PROVIDERS_JSON",
        '{"tenant-a":{"issuer":"https://a.example","audience":"agent-bom"}}',
    )
    posture = derive_auth_posture(api_key_configured=False, allow_unauthenticated=False, listener_host="127.0.0.1")
    with pytest.raises(AuthPostureError):
        validate_auth_posture(posture)


def test_validate_auth_posture_accepts_valid_combo(monkeypatch):
    # Trusted proxy + direct OIDC on one listener is allowed today; consolidation
    # must not tighten it into a startup error.
    monkeypatch.setenv("AGENT_BOM_OIDC_ISSUER", "https://corp.okta.com")
    monkeypatch.setenv("AGENT_BOM_OIDC_AUDIENCE", "agent-bom")
    monkeypatch.setenv("AGENT_BOM_TRUST_PROXY_AUTH", "1")
    monkeypatch.setenv("AGENT_BOM_TRUST_PROXY_AUTH_SECRET", "x" * 40)
    posture = derive_auth_posture(api_key_configured=False, allow_unauthenticated=False, listener_host="0.0.0.0")
    assert posture.oidc_bearer is True
    assert posture.trusted_proxy is True
    validate_auth_posture(posture)  # must not raise


def test_programmatic_auth_excludes_browser_only_sso(monkeypatch):
    # oidc_browser is browser-interactive and never gated the programmatic serve
    # check; keep it out of programmatic_auth_configured.
    posture = AuthPosture(
        listener_host="0.0.0.0",
        listener_loopback=False,
        api_key=False,
        oidc_bearer=False,
        oidc_browser=True,
        snowflake_oauth=False,
        scim_bearer=False,
        saml=False,
        trusted_proxy=False,
        anonymous_allowed=False,
        oidc_config_invalid=False,
        oidc_config_error=None,
    )
    assert posture.auth_configured is True  # oidc_browser counts as configured
    assert posture.programmatic_auth_configured is False  # but not for the serve gate


# ── SoT alignment: middleware runtime status derived from the posture ────────


def test_runtime_status_matches_applied_posture(monkeypatch):
    monkeypatch.setenv("AGENT_BOM_OIDC_ISSUER", "https://corp.okta.com")
    monkeypatch.setenv("AGENT_BOM_OIDC_AUDIENCE", "agent-bom")
    posture = derive_auth_posture(api_key_configured=True, allow_unauthenticated=False, listener_host="127.0.0.1")
    apply_auth_posture(posture)
    try:
        status = get_auth_runtime_status()
        stored = get_auth_posture()
        assert stored == posture
        # /health + operator surfaces read the runtime status; it must be derived
        # from the same posture, not a parallel computation.
        assert status["auth_configured"] is posture.auth_configured
        assert status["configured_modes"] == posture.configured_modes
        assert status["recommended_ui_mode"] == posture.recommended_ui_mode
        assert status["unauthenticated_allowed"] is posture.anonymous_allowed
    finally:
        # restore a clean default
        apply_auth_posture(derive_auth_posture(api_key_configured=False, allow_unauthenticated=False, listener_host="127.0.0.1"))


def test_configure_auth_runtime_still_populates_posture():
    # Backward-compat entry point used by SSO tests keeps working and now also
    # stores a coherent posture object.
    configure_auth_runtime(
        api_key_configured=True,
        oidc_enabled=False,
        trusted_proxy_enabled=False,
        unauthenticated_allowed=False,
    )
    posture = get_auth_posture()
    assert posture.api_key is True
    assert "api_key" in posture.configured_modes
    status = get_auth_runtime_status()
    assert status["configured_modes"] == posture.configured_modes


# ── structured startup summary line ──────────────────────────────────────────


def test_summary_line_is_structured_and_single(monkeypatch):
    monkeypatch.setenv("AGENT_BOM_OIDC_ISSUER", "https://corp.okta.com")
    monkeypatch.setenv("AGENT_BOM_OIDC_AUDIENCE", "agent-bom")
    posture = derive_auth_posture(api_key_configured=True, allow_unauthenticated=False, listener_host="0.0.0.0")
    line = posture.summary_line()
    assert "\n" not in line
    assert "sources=" in line
    assert "oidc_bearer" in line and "api_key" in line
    assert "anonymous=off" in line
    assert "listener=0.0.0.0" in line
    assert "non-loopback" in line


def test_startup_log_emits_one_posture_line(caplog, monkeypatch):
    from agent_bom.api.server import _log_control_plane_auth_posture

    monkeypatch.setenv("AGENT_BOM_OIDC_ISSUER", "https://corp.okta.com")
    monkeypatch.setenv("AGENT_BOM_OIDC_AUDIENCE", "agent-bom")
    apply_auth_posture(derive_auth_posture(api_key_configured=True, allow_unauthenticated=False, listener_host="127.0.0.1"))
    try:
        with caplog.at_level(logging.INFO, logger="agent_bom.api.server"):
            _log_control_plane_auth_posture()
        posture_lines = [r.getMessage() for r in caplog.records if "auth posture:" in r.getMessage()]
        assert len(posture_lines) == 1
        assert "sources=" in posture_lines[0]
    finally:
        apply_auth_posture(derive_auth_posture(api_key_configured=False, allow_unauthenticated=False, listener_host="127.0.0.1"))
