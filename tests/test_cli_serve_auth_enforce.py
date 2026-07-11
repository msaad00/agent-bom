"""CLI auth-enforcement tests for `agent-bom serve` (#2196, #3803 audit fixes).

Verify `_enforce_auth_defaults` recognises every accepted auth path
(API key, OIDC, SCIM bearer, SAML SSO) and emits a loud warning when
`--allow-insecure-no-auth` is passed alongside a configured auth method
instead of silently doing nothing.
"""

from __future__ import annotations

import click
import pytest

from agent_bom.cli._server import (
    _api_auth_summary,
    _enforce_auth_defaults,
    _generate_dev_api_key,
    _should_auto_generate_dev_key,
)


def test_enforce_auth_defaults_loopback_always_passes() -> None:
    """Loopback binds skip the check entirely."""
    _enforce_auth_defaults("serve", "127.0.0.1", api_key=None, allow_insecure_no_auth=False)
    _enforce_auth_defaults("serve", "localhost", api_key=None, allow_insecure_no_auth=False)
    _enforce_auth_defaults("serve", "::1", api_key=None, allow_insecure_no_auth=False)


def test_enforce_auth_defaults_api_key_satisfies_check() -> None:
    """API key set => non-loopback bind allowed without --allow-insecure-no-auth."""
    _enforce_auth_defaults("serve", "0.0.0.0", api_key="secret", allow_insecure_no_auth=False)


def test_enforce_auth_defaults_scim_token_satisfies_check(monkeypatch: pytest.MonkeyPatch) -> None:
    """SCIM bearer token alone is recognised as a valid auth path on non-loopback.

    Pre-#2196, only API key and OIDC were recognised, so operators with only
    SCIM configured hit a misleading "set api_key or use --allow-insecure-no-auth"
    error.
    """
    monkeypatch.setenv("AGENT_BOM_SCIM_BEARER_TOKEN", "x" * 32)
    _enforce_auth_defaults("serve", "0.0.0.0", api_key=None, allow_insecure_no_auth=False)


def _set_saml_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Configure the minimum SAML IdP + SP env for `SAMLConfig.enabled` to be True."""
    monkeypatch.setenv("AGENT_BOM_SAML_IDP_ENTITY_ID", "https://idp.example.com/metadata")
    monkeypatch.setenv("AGENT_BOM_SAML_IDP_SSO_URL", "https://idp.example.com/sso")
    monkeypatch.setenv("AGENT_BOM_SAML_IDP_X509_CERT", "-----BEGIN CERTIFICATE-----test-----END CERTIFICATE-----")
    monkeypatch.setenv("AGENT_BOM_SAML_SP_ENTITY_ID", "https://agent-bom.example.com/saml/metadata")
    monkeypatch.setenv("AGENT_BOM_SAML_SP_ACS_URL", "https://agent-bom.example.com/v1/auth/saml/login")


def test_enforce_auth_defaults_saml_satisfies_check(monkeypatch: pytest.MonkeyPatch) -> None:
    """SAML SSO config alone is recognised as a valid auth path on non-loopback.

    Regression for #3803: SAML-only deployments (browser SSO minting short-lived
    session API keys) previously hit the misleading "set api_key / OIDC / SCIM or
    use --allow-insecure-no-auth" refusal even though the API-key middleware still
    authenticates every request when SAML is configured.
    """
    monkeypatch.delenv("AGENT_BOM_SCIM_BEARER_TOKEN", raising=False)
    monkeypatch.delenv("AGENT_BOM_OIDC_ISSUER", raising=False)
    _set_saml_env(monkeypatch)
    _enforce_auth_defaults("serve", "0.0.0.0", api_key=None, allow_insecure_no_auth=False)


def test_enforce_auth_defaults_partial_saml_still_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    """An incomplete SAML config (missing SP settings) does NOT count as auth.

    Only a fully-formed IdP + SP config satisfies `SAMLConfig.enabled`; a stray
    IdP entity id alone must stay fail-closed on a non-loopback bind.
    """
    monkeypatch.delenv("AGENT_BOM_SCIM_BEARER_TOKEN", raising=False)
    monkeypatch.delenv("AGENT_BOM_OIDC_ISSUER", raising=False)
    monkeypatch.delenv("AGENT_BOM_SAML_SP_ENTITY_ID", raising=False)
    monkeypatch.delenv("AGENT_BOM_SAML_SP_ACS_URL", raising=False)
    monkeypatch.setenv("AGENT_BOM_SAML_IDP_ENTITY_ID", "https://idp.example.com/metadata")
    with pytest.raises(click.ClickException, match="Refusing to expose"):
        _enforce_auth_defaults("serve", "0.0.0.0", api_key=None, allow_insecure_no_auth=False)


def test_enforce_auth_defaults_no_auth_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    """Non-loopback bind with no auth path AND no override raises ClickException."""
    _clear_auth_env(monkeypatch)
    with pytest.raises(click.ClickException, match="Refusing to expose"):
        _enforce_auth_defaults("serve", "0.0.0.0", api_key=None, allow_insecure_no_auth=False)


def test_enforce_auth_defaults_explicit_override_passes(monkeypatch: pytest.MonkeyPatch) -> None:
    """--allow-insecure-no-auth allows non-loopback bind even without auth."""
    _clear_auth_env(monkeypatch)
    _enforce_auth_defaults("serve", "0.0.0.0", api_key=None, allow_insecure_no_auth=True)


def test_enforce_auth_defaults_warns_on_conflict(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """When --allow-insecure-no-auth AND an auth method are both set, warn.

    The CLI flag's name is misleading otherwise: requests still get
    authenticated by the SCIM/OIDC/API-key middleware. The warning makes
    the actual posture visible.
    """
    monkeypatch.setenv("AGENT_BOM_SCIM_BEARER_TOKEN", "x" * 32)
    _enforce_auth_defaults("serve", "0.0.0.0", api_key=None, allow_insecure_no_auth=True)
    captured = capsys.readouterr()
    assert "warning" in captured.err.lower()
    assert "SCIM-bearer" in captured.err


def test_enforce_auth_defaults_warns_on_api_key_conflict(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """API key + --allow-insecure-no-auth also warns."""
    monkeypatch.delenv("AGENT_BOM_SCIM_BEARER_TOKEN", raising=False)
    _enforce_auth_defaults("serve", "0.0.0.0", api_key="secret", allow_insecure_no_auth=True)
    captured = capsys.readouterr()
    assert "warning" in captured.err.lower()
    assert "API-key" in captured.err


def test_enforce_auth_defaults_warns_on_saml_conflict(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """SAML + --allow-insecure-no-auth warns and names SAML in the active set."""
    monkeypatch.delenv("AGENT_BOM_SCIM_BEARER_TOKEN", raising=False)
    monkeypatch.delenv("AGENT_BOM_OIDC_ISSUER", raising=False)
    _set_saml_env(monkeypatch)
    _enforce_auth_defaults("serve", "0.0.0.0", api_key=None, allow_insecure_no_auth=True)
    captured = capsys.readouterr()
    assert "warning" in captured.err.lower()
    assert "SAML" in captured.err


def _clear_auth_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in (
        "AGENT_BOM_API_KEY",
        "AGENT_BOM_API_KEYS",
        "AGENT_BOM_OIDC_ISSUER",
        "AGENT_BOM_OIDC_TENANT_PROVIDERS_JSON",
        "AGENT_BOM_TRUST_PROXY_AUTH",
        "AGENT_BOM_SCIM_BEARER_TOKEN",
        "AGENT_BOM_SAML_IDP_ENTITY_ID",
        "AGENT_BOM_SAML_IDP_SSO_URL",
        "AGENT_BOM_SAML_IDP_X509_CERT",
        "AGENT_BOM_SAML_SP_ENTITY_ID",
        "AGENT_BOM_SAML_SP_ACS_URL",
        "AGENT_BOM_ALLOW_UNAUTHENTICATED_API",
        "AGENT_BOM_NO_AUTO_DEV_KEY",
    ):
        monkeypatch.delenv(name, raising=False)


def test_resolve_allow_unauthenticated_honors_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """The env opt-out must resolve on the CLI path even when the flag is False.

    Regression for the P0 bug: `serve` passes --allow-insecure-no-auth as an
    explicit False, which previously masked AGENT_BOM_ALLOW_UNAUTHENTICATED_API=1.
    """
    from agent_bom.cli._server import _resolve_allow_unauthenticated

    _clear_auth_env(monkeypatch)
    assert _resolve_allow_unauthenticated(False) is False
    monkeypatch.setenv("AGENT_BOM_ALLOW_UNAUTHENTICATED_API", "1")
    assert _resolve_allow_unauthenticated(False) is True
    _clear_auth_env(monkeypatch)
    assert _resolve_allow_unauthenticated(True) is True


def test_api_auth_summary_claims_unauthenticated_only_when_effective(monkeypatch: pytest.MonkeyPatch) -> None:
    """Banner says 'local unauthenticated mode' iff the server truly allows it."""
    _clear_auth_env(monkeypatch)
    # Loopback + env opt-out => unauthenticated is real => banner is truthful.
    monkeypatch.setenv("AGENT_BOM_ALLOW_UNAUTHENTICATED_API", "1")
    summary = _api_auth_summary(
        host="127.0.0.1",
        api_key=None,
        oidc_enabled=False,
        allow_unauthenticated=True,
    )
    assert "local unauthenticated mode" in summary


def test_api_auth_summary_is_accurate_when_failing_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    """With no auth and no opt-out, the banner must NOT claim unauthenticated access."""
    _clear_auth_env(monkeypatch)
    summary = _api_auth_summary(
        host="127.0.0.1",
        api_key=None,
        oidc_enabled=False,
        allow_unauthenticated=False,
    )
    assert "unauthenticated" not in summary.lower()
    assert "fail closed" in summary.lower()
    assert "--allow-insecure-no-auth" in summary


def test_api_auth_summary_prefers_api_key(monkeypatch: pytest.MonkeyPatch) -> None:
    """A configured API key is reported even if the env opt-out is also set."""
    _clear_auth_env(monkeypatch)
    monkeypatch.setenv("AGENT_BOM_ALLOW_UNAUTHENTICATED_API", "1")
    summary = _api_auth_summary(
        host="127.0.0.1",
        api_key="secret",
        oidc_enabled=False,
        allow_unauthenticated=True,
    )
    assert "API key required" in summary


# ── Zero-config loopback dev key ────────────────────────────────────────────


def test_should_auto_generate_dev_key_loopback_no_auth(monkeypatch: pytest.MonkeyPatch) -> None:
    """Bare loopback serve with no auth configured => auto dev key."""
    _clear_auth_env(monkeypatch)
    for host in ("127.0.0.1", "localhost", "::1"):
        assert _should_auto_generate_dev_key(host=host, api_key=None, allow_insecure_no_auth=False) is True


def test_should_auto_generate_dev_key_never_on_non_loopback(monkeypatch: pytest.MonkeyPatch) -> None:
    """A non-loopback bind must NEVER auto-generate a key (stays fail-closed)."""
    _clear_auth_env(monkeypatch)
    assert _should_auto_generate_dev_key(host="0.0.0.0", api_key=None, allow_insecure_no_auth=False) is False
    assert _should_auto_generate_dev_key(host="192.168.1.10", api_key=None, allow_insecure_no_auth=False) is False


def test_should_auto_generate_dev_key_opt_out(monkeypatch: pytest.MonkeyPatch) -> None:
    """AGENT_BOM_NO_AUTO_DEV_KEY=1 restores the current fail-closed behaviour."""
    _clear_auth_env(monkeypatch)
    monkeypatch.setenv("AGENT_BOM_NO_AUTO_DEV_KEY", "1")
    assert _should_auto_generate_dev_key(host="127.0.0.1", api_key=None, allow_insecure_no_auth=False) is False


def test_should_auto_generate_dev_key_explicit_auth_wins(monkeypatch: pytest.MonkeyPatch) -> None:
    """An explicit key/flag/env auth path suppresses the auto dev key."""
    _clear_auth_env(monkeypatch)
    assert _should_auto_generate_dev_key(host="127.0.0.1", api_key="secret", allow_insecure_no_auth=False) is False
    assert _should_auto_generate_dev_key(host="127.0.0.1", api_key=None, allow_insecure_no_auth=True) is False

    _clear_auth_env(monkeypatch)
    monkeypatch.setenv("AGENT_BOM_API_KEYS", "raw:admin")
    assert _should_auto_generate_dev_key(host="127.0.0.1", api_key=None, allow_insecure_no_auth=False) is False

    _clear_auth_env(monkeypatch)
    monkeypatch.setenv("AGENT_BOM_SCIM_BEARER_TOKEN", "x" * 32)
    assert _should_auto_generate_dev_key(host="127.0.0.1", api_key=None, allow_insecure_no_auth=False) is False

    _clear_auth_env(monkeypatch)
    monkeypatch.setenv("AGENT_BOM_ALLOW_UNAUTHENTICATED_API", "1")
    assert _should_auto_generate_dev_key(host="127.0.0.1", api_key=None, allow_insecure_no_auth=False) is False

    _clear_auth_env(monkeypatch)
    monkeypatch.setenv("AGENT_BOM_TRUST_PROXY_AUTH", "1")
    assert _should_auto_generate_dev_key(host="127.0.0.1", api_key=None, allow_insecure_no_auth=False) is False

    _clear_auth_env(monkeypatch)
    _set_saml_env(monkeypatch)
    assert _should_auto_generate_dev_key(host="127.0.0.1", api_key=None, allow_insecure_no_auth=False) is False


def test_api_auth_summary_reports_saml(monkeypatch: pytest.MonkeyPatch) -> None:
    """With only SAML configured, the banner names SAML rather than fail-closed."""
    _clear_auth_env(monkeypatch)
    _set_saml_env(monkeypatch)
    summary = _api_auth_summary(
        host="0.0.0.0",
        api_key=None,
        oidc_enabled=False,
        allow_unauthenticated=False,
    )
    assert "SAML" in summary
    assert "fail closed" not in summary.lower()


def test_generate_dev_api_key_is_prefixed_and_unique() -> None:
    """Dev keys carry the abk_ prefix and are per-call random."""
    first = _generate_dev_api_key()
    second = _generate_dev_api_key()
    assert first.startswith("abk_")
    assert second.startswith("abk_")
    assert first != second


def test_api_auth_summary_reports_dev_key(monkeypatch: pytest.MonkeyPatch) -> None:
    """When a dev key is minted (and no explicit key), the banner is honest about it."""
    _clear_auth_env(monkeypatch)
    summary = _api_auth_summary(
        host="127.0.0.1",
        api_key=None,
        oidc_enabled=False,
        allow_unauthenticated=False,
        dev_api_key="abk_example",
    )
    assert "auto dev API key" in summary
    assert "loopback" in summary.lower()
    assert "fail closed" not in summary.lower()


def test_api_auth_summary_explicit_key_beats_dev_key(monkeypatch: pytest.MonkeyPatch) -> None:
    """An explicit --api-key always wins over an (unexpected) dev key value."""
    _clear_auth_env(monkeypatch)
    summary = _api_auth_summary(
        host="127.0.0.1",
        api_key="secret",
        oidc_enabled=False,
        allow_unauthenticated=False,
        dev_api_key="abk_example",
    )
    assert "API key required" in summary
