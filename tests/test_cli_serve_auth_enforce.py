"""CLI auth-enforcement tests for `agent-bom serve` (#2196 audit fix).

Verify `_enforce_auth_defaults` recognises every accepted auth path
(API key, OIDC, SCIM bearer) and emits a loud warning when
`--allow-insecure-no-auth` is passed alongside a configured auth method
instead of silently doing nothing.
"""

from __future__ import annotations

import click
import pytest

from agent_bom.cli._server import _api_auth_summary, _enforce_auth_defaults


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


def test_enforce_auth_defaults_no_auth_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    """Non-loopback bind with no auth path AND no override raises ClickException."""
    monkeypatch.delenv("AGENT_BOM_SCIM_BEARER_TOKEN", raising=False)
    monkeypatch.delenv("AGENT_BOM_OIDC_ISSUER", raising=False)
    with pytest.raises(click.ClickException, match="Refusing to expose"):
        _enforce_auth_defaults("serve", "0.0.0.0", api_key=None, allow_insecure_no_auth=False)


def test_enforce_auth_defaults_explicit_override_passes(monkeypatch: pytest.MonkeyPatch) -> None:
    """--allow-insecure-no-auth allows non-loopback bind even without auth."""
    monkeypatch.delenv("AGENT_BOM_SCIM_BEARER_TOKEN", raising=False)
    monkeypatch.delenv("AGENT_BOM_OIDC_ISSUER", raising=False)
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


def _clear_auth_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in (
        "AGENT_BOM_API_KEY",
        "AGENT_BOM_API_KEYS",
        "AGENT_BOM_OIDC_ISSUER",
        "AGENT_BOM_OIDC_TENANT_PROVIDERS_JSON",
        "AGENT_BOM_TRUST_PROXY_AUTH",
        "AGENT_BOM_SCIM_BEARER_TOKEN",
        "AGENT_BOM_ALLOW_UNAUTHENTICATED_API",
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
