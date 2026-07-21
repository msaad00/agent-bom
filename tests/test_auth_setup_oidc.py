"""Tests for the `agent-bom auth setup-oidc` onboarding wizard.

The wizard only collects/validates/emits AGENT_BOM_OIDC_* config; it must not
fork the OIDC mechanism. Discovery is always mocked here — no network.
"""

from __future__ import annotations

import stat
from pathlib import Path
from unittest.mock import patch

from click.testing import CliRunner

from agent_bom.cli import main
from agent_bom.cli._auth_group import (
    OIDC_CALLBACK_PATH,
    build_oidc_env,
    check_issuer_connectivity,
    derive_redirect_uri,
    render_env_block,
)

_DISCOVERY_OK = {
    "authorization_endpoint": "https://accounts.google.com/o/oauth2/v2/auth",
    "token_endpoint": "https://oauth2.googleapis.com/token",
    "jwks_uri": "https://www.googleapis.com/oauth2/v3/certs",
    "issuer": "https://accounts.google.com",
}


# ── callback-path alignment guard ────────────────────────────────────────────


def test_callback_path_matches_versioned_route():
    from agent_bom.api.versioning import API_V1_PREFIX

    assert OIDC_CALLBACK_PATH == f"{API_V1_PREFIX}/auth/oidc/callback"


def test_derive_redirect_uri_appends_callback():
    assert derive_redirect_uri("https://abom.example.com/") == "https://abom.example.com/v1/auth/oidc/callback"
    assert derive_redirect_uri("https://abom.example.com") == "https://abom.example.com/v1/auth/oidc/callback"


def test_derive_redirect_uri_rejects_non_url():
    from agent_bom.cli._auth_group import OIDCSetupError

    for bad in ("", "abom.example.com", "ftp://x"):
        try:
            derive_redirect_uri(bad)
        except OIDCSetupError:
            continue
        raise AssertionError(f"expected rejection for {bad!r}")


# ── build_oidc_env: exact keys/values ────────────────────────────────────────


def test_build_env_google_public_client_single_tenant():
    env = build_oidc_env(
        issuer="https://accounts.google.com",
        client_id="abc.apps.googleusercontent.com",
        redirect_uri="https://abom.example.com/v1/auth/oidc/callback",
        client_secret="",  # PKCE public client
    )
    assert env == {
        "AGENT_BOM_OIDC_ISSUER": "https://accounts.google.com",
        "AGENT_BOM_OIDC_CLIENT_ID": "abc.apps.googleusercontent.com",
        "AGENT_BOM_OIDC_REDIRECT_URI": "https://abom.example.com/v1/auth/oidc/callback",
        "AGENT_BOM_OIDC_AUDIENCE": "abc.apps.googleusercontent.com",  # defaults to client_id
        "AGENT_BOM_OIDC_ALLOW_DEFAULT_TENANT": "1",  # single-tenant self-host
    }
    # order matters for readable output
    assert list(env)[0] == "AGENT_BOM_OIDC_ISSUER"


def test_build_env_confidential_client_includes_secret():
    env = build_oidc_env(
        issuer="https://accounts.google.com",
        client_id="cid",
        redirect_uri="https://x/v1/auth/oidc/callback",
        client_secret="topsecret",
    )
    assert env["AGENT_BOM_OIDC_CLIENT_SECRET"] == "topsecret"


def test_build_env_explicit_audience_and_role_claim():
    env = build_oidc_env(
        issuer="https://idp.example",
        client_id="cid",
        redirect_uri="https://x/v1/auth/oidc/callback",
        audience="agent-bom",
        role_claim="groups",
    )
    assert env["AGENT_BOM_OIDC_AUDIENCE"] == "agent-bom"
    assert env["AGENT_BOM_OIDC_ROLE_CLAIM"] == "groups"


def test_build_env_tenant_claim_disables_default_tenant():
    env = build_oidc_env(
        issuer="https://idp.example",
        client_id="cid",
        redirect_uri="https://x/v1/auth/oidc/callback",
        tenant_claim="org_id",
    )
    assert env["AGENT_BOM_OIDC_TENANT_CLAIM"] == "org_id"
    assert "AGENT_BOM_OIDC_ALLOW_DEFAULT_TENANT" not in env


def test_build_env_requires_core_fields():
    from agent_bom.cli._auth_group import OIDCSetupError

    for kwargs in (
        {"issuer": "", "client_id": "c", "redirect_uri": "https://x/cb"},
        {"issuer": "https://i", "client_id": "", "redirect_uri": "https://x/cb"},
        {"issuer": "https://i", "client_id": "c", "redirect_uri": ""},
    ):
        try:
            build_oidc_env(**kwargs)  # type: ignore[arg-type]
        except OIDCSetupError:
            continue
        raise AssertionError(f"expected rejection for {kwargs}")


# ── connectivity check (mocked discovery, no network) ────────────────────────


def test_connectivity_happy_path():
    with patch("agent_bom.api.oidc.discover_oidc", return_value=dict(_DISCOVERY_OK)) as mock:
        result = check_issuer_connectivity("https://accounts.google.com")
    mock.assert_called_once_with("https://accounts.google.com")
    assert result["reachable"] is True
    assert result["complete"] is True
    assert result["token_endpoint"] == "https://oauth2.googleapis.com/token"


def test_connectivity_unreachable_warns_not_raises():
    from agent_bom.api.oidc import OIDCError

    with patch("agent_bom.api.oidc.discover_oidc", side_effect=OIDCError("Failed to fetch discovery")):
        result = check_issuer_connectivity("https://unreachable.example")
    assert result["reachable"] is False
    assert result["complete"] is False
    assert "Failed to fetch" in str(result["warning"])


def test_connectivity_incomplete_when_endpoint_missing():
    partial = {"authorization_endpoint": "https://a", "jwks_uri": "https://j"}  # no token_endpoint
    with patch("agent_bom.api.oidc.discover_oidc", return_value=partial):
        result = check_issuer_connectivity("https://idp.example")
    assert result["reachable"] is True
    assert result["complete"] is False
    assert "token_endpoint" in result["missing"]  # type: ignore[operator]


# ── render ───────────────────────────────────────────────────────────────────


def test_render_env_block_is_dotenv():
    block = render_env_block(build_oidc_env(issuer="https://i", client_id="c", redirect_uri="https://x/cb"))
    assert "AGENT_BOM_OIDC_ISSUER=https://i" in block
    assert block.startswith("# agent-bom OIDC")


# ── CLI: non-interactive end to end ──────────────────────────────────────────


def test_cli_non_interactive_emits_env_block():
    runner = CliRunner()
    with patch("agent_bom.api.oidc.discover_oidc", return_value=dict(_DISCOVERY_OK)):
        result = runner.invoke(
            main,
            [
                "auth",
                "setup-oidc",
                "--non-interactive",
                "--provider",
                "google",
                "--client-id",
                "cid.apps.googleusercontent.com",
                "--client-secret",
                "shh",
                "--base-url",
                "https://abom.example.com",
            ],
        )
    assert result.exit_code == 0, result.output
    assert "AGENT_BOM_OIDC_ISSUER=https://accounts.google.com" in result.output
    assert "AGENT_BOM_OIDC_REDIRECT_URI=https://abom.example.com/v1/auth/oidc/callback" in result.output
    assert "AGENT_BOM_OIDC_AUDIENCE=cid.apps.googleusercontent.com" in result.output
    assert "AGENT_BOM_OIDC_CLIENT_SECRET=shh" in result.output
    assert "Google Cloud Console" in result.output
    # Nothing written without --write.
    assert "Not written" in result.output


def test_cli_non_interactive_missing_client_id_errors():
    runner = CliRunner()
    with patch("agent_bom.api.oidc.discover_oidc", return_value=dict(_DISCOVERY_OK)):
        result = runner.invoke(main, ["auth", "setup-oidc", "--non-interactive", "--provider", "google", "--base-url", "https://x.example"])
    assert result.exit_code != 0
    assert "client-id" in result.output


def test_cli_generic_provider_requires_issuer():
    runner = CliRunner()
    result = runner.invoke(
        main,
        ["auth", "setup-oidc", "--non-interactive", "--provider", "generic", "--client-id", "c", "--base-url", "https://x.example"],
    )
    assert result.exit_code != 0
    assert "issuer" in result.output.lower()


def test_cli_write_mode_creates_0644_file(tmp_path: Path):
    out = tmp_path / "secrets" / "oidc.env"
    runner = CliRunner()
    with patch("agent_bom.api.oidc.discover_oidc", return_value=dict(_DISCOVERY_OK)):
        result = runner.invoke(
            main,
            [
                "auth",
                "setup-oidc",
                "--non-interactive",
                "--provider",
                "google",
                "--client-id",
                "cid",
                "--client-secret",
                "topsecret",
                "--base-url",
                "https://abom.example.com",
                "--write",
                "--output",
                str(out),
            ],
        )
    assert result.exit_code == 0, result.output
    assert out.exists()
    mode = stat.S_IMODE(out.stat().st_mode)
    assert mode == 0o644, oct(mode)
    content = out.read_text()
    assert "AGENT_BOM_OIDC_CLIENT_ID=cid" in content
    assert "AGENT_BOM_OIDC_CLIENT_SECRET=topsecret" in content
    assert "Contains a client secret" in result.output


def test_cli_offline_issuer_warns_but_still_emits(tmp_path: Path):
    from agent_bom.api.oidc import OIDCError

    runner = CliRunner()
    with patch("agent_bom.api.oidc.discover_oidc", side_effect=OIDCError("Failed to fetch discovery: unreachable")):
        result = runner.invoke(
            main,
            [
                "auth",
                "setup-oidc",
                "--non-interactive",
                "--provider",
                "google",
                "--client-id",
                "cid",
                "--base-url",
                "https://abom.example.com",
            ],
        )
    assert result.exit_code == 0, result.output
    assert "Could not reach issuer discovery" in result.output
    assert "AGENT_BOM_OIDC_ISSUER=https://accounts.google.com" in result.output


def test_cli_interactive_prompts_and_confirms_write(tmp_path: Path):
    out = tmp_path / "oidc.env"
    runner = CliRunner()
    # provider preset? -> y ; issuer default ; client id ; secret ; base url ; audience default ; write? -> y
    stdin = "\n".join(["y", "", "cid.apps.googleusercontent.com", "s3cret", "https://abom.example.com", "", "y"]) + "\n"
    with (
        patch("agent_bom.api.oidc.discover_oidc", return_value=dict(_DISCOVERY_OK)),
        patch("agent_bom.cli._auth_group._stdin_is_tty", return_value=True),
    ):
        result = runner.invoke(main, ["auth", "setup-oidc", "--output", str(out)], input=stdin)
    assert result.exit_code == 0, result.output
    assert out.exists()
    content = out.read_text()
    assert "AGENT_BOM_OIDC_ISSUER=https://accounts.google.com" in content
    assert "AGENT_BOM_OIDC_CLIENT_SECRET=s3cret" in content
    assert "AGENT_BOM_OIDC_REDIRECT_URI=https://abom.example.com/v1/auth/oidc/callback" in content


def test_auth_group_listed_in_help():
    runner = CliRunner()
    result = runner.invoke(main, ["--help"])
    assert result.exit_code == 0
    assert "auth" in result.output
    sub = runner.invoke(main, ["auth", "--help"])
    assert sub.exit_code == 0
    assert "setup-oidc" in sub.output
