from __future__ import annotations

import base64
import os
from pathlib import Path

import pytest

from scripts.deploy.hosted_poc_preflight import main, run_preflight


def _fake_fernet_key() -> str:
    return base64.urlsafe_b64encode(b"0" * 32).decode("ascii")


VALID_ENV = {
    "POSTGRES_PASSWORD": "p" * 40,
    "POSTGRES_APP_PASSWORD": "a" * 40,
    "AGENT_BOM_API_KEY": "k" * 40,
    "AGENT_BOM_AUDIT_HMAC_KEY": "h" * 40,
    "AGENT_BOM_BROWSER_SESSION_SIGNING_KEY": "s" * 40,
    "AGENT_BOM_CONNECTIONS_KEY": _fake_fernet_key(),
    "NEXT_PUBLIC_API_URL": "https://demo.agent-bom.com",
    "CORS_ORIGINS": "https://demo.agent-bom.com,http://ui:3000",
    "AGENT_BOM_SESSION_COOKIE_SECURE": "1",
}


@pytest.fixture(autouse=True)
def hosted_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for key in list(os.environ):
        if key.startswith("AGENT_BOM_") or key in {
            "POSTGRES_PASSWORD",
            "POSTGRES_APP_PASSWORD",
            "NEXT_PUBLIC_API_URL",
            "CORS_ORIGINS",
        }:
            monkeypatch.delenv(key, raising=False)
    for key, value in VALID_ENV.items():
        monkeypatch.setenv(key, value)


def test_preflight_accepts_hosted_https_and_internal_ui_origin(tmp_path: Path) -> None:
    assert run_preflight(tmp_path, skip_compose=True, write_secret=False, force=False) == []


def test_preflight_rejects_localhost_api_url(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("NEXT_PUBLIC_API_URL", "http://localhost:8422")
    monkeypatch.setenv("CORS_ORIGINS", "http://localhost:8422,http://ui:3000")

    errors = run_preflight(tmp_path, skip_compose=True, write_secret=False, force=False)

    assert any("https://" in error for error in errors)
    assert any("localhost" in error for error in errors)


def test_preflight_rejects_wildcard_cors(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("CORS_ORIGINS", "*,https://demo.agent-bom.com")

    errors = run_preflight(tmp_path, skip_compose=True, write_secret=False, force=False)

    assert "CORS_ORIGINS must not contain '*' for hosted POC" in errors


def test_preflight_rejects_unauthenticated_api(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("AGENT_BOM_ALLOW_UNAUTHENTICATED_API", "true")

    errors = run_preflight(tmp_path, skip_compose=True, write_secret=False, force=False)

    assert "AGENT_BOM_ALLOW_UNAUTHENTICATED_API must be unset or false" in errors


def test_preflight_rejects_public_bind_host(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("AGENT_BOM_API_BIND_HOST", "0.0.0.0")

    errors = run_preflight(tmp_path, skip_compose=True, write_secret=False, force=False)

    assert "AGENT_BOM_API_BIND_HOST must stay loopback-only" in errors


def test_preflight_rejects_bad_connections_key(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("AGENT_BOM_CONNECTIONS_KEY", "not-a-fernet-key-but-long-enough-to-pass-length")

    errors = run_preflight(tmp_path, skip_compose=True, write_secret=False, force=False)

    assert any("Fernet key" in error or "32 bytes" in error for error in errors)


def test_preflight_rejects_reused_secret_values(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("POSTGRES_APP_PASSWORD", VALID_ENV["POSTGRES_PASSWORD"])

    errors = run_preflight(tmp_path, skip_compose=True, write_secret=False, force=False)

    assert any("POSTGRES_APP_PASSWORD must not reuse" in error for error in errors)


def test_preflight_rejects_ephemeral_audit_hmac(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("AGENT_BOM_ALLOW_EPHEMERAL_AUDIT_HMAC", "1")

    errors = run_preflight(tmp_path, skip_compose=True, write_secret=False, force=False)

    assert "AGENT_BOM_ALLOW_EPHEMERAL_AUDIT_HMAC must be unset or false" in errors


def test_preflight_can_write_postgres_secret(tmp_path: Path) -> None:
    errors = run_preflight(tmp_path, skip_compose=True, write_secret=True, force=False)

    secret = tmp_path / "deploy" / "secrets" / "postgres_password"
    assert errors == []
    assert secret.read_text(encoding="utf-8") == VALID_ENV["POSTGRES_PASSWORD"]
    assert oct(secret.stat().st_mode & 0o777) == "0o400"


def test_cli_returns_nonzero_on_failed_preflight(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("NEXT_PUBLIC_API_URL", "http://localhost:8422")

    assert main(["--root", str(tmp_path), "--skip-compose"]) == 1
