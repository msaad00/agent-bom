from __future__ import annotations

import base64
import os
from pathlib import Path

import pytest

from scripts.deploy.hosted_poc_preflight import main, run_preflight


def _fake_fernet_key() -> str:
    return base64.urlsafe_b64encode(b"0" * 32).decode("ascii")


VALID_ENV = {
    "AGENT_BOM_API_KEY": "k" * 40,
    "AGENT_BOM_AUDIT_HMAC_KEY": "h" * 40,
    "AGENT_BOM_BROWSER_SESSION_SIGNING_KEY": "s" * 40,
    "AGENT_BOM_CONNECTIONS_KEY": _fake_fernet_key(),
    "NEXT_PUBLIC_API_URL": "https://demo.agent-bom.com",
    "CORS_ORIGINS": "https://demo.agent-bom.com,http://ui:3000",
    "AGENT_BOM_SESSION_COOKIE_SECURE": "1",
}


def _seed_postgres_secrets(root: Path) -> None:
    secrets_dir = root / "deploy" / "secrets"
    secrets_dir.mkdir(parents=True, exist_ok=True)
    (secrets_dir / "postgres_password").write_text("p" * 40, encoding="utf-8")
    (secrets_dir / "postgres_app_password").write_text("a" * 40, encoding="utf-8")


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
    _seed_postgres_secrets(tmp_path)
    assert run_preflight(tmp_path, skip_compose=True, write_secret=False, force=False) == []


def test_preflight_rejects_localhost_api_url(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _seed_postgres_secrets(tmp_path)
    monkeypatch.setenv("NEXT_PUBLIC_API_URL", "http://localhost:8422")
    monkeypatch.setenv("CORS_ORIGINS", "http://localhost:8422,http://ui:3000")

    errors = run_preflight(tmp_path, skip_compose=True, write_secret=False, force=False)

    assert any("https://" in error for error in errors)
    assert any("localhost" in error for error in errors)


def test_preflight_rejects_wildcard_cors(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _seed_postgres_secrets(tmp_path)
    monkeypatch.setenv("CORS_ORIGINS", "*,https://demo.agent-bom.com")

    errors = run_preflight(tmp_path, skip_compose=True, write_secret=False, force=False)

    assert "CORS_ORIGINS must not contain '*' for hosted POC" in errors


def test_preflight_rejects_unauthenticated_api(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _seed_postgres_secrets(tmp_path)
    monkeypatch.setenv("AGENT_BOM_ALLOW_UNAUTHENTICATED_API", "true")

    errors = run_preflight(tmp_path, skip_compose=True, write_secret=False, force=False)

    assert "AGENT_BOM_ALLOW_UNAUTHENTICATED_API must be unset or false" in errors


def test_preflight_rejects_public_bind_host(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _seed_postgres_secrets(tmp_path)
    monkeypatch.setenv("AGENT_BOM_API_BIND_HOST", "0.0.0.0")

    errors = run_preflight(tmp_path, skip_compose=True, write_secret=False, force=False)

    assert "AGENT_BOM_API_BIND_HOST must stay loopback-only" in errors


def test_preflight_rejects_bad_connections_key(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _seed_postgres_secrets(tmp_path)
    monkeypatch.setenv("AGENT_BOM_CONNECTIONS_KEY", "not-a-fernet-key-but-long-enough-to-pass-length")

    errors = run_preflight(tmp_path, skip_compose=True, write_secret=False, force=False)

    assert any("Fernet key" in error or "32 bytes" in error for error in errors)


def test_preflight_rejects_postgres_password_env(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _seed_postgres_secrets(tmp_path)
    monkeypatch.setenv("POSTGRES_PASSWORD", "p" * 40)

    errors = run_preflight(tmp_path, skip_compose=True, write_secret=False, force=False)

    assert any("POSTGRES_PASSWORD must not be set" in error for error in errors)


def test_preflight_rejects_reused_secret_files(tmp_path: Path) -> None:
    secrets_dir = tmp_path / "deploy" / "secrets"
    secrets_dir.mkdir(parents=True)
    shared = "x" * 40
    (secrets_dir / "postgres_password").write_text(shared, encoding="utf-8")
    (secrets_dir / "postgres_app_password").write_text(shared, encoding="utf-8")

    errors = run_preflight(tmp_path, skip_compose=True, write_secret=False, force=False)

    assert any("must not reuse the same secret value" in error for error in errors)


def test_preflight_rejects_ephemeral_audit_hmac(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _seed_postgres_secrets(tmp_path)
    monkeypatch.setenv("AGENT_BOM_ALLOW_EPHEMERAL_AUDIT_HMAC", "1")

    errors = run_preflight(tmp_path, skip_compose=True, write_secret=False, force=False)

    assert "AGENT_BOM_ALLOW_EPHEMERAL_AUDIT_HMAC must be unset or false" in errors


def test_preflight_can_write_postgres_secrets(tmp_path: Path) -> None:
    errors = run_preflight(tmp_path, skip_compose=True, write_secret=True, force=False)

    admin = tmp_path / "deploy" / "secrets" / "postgres_password"
    app = tmp_path / "deploy" / "secrets" / "postgres_app_password"
    assert errors == []
    assert len(admin.read_text(encoding="utf-8")) >= 32
    assert len(app.read_text(encoding="utf-8")) >= 32
    assert admin.read_text(encoding="utf-8") != app.read_text(encoding="utf-8")
    assert oct(admin.stat().st_mode & 0o777) == "0o400"
    assert oct(app.stat().st_mode & 0o777) == "0o400"


def test_cli_returns_nonzero_on_failed_preflight(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _seed_postgres_secrets(tmp_path)
    monkeypatch.setenv("NEXT_PUBLIC_API_URL", "http://localhost:8422")

    assert main(["--root", str(tmp_path), "--skip-compose"]) == 1
