"""Tests for hosted POC preflight — file-only secrets."""

from __future__ import annotations

import base64
import os
from pathlib import Path

import pytest

from scripts.deploy.hosted_poc_preflight import main, run_preflight


def _fake_fernet_key() -> str:
    return base64.urlsafe_b64encode(b"0" * 32).decode("ascii")


VALID_ENV = {
    "NEXT_PUBLIC_API_URL": "https://demo.agent-bom.com",
    "CORS_ORIGINS": "https://demo.agent-bom.com,http://ui:3000",
    "AGENT_BOM_SESSION_COOKIE_SECURE": "1",
}


def _seed_secret_files(root: Path) -> None:
    secrets_dir = root / "deploy" / "secrets"
    secrets_dir.mkdir(parents=True, exist_ok=True)
    (secrets_dir / "postgres_password").write_text("p" * 40, encoding="utf-8")
    (secrets_dir / "postgres_app_password").write_text("a" * 40, encoding="utf-8")
    (secrets_dir / "api_key").write_text("k" * 40, encoding="utf-8")
    (secrets_dir / "audit_hmac_key").write_text("h" * 40, encoding="utf-8")
    (secrets_dir / "browser_session_signing_key").write_text("s" * 40, encoding="utf-8")
    (secrets_dir / "connections_key").write_text(_fake_fernet_key(), encoding="utf-8")


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
    _seed_secret_files(tmp_path)
    assert run_preflight(tmp_path, skip_compose=True, write_secret=False, force=False) == []


def test_preflight_rejects_localhost_api_url(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _seed_secret_files(tmp_path)
    monkeypatch.setenv("NEXT_PUBLIC_API_URL", "http://localhost:8422")
    monkeypatch.setenv("CORS_ORIGINS", "http://localhost:8422,http://ui:3000")

    errors = run_preflight(tmp_path, skip_compose=True, write_secret=False, force=False)

    assert any("https://" in error for error in errors)
    assert any("localhost" in error for error in errors)


def test_preflight_rejects_wildcard_cors(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _seed_secret_files(tmp_path)
    monkeypatch.setenv("CORS_ORIGINS", "*,https://demo.agent-bom.com")

    errors = run_preflight(tmp_path, skip_compose=True, write_secret=False, force=False)

    assert "CORS_ORIGINS must not contain '*' for hosted POC" in errors


def test_preflight_rejects_unauthenticated_api(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _seed_secret_files(tmp_path)
    monkeypatch.setenv("AGENT_BOM_ALLOW_UNAUTHENTICATED_API", "true")

    errors = run_preflight(tmp_path, skip_compose=True, write_secret=False, force=False)

    assert "AGENT_BOM_ALLOW_UNAUTHENTICATED_API must be unset or false" in errors


def test_preflight_rejects_public_bind_host(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _seed_secret_files(tmp_path)
    monkeypatch.setenv("AGENT_BOM_API_BIND_HOST", "0.0.0.0")

    errors = run_preflight(tmp_path, skip_compose=True, write_secret=False, force=False)

    assert "AGENT_BOM_API_BIND_HOST must stay loopback-only" in errors


def test_preflight_rejects_bad_connections_key_file(tmp_path: Path) -> None:
    _seed_secret_files(tmp_path)
    (tmp_path / "deploy" / "secrets" / "connections_key").write_text(
        "not-a-fernet-key-but-long-enough-to-pass-length",
        encoding="utf-8",
    )

    errors = run_preflight(tmp_path, skip_compose=True, write_secret=False, force=False)

    assert any("Fernet key" in error or "32 bytes" in error for error in errors)


def test_preflight_rejects_secret_env(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _seed_secret_files(tmp_path)
    monkeypatch.setenv("AGENT_BOM_API_KEY", "k" * 40)

    errors = run_preflight(tmp_path, skip_compose=True, write_secret=False, force=False)

    assert any("AGENT_BOM_API_KEY must not be set" in error for error in errors)


def test_preflight_rejects_postgres_password_env(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _seed_secret_files(tmp_path)
    monkeypatch.setenv("POSTGRES_PASSWORD", "p" * 40)

    errors = run_preflight(tmp_path, skip_compose=True, write_secret=False, force=False)

    assert any("POSTGRES_PASSWORD must not be set" in error for error in errors)


def test_preflight_rejects_reused_secret_files(tmp_path: Path) -> None:
    secrets_dir = tmp_path / "deploy" / "secrets"
    secrets_dir.mkdir(parents=True)
    shared = "x" * 40
    for name in (
        "postgres_password",
        "postgres_app_password",
        "api_key",
        "audit_hmac_key",
        "browser_session_signing_key",
    ):
        (secrets_dir / name).write_text(shared, encoding="utf-8")
    (secrets_dir / "connections_key").write_text(_fake_fernet_key(), encoding="utf-8")

    errors = run_preflight(tmp_path, skip_compose=True, write_secret=False, force=False)

    assert any("must not reuse the same secret value" in error for error in errors)


def test_preflight_rejects_ephemeral_audit_hmac(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _seed_secret_files(tmp_path)
    monkeypatch.setenv("AGENT_BOM_ALLOW_EPHEMERAL_AUDIT_HMAC", "1")

    errors = run_preflight(tmp_path, skip_compose=True, write_secret=False, force=False)

    assert "AGENT_BOM_ALLOW_EPHEMERAL_AUDIT_HMAC must be unset or false" in errors


def test_preflight_can_write_secret_files(tmp_path: Path) -> None:
    errors = run_preflight(tmp_path, skip_compose=True, write_secret=True, force=False)

    secrets_dir = tmp_path / "deploy" / "secrets"
    assert errors == []
    for name in (
        "postgres_password",
        "postgres_app_password",
        "api_key",
        "audit_hmac_key",
        "browser_session_signing_key",
        "connections_key",
    ):
        path = secrets_dir / name
        assert len(path.read_text(encoding="utf-8")) >= 32
        assert oct(path.stat().st_mode & 0o777) == "0o400"


def test_cli_returns_nonzero_without_printing_secret_values(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _seed_secret_files(tmp_path)
    secret_value = "control-plane-secret-that-must-not-be-logged"
    (tmp_path / "deploy" / "secrets" / "api_key").write_text(secret_value, encoding="utf-8")
    monkeypatch.setenv("NEXT_PUBLIC_API_URL", "http://localhost:8422")
    monkeypatch.setenv("AGENT_BOM_API_KEY", secret_value)

    assert main(["--root", str(tmp_path), "--skip-compose"]) == 1
    captured = capsys.readouterr()
    assert secret_value not in captured.out
    assert secret_value not in captured.err
