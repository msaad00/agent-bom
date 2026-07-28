"""Unit tests for deploy/supabase/postgres/compose_migrate.py helpers."""

from __future__ import annotations

from pathlib import Path

import pytest

from deploy.supabase.postgres import compose_migrate as cm


def test_resolve_database_url_requires_explicit_admin_url(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    secret = tmp_path / "postgres_password"
    secret.write_text("s3cret\n", encoding="utf-8")
    monkeypatch.delenv("ALEMBIC_DATABASE_URL", raising=False)
    monkeypatch.setenv("AGENT_BOM_POSTGRES_URL", "postgresql://agent_bom@postgres:5432/agent_bom")
    monkeypatch.setenv("AGENT_BOM_POSTGRES_PASSWORD_FILE", str(secret))

    with pytest.raises(SystemExit, match="ALEMBIC_DATABASE_URL"):
        cm._resolve_database_url()


def test_resolve_database_url_keeps_embedded_password(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("AGENT_BOM_POSTGRES_PASSWORD_FILE", raising=False)
    monkeypatch.setenv(
        "ALEMBIC_DATABASE_URL",
        "postgresql://agent_bom:already@postgres:5432/agent_bom",
    )
    assert cm._resolve_database_url() == "postgresql+psycopg://agent_bom:already@postgres:5432/agent_bom"


def test_resolve_database_url_percent_encodes_spaces_in_userinfo(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    secret = tmp_path / "postgres_password"
    secret.write_text("p@ss:/?#%&+ space\n", encoding="utf-8")
    monkeypatch.setenv("ALEMBIC_DATABASE_URL", "postgresql://agent_bom@postgres:5432/agent_bom")
    monkeypatch.setenv("ALEMBIC_DATABASE_PASSWORD_FILE", str(secret))

    assert "p%40ss%3A%2F%3F%23%25%26%2B%20space" in cm._resolve_database_url()


def test_resolve_database_url_uses_distinct_alembic_password_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    admin_secret = tmp_path / "postgres_admin_password"
    admin_secret.write_text("admin:p@ss\n", encoding="utf-8")
    app_secret = tmp_path / "postgres_app_password"
    app_secret.write_text("app-secret\n", encoding="utf-8")
    monkeypatch.setenv("ALEMBIC_DATABASE_URL", "postgresql://agent_bom@postgres:5432/agent_bom")
    monkeypatch.setenv("ALEMBIC_DATABASE_PASSWORD_FILE", str(admin_secret))
    monkeypatch.setenv("AGENT_BOM_POSTGRES_URL", "postgresql://agent_bom_app@postgres:5432/agent_bom")
    monkeypatch.setenv("AGENT_BOM_POSTGRES_PASSWORD_FILE", str(app_secret))

    url = cm._resolve_database_url()

    assert "agent_bom:admin%3Ap%40ss@postgres" in url
    assert "app-secret" not in url


@pytest.mark.parametrize(
    ("raw", "expected"),
    (
        ("postgres://user@db/app", "postgresql+psycopg://user@db/app"),
        ("postgresql://user@db/app", "postgresql+psycopg://user@db/app"),
        ("postgresql+psycopg://user@db/app", "postgresql+psycopg://user@db/app"),
        ("postgresql+asyncpg://user@db/app", "postgresql+asyncpg://user@db/app"),
    ),
)
def test_normalize_sqlalchemy_url_selects_shipped_driver(raw: str, expected: str) -> None:
    assert cm._normalize_sqlalchemy_url(raw) == expected


def test_alembic_env_normalizes_driverless_postgres_urls() -> None:
    env_source = (Path(__file__).parents[1] / "deploy/supabase/postgres/alembic/env.py").read_text(encoding="utf-8")
    assert "from deploy.supabase.postgres.compose_migrate import _normalize_sqlalchemy_url" in env_source
    assert "url = _normalize_sqlalchemy_url(url)" in env_source


def test_alembic_env_never_falls_back_to_the_runtime_app_url() -> None:
    env_source = (Path(__file__).parents[1] / "deploy/supabase/postgres/alembic/env.py").read_text(encoding="utf-8")

    assert 'os.environ.get("ALEMBIC_DATABASE_URL") or os.environ.get("AGENT_BOM_POSTGRES_URL")' not in env_source
    assert "Set ALEMBIC_DATABASE_URL before running Alembic migrations." in env_source


def test_main_reconciles_runtime_role_passwords_after_every_upgrade(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    calls: list[object] = []
    monkeypatch.setattr(cm, "_repo_root", lambda: tmp_path)
    monkeypatch.setattr(cm, "_resolve_database_url", lambda: "postgresql+psycopg://admin@db/app")
    monkeypatch.setattr(cm, "_needs_baseline_stamp", lambda _url: False)
    monkeypatch.setattr(cm, "_run_alembic", lambda _root, *args: calls.append(args))
    monkeypatch.setattr(cm, "_reconcile_runtime_role_passwords", lambda url: calls.append(("reconcile", url)))

    assert cm.main() == 0
    assert calls == [
        (cm.ALEMBIC_CONFIG, "upgrade", "head"),
        ("reconcile", "postgresql+psycopg://admin@db/app"),
    ]


def test_main_preserves_custom_alembic_config(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    calls: list[tuple[str, ...]] = []
    monkeypatch.setattr(cm, "_repo_root", lambda: tmp_path)
    monkeypatch.setattr(cm, "_resolve_database_url", lambda: "postgresql+psycopg://admin@db/app")
    monkeypatch.setattr(cm, "_needs_baseline_stamp", lambda _url: False)
    monkeypatch.setattr(cm, "_run_alembic", lambda _root, *args: calls.append(args))
    monkeypatch.setattr(cm, "_reconcile_runtime_role_passwords", lambda _url: None)

    assert cm.main(["--config", "deploy/custom-alembic.ini"]) == 0
    assert calls == [("deploy/custom-alembic.ini", "upgrade", "head")]
