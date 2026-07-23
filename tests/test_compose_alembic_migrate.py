"""Unit tests for deploy/supabase/postgres/compose_migrate.py helpers."""

from __future__ import annotations

from pathlib import Path

import pytest

from deploy.supabase.postgres import compose_migrate as cm


def test_resolve_database_url_injects_password_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    secret = tmp_path / "postgres_password"
    secret.write_text("s3cret\n", encoding="utf-8")
    monkeypatch.delenv("ALEMBIC_DATABASE_URL", raising=False)
    monkeypatch.setenv("AGENT_BOM_POSTGRES_URL", "postgresql://agent_bom@postgres:5432/agent_bom")
    monkeypatch.setenv("AGENT_BOM_POSTGRES_PASSWORD_FILE", str(secret))

    url = cm._resolve_database_url()
    assert url.startswith("postgresql+psycopg://agent_bom:")
    assert "@postgres:5432/agent_bom" in url
    assert "s3cret" in url


def test_resolve_database_url_keeps_embedded_password(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("AGENT_BOM_POSTGRES_PASSWORD_FILE", raising=False)
    monkeypatch.setenv(
        "AGENT_BOM_POSTGRES_URL",
        "postgresql://agent_bom:already@postgres:5432/agent_bom",
    )
    assert cm._resolve_database_url() == "postgresql+psycopg://agent_bom:already@postgres:5432/agent_bom"


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
