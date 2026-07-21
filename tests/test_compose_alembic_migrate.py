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
    assert url.startswith("postgresql://agent_bom:")
    assert "@postgres:5432/agent_bom" in url
    assert "s3cret" in url


def test_resolve_database_url_keeps_embedded_password(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("AGENT_BOM_POSTGRES_PASSWORD_FILE", raising=False)
    monkeypatch.setenv(
        "AGENT_BOM_POSTGRES_URL",
        "postgresql://agent_bom:already@postgres:5432/agent_bom",
    )
    assert cm._resolve_database_url() == "postgresql://agent_bom:already@postgres:5432/agent_bom"
