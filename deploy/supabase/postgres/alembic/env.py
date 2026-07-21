from __future__ import annotations

import os
from logging.config import fileConfig

from alembic import context
from sqlalchemy import engine_from_config, pool

config = context.config

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = None


def _database_url() -> str:
    """Resolve the Alembic DSN.

    Prefer ``ALEMBIC_DATABASE_URL``, else ``AGENT_BOM_POSTGRES_URL``. When the
    URL has a username but no embedded password, load
    ``AGENT_BOM_POSTGRES_PASSWORD_FILE`` (Docker Compose secret mount) the same
    way the API does — Compose must not put bootstrap passwords in env values.
    """
    from pathlib import Path
    from urllib.parse import quote_plus, urlsplit, urlunsplit

    url = os.environ.get("ALEMBIC_DATABASE_URL") or os.environ.get("AGENT_BOM_POSTGRES_URL")
    if not url:
        raise RuntimeError("Set ALEMBIC_DATABASE_URL or AGENT_BOM_POSTGRES_URL before running Alembic migrations.")
    parts = urlsplit(url)
    if parts.password:
        return url
    password_file = os.environ.get("AGENT_BOM_POSTGRES_PASSWORD_FILE", "").strip()
    if not password_file:
        return url
    path = Path(password_file)
    if not path.is_file():
        raise RuntimeError(f"AGENT_BOM_POSTGRES_PASSWORD_FILE not found: {password_file}")
    password = path.read_text(encoding="utf-8").strip("\r\n")
    if not password:
        raise RuntimeError(f"AGENT_BOM_POSTGRES_PASSWORD_FILE is empty: {password_file}")
    if not parts.username or not parts.hostname:
        raise RuntimeError("AGENT_BOM_POSTGRES_URL must include a username and hostname when using a password file.")
    netloc = f"{quote_plus(parts.username)}:{quote_plus(password)}@{parts.hostname}"
    if parts.port:
        netloc = f"{netloc}:{parts.port}"
    return urlunsplit((parts.scheme, netloc, parts.path, parts.query, parts.fragment))


def run_migrations_offline() -> None:
    context.configure(
        url=_database_url(),
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )

    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    section = config.get_section(config.config_ini_section, {})
    section["sqlalchemy.url"] = _database_url()

    connectable = engine_from_config(
        section,
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    with connectable.connect() as connection:
        context.configure(connection=connection, target_metadata=target_metadata)

        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
