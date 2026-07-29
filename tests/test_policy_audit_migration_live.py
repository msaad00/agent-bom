"""Live Postgres contract for the policy-audit rolling migration."""

from __future__ import annotations

import json
import os
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit
from uuid import uuid4

import pytest

pytestmark = pytest.mark.skipif(
    not os.environ.get("AGENT_BOM_POSTGRES_ADMIN_URL"),
    reason="AGENT_BOM_POSTGRES_ADMIN_URL is required for the live policy-audit migration contract",
)

REPO_ROOT = Path(__file__).parent.parent
ALEMBIC_DIR = REPO_ROOT / "deploy" / "supabase" / "postgres"


def _with_database(url: str, database: str) -> str:
    parts = urlsplit(url)
    return urlunsplit((parts.scheme, parts.netloc, f"/{database}", parts.query, parts.fragment))


def _sqlalchemy_url(url: str) -> str:
    if url.startswith("postgresql://"):
        return url.replace("postgresql://", "postgresql+psycopg://", 1)
    return url


def test_legacy_rows_backfill_and_old_writer_remains_compatible(monkeypatch) -> None:
    """Upgrade an old global-key table, then write with the old SQL contract."""
    import psycopg
    from alembic import command
    from alembic.config import Config
    from psycopg import sql

    admin_url = os.environ["AGENT_BOM_POSTGRES_ADMIN_URL"]
    database = f"abom_policy_migration_{uuid4().hex[:12]}"
    database_url = _with_database(admin_url, database)

    with psycopg.connect(admin_url, autocommit=True) as conn:
        conn.execute(sql.SQL("CREATE DATABASE {}").format(sql.Identifier(database)))
    try:
        with psycopg.connect(database_url) as conn:
            conn.execute(
                """
                CREATE TABLE policy_audit_log (
                    id SERIAL PRIMARY KEY,
                    entry_id TEXT,
                    ts TEXT NOT NULL,
                    team_id TEXT NOT NULL DEFAULT 'default',
                    data JSONB NOT NULL
                )
                """
            )
            conn.execute("CREATE UNIQUE INDEX uq_policy_audit_log_entry ON policy_audit_log(entry_id)")
            conn.execute("ALTER TABLE policy_audit_log ENABLE ROW LEVEL SECURITY")
            conn.execute("ALTER TABLE policy_audit_log FORCE ROW LEVEL SECURITY")
            conn.execute(
                "INSERT INTO policy_audit_log (entry_id, ts, team_id, data) VALUES (%s, %s, %s, %s)",
                ("shared", "2026-07-28T00:00:00Z", "tenant-a", json.dumps({"entry_id": "shared"})),
            )

        cfg = Config(str(ALEMBIC_DIR / "alembic.ini"))
        cfg.set_main_option("script_location", str(ALEMBIC_DIR / "alembic"))
        monkeypatch.setenv("ALEMBIC_DATABASE_URL", _sqlalchemy_url(database_url))
        command.stamp(cfg, "20260728_03")
        command.upgrade(cfg, "head")

        with psycopg.connect(database_url) as conn:
            # This is the exact SQL shape used by pre-migration replicas.
            old_insert = """
                INSERT INTO policy_audit_log (entry_id, ts, team_id, data)
                VALUES (%s, %s, %s, %s)
                ON CONFLICT (entry_id) DO NOTHING
            """
            conn.execute(
                old_insert,
                ("shared", "2026-07-29T00:00:00Z", "tenant-a", json.dumps({"entry_id": "shared"})),
            )
            conn.execute(
                old_insert,
                ("shared", "2026-07-29T00:00:01Z", "tenant-b", json.dumps({"entry_id": "shared"})),
            )

            rows = conn.execute(
                """
                SELECT entry_id, logical_entry_id, team_id, data ->> 'entry_id'
                  FROM policy_audit_log
                 WHERE logical_entry_id = 'shared'
                 ORDER BY team_id
                """
            ).fetchall()
            indexdef = conn.execute(
                "SELECT indexdef FROM pg_indexes WHERE indexname = 'uq_policy_audit_log_entry'"
            ).fetchone()
            rls = conn.execute(
                """
                SELECT relrowsecurity, relforcerowsecurity
                  FROM pg_class
                 WHERE oid = 'public.policy_audit_log'::regclass
                """
            ).fetchone()

        assert [(row[1], row[2], row[3]) for row in rows] == [
            ("shared", "tenant-a", "shared"),
            ("shared", "tenant-b", "shared"),
        ]
        assert rows[0][0] != rows[1][0]
        assert indexdef is not None and "(entry_id)" in indexdef[0]
        assert "team_id, entry_id" not in indexdef[0]
        assert rls == (True, True)
    finally:
        with psycopg.connect(admin_url, autocommit=True) as conn:
            conn.execute(sql.SQL("DROP DATABASE IF EXISTS {} WITH (FORCE)").format(sql.Identifier(database)))
