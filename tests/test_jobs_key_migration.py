"""Populated and minimal-schema tenant key migrations on a disposable database."""

import os
from uuid import uuid4

import pytest

from agent_bom.api.storage.jobs_schema import POSTGRES_TENANT_KEYS

pytestmark = pytest.mark.skipif(not os.environ.get("AGENT_BOM_TEST_ADMIN_URL"), reason="requires task-owned migration database")


@pytest.fixture
def database():
    import psycopg
    from psycopg import sql
    from psycopg.conninfo import make_conninfo

    admin = os.environ["AGENT_BOM_TEST_ADMIN_URL"]
    name = "jobs_migration_" + uuid4().hex
    with psycopg.connect(admin, autocommit=True) as conn:
        conn.execute(sql.SQL("CREATE DATABASE {}").format(sql.Identifier(name)))
    try:
        with psycopg.connect(make_conninfo(admin, dbname=name)) as conn:
            yield conn
    finally:
        with psycopg.connect(admin, autocommit=True) as conn:
            conn.execute(sql.SQL("DROP DATABASE {}").format(sql.Identifier(name)))


def test_minimal_legacy_queue_keeps_its_tenant_and_lease(database):
    database.execute("CREATE TABLE scan_jobs(job_id TEXT PRIMARY KEY)")
    database.execute("INSERT INTO scan_jobs VALUES ('legacy')")
    database.execute("""CREATE TABLE scan_dispatch_queue(job_id TEXT PRIMARY KEY REFERENCES scan_jobs(job_id),
        tenant_id TEXT NOT NULL, claimed_by TEXT, lease_expires_at TEXT)""")
    database.execute("INSERT INTO scan_dispatch_queue VALUES ('legacy','tenant','worker:token','2099-01-01')")
    for _ in range(2):
        database.execute(POSTGRES_TENANT_KEYS)
    assert database.execute("SELECT job_id,team_id FROM scan_jobs").fetchall() == [("legacy", "tenant")]
    assert database.execute("SELECT * FROM scan_dispatch_queue").fetchall() == [("legacy", "tenant", "worker:token", "2099-01-01")]


@pytest.mark.parametrize("inconsistent", [False, True])
def test_populated_all_foreign_keys_atomic_upgrade_and_cascade(database, inconsistent):
    import psycopg

    # Keep payload/timestamps and dependent rows populated while replacing all
    # five deployed references. A bad child must roll back every changed key.
    database.execute("CREATE TABLE scan_jobs(job_id TEXT PRIMARY KEY,team_id TEXT NOT NULL,data JSONB,created_at TEXT)")
    database.execute("INSERT INTO scan_jobs VALUES ('same','a','{\"child_job_ids\":[\"child\"]}','2026')")
    dependencies = [
        ("cis_benchmark_checks", "team_id", "scan_id"),
        ("scan_dispatch_queue", "tenant_id", "job_id"),
        ("findings", "team_id", "scan_run_id"),
        ("agents", "team_id", "scan_run_id"),
        ("policy_results", "team_id", "scan_run_id"),
    ]
    from psycopg import sql

    for table, tenant_col, job_col in dependencies:
        database.execute(
            sql.SQL("CREATE TABLE {}({} TEXT NOT NULL, {} TEXT PRIMARY KEY REFERENCES scan_jobs(job_id) ON DELETE CASCADE)").format(
                sql.Identifier(table), sql.Identifier(tenant_col), sql.Identifier(job_col)
            )
        )
        database.execute(
            sql.SQL("INSERT INTO {} VALUES (%s,'same')").format(sql.Identifier(table)),
            ("wrong" if inconsistent and table == "findings" else "a",),
        )
    database.commit()
    if inconsistent:
        with pytest.raises(psycopg.errors.ForeignKeyViolation):
            database.execute(POSTGRES_TENANT_KEYS)
        database.rollback()
        assert (
            database.execute(
                "SELECT pg_get_constraintdef(oid) FROM pg_constraint WHERE conrelid='scan_jobs'::regclass AND contype='p'"
            ).fetchone()[0]
            == "PRIMARY KEY (job_id)"
        )
    else:
        for _ in range(2):
            database.execute(POSTGRES_TENANT_KEYS)
        database.execute("INSERT INTO scan_jobs VALUES ('same','b','{}','2026')")
        database.execute("INSERT INTO scan_dispatch_queue VALUES ('b','same')")
        database.execute("DELETE FROM scan_jobs WHERE team_id='b'")
    assert database.execute("SELECT data,created_at FROM scan_jobs WHERE team_id='a'").fetchone() == ({"child_job_ids": ["child"]}, "2026")
    for table, _, _ in dependencies:
        assert database.execute(sql.SQL("SELECT count(*) FROM {}").format(sql.Identifier(table))).fetchone()[0] == 1


def test_full_bootstrap_upgrade_preserves_populated_schema(database):
    import subprocess
    import sys
    from pathlib import Path

    root = Path(__file__).resolve().parents[1]
    name = database.info.dbname
    sql = (root / "deploy/supabase/postgres/init.sql").read_text().replace("ON DATABASE agent_bom TO", f"ON DATABASE {name} TO")
    database.execute(sql)
    database.execute((root / "deploy/supabase/postgres/runtime-schema.sql").read_text())
    database.execute("INSERT INTO teams(team_id,name,slug) VALUES ('a','a','a') ON CONFLICT DO NOTHING")
    database.execute("""INSERT INTO scan_jobs(job_id,team_id,status,created_at,child_job_ids,data)
        VALUES ('same','a','running','2026','["child"]','{"kept":true}')""")
    database.execute("""INSERT INTO scan_dispatch_queue(job_id,tenant_id,created_at,status,claimed_by,lease_expires_at)
        VALUES ('same','a','2026','running','worker:kept','2099')""")
    database.execute("INSERT INTO cis_benchmark_checks(scan_id,team_id,cloud,check_id) VALUES ('same','a','aws','check')")
    database.commit()
    env = os.environ.copy()
    # Alembic accepts a URL, not libpq's keyword DSN.
    from urllib.parse import urlsplit, urlunsplit

    parts = urlsplit(os.environ["AGENT_BOM_TEST_ADMIN_URL"])
    env["ALEMBIC_DATABASE_URL"] = urlunsplit((parts.scheme, parts.netloc, "/" + name, parts.query, parts.fragment))
    args = [sys.executable, "-m", "alembic", "-c", "deploy/supabase/postgres/alembic.ini"]
    for operation in (("stamp", "20260416_01"), ("upgrade", "head"), ("upgrade", "head")):
        result = subprocess.run([*args, *operation], cwd=root, env=env, capture_output=True, text=True)
        assert result.returncode == 0, result.stderr
    assert database.execute("SELECT data,child_job_ids FROM scan_jobs WHERE job_id='same'").fetchone() == ({"kept": True}, ["child"])
    assert database.execute("SELECT tenant_id,claimed_by,lease_expires_at FROM scan_dispatch_queue").fetchall() == [
        ("a", "worker:kept", "2099")
    ]
    assert database.execute("SELECT version FROM control_plane_schema_versions WHERE component='scan_jobs'").fetchone()[0] == 3
    before_revision = database.execute("SELECT revision FROM job_overview_revisions WHERE tenant_id='a'").fetchone()[0]
    database.execute("UPDATE scan_jobs SET status='done' WHERE job_id='same' AND team_id='a'")
    assert database.execute("SELECT revision FROM job_overview_revisions WHERE tenant_id='a'").fetchone()[0] == before_revision + 1
    assert database.execute("SELECT relrowsecurity,relforcerowsecurity FROM pg_class WHERE oid='scan_jobs'::regclass").fetchone() == (
        True,
        True,
    )
