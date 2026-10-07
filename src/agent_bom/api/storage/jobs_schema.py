"""Transactional tenant-key upgrades; runtime Postgres deployments use Alembic."""

from __future__ import annotations

import sqlite3

JOBS_SCHEMA_VERSION = 3

# Both the development bootstrap and Alembic use this exact transaction. Unknown
# dependencies and inconsistent child ownership abort the upgrade, preserving data.
POSTGRES_TENANT_KEYS = """
DO $$
DECLARE
    dep RECORD;
    fk RECORD;
    pk TEXT;
BEGIN
    LOCK TABLE scan_jobs IN ACCESS EXCLUSIVE MODE;
    -- The oldest supported checkpoint has only job_id. Its durable routing row
    -- is the sole recorded tenant authority; never overwrite an existing team.
    IF NOT EXISTS (SELECT 1 FROM pg_attribute WHERE attrelid='scan_jobs'::regclass
                   AND attname='team_id' AND NOT attisdropped) THEN
        ALTER TABLE scan_jobs ADD COLUMN team_id TEXT NOT NULL DEFAULT 'default';
        IF to_regclass('public.scan_dispatch_queue') IS NOT NULL THEN
            UPDATE scan_jobs j SET team_id=q.tenant_id FROM scan_dispatch_queue q WHERE q.job_id=j.job_id;
        END IF;
    END IF;
    IF EXISTS (
        SELECT 1 FROM pg_constraint c JOIN pg_attribute a
        ON a.attrelid=c.conrelid AND a.attnum=ANY(c.conkey)
        WHERE c.conrelid='scan_jobs'::regclass AND c.contype='p' AND a.attname='team_id'
    ) THEN
        RETURN;
    END IF;
    FOR dep IN SELECT * FROM (VALUES
        ('cis_benchmark_checks', 'team_id', 'scan_id'),
        ('scan_dispatch_queue', 'tenant_id', 'job_id'),
        ('findings', 'team_id', 'scan_run_id'),
        ('agents', 'team_id', 'scan_run_id'),
        ('policy_results', 'team_id', 'scan_run_id')
    ) AS deps(tbl, tenant_col, job_col)
    LOOP
        IF to_regclass('public.' || dep.tbl) IS NULL THEN CONTINUE; END IF;
        EXECUTE format('LOCK TABLE %I IN ACCESS EXCLUSIVE MODE', dep.tbl);
        FOR fk IN SELECT conname FROM pg_constraint
            WHERE conrelid=to_regclass('public.' || dep.tbl)
              AND confrelid='scan_jobs'::regclass AND contype='f'
        LOOP
            EXECUTE format('ALTER TABLE %I DROP CONSTRAINT %I', dep.tbl, fk.conname);
        END LOOP;
    END LOOP;
    SELECT conname INTO pk FROM pg_constraint WHERE conrelid='scan_jobs'::regclass AND contype='p';
    IF pk IS NOT NULL THEN EXECUTE format('ALTER TABLE scan_jobs DROP CONSTRAINT %I', pk); END IF;
    ALTER TABLE scan_jobs ADD CONSTRAINT scan_jobs_pkey PRIMARY KEY (team_id, job_id);
    IF to_regclass('public.scan_dispatch_queue') IS NOT NULL THEN
        SELECT conname INTO pk FROM pg_constraint WHERE conrelid='scan_dispatch_queue'::regclass AND contype='p';
        IF pk IS NOT NULL THEN EXECUTE format('ALTER TABLE scan_dispatch_queue DROP CONSTRAINT %I', pk); END IF;
        ALTER TABLE scan_dispatch_queue ADD CONSTRAINT scan_dispatch_queue_pkey PRIMARY KEY (tenant_id, job_id);
    END IF;
    FOR dep IN SELECT * FROM (VALUES
        ('cis_benchmark_checks', 'team_id', 'scan_id'),
        ('scan_dispatch_queue', 'tenant_id', 'job_id'),
        ('findings', 'team_id', 'scan_run_id'),
        ('agents', 'team_id', 'scan_run_id'),
        ('policy_results', 'team_id', 'scan_run_id')
    ) AS deps(tbl, tenant_col, job_col)
    LOOP
        IF to_regclass('public.' || dep.tbl) IS NULL THEN CONTINUE; END IF;
        EXECUTE format('ALTER TABLE %I ADD CONSTRAINT %I FOREIGN KEY (%I, %I) '
            'REFERENCES scan_jobs(team_id, job_id) ON DELETE CASCADE',
            dep.tbl, dep.tbl || '_tenant_job_fk', dep.tenant_col, dep.job_col);
    END LOOP;
END $$;
"""


def migrate_sqlite_job_key(conn: sqlite3.Connection) -> None:
    """Rebuild the legacy global key atomically, preserving payloads and indexes."""
    columns = conn.execute("PRAGMA table_info(jobs)").fetchall()
    if [row[1] for row in sorted(columns, key=lambda row: row[5]) if row[5]] == ["tenant_id", "job_id"]:
        return
    # This file has no application-owned dependent tables. Refuse an unknown
    # extension rather than silently cascading/deleting its rows during rebuild.
    for (table,) in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall():
        quoted = '"' + table.replace('"', '""') + '"'
        if any(row[2] == "jobs" for row in conn.execute(f"PRAGMA foreign_key_list({quoted})")):  # nosec B608 - quoted identifier
            raise RuntimeError("Jobs key migration requires review of dependent SQLite tables")
    saved = conn.execute(
        "SELECT sql FROM sqlite_master WHERE tbl_name='jobs' AND type IN ('index','trigger') AND sql IS NOT NULL"
    ).fetchall()
    definitions = []
    for _, name, kind, nonnull, default, _ in columns:
        quoted = '"' + name.replace('"', '""') + '"'
        definitions.append(
            f"{quoted} {kind}"
            + (" NOT NULL" if nonnull or name in {"job_id", "tenant_id"} else "")
            + (f" DEFAULT {default}" if default is not None else "")
        )
    definitions.append("PRIMARY KEY (tenant_id, job_id)")
    conn.execute(f"CREATE TABLE jobs_tenant_upgrade ({', '.join(definitions)})")  # nosec B608 - schema metadata only
    conn.execute("INSERT INTO jobs_tenant_upgrade SELECT * FROM jobs")
    conn.execute("DROP TABLE jobs")
    conn.execute("ALTER TABLE jobs_tenant_upgrade RENAME TO jobs")
    for (statement,) in saved:
        conn.execute(statement)
