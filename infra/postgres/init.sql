-- agent-bom PostgreSQL initialization
-- Runs once on first container start via docker-entrypoint-initdb.d
--
-- Principle: POSTGRES_USER (admin) owns the schema and creates tables.
-- A separate app user (agent_bom_app) gets DML-only access.
-- A read-only role exists for dashboards and BI tools.
--
-- Auth: scram-sha-256 (set via POSTGRES_INITDB_ARGS + runtime config)
-- All tables use IF NOT EXISTS — safe to re-run.

-- ── Extensions ────────────────────────────────────────────────────────────────

CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- ── Tables: Scan Jobs ─────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS scan_jobs (
    job_id       TEXT PRIMARY KEY,
    status       TEXT NOT NULL,
    created_at   TEXT NOT NULL,
    completed_at TEXT,
    data         JSONB NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_jobs_status ON scan_jobs(status);
CREATE INDEX IF NOT EXISTS idx_jobs_created ON scan_jobs(created_at DESC);

-- ── Tables: Fleet Agents ──────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS fleet_agents (
    agent_id        TEXT PRIMARY KEY,
    name            TEXT NOT NULL,
    lifecycle_state TEXT NOT NULL,
    trust_score     REAL DEFAULT 0.0,
    tenant_id       TEXT DEFAULT 'default',
    updated_at      TEXT NOT NULL,
    data            JSONB NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_fleet_name ON fleet_agents(name);
CREATE INDEX IF NOT EXISTS idx_fleet_state ON fleet_agents(lifecycle_state);
CREATE INDEX IF NOT EXISTS idx_fleet_tenant ON fleet_agents(tenant_id);

-- ── Tables: Gateway Policies ──────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS gateway_policies (
    policy_id TEXT PRIMARY KEY,
    data      JSONB NOT NULL
);

CREATE TABLE IF NOT EXISTS policy_audit_log (
    id   SERIAL PRIMARY KEY,
    ts   TEXT NOT NULL,
    data JSONB NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_audit_ts ON policy_audit_log(ts DESC);

-- ── Tables: Scan Schedules ────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS scan_schedules (
    schedule_id TEXT PRIMARY KEY,
    enabled     INTEGER DEFAULT 1,
    next_run    TEXT,
    data        JSONB NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_schedules_due
    ON scan_schedules(next_run)
    WHERE enabled = 1 AND next_run IS NOT NULL;

-- ── Tables: OSV Scan Cache ────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS osv_cache (
    cache_key  TEXT PRIMARY KEY,
    vulns_json TEXT NOT NULL,
    cached_at  REAL NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_cache_age ON osv_cache(cached_at);

-- ══════════════════════════════════════════════════════════════════════════════
-- LEAST PRIVILEGE: App user — DML only, no DDL (cannot CREATE/DROP/ALTER)
-- ══════════════════════════════════════════════════════════════════════════════

-- Password is injected via POSTGRES_APP_PASSWORD env var in the wrapper script.
-- If not set, this block is skipped and the admin user is used (dev fallback).
DO $$
DECLARE
    app_pass TEXT;
BEGIN
    -- Read password from env via current_setting (set by init wrapper)
    app_pass := current_setting('init.app_password', true);

    IF app_pass IS NOT NULL AND app_pass != '' THEN
        -- Create app user if not exists
        IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'agent_bom_app') THEN
            EXECUTE format('CREATE ROLE agent_bom_app LOGIN PASSWORD %L', app_pass);
        ELSE
            EXECUTE format('ALTER ROLE agent_bom_app PASSWORD %L', app_pass);
        END IF;

        -- Connection limit: prevent app from exhausting all connections
        ALTER ROLE agent_bom_app CONNECTION LIMIT 20;

        -- Statement timeout: kill runaway queries after 30 seconds
        ALTER ROLE agent_bom_app SET statement_timeout = '30s';

        -- Lock timeout: don't wait forever for row locks
        ALTER ROLE agent_bom_app SET lock_timeout = '5s';

        -- DML only: SELECT, INSERT, UPDATE, DELETE on all current + future tables
        GRANT CONNECT ON DATABASE agent_bom TO agent_bom_app;
        GRANT USAGE ON SCHEMA public TO agent_bom_app;
        GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO agent_bom_app;
        GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO agent_bom_app;
        ALTER DEFAULT PRIVILEGES IN SCHEMA public
            GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO agent_bom_app;
        ALTER DEFAULT PRIVILEGES IN SCHEMA public
            GRANT USAGE, SELECT ON SEQUENCES TO agent_bom_app;

        -- Explicitly deny DDL — app cannot CREATE, DROP, ALTER, or TRUNCATE
        REVOKE CREATE ON SCHEMA public FROM agent_bom_app;

        RAISE NOTICE 'agent_bom_app user created with DML-only access';
    ELSE
        RAISE NOTICE 'POSTGRES_APP_PASSWORD not set — skipping app user creation (dev mode)';
    END IF;
END
$$;

-- ══════════════════════════════════════════════════════════════════════════════
-- READ-ONLY ROLE: For dashboards, BI tools, and audit queries
-- ══════════════════════════════════════════════════════════════════════════════

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'agent_bom_readonly') THEN
        CREATE ROLE agent_bom_readonly NOLOGIN;
    END IF;
END
$$;

GRANT CONNECT ON DATABASE agent_bom TO agent_bom_readonly;
GRANT USAGE ON SCHEMA public TO agent_bom_readonly;
GRANT SELECT ON ALL TABLES IN SCHEMA public TO agent_bom_readonly;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT ON TABLES TO agent_bom_readonly;

-- ══════════════════════════════════════════════════════════════════════════════
-- SUMMARY
-- ══════════════════════════════════════════════════════════════════════════════
--
--  Role               | Can do                          | Cannot do
--  -------------------|--------------------------------|---------------------------
--  agent_bom (admin)  | DDL + DML (schema owner)       | — (superuser on this DB)
--  agent_bom_app      | SELECT, INSERT, UPDATE, DELETE  | CREATE, DROP, ALTER, TRUNCATE
--  agent_bom_readonly | SELECT only                     | Any writes
--
--  Connection: AGENT_BOM_POSTGRES_URL=postgresql://agent_bom_app:<pw>@<host>:5432/agent_bom
