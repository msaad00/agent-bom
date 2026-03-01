-- agent-bom PostgreSQL initialization
-- Runs once on first container start via docker-entrypoint-initdb.d
--
-- Security: scram-sha-256 auth, least-privilege roles, row-level defaults.
-- All tables use IF NOT EXISTS — safe to re-run.

-- ── Extensions ────────────────────────────────────────────────────────────────

-- pgcrypto for gen_random_uuid() if needed
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

-- ── Read-only role for dashboards / BI tools ──────────────────────────────────

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'agent_bom_readonly') THEN
        CREATE ROLE agent_bom_readonly NOLOGIN;
    END IF;
END
$$;

GRANT SELECT ON ALL TABLES IN SCHEMA public TO agent_bom_readonly;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT ON TABLES TO agent_bom_readonly;

-- Done. All 5 store backends ready.
-- Connection: AGENT_BOM_POSTGRES_URL=postgresql://agent_bom:<password>@<host>:5432/agent_bom
