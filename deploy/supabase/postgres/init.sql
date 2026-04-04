-- agent-bom PostgreSQL initialization
-- Runs once on first container start via docker-entrypoint-initdb.d
-- Also used as the Supabase project schema migration.
--
-- Principle: POSTGRES_USER (admin) owns the schema and creates tables.
-- A separate app user (agent_bom_app) gets DML-only access.
-- A read-only role exists for dashboards and BI tools.
--
-- Auth: scram-sha-256 (set via POSTGRES_INITDB_ARGS + runtime config)
-- All DDL uses IF NOT EXISTS — safe to re-run on an existing database.
--
-- Tables
--   teams              Multi-tenant team registry
--   scan_jobs          Async scan job lifecycle + results
--   findings           Normalized vulnerability findings (per scan)
--   agents             Discovered AI agents/clients (per scan)
--   policy_results     Per-scan policy evaluation outcomes
--   api_keys           Persistent RBAC API key store
--   job_queue          Background task queue (enrichment, reports, etc.)
--   fleet_agents       Managed agent lifecycle with governance state
--   gateway_policies   Runtime MCP enforcement policies
--   policy_audit_log   Runtime policy audit trail
--   scan_schedules     Recurring scan configuration
--   osv_cache          OSV vulnerability response cache

-- ── Extensions ────────────────────────────────────────────────────────────────

CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- ── Table: teams ──────────────────────────────────────────────────────────────
-- Central multi-tenant entity. All other tables reference team_id.
-- 'default' team pre-seeded for single-tenant / self-hosted deployments.

CREATE TABLE IF NOT EXISTS teams (
    team_id    TEXT PRIMARY KEY,
    name       TEXT NOT NULL,
    slug       TEXT UNIQUE NOT NULL,
    created_at TEXT NOT NULL DEFAULT to_char(now() AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"'),
    updated_at TEXT NOT NULL DEFAULT to_char(now() AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"'),
    metadata   JSONB NOT NULL DEFAULT '{}'::jsonb
);

INSERT INTO teams (team_id, name, slug)
    VALUES ('default', 'Default', 'default')
    ON CONFLICT (team_id) DO NOTHING;

-- ── Tables: Scan Jobs ─────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS scan_jobs (
    job_id       TEXT PRIMARY KEY,
    status       TEXT NOT NULL,
    created_at   TEXT NOT NULL,
    completed_at TEXT,
    team_id      TEXT NOT NULL DEFAULT 'default' REFERENCES teams(team_id) ON DELETE CASCADE,
    triggered_by TEXT,
    data         JSONB NOT NULL
);

-- Idempotent: add team_id to existing scan_jobs tables that predate this migration
DO $$ BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'scan_jobs' AND column_name = 'team_id'
    ) THEN
        ALTER TABLE scan_jobs
            ADD COLUMN team_id TEXT NOT NULL DEFAULT 'default' REFERENCES teams(team_id) ON DELETE CASCADE,
            ADD COLUMN triggered_by TEXT;
    END IF;
END $$;

CREATE INDEX IF NOT EXISTS idx_jobs_status  ON scan_jobs(status);
CREATE INDEX IF NOT EXISTS idx_jobs_created ON scan_jobs(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_jobs_team_status  ON scan_jobs(team_id, status);
CREATE INDEX IF NOT EXISTS idx_jobs_team_created ON scan_jobs(team_id, created_at DESC);

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
    team_id   TEXT NOT NULL DEFAULT 'default',
    data      JSONB NOT NULL
);

CREATE TABLE IF NOT EXISTS policy_audit_log (
    id      SERIAL PRIMARY KEY,
    ts      TEXT NOT NULL,
    team_id TEXT NOT NULL DEFAULT 'default',
    data    JSONB NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_audit_ts ON policy_audit_log(ts DESC);
CREATE INDEX IF NOT EXISTS idx_gateway_policies_team ON gateway_policies(team_id);
CREATE INDEX IF NOT EXISTS idx_policy_audit_log_team_ts ON policy_audit_log(team_id, ts DESC);

-- ── Tables: Scan Schedules ────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS scan_schedules (
    schedule_id TEXT PRIMARY KEY,
    enabled     INTEGER DEFAULT 1,
    next_run    TEXT,
    tenant_id   TEXT NOT NULL DEFAULT 'default',
    data        JSONB NOT NULL
);

DO $$ BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'scan_schedules' AND column_name = 'tenant_id'
    ) THEN
        ALTER TABLE scan_schedules ADD COLUMN tenant_id TEXT NOT NULL DEFAULT 'default';
    END IF;
END $$;

CREATE INDEX IF NOT EXISTS idx_schedules_due
    ON scan_schedules(next_run)
    WHERE enabled = 1 AND next_run IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_schedules_tenant_due
    ON scan_schedules(tenant_id, enabled, next_run);

-- ── Tables: OSV Scan Cache ────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS osv_cache (
    cache_key  TEXT PRIMARY KEY,
    vulns_json TEXT NOT NULL,
    cached_at  REAL NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_cache_age ON osv_cache(cached_at);

-- ── Table: findings ───────────────────────────────────────────────────────────
-- Normalized vulnerability findings extracted from scan results.
-- One row per (scan_run, CVE, package). Enables cross-scan analytics and
-- filtered compliance queries without deserializing full scan JSONB.

CREATE TABLE IF NOT EXISTS findings (
    finding_id            TEXT PRIMARY KEY,   -- uuid
    scan_run_id           TEXT NOT NULL REFERENCES scan_jobs(job_id) ON DELETE CASCADE,
    team_id               TEXT NOT NULL DEFAULT 'default' REFERENCES teams(team_id) ON DELETE CASCADE,

    -- Vulnerability identity
    cve_id                TEXT NOT NULL,      -- CVE-YYYY-NNNNN or GHSA-xxxx-yyyy-zzzz
    summary               TEXT,

    -- Affected package
    package_name          TEXT NOT NULL,
    package_version       TEXT NOT NULL,
    package_ecosystem     TEXT NOT NULL,      -- npm, pypi, cargo, go, maven, nuget, rubygems
    package_purl          TEXT,

    -- Severity & scoring
    severity              TEXT NOT NULL,      -- critical, high, medium, low, none
    cvss_score            REAL,
    epss_score            REAL,
    epss_percentile       REAL,
    is_kev                BOOLEAN NOT NULL DEFAULT FALSE,
    kev_date_added        TEXT,
    kev_due_date          TEXT,

    -- Remediation
    fixed_version         TEXT,
    vex_status            TEXT,               -- affected, not_affected, fixed, under_investigation
    exploitability        TEXT,

    -- Blast radius impact
    blast_radius_risk     REAL,               -- 0.0–10.0 computed risk score
    affected_server_count INTEGER NOT NULL DEFAULT 0,
    affected_agent_count  INTEGER NOT NULL DEFAULT 0,
    exposed_credentials   JSONB NOT NULL DEFAULT '[]'::jsonb,  -- array of cred var names

    -- Compliance tags from 13 frameworks
    compliance_tags       JSONB NOT NULL DEFAULT '{}'::jsonb,  -- {owasp_llm: [...], atlas: [...], ...}

    -- CWE lineage
    cwe_ids               JSONB NOT NULL DEFAULT '[]'::jsonb,  -- ["CWE-79", ...]

    created_at            TEXT NOT NULL DEFAULT to_char(now() AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"')
);

CREATE INDEX IF NOT EXISTS idx_findings_scan       ON findings(scan_run_id);
CREATE INDEX IF NOT EXISTS idx_findings_team       ON findings(team_id);
CREATE INDEX IF NOT EXISTS idx_findings_cve        ON findings(cve_id);
CREATE INDEX IF NOT EXISTS idx_findings_severity   ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_findings_kev        ON findings(is_kev) WHERE is_kev = TRUE;
CREATE INDEX IF NOT EXISTS idx_findings_pkg        ON findings(package_name, package_ecosystem);
CREATE INDEX IF NOT EXISTS idx_findings_compliance ON findings USING GIN(compliance_tags);
CREATE INDEX IF NOT EXISTS idx_findings_team_sev   ON findings(team_id, severity);

-- ── Table: agents ─────────────────────────────────────────────────────────────
-- AI agents/clients discovered per scan run. Separate from fleet_agents
-- (which tracks governed, long-lived agent lifecycle). This table records
-- point-in-time discovery snapshots.

CREATE TABLE IF NOT EXISTS agents (
    agent_id           TEXT PRIMARY KEY,   -- uuid per discovery
    scan_run_id        TEXT NOT NULL REFERENCES scan_jobs(job_id) ON DELETE CASCADE,
    team_id            TEXT NOT NULL DEFAULT 'default' REFERENCES teams(team_id) ON DELETE CASCADE,

    name               TEXT NOT NULL,
    agent_type         TEXT NOT NULL,      -- claude-desktop, cursor, windsurf, cline, custom, etc.
    config_path        TEXT,
    source             TEXT,               -- local, snowflake, aws, kubernetes, docker
    parent_agent       TEXT,               -- for delegation chains

    -- Discovery stats
    mcp_server_count   INTEGER NOT NULL DEFAULT 0,
    package_count      INTEGER NOT NULL DEFAULT 0,
    vuln_count         INTEGER NOT NULL DEFAULT 0,
    critical_count     INTEGER NOT NULL DEFAULT 0,

    metadata           JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at         TEXT NOT NULL DEFAULT to_char(now() AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"')
);

CREATE INDEX IF NOT EXISTS idx_agents_scan ON agents(scan_run_id);
CREATE INDEX IF NOT EXISTS idx_agents_team ON agents(team_id);
CREATE INDEX IF NOT EXISTS idx_agents_type ON agents(agent_type);

-- ── Table: policy_results ─────────────────────────────────────────────────────
-- Per-scan policy evaluation outcomes. Records which policies were checked,
-- which passed/failed, and which conditions triggered.

CREATE TABLE IF NOT EXISTS policy_results (
    result_id             TEXT PRIMARY KEY,   -- uuid
    scan_run_id           TEXT NOT NULL REFERENCES scan_jobs(job_id) ON DELETE CASCADE,
    team_id               TEXT NOT NULL DEFAULT 'default' REFERENCES teams(team_id) ON DELETE CASCADE,

    policy_id             TEXT REFERENCES gateway_policies(policy_id) ON DELETE SET NULL,
    policy_name           TEXT NOT NULL,
    status                TEXT NOT NULL,      -- pass, fail, skipped
    severity_on_fail      TEXT,               -- critical, high, medium, low

    conditions_triggered  JSONB NOT NULL DEFAULT '[]'::jsonb,  -- ["blocked_tools", "min_scorecard_score"]
    remediation_guidance  TEXT,

    created_at            TEXT NOT NULL DEFAULT to_char(now() AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"')
);

CREATE INDEX IF NOT EXISTS idx_policy_results_scan   ON policy_results(scan_run_id);
CREATE INDEX IF NOT EXISTS idx_policy_results_team   ON policy_results(team_id, status);
CREATE INDEX IF NOT EXISTS idx_policy_results_policy ON policy_results(policy_id);

-- ── Table: api_keys ───────────────────────────────────────────────────────────
-- Persistent RBAC API key storage. Replaces the in-memory KeyStore so keys
-- survive restarts. key_hash is a scrypt KDF; raw key is never stored.

CREATE TABLE IF NOT EXISTS api_keys (
    key_id      TEXT PRIMARY KEY,
    key_hash    TEXT NOT NULL,      -- scrypt(raw_key, salt) hex
    key_salt    TEXT NOT NULL,      -- hex-encoded KDF salt
    key_prefix  TEXT NOT NULL,      -- first 8 chars for UI display (not secret)
    name        TEXT NOT NULL,
    role        TEXT NOT NULL,      -- admin, analyst, viewer
    team_id     TEXT NOT NULL DEFAULT 'default' REFERENCES teams(team_id) ON DELETE CASCADE,
    scopes      JSONB NOT NULL DEFAULT '[]'::jsonb,   -- [] = all; ["GET /v1/scan*"] = filtered
    created_by  TEXT,
    created_at  TEXT NOT NULL DEFAULT to_char(now() AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"'),
    expires_at  TEXT,               -- NULL = never
    last_used   TEXT,
    revoked     BOOLEAN NOT NULL DEFAULT FALSE
);

CREATE INDEX IF NOT EXISTS idx_api_keys_team   ON api_keys(team_id);
CREATE INDEX IF NOT EXISTS idx_api_keys_prefix ON api_keys(key_prefix);   -- fast lookup during auth
CREATE INDEX IF NOT EXISTS idx_api_keys_active ON api_keys(team_id, revoked) WHERE revoked = FALSE;

-- ── Table: exceptions ────────────────────────────────────────────────────────
-- Persistent vulnerability exceptions and false positives. team_id keeps
-- exception workflows tenant-scoped in hosted deployments.

CREATE TABLE IF NOT EXISTS exceptions (
    exception_id TEXT PRIMARY KEY,
    vuln_id      TEXT NOT NULL,
    package_name TEXT NOT NULL,
    server_name  TEXT NOT NULL DEFAULT '',
    reason       TEXT NOT NULL DEFAULT '',
    requested_by TEXT NOT NULL DEFAULT '',
    approved_by  TEXT NOT NULL DEFAULT '',
    status       TEXT NOT NULL DEFAULT 'pending',
    created_at   TEXT NOT NULL DEFAULT to_char(now() AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"'),
    expires_at   TEXT NOT NULL DEFAULT '',
    approved_at  TEXT NOT NULL DEFAULT '',
    revoked_at   TEXT NOT NULL DEFAULT '',
    team_id      TEXT NOT NULL DEFAULT 'default' REFERENCES teams(team_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_exc_status ON exceptions(status);
CREATE INDEX IF NOT EXISTS idx_exc_team   ON exceptions(team_id);
CREATE INDEX IF NOT EXISTS idx_exc_vuln   ON exceptions(vuln_id);

-- ── Table: job_queue ──────────────────────────────────────────────────────────
-- Background task queue for async operations: CVE enrichment, report
-- generation, policy batch evaluation. Separate from scan_jobs so each
-- concern can be tracked independently.

CREATE TABLE IF NOT EXISTS job_queue (
    job_id        TEXT PRIMARY KEY,   -- uuid
    job_type      TEXT NOT NULL,      -- scan, enrich, policy_evaluate, generate_report, sbom_export
    status        TEXT NOT NULL DEFAULT 'pending',  -- pending, running, completed, failed, cancelled
    team_id       TEXT NOT NULL DEFAULT 'default' REFERENCES teams(team_id) ON DELETE CASCADE,

    payload       JSONB NOT NULL DEFAULT '{}'::jsonb,
    result        JSONB,
    error         TEXT,
    retries       INTEGER NOT NULL DEFAULT 0,
    max_retries   INTEGER NOT NULL DEFAULT 3,

    scheduled_for TEXT NOT NULL DEFAULT to_char(now() AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"'),
    created_at    TEXT NOT NULL DEFAULT to_char(now() AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"'),
    started_at    TEXT,
    completed_at  TEXT
);

CREATE INDEX IF NOT EXISTS idx_jobq_status_due ON job_queue(status, scheduled_for)
    WHERE status IN ('pending', 'running');
CREATE INDEX IF NOT EXISTS idx_jobq_team       ON job_queue(team_id);
CREATE INDEX IF NOT EXISTS idx_jobq_type       ON job_queue(job_type);

-- ══════════════════════════════════════════════════════════════════════════════
-- TENANT RLS HELPERS + POLICIES
-- ══════════════════════════════════════════════════════════════════════════════
--
-- Request handlers set app.tenant_id on the Postgres session. Internal trusted
-- scheduler tasks can set app.bypass_rls=1 for cross-tenant maintenance work.

CREATE OR REPLACE FUNCTION public.abom_current_tenant()
RETURNS TEXT
LANGUAGE SQL
STABLE
AS $$
    SELECT COALESCE(NULLIF(current_setting('app.tenant_id', true), ''), 'default')
$$;

CREATE OR REPLACE FUNCTION public.abom_rls_bypass()
RETURNS BOOLEAN
LANGUAGE SQL
STABLE
AS $$
    SELECT COALESCE(NULLIF(current_setting('app.bypass_rls', true), ''), '0') = '1'
$$;

ALTER TABLE gateway_policies ENABLE ROW LEVEL SECURITY;
ALTER TABLE gateway_policies FORCE ROW LEVEL SECURITY;

ALTER TABLE policy_audit_log ENABLE ROW LEVEL SECURITY;
ALTER TABLE policy_audit_log FORCE ROW LEVEL SECURITY;

ALTER TABLE fleet_agents ENABLE ROW LEVEL SECURITY;
ALTER TABLE fleet_agents FORCE ROW LEVEL SECURITY;

ALTER TABLE scan_jobs ENABLE ROW LEVEL SECURITY;
ALTER TABLE scan_jobs FORCE ROW LEVEL SECURITY;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_policies
        WHERE schemaname = 'public'
          AND tablename = 'scan_jobs'
          AND policyname = 'scan_jobs_tenant_isolation'
    ) THEN
        CREATE POLICY scan_jobs_tenant_isolation ON scan_jobs
            USING (public.abom_rls_bypass() OR team_id = public.abom_current_tenant())
            WITH CHECK (public.abom_rls_bypass() OR team_id = public.abom_current_tenant());
    END IF;
END
$$;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_policies
        WHERE schemaname = 'public'
          AND tablename = 'gateway_policies'
          AND policyname = 'gateway_policies_tenant_isolation'
    ) THEN
        CREATE POLICY gateway_policies_tenant_isolation ON gateway_policies
            USING (public.abom_rls_bypass() OR team_id = public.abom_current_tenant())
            WITH CHECK (public.abom_rls_bypass() OR team_id = public.abom_current_tenant());
    END IF;
END
$$;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_policies
        WHERE schemaname = 'public'
          AND tablename = 'policy_audit_log'
          AND policyname = 'policy_audit_log_tenant_isolation'
    ) THEN
        CREATE POLICY policy_audit_log_tenant_isolation ON policy_audit_log
            USING (public.abom_rls_bypass() OR team_id = public.abom_current_tenant())
            WITH CHECK (public.abom_rls_bypass() OR team_id = public.abom_current_tenant());
    END IF;
END
$$;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_policies
        WHERE schemaname = 'public'
          AND tablename = 'fleet_agents'
          AND policyname = 'fleet_agents_tenant_isolation'
    ) THEN
        CREATE POLICY fleet_agents_tenant_isolation ON fleet_agents
            USING (public.abom_rls_bypass() OR tenant_id = public.abom_current_tenant())
            WITH CHECK (public.abom_rls_bypass() OR tenant_id = public.abom_current_tenant());
    END IF;
END
$$;

ALTER TABLE scan_schedules ENABLE ROW LEVEL SECURITY;
ALTER TABLE scan_schedules FORCE ROW LEVEL SECURITY;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_policies
        WHERE schemaname = 'public'
          AND tablename = 'scan_schedules'
          AND policyname = 'scan_schedules_tenant_isolation'
    ) THEN
        CREATE POLICY scan_schedules_tenant_isolation ON scan_schedules
            USING (public.abom_rls_bypass() OR tenant_id = public.abom_current_tenant())
            WITH CHECK (public.abom_rls_bypass() OR tenant_id = public.abom_current_tenant());
    END IF;
END
$$;

ALTER TABLE api_keys ENABLE ROW LEVEL SECURITY;
ALTER TABLE api_keys FORCE ROW LEVEL SECURITY;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_policies
        WHERE schemaname = 'public'
          AND tablename = 'api_keys'
          AND policyname = 'api_keys_tenant_isolation'
    ) THEN
        CREATE POLICY api_keys_tenant_isolation ON api_keys
            USING (public.abom_rls_bypass() OR team_id = public.abom_current_tenant())
            WITH CHECK (public.abom_rls_bypass() OR team_id = public.abom_current_tenant());
    END IF;
END
$$;

ALTER TABLE exceptions ENABLE ROW LEVEL SECURITY;
ALTER TABLE exceptions FORCE ROW LEVEL SECURITY;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_policies
        WHERE schemaname = 'public'
          AND tablename = 'exceptions'
          AND policyname = 'exceptions_tenant_isolation'
    ) THEN
        CREATE POLICY exceptions_tenant_isolation ON exceptions
            USING (public.abom_rls_bypass() OR team_id = public.abom_current_tenant())
            WITH CHECK (public.abom_rls_bypass() OR team_id = public.abom_current_tenant());
    END IF;
END
$$;

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
--
--  Schema (12 tables):
--   teams              — multi-tenant team registry (FK root)
--   scan_jobs          — async scan job lifecycle + full result JSONB
--   findings           — normalized vulnerability findings (per scan, per CVE)
--   agents             — discovered AI agents per scan (point-in-time)
--   policy_results     — per-scan policy evaluation outcomes
--   api_keys           — persistent RBAC API key store (scrypt KDF)
--   job_queue          — background async task queue
--   fleet_agents       — governed agent lifecycle (long-lived)
--   gateway_policies   — runtime MCP enforcement policies
--   policy_audit_log   — runtime policy audit trail (HMAC-verified)
--   scan_schedules     — recurring scan cron configuration
--   osv_cache          — OSV vulnerability API response cache
