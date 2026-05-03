-- =============================================================================
-- DCM migration V001 — agent-bom Native App core schema
-- =============================================================================
-- DCM (Database Change Management) project for the Native App's internal
-- schema. Runs deterministically across environments (dev → staging → prod
-- Snowflake accounts). Mirrors the existing Postgres DDL in
-- src/agent_bom/api/postgres_*.py so the same model ships to both backends.
--
-- Naming: V<seq>__<description>.sql per DCM convention.
-- =============================================================================

-- ─── 1. Schema + application role (idempotent) ───────────────────────────────
CREATE SCHEMA IF NOT EXISTS core
    COMMENT = 'agent-bom Native App internal schema';

-- App role created in setup.sql (the Native App entry point); we don't
-- redeclare it here so DCM doesn't fight with the application installer.

-- ─── 2. Scan + inventory tables ──────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS core.scan_jobs (
    job_id         VARCHAR PRIMARY KEY,
    tenant_id      VARCHAR NOT NULL DEFAULT 'default',
    status         VARCHAR NOT NULL,
    created_at     TIMESTAMP_TZ NOT NULL,
    completed_at   TIMESTAMP_TZ,
    data           VARIANT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_scan_jobs_tenant_status
    ON core.scan_jobs(tenant_id, status);

CREATE TABLE IF NOT EXISTS core.fleet_agents (
    agent_id        VARCHAR PRIMARY KEY,
    tenant_id       VARCHAR NOT NULL DEFAULT 'default',
    name            VARCHAR NOT NULL,
    lifecycle_state VARCHAR NOT NULL,
    trust_score     FLOAT DEFAULT 0.0,
    updated_at      TIMESTAMP_TZ NOT NULL,
    data            VARIANT NOT NULL
);

-- ─── 3. Compliance Hub tables (matches PostgresComplianceHubStore schema) ────
-- Mirrors src/agent_bom/api/postgres_compliance_hub.py:_init_tables.
CREATE TABLE IF NOT EXISTS core.compliance_hub_findings (
    tenant_id                   VARCHAR NOT NULL DEFAULT 'default',
    finding_id                  VARCHAR NOT NULL,
    ingested_at                 VARCHAR NOT NULL,
    source                      VARCHAR NOT NULL,
    applicable_frameworks_csv   VARCHAR NOT NULL DEFAULT '',
    payload                     VARIANT NOT NULL,
    ordinal                     NUMBER AUTOINCREMENT,
    PRIMARY KEY (tenant_id, finding_id, ordinal)
);
CREATE INDEX IF NOT EXISTS idx_hub_findings_tenant_order
    ON core.compliance_hub_findings(tenant_id, ordinal);

-- ─── 4. Findings-by-framework (Phase 2 target table) ─────────────────────────
-- Phase 2 (#2211) populates this via core.apply_compliance_hub() Snowpark
-- proc. Phase 1 just materialises the schema so Phase 2 can land cleanly.
CREATE TABLE IF NOT EXISTS core.findings_by_framework (
    finding_id     VARCHAR NOT NULL,
    framework_slug VARCHAR NOT NULL,
    tenant_id      VARCHAR NOT NULL DEFAULT 'default',
    severity       VARCHAR,
    finding_type   VARCHAR,
    asset_type     VARCHAR,
    asset_name     VARCHAR,
    classified_at  TIMESTAMP_TZ DEFAULT CURRENT_TIMESTAMP(),
    payload        VARIANT,
    PRIMARY KEY (finding_id, framework_slug)
);
CREATE INDEX IF NOT EXISTS idx_findings_by_framework_lookup
    ON core.findings_by_framework(tenant_id, framework_slug, severity);

-- ─── 5. Audit log (matches PostgresAuditStore schema) ────────────────────────
CREATE TABLE IF NOT EXISTS core.policy_audit_log (
    entry_id       VARCHAR PRIMARY KEY,
    tenant_id      VARCHAR NOT NULL DEFAULT 'default',
    policy_id      VARCHAR,
    actor          VARCHAR,
    action_taken   VARCHAR NOT NULL,
    timestamp      TIMESTAMP_TZ NOT NULL,
    prev_hash      VARCHAR,
    record_hash    VARCHAR,
    data           VARIANT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_audit_tenant_time
    ON core.policy_audit_log(tenant_id, timestamp);

-- ─── 6. Reference-binding tracker ────────────────────────────────────────────
-- Records which customer-bound tables/stages were resolved at install.
-- Drives the dashboard's "data source" panel + the Phase 2 Snowpark proc's
-- table-discovery loop.
CREATE TABLE IF NOT EXISTS core.bound_references (
    reference_name VARCHAR NOT NULL,
    object_type    VARCHAR NOT NULL,        -- TABLE | STAGE
    object_name    VARCHAR NOT NULL,        -- fully-qualified
    bound_at       TIMESTAMP_TZ DEFAULT CURRENT_TIMESTAMP(),
    PRIMARY KEY (reference_name, object_name)
);

-- ─── 7. Grants for the application role ──────────────────────────────────────
GRANT USAGE ON SCHEMA core TO APPLICATION ROLE app_user;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA core
    TO APPLICATION ROLE app_user;

-- ─── 8. DCM checksum (for drift detection) ───────────────────────────────────
-- DCM tracks applied migrations in its own metadata table; nothing further
-- to declare here. To diff desired vs current state on a target account:
--   snow sql -q "EXECUTE IMMEDIATE FROM 'dcm/V001__core_schema.sql' DRY_RUN"
-- =============================================================================
