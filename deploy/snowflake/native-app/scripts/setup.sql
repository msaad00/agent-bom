-- =============================================================================
-- agent-bom Native App: Installation Script
-- Runs automatically when a consumer installs the app from the Marketplace.
-- =============================================================================

-- 1. Application Role
CREATE APPLICATION ROLE IF NOT EXISTS app_user;

-- 2. Schema
CREATE SCHEMA IF NOT EXISTS core;
GRANT USAGE ON SCHEMA core TO APPLICATION ROLE app_user;

-- 3. Tables
CREATE TABLE IF NOT EXISTS core.scan_jobs (
    job_id VARCHAR PRIMARY KEY,
    status VARCHAR NOT NULL,
    created_at TIMESTAMP_TZ NOT NULL,
    completed_at TIMESTAMP_TZ,
    data VARIANT NOT NULL
);

CREATE TABLE IF NOT EXISTS core.fleet_agents (
    agent_id VARCHAR PRIMARY KEY,
    name VARCHAR NOT NULL,
    lifecycle_state VARCHAR NOT NULL,
    trust_score FLOAT DEFAULT 0.0,
    updated_at TIMESTAMP_TZ NOT NULL,
    data VARIANT NOT NULL
);

CREATE TABLE IF NOT EXISTS core.gateway_policies (
    policy_id VARCHAR PRIMARY KEY,
    name VARCHAR NOT NULL,
    mode VARCHAR NOT NULL,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    updated_at TIMESTAMP_TZ,
    data VARIANT NOT NULL
);

CREATE TABLE IF NOT EXISTS core.policy_audit_log (
    entry_id VARCHAR PRIMARY KEY,
    policy_id VARCHAR NOT NULL,
    agent_name VARCHAR,
    action_taken VARCHAR,
    timestamp TIMESTAMP_TZ,
    data VARIANT NOT NULL
);

-- 3b. App configuration table
CREATE TABLE IF NOT EXISTS core.app_config (
    key VARCHAR PRIMARY KEY,
    value VARIANT NOT NULL,
    updated_at TIMESTAMP_TZ DEFAULT CURRENT_TIMESTAMP()
);

INSERT INTO core.app_config (key, value)
    SELECT 'scan_interval_hours', PARSE_JSON('6')
    WHERE NOT EXISTS (SELECT 1 FROM core.app_config WHERE key = 'scan_interval_hours');

INSERT INTO core.app_config (key, value)
    SELECT 'retention_days', PARSE_JSON('90')
    WHERE NOT EXISTS (SELECT 1 FROM core.app_config WHERE key = 'retention_days');

INSERT INTO core.app_config (key, value)
    SELECT 'enable_scanner_service', PARSE_JSON('false')
    WHERE NOT EXISTS (SELECT 1 FROM core.app_config WHERE key = 'enable_scanner_service');

INSERT INTO core.app_config (key, value)
    SELECT 'enable_mcp_runtime_service', PARSE_JSON('false')
    WHERE NOT EXISTS (SELECT 1 FROM core.app_config WHERE key = 'enable_mcp_runtime_service');

INSERT INTO core.app_config (key, value)
    SELECT 'advisory_egress_enabled', PARSE_JSON('false')
    WHERE NOT EXISTS (SELECT 1 FROM core.app_config WHERE key = 'advisory_egress_enabled');

-- 3c. Governance findings table
CREATE TABLE IF NOT EXISTS core.governance_findings (
    finding_id VARCHAR PRIMARY KEY,
    category VARCHAR NOT NULL,
    severity VARCHAR NOT NULL,
    entity_type VARCHAR,
    entity_name VARCHAR,
    detail VARIANT NOT NULL,
    detected_at TIMESTAMP_TZ DEFAULT CURRENT_TIMESTAMP(),
    resolved_at TIMESTAMP_TZ
);

-- 3d. Activity events table
CREATE TABLE IF NOT EXISTS core.activity_events (
    event_id VARCHAR PRIMARY KEY,
    event_type VARCHAR NOT NULL,
    agent_name VARCHAR,
    detail VARIANT NOT NULL,
    created_at TIMESTAMP_TZ DEFAULT CURRENT_TIMESTAMP()
);

-- 4. Grant table access to app role
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA core TO APPLICATION ROLE app_user;

-- 5. Vulnerability view (flattens VARIANT JSON for fast queries)
CREATE OR REPLACE VIEW core.vulnerabilities AS
SELECT
    j.job_id,
    j.created_at AS scan_time,
    a.value:name::VARCHAR AS agent_name,
    s.value:name::VARCHAR AS server_name,
    p.value:name::VARCHAR AS package_name,
    p.value:version::VARCHAR AS package_version,
    p.value:ecosystem::VARCHAR AS ecosystem,
    v.value:id::VARCHAR AS vuln_id,
    v.value:severity::VARCHAR AS severity,
    v.value:cvss_score::FLOAT AS cvss_score,
    v.value:epss_score::FLOAT AS epss_score,
    v.value:is_kev::BOOLEAN AS is_kev,
    v.value:fixed_version::VARCHAR AS fixed_version
FROM core.scan_jobs j,
    LATERAL FLATTEN(INPUT => j.data:agents, OUTER => TRUE) a,
    LATERAL FLATTEN(INPUT => a.value:mcp_servers, OUTER => TRUE) s,
    LATERAL FLATTEN(INPUT => s.value:packages, OUTER => TRUE) p,
    LATERAL FLATTEN(INPUT => p.value:vulnerabilities, OUTER => TRUE) v
WHERE j.status = 'done'
  AND v.value:id IS NOT NULL;

GRANT SELECT ON VIEW core.vulnerabilities TO APPLICATION ROLE app_user;

-- 6. Cleanup stored procedure (removes completed jobs older than ttl_days)
CREATE OR REPLACE PROCEDURE core.cleanup_old_jobs(ttl_days INT)
    RETURNS VARCHAR
    LANGUAGE SQL
AS
BEGIN
    DELETE FROM core.scan_jobs
    WHERE status IN ('done', 'failed')
      AND completed_at IS NOT NULL
      AND DATEDIFF(DAY, completed_at, CURRENT_TIMESTAMP()) > :ttl_days;
    RETURN 'Cleanup complete';
END;

GRANT USAGE ON PROCEDURE core.cleanup_old_jobs(INT) TO APPLICATION ROLE app_user;

-- 8. Configuration stored procedures
CREATE OR REPLACE PROCEDURE core.set_config(config_key VARCHAR, config_value VARIANT)
    RETURNS VARCHAR
    LANGUAGE SQL
AS
BEGIN
    MERGE INTO core.app_config t
    USING (SELECT :config_key AS key, :config_value AS value) s
    ON t.key = s.key
    WHEN MATCHED THEN UPDATE SET value = s.value, updated_at = CURRENT_TIMESTAMP()
    WHEN NOT MATCHED THEN INSERT (key, value, updated_at) VALUES (s.key, s.value, CURRENT_TIMESTAMP());
    RETURN 'OK';
END;

CREATE OR REPLACE PROCEDURE core.get_config(config_key VARCHAR)
    RETURNS VARIANT
    LANGUAGE SQL
AS
BEGIN
    LET result VARIANT;
    SELECT value INTO :result FROM core.app_config WHERE key = :config_key;
    RETURN :result;
END;

GRANT USAGE ON PROCEDURE core.set_config(VARCHAR, VARIANT) TO APPLICATION ROLE app_user;
GRANT USAGE ON PROCEDURE core.get_config(VARCHAR) TO APPLICATION ROLE app_user;

-- 9. Trigger scan stored procedure
CREATE OR REPLACE PROCEDURE core.trigger_scan()
    RETURNS VARCHAR
    LANGUAGE SQL
AS
DECLARE
    job_id VARCHAR DEFAULT UUID_STRING();
BEGIN
    INSERT INTO core.scan_jobs (job_id, status, created_at, data)
    VALUES (:job_id, 'pending', CURRENT_TIMESTAMP(), PARSE_JSON('{}'));

    INSERT INTO core.activity_events (event_id, event_type, detail, created_at)
    VALUES (UUID_STRING(), 'scan_started', PARSE_JSON('{"job_id": "' || :job_id || '"}'), CURRENT_TIMESTAMP());

    RETURN 'Scan queued: ' || :job_id;
END;

GRANT USAGE ON PROCEDURE core.trigger_scan() TO APPLICATION ROLE app_user;

-- 10. Customer post-install health check.
-- This is intentionally read-only and surfaces the service toggles that matter
-- during Marketplace/private-preview validation.
CREATE OR REPLACE PROCEDURE core.health_check()
    RETURNS VARIANT
    LANGUAGE SQL
AS
BEGIN
    RETURN OBJECT_CONSTRUCT(
        'status', 'ok',
        'api_service', 'core.agent_bom_api',
        'scanner_service_enabled', (
            SELECT COALESCE(value::BOOLEAN, FALSE)
            FROM core.app_config
            WHERE key = 'enable_scanner_service'
        ),
        'mcp_runtime_service_enabled', (
            SELECT COALESCE(value::BOOLEAN, FALSE)
            FROM core.app_config
            WHERE key = 'enable_mcp_runtime_service'
        ),
        'advisory_egress_enabled', (
            SELECT COALESCE(value::BOOLEAN, FALSE)
            FROM core.app_config
            WHERE key = 'advisory_egress_enabled'
        )
    );
END;

GRANT USAGE ON PROCEDURE core.health_check() TO APPLICATION ROLE app_user;

-- 11. Auto-scan scheduled task (consumer starts with ALTER TASK ... RESUME)
CREATE OR REPLACE TASK core.auto_scan_task
    WAREHOUSE = 'COMPUTE_WH'
    SCHEDULE = 'USING CRON 0 */6 * * * UTC'
AS
    CALL core.trigger_scan();

-- Phase 2: Compliance Hub Snowpark proc (V002__compliance_proc.sql)
-- Creates core.apply_compliance_hub() and core.compliance_posture view.
EXECUTE IMMEDIATE FROM 'dcm/V002__compliance_proc.sql';

-- 12. SPCS service — API + Next.js UI (Phase 3)
-- Consumer must provision a compute pool and grant it to the app before this runs.
-- manifest.yml default_web_endpoint → ui endpoint (port 3000) opens on app launch.
CREATE SERVICE IF NOT EXISTS core.agent_bom_api
    IN COMPUTE POOL consumer_pool  -- consumer must grant this
    FROM SPECIFICATION_FILE = '/service-spec.yaml'
    MIN_INSTANCES = 1
    MAX_INSTANCES = 1;

GRANT USAGE ON SERVICE core.agent_bom_api TO APPLICATION ROLE app_user;
-- Service roles surface each endpoint independently so consumers can grant
-- API or UI access without exposing both.
GRANT SERVICE ROLE core.agent_bom_api!api TO APPLICATION ROLE app_user;
GRANT SERVICE ROLE core.agent_bom_api!ui  TO APPLICATION ROLE app_user;

-- 13. Phase 4 opt-in SPCS scanner service
-- Egress is not available to this container unless the customer binds all
-- advisory-feed EAI references and explicitly calls this procedure.
CREATE OR REPLACE PROCEDURE core.enable_scanner_service()
    RETURNS VARCHAR
    LANGUAGE SQL
AS
BEGIN
    CREATE SERVICE IF NOT EXISTS core.agent_bom_scanner
        IN COMPUTE POOL consumer_pool
        FROM SPECIFICATION_FILE = '/service-specs/scanner-service.yaml'
        EXTERNAL_ACCESS_INTEGRATIONS = (
            reference('osv_dev'),
            reference('cisa_kev'),
            reference('first_epss'),
            reference('github_ghsa')
        )
        MIN_INSTANCES = 1
        MAX_INSTANCES = 1
        AUTO_RESUME = FALSE;

    GRANT USAGE ON SERVICE core.agent_bom_scanner TO APPLICATION ROLE app_user;
    GRANT SERVICE ROLE core.agent_bom_scanner!scanner TO APPLICATION ROLE app_user;

    CALL core.set_config('enable_scanner_service', PARSE_JSON('true'));
    CALL core.set_config('advisory_egress_enabled', PARSE_JSON('true'));
    RETURN 'Scanner service created. Resume explicitly with ALTER SERVICE core.agent_bom_scanner RESUME.';
END;

GRANT USAGE ON PROCEDURE core.enable_scanner_service() TO APPLICATION ROLE app_user;

-- 14. Phase 4 optional MCP runtime service
-- The runtime is default-off and requires a caller-provided bearer token.
-- No advisory-feed EAI is attached here; this service has Snowflake-only
-- networking unless a future procedure deliberately adds bounded egress.
CREATE OR REPLACE PROCEDURE core.enable_mcp_runtime_service(mcp_bearer_token VARCHAR)
    RETURNS VARCHAR
    LANGUAGE SQL
AS
BEGIN
    IF (mcp_bearer_token IS NULL OR LENGTH(TRIM(mcp_bearer_token)) < 32) THEN
        RETURN 'MCP runtime not created: provide a bearer token with at least 32 characters.';
    END IF;

    CREATE SERVICE IF NOT EXISTS core.agent_bom_mcp_runtime
        IN COMPUTE POOL consumer_pool
        FROM SPECIFICATION_TEMPLATE_FILE = '/service-specs/mcp-runtime-service.yaml'
        USING (mcp_bearer_token => :mcp_bearer_token)
        MIN_INSTANCES = 1
        MAX_INSTANCES = 1
        AUTO_RESUME = FALSE;

    GRANT USAGE ON SERVICE core.agent_bom_mcp_runtime TO APPLICATION ROLE app_user;
    GRANT SERVICE ROLE core.agent_bom_mcp_runtime!mcp_runtime TO APPLICATION ROLE app_user;

    CALL core.set_config('enable_mcp_runtime_service', PARSE_JSON('true'));
    RETURN 'MCP runtime service created. Resume explicitly with ALTER SERVICE core.agent_bom_mcp_runtime RESUME.';
END;

GRANT USAGE ON PROCEDURE core.enable_mcp_runtime_service(VARCHAR) TO APPLICATION ROLE app_user;
