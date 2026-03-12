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

-- 10. Auto-scan scheduled task (consumer starts with ALTER TASK ... RESUME)
CREATE OR REPLACE TASK core.auto_scan_task
    WAREHOUSE = 'COMPUTE_WH'
    SCHEDULE = 'USING CRON 0 */6 * * * UTC'
AS
    CALL core.trigger_scan();

-- 7. Streamlit dashboard (default_streamlit in manifest)
CREATE STREAMLIT IF NOT EXISTS core.dashboard
    FROM 'streamlit'
    MAIN_FILE = 'dashboard.py';
GRANT USAGE ON STREAMLIT core.dashboard TO APPLICATION ROLE app_user;

-- 6. Service (agent-bom API in Snowpark Container Services)
-- Note: compute pool must be created by the consumer and granted to the app.
-- The app creates the service once a compute pool is available.
CREATE SERVICE IF NOT EXISTS core.agent_bom_api
    IN COMPUTE POOL consumer_pool  -- consumer must grant this
    FROM SPECIFICATION_FILE = '/service-spec.yaml'
    MIN_INSTANCES = 1
    MAX_INSTANCES = 1;

GRANT USAGE ON SERVICE core.agent_bom_api TO APPLICATION ROLE app_user;
