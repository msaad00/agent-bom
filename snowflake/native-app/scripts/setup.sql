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

-- 4. Grant table access to app role
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA core TO APPLICATION ROLE app_user;

-- 5. Streamlit dashboard (default_streamlit in manifest)
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
