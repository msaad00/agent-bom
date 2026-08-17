-- =============================================================================
-- agent-bom: Snowpark Container Services deployment
-- Run this script in a Snowflake worksheet to set up the full environment.
-- =============================================================================

-- 1. Database & Schema
CREATE DATABASE IF NOT EXISTS AGENT_BOM;
USE DATABASE AGENT_BOM;
CREATE SCHEMA IF NOT EXISTS PUBLIC;
USE SCHEMA PUBLIC;

-- 2. Tables (same schema as snowflake_store.py auto-creates)
CREATE TABLE IF NOT EXISTS scan_jobs (
    job_id VARCHAR PRIMARY KEY,
    status VARCHAR NOT NULL,
    created_at TIMESTAMP_TZ NOT NULL,
    completed_at TIMESTAMP_TZ,
    data VARIANT NOT NULL
);

-- Keyed by (tenant_id, agent_id): agent IDs are derived from agent content with
-- no tenant component, so a bare agent_id key let one tenant's registration
-- overwrite another's. Snowflake does not enforce PRIMARY KEY on standard
-- tables, so the MERGE predicates in snowflake_store.py are what keep the
-- tenants apart; this declaration documents the intended key.
CREATE TABLE IF NOT EXISTS fleet_agents (
    agent_id VARCHAR NOT NULL,
    tenant_id VARCHAR NOT NULL DEFAULT 'default',
    name VARCHAR NOT NULL,
    lifecycle_state VARCHAR NOT NULL,
    trust_score FLOAT DEFAULT 0.0,
    updated_at TIMESTAMP_TZ NOT NULL,
    data VARIANT NOT NULL,
    PRIMARY KEY (tenant_id, agent_id)
);

CREATE TABLE IF NOT EXISTS fleet_endpoints (
    tenant_id VARCHAR NOT NULL,
    endpoint_id VARCHAR NOT NULL,
    completeness VARCHAR NOT NULL,
    updated_at TIMESTAMP_TZ NOT NULL,
    data VARIANT NOT NULL,
    PRIMARY KEY (tenant_id, endpoint_id)
);

CREATE TABLE IF NOT EXISTS gateway_policies (
    policy_id VARCHAR PRIMARY KEY,
    name VARCHAR NOT NULL,
    mode VARCHAR NOT NULL,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    updated_at TIMESTAMP_TZ,
    data VARIANT NOT NULL
);

CREATE TABLE IF NOT EXISTS policy_audit_log (
    entry_id VARCHAR PRIMARY KEY,
    policy_id VARCHAR NOT NULL,
    agent_name VARCHAR,
    action_taken VARCHAR,
    timestamp TIMESTAMP_TZ,
    data VARIANT NOT NULL
);

-- 3. Image Repository
CREATE IMAGE REPOSITORY IF NOT EXISTS agent_bom_repo;

-- After creating the repo, push the Docker image:
--   docker tag agent-bom:latest <account>.registry.snowflakecomputing.com/agent_bom/public/agent_bom_repo/agent-bom:latest
--   docker push <account>.registry.snowflakecomputing.com/agent_bom/public/agent_bom_repo/agent-bom:latest

-- 4. Compute Pool
CREATE COMPUTE POOL IF NOT EXISTS agent_bom_pool
    MIN_NODES = 1
    MAX_NODES = 1
    INSTANCE_FAMILY = CPU_X64_XS;

-- 5. Service
CREATE SERVICE IF NOT EXISTS agent_bom_service
    IN COMPUTE POOL agent_bom_pool
    FROM @agent_bom.public.agent_bom_repo
    SPECIFICATION_FILE = 'service-spec.yaml'
    MIN_INSTANCES = 1
    MAX_INSTANCES = 1;

-- 6. Grant endpoint access
GRANT USAGE ON SERVICE agent_bom_service TO ROLE PUBLIC;

-- 7. Check service status
-- CALL SYSTEM$GET_SERVICE_STATUS('agent_bom_service');
-- CALL SYSTEM$GET_SERVICE_LOGS('agent_bom_service', '0', 'agent-bom', 100);
