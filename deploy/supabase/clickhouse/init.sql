-- agent-bom ClickHouse analytics schema
-- Idempotent — safe to re-run on existing databases.

CREATE DATABASE IF NOT EXISTS agent_bom;

-- 0. Control-plane schema inventory for release/upgrade readiness checks
CREATE TABLE IF NOT EXISTS agent_bom.control_plane_schema_versions (
    component String,
    version UInt16,
    updated_at DateTime DEFAULT now()
) ENGINE = ReplacingMergeTree(updated_at)
ORDER BY component;

-- 1. Vulnerability scan results (append-only)
CREATE TABLE IF NOT EXISTS agent_bom.vulnerability_scans (
    scan_id String,
    scan_timestamp DateTime DEFAULT now(),
    tenant_id String DEFAULT 'default',
    package_name String,
    package_version String,
    ecosystem LowCardinality(String),
    cve_id String,
    cvss_score Float32,
    epss_score Float32,
    severity LowCardinality(String),
    source LowCardinality(String),
    agent_name String,
    environment LowCardinality(String),
    cmmc_tags Array(String)
) ENGINE = MergeTree()
ORDER BY (scan_timestamp, severity, agent_name)
PARTITION BY toYYYYMM(scan_timestamp);

-- 2. Runtime protection events (append-only)
CREATE TABLE IF NOT EXISTS agent_bom.runtime_events (
    event_id String,
    event_timestamp DateTime DEFAULT now(),
    tenant_id String DEFAULT 'default',
    event_type LowCardinality(String),
    detector LowCardinality(String),
    severity LowCardinality(String),
    tool_name String,
    message String,
    agent_name String,
    session_id String DEFAULT '',
    trace_id String DEFAULT '',
    request_id String DEFAULT '',
    source_id String DEFAULT ''
) ENGINE = MergeTree()
ORDER BY (event_timestamp, event_type, agent_name)
PARTITION BY toYYYYMM(event_timestamp);

-- 3. Posture scores (periodic snapshots)
CREATE TABLE IF NOT EXISTS agent_bom.posture_scores (
    measured_at DateTime DEFAULT now(),
    tenant_id String DEFAULT 'default',
    agent_name String,
    total_packages UInt32,
    critical_vulns UInt32,
    high_vulns UInt32,
    medium_vulns UInt32,
    posture_grade LowCardinality(String),
    risk_score Float32,
    compliance_score Float32
) ENGINE = MergeTree()
ORDER BY (measured_at, agent_name)
PARTITION BY toYYYYMM(measured_at)
TTL measured_at + INTERVAL 2 YEAR;

-- 4. Scan metadata (one row per scan run)
CREATE TABLE IF NOT EXISTS agent_bom.scan_metadata (
    scan_id String,
    scan_timestamp DateTime DEFAULT now(),
    tenant_id String DEFAULT 'default',
    agent_count UInt32,
    package_count UInt32,
    vuln_count UInt32,
    critical_count UInt32,
    high_count UInt32,
    posture_grade LowCardinality(String),
    scan_duration_ms UInt32,
    source LowCardinality(String),
    aisvs_score Float32 DEFAULT 0.0,
    has_runtime_correlation UInt8 DEFAULT 0
) ENGINE = MergeTree()
ORDER BY (scan_timestamp, scan_id)
PARTITION BY toYYYYMM(scan_timestamp)
TTL scan_timestamp + INTERVAL 2 YEAR;

-- 5. Fleet agent snapshots (trust/lifecycle over time)
CREATE TABLE IF NOT EXISTS agent_bom.fleet_agents (
    measured_at DateTime DEFAULT now(),
    agent_name String,
    agent_type LowCardinality(String),
    lifecycle_state LowCardinality(String),
    trust_score Float32,
    server_count UInt32,
    package_count UInt32,
    credential_count UInt32,
    vuln_count UInt32,
    tenant_id String
) ENGINE = MergeTree()
ORDER BY (measured_at, tenant_id, agent_name)
PARTITION BY toYYYYMM(measured_at)
TTL measured_at + INTERVAL 2 YEAR;

-- 6. Compliance control observations
CREATE TABLE IF NOT EXISTS agent_bom.compliance_controls (
    measured_at DateTime DEFAULT now(),
    scan_id String,
    tenant_id String DEFAULT 'default',
    framework LowCardinality(String),
    control_id String,
    control_name String,
    status LowCardinality(String),
    finding_count UInt32,
    score Float32
) ENGINE = MergeTree()
ORDER BY (measured_at, framework, control_id)
PARTITION BY toYYYYMM(measured_at)
TTL measured_at + INTERVAL 2 YEAR;

-- 7. Audit events for trend/forensics dashboards
CREATE TABLE IF NOT EXISTS agent_bom.audit_events (
    event_timestamp DateTime DEFAULT now(),
    entry_id String,
    action LowCardinality(String),
    actor String,
    resource String,
    tenant_id String,
    session_id String DEFAULT '',
    trace_id String DEFAULT '',
    request_id String DEFAULT ''
) ENGINE = MergeTree()
ORDER BY (event_timestamp, tenant_id, action)
PARTITION BY toYYYYMM(event_timestamp)
TTL event_timestamp + INTERVAL 2 YEAR;

-- 8. CIS benchmark check observations with remediation fields indexed
CREATE TABLE IF NOT EXISTS agent_bom.cis_benchmark_checks (
    measured_at DateTime DEFAULT now(),
    scan_id String,
    tenant_id String DEFAULT 'default',
    cloud LowCardinality(String),
    check_id String,
    title String,
    status LowCardinality(String),
    severity LowCardinality(String),
    cis_section String,
    evidence String,
    resource_ids Array(String),
    remediation String,
    fix_cli String,
    fix_console String,
    effort LowCardinality(String),
    priority UInt8,
    guardrails Array(String),
    requires_human_review UInt8
) ENGINE = MergeTree()
ORDER BY (measured_at, tenant_id, cloud, status, priority, check_id)
PARTITION BY toYYYYMM(measured_at)
TTL measured_at + INTERVAL 2 YEAR;

-- Forward-compatible migrations for deployments created from older init.sql
-- revisions. These mirror the runtime ClickHouse client migrations.
ALTER TABLE agent_bom.vulnerability_scans ADD COLUMN IF NOT EXISTS tenant_id String DEFAULT 'default';
ALTER TABLE agent_bom.runtime_events ADD COLUMN IF NOT EXISTS tenant_id String DEFAULT 'default';
ALTER TABLE agent_bom.runtime_events ADD COLUMN IF NOT EXISTS session_id String DEFAULT '';
ALTER TABLE agent_bom.runtime_events ADD COLUMN IF NOT EXISTS trace_id String DEFAULT '';
ALTER TABLE agent_bom.runtime_events ADD COLUMN IF NOT EXISTS request_id String DEFAULT '';
ALTER TABLE agent_bom.runtime_events ADD COLUMN IF NOT EXISTS source_id String DEFAULT '';
ALTER TABLE agent_bom.posture_scores ADD COLUMN IF NOT EXISTS tenant_id String DEFAULT 'default';
ALTER TABLE agent_bom.scan_metadata ADD COLUMN IF NOT EXISTS tenant_id String DEFAULT 'default';
ALTER TABLE agent_bom.compliance_controls ADD COLUMN IF NOT EXISTS tenant_id String DEFAULT 'default';
ALTER TABLE agent_bom.audit_events ADD COLUMN IF NOT EXISTS session_id String DEFAULT '';
ALTER TABLE agent_bom.audit_events ADD COLUMN IF NOT EXISTS trace_id String DEFAULT '';
ALTER TABLE agent_bom.audit_events ADD COLUMN IF NOT EXISTS request_id String DEFAULT '';
ALTER TABLE agent_bom.cis_benchmark_checks ADD COLUMN IF NOT EXISTS tenant_id String DEFAULT 'default';
ALTER TABLE agent_bom.cis_benchmark_checks ADD COLUMN IF NOT EXISTS remediation String DEFAULT '{}';

INSERT INTO agent_bom.control_plane_schema_versions (component, version) VALUES ('analytics', 1);
