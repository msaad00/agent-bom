-- agent-bom ClickHouse analytics schema
-- Idempotent — safe to re-run on existing databases.

CREATE DATABASE IF NOT EXISTS agent_bom;

-- 1. Vulnerability scan results (append-only)
CREATE TABLE IF NOT EXISTS agent_bom.vulnerability_scans (
    scan_id String,
    scan_timestamp DateTime DEFAULT now(),
    package_name String,
    package_version String,
    ecosystem LowCardinality(String),
    cve_id String,
    cvss_score Float32,
    epss_score Float32,
    severity LowCardinality(String),
    source LowCardinality(String),
    agent_name String,
    environment LowCardinality(String)
) ENGINE = MergeTree()
ORDER BY (scan_timestamp, severity, agent_name)
PARTITION BY toYYYYMM(scan_timestamp);

-- 2. Runtime protection events (append-only)
CREATE TABLE IF NOT EXISTS agent_bom.runtime_events (
    event_id String,
    event_timestamp DateTime DEFAULT now(),
    event_type LowCardinality(String),
    detector LowCardinality(String),
    severity LowCardinality(String),
    tool_name String,
    message String,
    agent_name String
) ENGINE = MergeTree()
ORDER BY (event_timestamp, event_type, agent_name)
PARTITION BY toYYYYMM(event_timestamp);

-- 3. Posture scores (periodic snapshots)
CREATE TABLE IF NOT EXISTS agent_bom.posture_scores (
    measured_at DateTime DEFAULT now(),
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
    agent_count UInt32,
    package_count UInt32,
    vuln_count UInt32,
    critical_count UInt32,
    high_count UInt32,
    posture_grade LowCardinality(String),
    scan_duration_ms UInt32,
    source LowCardinality(String)
) ENGINE = MergeTree()
ORDER BY (scan_timestamp, scan_id)
PARTITION BY toYYYYMM(scan_timestamp)
TTL scan_timestamp + INTERVAL 2 YEAR;
