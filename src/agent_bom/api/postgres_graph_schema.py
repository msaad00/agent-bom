"""Bootstrap DDL for the Postgres graph store, executed in declaration order."""

from __future__ import annotations

_GRAPH_TABLES_DDL: tuple[str, ...] = (
    """
                CREATE TABLE IF NOT EXISTS graph_nodes (
                    id TEXT NOT NULL,
                    entity_type TEXT NOT NULL,
                    label TEXT NOT NULL,
                    category_uid INTEGER DEFAULT 0,
                    class_uid INTEGER DEFAULT 0,
                    type_uid INTEGER DEFAULT 0,
                    status TEXT DEFAULT 'active',
                    risk_score DOUBLE PRECISION DEFAULT 0.0,
                    severity TEXT DEFAULT '',
                    severity_id INTEGER DEFAULT 0,
                    first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL,
                    attributes TEXT DEFAULT '{}',
                    compliance_tags TEXT DEFAULT '[]',
                    data_sources TEXT DEFAULT '[]',
                    dimensions TEXT DEFAULT '{}',
                    scan_id TEXT NOT NULL,
                    tenant_id TEXT NOT NULL DEFAULT 'default',
                    PRIMARY KEY (id, scan_id, tenant_id)
                )
                """,
    "CREATE INDEX IF NOT EXISTS idx_pg_graph_nodes_entity_type ON graph_nodes(entity_type)",
    "CREATE INDEX IF NOT EXISTS idx_pg_graph_nodes_scan ON graph_nodes(tenant_id, scan_id)",
    """
                CREATE INDEX IF NOT EXISTS idx_pg_graph_nodes_scan_order
                ON graph_nodes(tenant_id, scan_id, severity_id DESC, risk_score DESC, label)
                """,
    """
                CREATE INDEX IF NOT EXISTS idx_pg_graph_nodes_scan_id_cover
                ON graph_nodes(tenant_id, scan_id, id) INCLUDE (attributes)
                """,
    """
                CREATE TABLE IF NOT EXISTS graph_edges (
                    source_id TEXT NOT NULL,
                    target_id TEXT NOT NULL,
                    relationship TEXT NOT NULL,
                    direction TEXT DEFAULT 'directed',
                    weight DOUBLE PRECISION DEFAULT 1.0,
                    traversable INTEGER DEFAULT 1,
                    first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL,
                    valid_from TEXT DEFAULT '',
                    valid_to TEXT DEFAULT NULL,
                    confidence DOUBLE PRECISION DEFAULT 1.0,
                    provenance TEXT DEFAULT '{}',
                    source_scan_id TEXT DEFAULT '',
                    source_run_id TEXT DEFAULT '',
                    evidence TEXT DEFAULT '{}',
                    activity_id INTEGER DEFAULT 1,
                    scan_id TEXT NOT NULL,
                    tenant_id TEXT NOT NULL DEFAULT 'default',
                    PRIMARY KEY (source_id, target_id, relationship, scan_id, tenant_id)
                )
                """,
    "CREATE INDEX IF NOT EXISTS idx_pg_graph_edges_scan ON graph_edges(tenant_id, scan_id)",
    "CREATE INDEX IF NOT EXISTS idx_pg_graph_edges_scan_source ON graph_edges(tenant_id, scan_id, source_id)",
    "CREATE INDEX IF NOT EXISTS idx_pg_graph_edges_snapshot_key ON graph_edges(tenant_id, scan_id, source_id, target_id, relationship)",
    "CREATE INDEX IF NOT EXISTS idx_pg_graph_edges_scan_target ON graph_edges(tenant_id, scan_id, target_id)",
    "CREATE INDEX IF NOT EXISTS idx_pg_adjacency_out ON graph_edges(tenant_id, scan_id, "
    'source_id COLLATE "C", target_id COLLATE "C", relationship COLLATE "C")',
    "CREATE INDEX IF NOT EXISTS idx_pg_adjacency_in ON graph_edges(tenant_id, scan_id, "
    'target_id COLLATE "C", source_id COLLATE "C", relationship COLLATE "C")',
    "CREATE INDEX IF NOT EXISTS idx_pg_graph_edges_valid ON graph_edges(tenant_id, valid_from, valid_to)",
    """
                CREATE INDEX IF NOT EXISTS idx_pg_graph_edges_scan_source_traversable
                ON graph_edges(tenant_id, scan_id, source_id)
                WHERE traversable = 1
                """,
    """
                CREATE TABLE IF NOT EXISTS graph_snapshots (
                    scan_id TEXT NOT NULL,
                    tenant_id TEXT NOT NULL DEFAULT 'default',
                    created_at TEXT NOT NULL,
                    node_count INTEGER DEFAULT 0,
                    edge_count INTEGER DEFAULT 0,
                    risk_summary TEXT DEFAULT '{}',
                    node_type_counts TEXT DEFAULT NULL,
                    analysis_status TEXT NOT NULL DEFAULT '{}',
                    snapshot_kind TEXT NOT NULL DEFAULT 'scan' CHECK (snapshot_kind IN ('scan', 'correlation')),
                    correlation_id TEXT DEFAULT NULL,
                    evidence_manifest_sha256 TEXT NOT NULL DEFAULT '',
                    snapshot_generation TEXT NOT NULL DEFAULT '',
                    PRIMARY KEY (scan_id, tenant_id)
                )
                """,
)


_GRAPH_TABLES_MIGRATION_DDL: tuple[str, ...] = (
    "ALTER TABLE graph_snapshots ADD COLUMN IF NOT EXISTS node_type_counts TEXT DEFAULT NULL",
    "ALTER TABLE graph_snapshots ADD COLUMN IF NOT EXISTS snapshot_kind TEXT NOT NULL DEFAULT 'scan'",
    "ALTER TABLE graph_snapshots ADD COLUMN IF NOT EXISTS correlation_id TEXT DEFAULT NULL",
    "ALTER TABLE graph_snapshots ADD COLUMN IF NOT EXISTS evidence_manifest_sha256 TEXT NOT NULL DEFAULT ''",
    "CREATE INDEX IF NOT EXISTS idx_pg_graph_snapshots_recent ON graph_snapshots(tenant_id, created_at DESC)",
    """
                CREATE TABLE IF NOT EXISTS graph_correlation_runs (
                    correlation_id TEXT NOT NULL,
                    tenant_id TEXT NOT NULL DEFAULT 'default',
                    idempotency_key TEXT NOT NULL,
                    name TEXT NOT NULL DEFAULT '',
                    status TEXT NOT NULL CHECK (status IN ('pending', 'running', 'complete', 'failed')),
                    max_age_hours INTEGER NOT NULL CHECK (max_age_hours BETWEEN 1 AND 8760),
                    allow_stale INTEGER NOT NULL DEFAULT 0 CHECK (allow_stale IN (0, 1)),
                    input_manifest TEXT NOT NULL DEFAULT '[]',
                    result_manifest TEXT NOT NULL DEFAULT '{}',
                    manifest_sha256 TEXT NOT NULL DEFAULT '',
                    output_scan_id TEXT NOT NULL DEFAULT '',
                    failure_code TEXT NOT NULL DEFAULT '',
                    created_at TEXT NOT NULL,
                    started_at TEXT NOT NULL DEFAULT '',
                    completed_at TEXT NOT NULL DEFAULT '',
                    execution_owner TEXT NOT NULL DEFAULT '',
                    execution_lease_expires_at TEXT NOT NULL DEFAULT '',
                    PRIMARY KEY (correlation_id, tenant_id),
                    UNIQUE (tenant_id, idempotency_key)
                )
                """,
    "CREATE INDEX IF NOT EXISTS idx_pg_graph_correlation_runs_recent ON graph_correlation_runs(tenant_id, created_at DESC)",
    "ALTER TABLE graph_correlation_runs ADD COLUMN IF NOT EXISTS result_manifest TEXT NOT NULL DEFAULT '{}'",
    "ALTER TABLE graph_correlation_runs ADD COLUMN IF NOT EXISTS execution_owner TEXT NOT NULL DEFAULT ''",
    "ALTER TABLE graph_correlation_runs ADD COLUMN IF NOT EXISTS execution_lease_expires_at TEXT NOT NULL DEFAULT ''",
    """
                CREATE TABLE IF NOT EXISTS attack_paths (
                    source_node TEXT NOT NULL,
                    target_node TEXT NOT NULL,
                    hop_count INTEGER DEFAULT 0,
                    composite_risk DOUBLE PRECISION DEFAULT 0.0,
                    summary TEXT DEFAULT '',
                    path_nodes TEXT DEFAULT '[]',
                    path_edges TEXT DEFAULT '[]',
                    credential_exposure TEXT DEFAULT '[]',
                    tool_exposure TEXT DEFAULT '[]',
                    vuln_ids TEXT DEFAULT '[]',
                    reachability TEXT DEFAULT 'unknown',
                    reachability_basis TEXT DEFAULT '[]',
                    technique_mappings TEXT DEFAULT '[]',
                    hop_evidence TEXT DEFAULT '[]',
                    analysis TEXT DEFAULT '{}',
                    scan_id TEXT NOT NULL,
                    tenant_id TEXT NOT NULL DEFAULT 'default',
                    computed_at TEXT NOT NULL,
                    PRIMARY KEY (source_node, target_node, scan_id, tenant_id)
                )
                """,
    "CREATE INDEX IF NOT EXISTS idx_pg_attack_paths_scan ON attack_paths(tenant_id, scan_id)",
    "CREATE INDEX IF NOT EXISTS idx_pg_attack_paths_scan_risk ON attack_paths(tenant_id, scan_id, composite_risk DESC)",
    """
                CREATE INDEX IF NOT EXISTS idx_pg_attack_paths_source_risk
                ON attack_paths(tenant_id, scan_id, source_node, composite_risk DESC, target_node)
                """,
    "ALTER TABLE attack_paths ADD COLUMN IF NOT EXISTS summary TEXT DEFAULT ''",
    "ALTER TABLE attack_paths ADD COLUMN IF NOT EXISTS tool_exposure TEXT DEFAULT '[]'",
    "ALTER TABLE attack_paths ADD COLUMN IF NOT EXISTS technique_mappings TEXT DEFAULT '[]'",
    "ALTER TABLE attack_paths ADD COLUMN IF NOT EXISTS reachability TEXT DEFAULT 'unknown'",
    "ALTER TABLE attack_paths ADD COLUMN IF NOT EXISTS reachability_basis TEXT DEFAULT '[]'",
    "ALTER TABLE attack_paths ADD COLUMN IF NOT EXISTS hop_evidence TEXT DEFAULT '[]'",
    "ALTER TABLE attack_paths ADD COLUMN IF NOT EXISTS analysis TEXT DEFAULT '{}'",
    "ALTER TABLE graph_snapshots ADD COLUMN IF NOT EXISTS analysis_status TEXT NOT NULL DEFAULT '{}'",
    "ALTER TABLE graph_edges ADD COLUMN IF NOT EXISTS valid_from TEXT DEFAULT ''",
    "ALTER TABLE graph_edges ADD COLUMN IF NOT EXISTS valid_to TEXT DEFAULT NULL",
    "ALTER TABLE graph_edges ADD COLUMN IF NOT EXISTS confidence DOUBLE PRECISION DEFAULT 1.0",
    "ALTER TABLE graph_edges ADD COLUMN IF NOT EXISTS provenance TEXT DEFAULT '{}'",
    "ALTER TABLE graph_edges ADD COLUMN IF NOT EXISTS source_scan_id TEXT DEFAULT ''",
    "ALTER TABLE graph_edges ADD COLUMN IF NOT EXISTS source_run_id TEXT DEFAULT ''",
    "UPDATE graph_edges SET valid_from = first_seen WHERE valid_from = '' OR valid_from IS NULL",
    "UPDATE graph_edges SET source_scan_id = scan_id WHERE source_scan_id = '' OR source_scan_id IS NULL",
    """
                CREATE TABLE IF NOT EXISTS interaction_risks (
                    pattern TEXT NOT NULL,
                    agents TEXT NOT NULL,
                    risk_score DOUBLE PRECISION DEFAULT 0.0,
                    description TEXT DEFAULT '',
                    owasp_agentic_tag TEXT DEFAULT NULL,
                    scan_id TEXT NOT NULL,
                    tenant_id TEXT NOT NULL DEFAULT 'default',
                    PRIMARY KEY (pattern, agents, scan_id, tenant_id)
                )
                """,
    "CREATE INDEX IF NOT EXISTS idx_pg_interaction_risks_scan ON interaction_risks(tenant_id, scan_id)",
    """
                CREATE TABLE IF NOT EXISTS graph_filter_presets (
                    name TEXT NOT NULL,
                    tenant_id TEXT NOT NULL DEFAULT 'default',
                    description TEXT DEFAULT '',
                    filters TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    PRIMARY KEY (name, tenant_id)
                )
                """,
    """
                CREATE TABLE IF NOT EXISTS graph_node_search (
                    node_id TEXT NOT NULL,
                    tenant_id TEXT NOT NULL DEFAULT 'default',
                    scan_id TEXT NOT NULL,
                    entity_type TEXT NOT NULL,
                    severity TEXT DEFAULT '',
                    compliance_tags TEXT DEFAULT '',
                    data_sources TEXT DEFAULT '',
                    search_text TEXT NOT NULL,
                    PRIMARY KEY (node_id, scan_id, tenant_id)
                )
                """,
    """
                CREATE INDEX IF NOT EXISTS idx_pg_graph_node_search_scope
                ON graph_node_search(tenant_id, scan_id, entity_type)
                """,
    """
                CREATE INDEX IF NOT EXISTS idx_pg_graph_node_search_severity
                ON graph_node_search(tenant_id, scan_id, severity)
                """,
)
