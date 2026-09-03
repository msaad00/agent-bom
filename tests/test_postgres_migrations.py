"""Tests for the Alembic migration scaffolding on the enterprise Postgres path."""

from __future__ import annotations

import importlib.util
import re
import sys
from pathlib import Path
from types import SimpleNamespace

POSTGRES_DIR = Path(__file__).parent.parent / "deploy" / "supabase" / "postgres"
ALEMBIC_DIR = POSTGRES_DIR / "alembic"
VERSIONS_DIR = ALEMBIC_DIR / "versions"
BASELINE = VERSIONS_DIR / "20260416_01_control_plane_baseline.py"
GRAPH_HOT_PATH_INDEXES = VERSIONS_DIR / "20260513_01_graph_hot_path_indexes.py"
POSTGRES_STORE_PARITY = VERSIONS_DIR / "20260717_01_postgres_store_parity.py"
GRAPH_ANALYSIS_STATUS = VERSIONS_DIR / "20260717_02_graph_analysis_status.py"
GRAPH_SNAPSHOT_JSON_PARITY = VERSIONS_DIR / "20260717_03_graph_snapshot_json_parity.py"
RUNTIME_SCHEMA_AUTHORITY = VERSIONS_DIR / "20260718_01_runtime_schema_authority.py"
CLOUD_CONNECTIONS_SCOPE_COLUMNS = VERSIONS_DIR / "20260724_02_cloud_connections_scope_columns.py"
MANAGED_TRIAL_INVITATIONS = VERSIONS_DIR / "20260724_03_managed_trial_invitations.py"
TICKETING_SCHEMA_AUTHORITY = VERSIONS_DIR / "20260726_01_ticketing_schema_authority.py"
RUNTIME_EVIDENCE_TIMESTAMP_AUTHORITY = VERSIONS_DIR / "20260727_01_runtime_evidence_timestamp_authority.py"
MCP_PROFILE_BINDING_AUTHORITY = VERSIONS_DIR / "20260728_01_mcp_profile_binding_authority.py"
GATEWAY_ACTIVITY_LEDGER = VERSIONS_DIR / "20260728_02_gateway_activity_ledger.py"
TRUSTED_MAINTENANCE_RLS = VERSIONS_DIR / "20260728_03_trusted_maintenance_rls.py"
GATEWAY_ACTIVITY_WINDOW_INDEX = VERSIONS_DIR / "20260729_02_gateway_activity_window_index.py"
PARTITION_CHILD_RLS = VERSIONS_DIR / "20260729_03_partition_child_rls.py"
GRAPH_EDGE_SNAPSHOT_KEY_INDEX = VERSIONS_DIR / "20260730_01_graph_edge_snapshot_key_index.py"
TEAMS_TENANT_RLS = VERSIONS_DIR / "20260730_02_teams_tenant_rls.py"
OBSERVATION_PARTITION_RUNWAY = VERSIONS_DIR / "20260731_01_observation_partition_runway.py"
FLEET_AGENTS_TENANT_KEY = VERSIONS_DIR / "20260801_01_fleet_agents_tenant_scoped_key.py"
POSTGRES_MCP_CONFIG_STORE = Path(__file__).parent.parent / "src" / "agent_bom" / "api" / "postgres_mcp_config.py"
AUDIT_FORK_GUARD_INDEX = VERSIONS_DIR / "20260719_01_audit_fork_guard_index.py"
HUB_OBSERVATIONS_PARTITION = VERSIONS_DIR / "20260705_01_hub_observations_partition.py"
BOOTSTRAP = ALEMBIC_DIR / "bootstrap.py"
RUNTIME_SCHEMA_SQL = POSTGRES_DIR / "runtime-schema.sql"
HUB_LEDGER_SCAN_ID = VERSIONS_DIR / "20260818_01_hub_ledger_scan_id.py"
TENANT_BINDING_AUTHORITY = VERSIONS_DIR / "20260819_01_tenant_binding_authority.py"
HUB_OVERVIEW_REVISION = VERSIONS_DIR / "20260827_01_hub_overview_revision.py"
GRAPH_CORRELATIONS = VERSIONS_DIR / "20260830_01_graph_correlations.py"
ATTACK_PATH_EVIDENCE = VERSIONS_DIR / "20260830_02_graph_correlation_mechanical.py"
CLOUD_CONNECTION_CAPABILITY_EVIDENCE = VERSIONS_DIR / "20260830_03_cloud_connection_capability_evidence.py"
OBSERVATION_PARTITION_RETENTION_WINDOW = VERSIONS_DIR / "20260901_01_observation_partition_retention_window.py"
EXECUTION_LEASES = VERSIONS_DIR / "20260903_01_execution_leases.py"

# The fork-guard UNIQUE index is spelled differently in its two schema sources:
# the dedicated migration concatenates two quoted Python string literals, while
# runtime-schema.sql packs the columns with no spaces. Canonicalise both (drop
# quotes + all whitespace, lowercase) before matching so the assertion tracks
# the DDL, not the formatting.
_FORK_GUARD_INDEX_CANON = "createuniqueindexifnotexistsaudit_log_team_prevsig_uniqonaudit_log(team_id,prev_signature)"


# The newest migration. One place to update when a revision lands, so the
# single-head property and the head's identity do not drift apart.
ALEMBIC_HEAD = "20260903_01"


def _canonical_sql(text: str) -> str:
    return re.sub(r"[\s\"]+", "", text).lower()


def _load_module(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_alembic_scaffolding_exists():
    assert (POSTGRES_DIR / "alembic.ini").exists()
    assert (ALEMBIC_DIR / "env.py").exists()
    assert BOOTSTRAP.exists()
    assert (ALEMBIC_DIR / "script.py.mako").exists()
    assert BASELINE.exists()
    assert GRAPH_HOT_PATH_INDEXES.exists()


def test_hub_overview_revision_is_durable_chained_and_tenant_isolated() -> None:
    sql = HUB_OVERVIEW_REVISION.read_text()
    assert re.search(r'revision\s*=\s*"20260827_01"', sql)
    assert re.search(r'down_revision\s*=\s*"20260825_01"', sql)
    assert "CREATE TABLE IF NOT EXISTS hub_overview_revisions" in sql
    assert "tenant_id TEXT PRIMARY KEY" in sql
    assert "revision BIGINT NOT NULL DEFAULT 0" in sql
    assert "ALTER TABLE hub_overview_revisions ENABLE ROW LEVEL SECURITY" in sql
    assert "ALTER TABLE hub_overview_revisions FORCE ROW LEVEL SECURITY" in sql
    assert "hub_overview_revisions_tenant_isolation" in sql
    assert "tenant_id = public.abom_current_tenant()" in sql
    assert "GRANT SELECT, INSERT, UPDATE, DELETE ON hub_overview_revisions TO agent_bom_app" in sql
    assert "VALUES ('compliance_hub', 2, now())" in sql


def test_graph_correlation_migration_is_additive_chained_and_tenant_isolated() -> None:
    sql = GRAPH_CORRELATIONS.read_text()
    assert re.search(r'revision\s*=\s*"20260830_01"', sql)
    assert re.search(r'down_revision\s*=\s*"20260827_01"', sql)
    assert "CREATE TABLE IF NOT EXISTS graph_correlation_runs" in sql
    assert "UNIQUE (tenant_id, idempotency_key)" in sql
    assert "ADD COLUMN IF NOT EXISTS snapshot_kind" in sql
    assert "ADD COLUMN IF NOT EXISTS correlation_id" in sql
    assert "ADD COLUMN IF NOT EXISTS evidence_manifest_sha256" in sql
    assert "ENABLE ROW LEVEL SECURITY" in sql
    assert "FORCE ROW LEVEL SECURITY" in sql
    assert "graph_correlation_runs_tenant_isolation" in sql
    assert "VALUES ('graph', 2, now())" in sql


def test_graph_correlation_migration_tolerates_legacy_schema_without_graph_snapshots() -> None:
    """Legacy checkpoints may predate the optional graph persistence tables."""

    sql = GRAPH_CORRELATIONS.read_text()
    assert "to_regclass('public.graph_snapshots') IS NOT NULL" in sql


def test_attack_path_evidence_migration_is_additive_and_legacy_safe() -> None:
    sql = ATTACK_PATH_EVIDENCE.read_text()
    assert re.search(r'revision\s*=\s*"20260830_02"', sql)
    assert re.search(r'down_revision\s*=\s*"20260830_01"', sql)
    assert "to_regclass('public.attack_paths') IS NOT NULL" in sql
    assert "ADD COLUMN IF NOT EXISTS hop_evidence" in sql
    assert "ADD COLUMN IF NOT EXISTS analysis" in sql
    assert "VALUES ('graph', 3, now())" in sql


def test_managed_trial_invitation_migration_is_chained_and_secret_minimal() -> None:
    sql = MANAGED_TRIAL_INVITATIONS.read_text()
    assert re.search(r'revision\s*=\s*"20260724_03"', sql)
    assert re.search(r'down_revision\s*=\s*"20260724_02"', sql)
    assert "CREATE TABLE IF NOT EXISTS managed_trial_invitations" in sql
    assert "CREATE TABLE IF NOT EXISTS managed_trial_tenants" in sql
    for column in (
        "token_digest",
        "email",
        "tenant_id",
        "state",
        "created_at",
        "expires_at",
        "accepted_at",
        "verified_subject",
        "trial_ends_at",
        "cleanup_after",
    ):
        assert column in sql
    for forbidden in ("raw_token", "api_key", "oidc_subject"):
        assert forbidden not in sql
    assert "ENABLE ROW LEVEL SECURITY" in sql
    assert "FORCE ROW LEVEL SECURITY" in sql
    assert "managed_trial_invitations_tenant_isolation" in sql
    assert "managed_trial_tenants_tenant_isolation" in sql


def test_ticketing_schema_authority_migration_is_chained_and_tenant_isolated() -> None:
    sql = TICKETING_SCHEMA_AUTHORITY.read_text()
    assert re.search(r'revision\s*=\s*"20260726_01"', sql)
    assert re.search(r'down_revision\s*=\s*"20260724_03"', sql)
    assert "CREATE TABLE IF NOT EXISTS ticketing_connections" in sql
    assert "CREATE TABLE IF NOT EXISTS ticket_links" in sql
    assert "UNIQUE (tenant_id, connection_id, dedupe_key)" in sql
    assert "idx_ticketing_connections_tenant" in sql
    assert "idx_ticket_links_tenant" in sql
    for table in ("ticketing_connections", "ticket_links"):
        assert f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY" in sql
        assert f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY" in sql
        assert f"{table}_tenant_isolation" in sql
        assert f"GRANT SELECT, INSERT, UPDATE, DELETE ON {table} TO agent_bom_app" in sql
    assert "VALUES ('ticketing_connections', 1, now())" in sql


def test_runtime_evidence_timestamp_migration_is_chained_and_typed() -> None:
    sql = RUNTIME_EVIDENCE_TIMESTAMP_AUTHORITY.read_text()
    assert re.search(r'revision\s*=\s*"20260727_01"', sql)
    assert re.search(r'down_revision\s*=\s*"20260726_01"', sql)
    assert "ALTER COLUMN observed_at TYPE TIMESTAMPTZ" in sql
    assert "USING observed_at::timestamptz" in sql
    assert "SET LOCAL TIME ZONE 'UTC'" in sql
    assert sql.index("set_config('app.bypass_rls', '1', true)") < sql.index("UPDATE runtime_workload_evidence AS target")
    assert "payload_json::jsonb" in sql
    assert "jsonb_build_object" in sql
    assert "'title', safe_title" in sql
    assert "'evidence', safe_evidence" in sql
    assert "'{}'::jsonb" in sql
    for credential_shape in (
        "AKIA",
        "ghp",
        "eyJ",
        "xox",
        "PRIVATE KEY",
        "://",
        "glpat",
        "ya29",
        "sk-(proj-)?",
        "Bearer",
        "password",
    ):
        assert credential_shape in sql
    for length_guard in (
        "length(tenant_id) > 256",
        "length(account_id) > 512",
        "length(workload_ref) > 2048",
        "length(workload_id) > 4096",
        "length(source_id) > 256",
        "length(source_kind) > 128",
        "length(dedup_key) > 512",
    ):
        assert length_guard in sql
    assert "'workload_id', workload_id" in sql
    assert sql.index("RAISE EXCEPTION") < sql.index("UPDATE runtime_workload_evidence AS target")
    assert "VALUES ('runtime_workload_evidence', 2, now())" in sql
    runtime_schema = RUNTIME_SCHEMA_SQL.read_text()
    assert "observed_at TIMESTAMPTZ NOT NULL" in runtime_schema
    assert "VALUES ('runtime_workload_evidence',2,now())" in runtime_schema


def test_mcp_profile_binding_migration_is_chained_unique_and_tenant_isolated() -> None:
    sql = MCP_PROFILE_BINDING_AUTHORITY.read_text()
    assert re.search(r'revision\s*=\s*"20260728_01"', sql)
    assert re.search(r'down_revision\s*=\s*"20260727_01"', sql)
    for column in ("identity_id", "issuer", "environment", "status", "revision", "updated_at"):
        assert f"ADD COLUMN IF NOT EXISTS {column}" in sql
    assert "UPDATE mcp_client_configs" in sql
    assert "WHEN revoked THEN 'revoked'" in sql
    assert "idx_mcp_client_configs_active_identity" in sql
    assert "idx_mcp_client_configs_identity_history" in sql
    assert "ON mcp_client_configs (tenant_id, identity_id)" in sql
    assert "btrim(identity_id) <> ''" in sql
    assert "WHERE identity_id IS NOT NULL AND btrim(identity_id) <> '' AND status = 'active' AND revoked = FALSE" in sql
    assert "identity_id = COALESCE(identity_id, '')" in sql
    assert "ALTER COLUMN identity_id SET DEFAULT ''" in sql
    assert "ALTER COLUMN identity_id SET NOT NULL" in sql
    assert "raise NotImplementedError" in sql
    assert "identity_id = COALESCE(identity_id, '')" in sql
    assert "ALTER COLUMN identity_id SET DEFAULT ''" in sql
    assert "ALTER COLUMN identity_id SET NOT NULL" in sql
    assert "ALTER TABLE mcp_client_configs ENABLE ROW LEVEL SECURITY" in sql
    assert "ALTER TABLE mcp_client_configs FORCE ROW LEVEL SECURITY" in sql
    assert "mcp_client_configs_tenant_isolation" in sql
    assert "GRANT SELECT, INSERT, UPDATE, DELETE ON mcp_client_configs TO agent_bom_app" in sql
    assert "VALUES ('mcp_client_configs', 2, now())" in sql

    runtime_schema = RUNTIME_SCHEMA_SQL.read_text()
    for column in ("identity_id", "issuer", "environment", "status", "revision", "updated_at"):
        assert column in runtime_schema
    assert "idx_mcp_client_configs_active_identity" in runtime_schema
    assert "idx_mcp_client_configs_identity_history" in runtime_schema
    assert "identity_id TEXT NOT NULL DEFAULT ''" in runtime_schema
    assert "VALUES ('mcp_client_configs',2,now())" in runtime_schema


def test_development_postgres_profile_bootstrap_upgrades_v1_before_indexes() -> None:
    source = POSTGRES_MCP_CONFIG_STORE.read_text()
    alter = source.index("ALTER TABLE mcp_client_configs ADD COLUMN IF NOT EXISTS identity_id")
    active_index = source.index("CREATE UNIQUE INDEX IF NOT EXISTS idx_mcp_client_configs_active_identity")
    assert alter < active_index
    assert "UPDATE mcp_client_configs SET identity_id = COALESCE(identity_id, '')" in source
    assert "ALTER TABLE mcp_client_configs ALTER COLUMN identity_id SET NOT NULL" in source
    assert source.count("btrim(identity_id) <> ''") >= 4
    assert "ON CONFLICT (config_id) DO UPDATE" not in source


def test_baseline_migration_points_at_bootstrap_sql():
    bootstrap = _load_module(BOOTSTRAP, "abom_alembic_bootstrap")
    sql = BASELINE.read_text()
    assert bootstrap.INIT_SQL.exists()
    assert bootstrap.SUPPLEMENTAL_SQL.exists()
    assert re.search(r'revision\s*=\s*"20260416_01"', sql)
    assert re.search(r"down_revision\s*=\s*None", sql)


def test_baseline_migration_rewrites_database_specific_grants():
    module = _load_module(BOOTSTRAP, "abom_alembic_bootstrap")
    sql = """
GRANT CONNECT ON DATABASE agent_bom TO agent_bom_app;
GRANT CONNECT ON DATABASE agent_bom TO agent_bom_maintenance;
GRANT CONNECT ON DATABASE agent_bom TO agent_bom_readonly;
"""
    rewritten = module.rewrite_bootstrap_sql(sql, "pilot_customer")
    assert "GRANT CONNECT ON DATABASE pilot_customer TO agent_bom_app;" in rewritten
    assert "GRANT CONNECT ON DATABASE pilot_customer TO agent_bom_maintenance;" in rewritten
    assert "GRANT CONNECT ON DATABASE pilot_customer TO agent_bom_readonly;" in rewritten
    assert "GRANT CONNECT ON DATABASE agent_bom TO agent_bom_app;" not in rewritten


def test_baseline_migration_executes_bootstrap_without_dbapi_parameters(monkeypatch):
    """Server-side ``%L`` format tokens must reach Postgres unchanged.

    psycopg3 treats percent tokens as client placeholders whenever SQLAlchemy
    passes an (even empty) parameter mapping to ``cursor.execute``.  The
    baseline contains PL/pgSQL ``format(... %L ...)`` expressions, so its
    driver execution must explicitly suppress DBAPI parameter handling.
    """
    monkeypatch.setitem(sys.modules, "alembic", SimpleNamespace(op=SimpleNamespace(get_bind=lambda: None)))
    module = _load_module(BASELINE, "abom_control_plane_baseline")
    bootstrap_sql = "DO $$ BEGIN PERFORM format('PASSWORD %L', 'secret'); END $$;"

    class _Result:
        def scalar_one(self):
            return "migration_contract"

    calls: list[tuple[str, dict[str, bool] | None]] = []

    class _Bind:
        def exec_driver_sql(self, sql, *, execution_options=None):
            calls.append((sql, execution_options))
            return _Result()

    monkeypatch.setattr(module.op, "get_bind", lambda: _Bind())
    monkeypatch.setattr(module, "load_bootstrap_sql", lambda database_name: bootstrap_sql)
    monkeypatch.setattr(module, "load_runtime_schema_sql", lambda: "-- runtime schema")

    module.upgrade()

    assert calls == [
        ("SELECT current_database()", None),
        (bootstrap_sql, {"no_parameters": True}),
        ("-- runtime schema", {"no_parameters": True}),
    ]


def test_graph_hot_path_index_migration_chains_from_baseline():
    sql = GRAPH_HOT_PATH_INDEXES.read_text()
    assert re.search(r'revision\s*=\s*"20260513_01"', sql)
    assert re.search(r'down_revision\s*=\s*"20260416_01"', sql)
    for index_name in (
        "idx_pg_graph_nodes_scan_id_cover",
        "idx_pg_graph_edges_scan_source_traversable",
        "idx_pg_attack_paths_source_risk",
        "idx_pg_graph_node_search_trgm",
        "idx_pg_graph_node_search_lower_trgm",
    ):
        assert index_name in sql
    assert "CREATE EXTENSION IF NOT EXISTS pg_trgm" in sql


def test_postgres_store_parity_migration_is_idempotent_and_chained():
    sql = POSTGRES_STORE_PARITY.read_text()
    assert re.search(r'revision\s*=\s*"20260717_01"', sql)
    assert re.search(r'down_revision\s*=\s*"20260705_01"', sql)
    assert "ADD COLUMN IF NOT EXISTS owner" in sql
    assert "ADD COLUMN IF NOT EXISTS workflow" in sql
    assert "PRIMARY KEY (tenant_id, agent, cost_center, owner, workflow)" in sql
    assert "target_table REGCLASS := to_regclass('llm_cost_budgets')" in sql
    assert "c.conrelid = target_table" in sql
    assert "ALTER TABLE %s DROP CONSTRAINT %I" in sql
    assert "n.nspname = current_schema()" not in sql
    assert "ALTER TABLE IF EXISTS cloud_connections ADD COLUMN IF NOT EXISTS last_scan_id" in sql


def test_graph_analysis_status_migration_is_idempotent_and_chained():
    sql = GRAPH_ANALYSIS_STATUS.read_text()
    assert re.search(r'revision\s*=\s*"20260717_02"', sql)
    assert re.search(r'down_revision\s*=\s*"20260717_01"', sql)
    assert "ADD COLUMN IF NOT EXISTS analysis_status JSONB NOT NULL" in sql


def test_graph_snapshot_json_parity_migration_is_idempotent_and_chained():
    assert GRAPH_SNAPSHOT_JSON_PARITY.exists()
    sql = GRAPH_SNAPSHOT_JSON_PARITY.read_text()
    assert re.search(r'revision\s*=\s*"20260717_03"', sql)
    assert re.search(r'down_revision\s*=\s*"20260717_02"', sql)
    for column in ("risk_summary", "analysis_status"):
        assert f"ALTER COLUMN {column} DROP DEFAULT" in sql
        assert f"ALTER COLUMN {column} TYPE TEXT" in sql
        assert f"ALTER COLUMN {column} SET DEFAULT '{{}}'" in sql


def test_audit_fork_guard_index_migration_is_chained_and_recreates_the_index() -> None:
    """The hash-chain fork-guard UNIQUE index must live in migration-owned SQL.

    ``PostgresAuditLog._ensure_fork_guard_index`` no longer runs when Postgres is
    authoritative (``_init_tables`` early-returns), so the ``UNIQUE (team_id,
    prev_signature)`` guard was left in no migration after #4232 — silently,
    because nothing asserted it. This is that missing regression guard: the
    dedicated migration must exist, chain from the runtime-schema-authority head,
    and (idempotently) recreate the index with the exact head key.
    """
    sql = AUDIT_FORK_GUARD_INDEX.read_text()
    assert re.search(r'revision\s*=\s*"20260719_01"', sql)
    assert re.search(r'down_revision\s*=\s*"20260718_01"', sql)
    assert _FORK_GUARD_INDEX_CANON in _canonical_sql(sql), "migration must CREATE UNIQUE INDEX audit_log_team_prevsig_uniq"
    assert "DROP INDEX IF EXISTS audit_log_team_prevsig_uniq" in sql  # reversible


def test_audit_fork_guard_index_is_present_in_runtime_schema_authority() -> None:
    """runtime-schema.sql is applied wholesale by the 20260718_01 head-authority
    migration, so the fork guard must be present there too (belt-and-suspenders
    with the dedicated 20260719_01 migration). A future edit that drops it from
    the migration-owned schema — the #4232 class of regression — fails here."""
    sql = RUNTIME_SCHEMA_SQL.read_text()
    assert _FORK_GUARD_INDEX_CANON in _canonical_sql(sql), "runtime-schema.sql must define audit_log_team_prevsig_uniq"


def test_runtime_schema_authority_is_the_alembic_head() -> None:
    assert RUNTIME_SCHEMA_AUTHORITY.exists()
    sql = RUNTIME_SCHEMA_AUTHORITY.read_text()
    assert re.search(r'revision\s*=\s*"20260718_01"', sql)
    assert re.search(r'down_revision\s*=\s*"20260717_03"', sql)
    assert "load_runtime_schema_sql" in sql


def test_cloud_connections_scope_columns_migration_is_idempotent_and_chained() -> None:
    """Existing deployments get the three Connections columns from a revision.

    The corrected runtime-schema.sql only reaches a database that replays
    20260718_01, i.e. a fresh install. Databases already at head need the
    additive ALTERs, with types and defaults identical to the store's DDL so
    both paths converge on one shape.
    """
    sql = CLOUD_CONNECTIONS_SCOPE_COLUMNS.read_text()
    assert re.search(r'revision\s*=\s*"20260724_02"', sql)
    assert re.search(r'down_revision\s*=\s*"20260724_01"', sql)
    for column_ddl in (
        "ADD COLUMN IF NOT EXISTS inventory_scope TEXT NOT NULL DEFAULT 'account'",
        "ADD COLUMN IF NOT EXISTS scan_mode TEXT NOT NULL DEFAULT 'full'",
        "ADD COLUMN IF NOT EXISTS auto_scan_on_create BOOLEAN NOT NULL DEFAULT TRUE",
    ):
        assert f"ALTER TABLE IF EXISTS cloud_connections {column_ddl}" in sql
    assert "VALUES ('cloud_connections', 1, now())" in sql
    assert "ON CONFLICT(component) DO UPDATE SET" in sql


def test_cloud_connection_capability_evidence_is_idempotent_and_chained() -> None:
    sql = CLOUD_CONNECTION_CAPABILITY_EVIDENCE.read_text()
    normalized_sql = re.sub(r'"\s*\n\s*"', "", sql)
    normalized_sql = re.sub(r"\s+", " ", normalized_sql)
    assert re.search(r'revision\s*=\s*"20260830_03"', sql)
    assert re.search(r'down_revision\s*=\s*"20260830_02"', sql)
    for column_ddl in (
        "ADD COLUMN IF NOT EXISTS capability_probe_status TEXT NOT NULL DEFAULT 'not_run'",
        "ADD COLUMN IF NOT EXISTS verified_capabilities TEXT NOT NULL DEFAULT '[]'",
    ):
        assert f"ALTER TABLE IF EXISTS cloud_connections {column_ddl}" in normalized_sql
    assert "VALUES ('cloud_connections', 1, now())" in sql
    assert "ON CONFLICT(component) DO UPDATE SET" in sql


def test_gateway_activity_ledger_migration_is_chained_durable_and_tenant_isolated() -> None:
    sql = GATEWAY_ACTIVITY_LEDGER.read_text()
    assert re.search(r'revision\s*=\s*"20260728_02"', sql)
    assert re.search(r'down_revision\s*=\s*"20260728_01"', sql)
    for table in (
        "gateway_activity_events",
        "gateway_activity_sequences",
        "gateway_activity_tombstones",
    ):
        assert f"CREATE TABLE IF NOT EXISTS {table}" in sql
        assert f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY" in sql
        assert f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY" in sql
    assert "policyname = '{table}_tenant_isolation'" in sql
    assert "CREATE POLICY {table}_tenant_isolation ON {table}" in sql
    assert "CREATE UNIQUE INDEX IF NOT EXISTS idx_gateway_activity_events_tenant_ordinal" in sql
    assert "CREATE INDEX IF NOT EXISTS idx_gateway_activity_tombstones_tenant_ordinal" in sql
    assert "VALUES ('runtime_events', 2, now())" in sql
    assert "DROP TABLE" not in sql


def test_gateway_activity_window_index_is_chained_and_matches_runtime_schema() -> None:
    sql = GATEWAY_ACTIVITY_WINDOW_INDEX.read_text()
    index_ddl = (
        "CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_gateway_activity_events_tenant_event_time "
        "ON gateway_activity_events(tenant_id, event_timestamp, "
        "((data::jsonb) ->> 'event_type'), ((data::jsonb) ->> 'reason_code'))"
    )
    assert re.search(r'revision\s*=\s*"20260729_02"', sql)
    assert re.search(r'down_revision\s*=\s*"20260729_01"', sql)
    assert _canonical_sql(index_ddl) in _canonical_sql(sql)
    runtime_index_ddl = index_ddl.replace(" CONCURRENTLY", "")
    assert _canonical_sql(runtime_index_ddl) in _canonical_sql(RUNTIME_SCHEMA_SQL.read_text())
    assert "SELECT to_regclass('public.gateway_activity_events')" in sql
    assert "autocommit_block" in sql
    assert "DROP TABLE" not in sql


def test_partition_child_rls_is_chained_idempotent_and_irreversible() -> None:
    sql = PARTITION_CHILD_RLS.read_text()
    assert re.search(r'revision\s*=\s*"20260729_03"', sql)
    assert re.search(r'down_revision\s*=\s*"20260729_02"', sql)
    assert "pg_inherits" in sql
    assert "audit_log" in sql
    assert "hub_findings_current_observations" in sql
    assert "ENABLE ROW LEVEL SECURITY" in sql
    assert "FORCE ROW LEVEL SECURITY" in sql
    assert "IF NOT EXISTS" in sql
    assert "CREATE POLICY" in sql
    assert "DROP POLICY" not in sql
    assert "DISABLE ROW LEVEL SECURITY" not in sql


def test_teams_tenant_rls_is_chained_idempotent_and_irreversible() -> None:
    """The FK root gets the same tenant-isolation contract as every other table.

    Modelled on ``20260729_03_partition_child_rls``: idempotent (guarded
    ``CREATE POLICY``), forward-only, and expressed with the shared
    ``abom_rls_bypass()`` / ``abom_current_tenant()`` helpers so the
    maintenance-role purge in ``tenant_lifecycle`` still works.
    """
    sql = TEAMS_TENANT_RLS.read_text()
    assert re.search(r'revision\s*=\s*"20260730_02"', sql)
    assert re.search(r'down_revision\s*=\s*"20260730_01"', sql)
    assert "ALTER TABLE teams ENABLE ROW LEVEL SECURITY" in sql
    assert "ALTER TABLE teams FORCE ROW LEVEL SECURITY" in sql
    assert "teams_tenant_isolation" in sql
    assert "team_id = public.abom_current_tenant()" in sql
    assert "public.abom_rls_bypass()" in sql
    # Idempotent, and never weakens isolation on replay or rollback.
    assert "IF NOT EXISTS" in sql
    assert "DROP POLICY" not in sql
    assert "DISABLE ROW LEVEL SECURITY" not in sql
    assert "NO FORCE ROW LEVEL SECURITY" not in sql


def test_there_is_exactly_one_alembic_head() -> None:
    """Nothing may chain past the newest revision without being noticed.

    Named by property rather than by revision id: this test previously pinned
    `20260801_01` literally, so every new migration edited the assertion and the
    *reason* for it — one head, no forks — drifted out of the name. The current
    head is asserted separately below, in one place.
    """
    revisions = {
        path.name: re.search(r'down_revision\s*=\s*"([^"]+)"', path.read_text())
        for path in VERSIONS_DIR.glob("*.py")
        if path.name != "__init__.py"
    }
    parents = {match.group(1) for match in revisions.values() if match}
    all_revisions = {
        match.group(1)
        for match in (re.search(r'^revision\s*=\s*"([^"]+)"', path.read_text(), re.M) for path in VERSIONS_DIR.glob("*.py"))
        if match
    }
    heads = all_revisions - parents
    assert heads == {ALEMBIC_HEAD}, f"expected a single head {ALEMBIC_HEAD!r}, found {sorted(heads)}"


def test_fleet_agents_tenant_key_is_chained_concurrent_and_irreversible() -> None:
    """The tenant-scoped fleet key follows the established migration contract.

    A tenant-less UNIQUE key is what let one customer's registration deny
    another's, so the replacement must actually carry ``tenant_id``, must build
    its index without holding a write lock for the duration, and must be
    forward-only — reverting to a global key would have to discard one of two
    tenants that now legitimately share an ``agent_id``.
    """
    sql = FLEET_AGENTS_TENANT_KEY.read_text()
    assert re.search(r'revision\s*=\s*"20260801_01"', sql)
    assert re.search(r'down_revision\s*=\s*"20260731_01"', sql)
    assert "CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS uq_fleet_agents_tenant_agent" in sql
    assert "fleet_agents(tenant_id, agent_id)" in sql
    assert "autocommit_block" in sql
    assert "PRIMARY KEY USING INDEX uq_fleet_agents_tenant_agent" in sql
    # RLS is suspended only under the exclusive lock, and always restored.
    assert "DISABLE ROW LEVEL SECURITY" in sql
    assert "ENABLE ROW LEVEL SECURITY" in sql
    assert "FORCE ROW LEVEL SECURITY" in sql
    assert "NotImplementedError" in sql


def test_observation_partition_runway_migration_provisions_a_year_ahead() -> None:
    """The migration must extend the runway, not just create 'a' partition."""
    from agent_bom.api.hub_observations_partition import OBSERVATION_PARTITION_RUNWAY_MONTHS

    sql = OBSERVATION_PARTITION_RUNWAY.read_text()
    assert re.search(r'revision\s*=\s*"20260731_01"', sql)
    assert re.search(r'down_revision\s*=\s*"20260730_02"', sql)
    assert "provision_observation_partition_runway" in sql
    # Reuses the shared helper (which forces RLS on each new child) rather than
    # hand-rolling CREATE TABLE ... PARTITION OF without tenant isolation.
    assert "CREATE TABLE" not in sql
    assert OBSERVATION_PARTITION_RUNWAY_MONTHS >= 12
    # Forward-only: dropping provisioned partitions would discard observations.
    assert "DROP TABLE" not in sql
    assert "DETACH PARTITION" not in sql


def test_observation_partition_runway_migration_uses_the_psycopg_driver_connection(monkeypatch) -> None:
    """Same psycopg ``%s`` execute contract unwrap as 20260705_01."""
    monkeypatch.setitem(sys.modules, "alembic", SimpleNamespace(op=SimpleNamespace(get_bind=lambda: None)))
    module = _load_module(OBSERVATION_PARTITION_RUNWAY, "abom_observation_partition_runway")
    driver_connection = object()
    bind = SimpleNamespace(connection=SimpleNamespace(driver_connection=driver_connection))
    seen: list[object] = []

    monkeypatch.setattr(module.op, "get_bind", lambda: bind)
    monkeypatch.setattr(module, "provision_observation_partition_runway", lambda conn: seen.append(conn))

    module.upgrade()

    assert seen == [driver_connection]


def test_observation_partition_retention_window_is_migration_owned_and_forward_only() -> None:
    sql = OBSERVATION_PARTITION_RETENTION_WINDOW.read_text()
    assert re.search(r'revision\s*=\s*"20260901_01"', sql)
    assert re.search(r'down_revision\s*=\s*"20260830_03"', sql)
    assert "provision_observation_partition_runway" in sql
    assert "driver_connection" in sql
    assert "DROP TABLE" not in sql
    assert "CREATE TABLE" not in sql


def test_execution_leases_are_idempotent_chained_and_monotonic() -> None:
    sql = EXECUTION_LEASES.read_text()
    assert re.search(r'revision\s*=\s*"20260903_01"', sql)
    assert re.search(r'down_revision\s*=\s*"20260901_01"', sql)
    for column_ddl in (
        "ALTER TABLE idempotency_keys ADD COLUMN IF NOT EXISTS reservation_owner TEXT NOT NULL DEFAULT ''",
        "ALTER TABLE idempotency_keys ADD COLUMN IF NOT EXISTS lease_expires_at TEXT NOT NULL DEFAULT ''",
        "ALTER TABLE graph_correlation_runs ADD COLUMN IF NOT EXISTS execution_owner TEXT NOT NULL DEFAULT ''",
        "ALTER TABLE graph_correlation_runs ADD COLUMN IF NOT EXISTS execution_lease_expires_at TEXT NOT NULL DEFAULT ''",
    ):
        assert column_ddl in sql
    assert "('idempotency', 2, NOW())" in sql
    assert "('graph', 4, NOW())" in sql
    assert "GREATEST(control_plane_schema_versions.version, EXCLUDED.version)" in sql
    assert "DROP COLUMN" not in sql


def test_graph_edge_snapshot_key_index_is_chained_and_matches_bootstrap() -> None:
    sql = GRAPH_EDGE_SNAPSHOT_KEY_INDEX.read_text()
    index_ddl = (
        "CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_pg_graph_edges_snapshot_key "
        "ON graph_edges(tenant_id, scan_id, source_id, target_id, relationship)"
    )
    assert re.search(r'revision\s*=\s*"20260730_01"', sql)
    assert re.search(r'down_revision\s*=\s*"20260729_03"', sql)
    assert _canonical_sql(index_ddl) in _canonical_sql(sql)
    bootstrap_index_ddl = index_ddl.replace(" CONCURRENTLY", "")
    assert _canonical_sql(bootstrap_index_ddl) in _canonical_sql((POSTGRES_DIR / "init.sql").read_text())
    assert "SELECT to_regclass('public.graph_edges')" in sql
    assert "autocommit_block" in sql
    assert "DROP TABLE" not in sql


def test_gateway_activity_window_index_allows_legacy_schema_without_ledger(monkeypatch) -> None:
    """A stamped 0.98.2 database may not have provisioned the optional ledger."""
    monkeypatch.setitem(sys.modules, "alembic", SimpleNamespace(op=SimpleNamespace()))
    migration = _load_module(GATEWAY_ACTIVITY_WINDOW_INDEX, "gateway_activity_window_index_legacy")
    statements: list[str] = []

    class _MissingRelationResult:
        @staticmethod
        def scalar():
            return None

    class _LegacyBind:
        @staticmethod
        def exec_driver_sql(statement: str):
            statements.append(statement)
            return _MissingRelationResult()

    def _unexpected_context():
        raise AssertionError("the concurrent index block must be skipped when the ledger is absent")

    migration.op = SimpleNamespace(
        get_bind=lambda: _LegacyBind(),
        get_context=_unexpected_context,
        execute=lambda _statement: (_ for _ in ()).throw(AssertionError("no index DDL is valid without the ledger")),
    )

    migration.upgrade()

    assert statements == ["SELECT to_regclass('public.gateway_activity_events')"]


def test_trusted_maintenance_migration_is_forward_only_and_preserves_queue_rows() -> None:
    sql = TRUSTED_MAINTENANCE_RLS.read_text()
    assert re.search(r'revision\s*=\s*"20260728_03"', sql)
    assert re.search(r'down_revision\s*=\s*"20260728_02"', sql)
    assert "agent_bom_rls_maintenance NOLOGIN" in sql
    assert "agent_bom_maintenance LOGIN NOSUPERUSER NOBYPASSRLS" in sql
    assert "agent_bom_app must never inherit agent_bom_rls_maintenance" in sql
    assert "GRANT agent_bom_rls_maintenance TO agent_bom_app" not in sql
    assert "GRANT agent_bom_rls_maintenance TO agent_bom_maintenance" in sql
    assert "pg_has_role(session_user, 'agent_bom_rls_maintenance', 'MEMBER')" in sql
    assert "CREATE TABLE IF NOT EXISTS scan_dispatch_queue" in sql
    assert "CREATE INDEX IF NOT EXISTS idx_dispatch_pending" in sql
    assert "ALTER TABLE scan_dispatch_queue ENABLE ROW LEVEL SECURITY" in sql
    assert "ALTER TABLE scan_dispatch_queue FORCE ROW LEVEL SECURITY" in sql
    assert "scan_dispatch_queue_tenant_isolation" in sql
    assert "scan_dispatch_queue_maintenance" in sql
    assert "tenant_id = public.abom_current_tenant()" in sql
    assert "TO agent_bom_rls_maintenance" in sql
    assert "GRANT USAGE ON SCHEMA public TO agent_bom_rls_maintenance" in sql
    assert "GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public" in sql
    assert "GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public" in sql
    assert "raise NotImplementedError" in sql
    for destructive in (
        "DROP TABLE scan_dispatch_queue",
        "TRUNCATE scan_dispatch_queue",
        "DELETE FROM scan_dispatch_queue",
    ):
        assert destructive not in sql


def test_trusted_maintenance_queue_policy_does_not_require_precreated_app_role() -> None:
    """Alembic must upgrade an empty database before runtime roles exist."""
    sql = TRUSTED_MAINTENANCE_RLS.read_text()
    policy = sql.split("CREATE POLICY scan_dispatch_queue_tenant_isolation", 1)[1].split('"""', 1)[0]
    assert "TO agent_bom_app" not in policy
    assert "tenant_id = public.abom_current_tenant()" in policy

    runtime = RUNTIME_SCHEMA_SQL.read_text()
    runtime_policy = runtime.split("CREATE POLICY scan_dispatch_queue_tenant_isolation", 1)[1].split(";", 1)[0]
    assert "TO agent_bom_app" not in runtime_policy

    forward = HUB_LEDGER_SCAN_ID.read_text()
    assert "DROP POLICY IF EXISTS scan_dispatch_queue_tenant_isolation" in forward
    assert "CREATE POLICY scan_dispatch_queue_tenant_isolation" in forward
    forward_policy = forward.split("CREATE POLICY scan_dispatch_queue_tenant_isolation", 1)[1].split('"', 1)[0]
    assert "TO agent_bom_app" not in forward_policy


def test_tenant_binding_authority_is_chained_secret_minimal_and_fail_closed() -> None:
    """The DB verifier may authenticate claims without exposing its HMAC keys."""
    sql = TENANT_BINDING_AUTHORITY.read_text()

    assert re.search(r'revision\s*=\s*"20260819_01"', sql)
    assert re.search(r'down_revision\s*=\s*"20260818_01"', sql)
    assert "CREATE EXTENSION IF NOT EXISTS pgcrypto" in sql
    assert "CREATE TABLE IF NOT EXISTS public.agent_bom_tenant_binding_keys" in sql
    assert "key_material BYTEA NOT NULL" in sql
    assert "octet_length(key_material) >= 32" in sql
    assert "CREATE OR REPLACE FUNCTION public.abom_verify_tenant_binding_claim" in sql
    assert "SECURITY DEFINER" in sql
    assert "SET search_path = pg_catalog" in sql
    assert "clock_timestamp()" in sql
    assert "p_issued_at > v_now + 30" in sql
    assert "p_issued_at < v_now - 30" in sql
    assert "p_nonce !~ '^[0-9a-f]{32}$'" in sql
    assert "p_signature !~ '^[0-9a-f]{64}$'" in sql
    assert "'v1:' || encode(convert_to(p_tenant_id, 'UTF8'), 'hex')" in sql
    assert "public.hmac(convert_to(v_canonical, 'UTF8'), key_material, 'sha256')" in sql
    assert "WHERE enabled" in sql
    assert "REVOKE ALL ON TABLE public.agent_bom_tenant_binding_keys FROM PUBLIC" in sql
    assert "REVOKE ALL ON FUNCTION public.abom_verify_tenant_binding_claim(TEXT, BIGINT, TEXT, TEXT) FROM PUBLIC" in sql
    for runtime_role in ("agent_bom_app", "agent_bom_readonly", "agent_bom_rls_maintenance", "agent_bom_maintenance"):
        assert f"REVOKE ALL ON TABLE public.agent_bom_tenant_binding_keys FROM {runtime_role}" in sql
    assert "GRANT EXECUTE ON FUNCTION public.abom_verify_tenant_binding_claim" in sql
    assert "raise NotImplementedError" in sql

    # New-install and supplemental-schema paths must carry the same authority,
    # but this mechanical stage deliberately leaves active RLS on app.tenant_id.
    init_schema = (POSTGRES_DIR / "init.sql").read_text()
    runtime_schema = RUNTIME_SCHEMA_SQL.read_text()
    for schema in (init_schema, runtime_schema):
        assert "CREATE TABLE IF NOT EXISTS public.agent_bom_tenant_binding_keys" in schema
        assert "CREATE OR REPLACE FUNCTION public.abom_verify_tenant_binding_claim" in schema
        assert "SECURITY DEFINER" in schema
        assert "SET search_path = pg_catalog" in schema
        assert "REVOKE ALL ON TABLE public.agent_bom_tenant_binding_keys FROM PUBLIC" in schema
        assert "tenant_id = public.abom_current_tenant()" in schema

    assert "COALESCE(NULLIF(current_setting('app.tenant_id', true), ''), 'default')" in init_schema


def test_hub_ledger_scan_id_migration_skips_backfill_when_ledger_is_absent(monkeypatch) -> None:
    """A pristine Alembic path may not provision the optional ledger table."""
    monkeypatch.setitem(sys.modules, "alembic", SimpleNamespace(op=SimpleNamespace()))
    migration = _load_module(HUB_LEDGER_SCAN_ID, "hub_ledger_scan_id_pristine")
    statements: list[str] = []
    probes: list[str] = []

    class _MissingRelationResult:
        @staticmethod
        def scalar() -> None:
            return None

    class _PristineBind:
        @staticmethod
        def exec_driver_sql(statement: str) -> _MissingRelationResult:
            probes.append(statement)
            return _MissingRelationResult()

    migration.op = SimpleNamespace(
        get_bind=lambda: _PristineBind(),
        execute=statements.append,
    )

    migration.upgrade()

    assert probes == ["SELECT to_regclass('public.compliance_hub_findings')"]
    assert any("ALTER TABLE IF EXISTS compliance_hub_findings" in statement for statement in statements)
    assert not any("UPDATE compliance_hub_findings" in statement for statement in statements)
    assert not any("idx_hub_findings_tenant_scan" in statement for statement in statements)


def test_trusted_maintenance_migration_preserves_explicit_superuser_acknowledgement(monkeypatch) -> None:
    """The dev escape hatch must not grant the app maintenance-marker membership."""
    monkeypatch.setitem(sys.modules, "alembic", SimpleNamespace(op=SimpleNamespace()))
    migration = _load_module(TRUSTED_MAINTENANCE_RLS, "trusted_maintenance_rls_ack_test")

    monkeypatch.delenv("AGENT_BOM_ALLOW_SUPERUSER_DB", raising=False)
    assert migration._allow_superuser_db() is False
    captured: list[str] = []
    migration.op = SimpleNamespace(execute=captured.append)
    migration._configure_runtime_passwords = lambda: None
    migration.upgrade()
    assert "AND NOT FALSE" in captured[0]

    monkeypatch.setenv("AGENT_BOM_ALLOW_SUPERUSER_DB", "1")
    assert migration._allow_superuser_db() is True
    captured.clear()
    migration.upgrade()
    assert "AND NOT TRUE" in captured[0]

    sql = TRUSTED_MAINTENANCE_RLS.read_text()
    assert "_allow_superuser_db()" in sql
    assert "GRANT agent_bom_rls_maintenance TO agent_bom_app" not in sql
    assert "agent_bom_app must never inherit agent_bom_rls_maintenance" in sql


def test_hub_partition_migration_uses_the_psycopg_driver_connection(monkeypatch):
    """The shared partition helper uses psycopg's ``%s`` execute contract."""
    monkeypatch.setitem(sys.modules, "alembic", SimpleNamespace(op=SimpleNamespace(get_bind=lambda: None)))
    module = _load_module(HUB_OBSERVATIONS_PARTITION, "abom_hub_observations_partition")
    driver_connection = object()
    bind = SimpleNamespace(connection=SimpleNamespace(driver_connection=driver_connection))
    seen: list[object] = []

    monkeypatch.setattr(module.op, "get_bind", lambda: bind)
    monkeypatch.setattr(module, "migrate_observations_to_partitioned", lambda conn: seen.append(conn) or True)
    monkeypatch.setattr(module, "ensure_observation_partitions", lambda conn: seen.append(conn))

    module.upgrade()

    assert seen == [driver_connection, driver_connection]
