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
HUB_OBSERVATIONS_PARTITION = VERSIONS_DIR / "20260705_01_hub_observations_partition.py"
BOOTSTRAP = ALEMBIC_DIR / "bootstrap.py"


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
GRANT CONNECT ON DATABASE agent_bom TO agent_bom_readonly;
"""
    rewritten = module.rewrite_bootstrap_sql(sql, "pilot_customer")
    assert "GRANT CONNECT ON DATABASE pilot_customer TO agent_bom_app;" in rewritten
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


def test_runtime_schema_authority_is_the_alembic_head() -> None:
    assert RUNTIME_SCHEMA_AUTHORITY.exists()
    sql = RUNTIME_SCHEMA_AUTHORITY.read_text()
    assert re.search(r'revision\s*=\s*"20260718_01"', sql)
    assert re.search(r'down_revision\s*=\s*"20260717_03"', sql)
    assert "load_runtime_schema_sql" in sql


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
