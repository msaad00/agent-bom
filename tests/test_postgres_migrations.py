"""Tests for the Alembic migration scaffolding on the enterprise Postgres path."""

from __future__ import annotations

import importlib.util
import re
from pathlib import Path

POSTGRES_DIR = Path(__file__).parent.parent / "deploy" / "supabase" / "postgres"
ALEMBIC_DIR = POSTGRES_DIR / "alembic"
VERSIONS_DIR = ALEMBIC_DIR / "versions"
BASELINE = VERSIONS_DIR / "20260416_01_control_plane_baseline.py"
GRAPH_HOT_PATH_INDEXES = VERSIONS_DIR / "20260513_01_graph_hot_path_indexes.py"
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
