"""Tests for the Alembic migration scaffolding on the enterprise Postgres path."""

from __future__ import annotations

import importlib.util
import re
from pathlib import Path

POSTGRES_DIR = Path(__file__).parent.parent / "deploy" / "supabase" / "postgres"
ALEMBIC_DIR = POSTGRES_DIR / "alembic"
VERSIONS_DIR = ALEMBIC_DIR / "versions"
BASELINE = VERSIONS_DIR / "20260416_01_control_plane_baseline.py"
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
