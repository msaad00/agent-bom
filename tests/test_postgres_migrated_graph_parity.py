"""Migration-owned Postgres graph round-trip against a real, freshly migrated db.

Opt-in live tier: proves the graph store works on a database whose schema was
created ONLY by Alembic (``alembic upgrade head``) — the store's dev-mode
bootstrap DDL never runs because ``AGENT_BOM_POSTGRES_URL`` is set. Regression
for the P1 where ``attack_paths.summary`` / ``tool_exposure`` /
``technique_mappings`` existed only in the bootstrap DDL, so every
migration-owned deployment 500'd on the first ``/v1/graph`` read.

Requires two opt-in env vars (skipped otherwise):
- ``AGENT_BOM_POSTGRES_ADMIN_URL`` — a CREATEDB-capable role used to create /
  drop the throwaway database and run Alembic (never used by the app).
- ``AGENT_BOM_POSTGRES_URL`` — the app-role URL template (its database path is
  rewritten to the throwaway database).
"""

from __future__ import annotations

import os
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit
from uuid import uuid4

import pytest

pytestmark = pytest.mark.skipif(
    not (os.environ.get("AGENT_BOM_POSTGRES_ADMIN_URL") and os.environ.get("AGENT_BOM_POSTGRES_URL")),
    reason="AGENT_BOM_POSTGRES_ADMIN_URL + AGENT_BOM_POSTGRES_URL are required for live migration parity tests",
)

REPO_ROOT = Path(__file__).parent.parent
ALEMBIC_DIR = REPO_ROOT / "deploy" / "supabase" / "postgres"


def _with_database(url: str, database: str) -> str:
    parts = urlsplit(url)
    return urlunsplit((parts.scheme, parts.netloc, f"/{database}", parts.query, parts.fragment))


def _sqlalchemy_url(url: str) -> str:
    """Force the psycopg3 SQLAlchemy driver (plain postgresql:// selects psycopg2)."""
    if url.startswith("postgresql://"):
        return url.replace("postgresql://", "postgresql+psycopg://", 1)
    return url


@pytest.fixture()
def migrated_fresh_database(monkeypatch):
    """Create a throwaway database, migrate it to Alembic head, point the app at it."""
    import psycopg

    admin_url = os.environ["AGENT_BOM_POSTGRES_ADMIN_URL"]
    app_url = os.environ["AGENT_BOM_POSTGRES_URL"]
    database = f"abom_mig_parity_{uuid4().hex[:12]}"

    with psycopg.connect(admin_url, autocommit=True) as conn:
        conn.execute(f'CREATE DATABASE "{database}"')
    try:
        from alembic import command
        from alembic.config import Config

        cfg = Config(str(ALEMBIC_DIR / "alembic.ini"))
        cfg.set_main_option("script_location", str(ALEMBIC_DIR / "alembic"))
        monkeypatch.setenv("ALEMBIC_DATABASE_URL", _sqlalchemy_url(_with_database(admin_url, database)))
        command.upgrade(cfg, "head")

        from agent_bom.api import postgres_common

        monkeypatch.setenv("AGENT_BOM_POSTGRES_URL", _with_database(app_url, database))
        postgres_common.reset_pool()
        yield database
        pool = postgres_common._pool
        if pool is not None:
            pool.close()
        postgres_common.reset_pool()
    finally:
        with psycopg.connect(admin_url, autocommit=True) as conn:
            conn.execute(f'DROP DATABASE IF EXISTS "{database}" WITH (FORCE)')


def test_attack_paths_round_trip_on_migration_owned_schema(migrated_fresh_database):
    from agent_bom.api.postgres_common import reset_current_tenant, set_current_tenant
    from agent_bom.api.postgres_graph import PostgresGraphStore
    from agent_bom.graph import AttackPath
    from agent_bom.graph.container import TechniqueMapping

    store = PostgresGraphStore()
    path = AttackPath(
        source="agent:web",
        target="secret:prod-db",
        hops=["agent:web", "secret:prod-db"],
        edges=["agent:web->secret:prod-db"],
        composite_risk=8.5,
        summary="internet-facing agent reaches a production secret",
        credential_exposure=["prod-db-password"],
        tool_exposure=["shell-tool"],
        vuln_ids=["CVE-2026-0001"],
        technique_mappings=[TechniqueMapping(hop_index=0, technique_id="T1078", technique_name="Valid Accounts", confidence=0.6)],
    )
    token = set_current_tenant("default")
    try:
        store.save_graph_streaming(
            scan_id="mig-parity-scan",
            tenant_id="default",
            nodes=[],
            edges=[],
            attack_paths=[path],
        )
        loaded = store.attack_paths_for_sources(tenant_id="default", scan_id="mig-parity-scan", source_ids={"agent:web"})
    finally:
        reset_current_tenant(token)

    assert len(loaded) == 1
    got = loaded[0]
    assert got.summary == "internet-facing agent reaches a production secret"
    assert got.tool_exposure == ["shell-tool"]
    assert got.credential_exposure == ["prod-db-password"]
    assert got.vuln_ids == ["CVE-2026-0001"]
    assert [m.technique_id for m in got.technique_mappings] == ["T1078"]
