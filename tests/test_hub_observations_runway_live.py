"""Live Postgres contract for the hub observations partition runway.

The unit guards in ``test_hub_observations_partition_runway`` freeze the clock
against a fake connection. This one asserts the same two properties against a
real ``alembic upgrade head`` database, because the failure mode was invisible
to every fake: partitions are always fresh immediately after a migration, and
partition children do not inherit the parent's row-level security.
"""

from __future__ import annotations

import os
from datetime import date, timedelta
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit
from uuid import uuid4

import pytest

pytestmark = pytest.mark.skipif(
    not os.environ.get("AGENT_BOM_POSTGRES_ADMIN_URL"),
    reason="AGENT_BOM_POSTGRES_ADMIN_URL is required for the live partition runway contract",
)

REPO_ROOT = Path(__file__).parent.parent
OBSERVATIONS_TABLE = "hub_findings_current_observations"

# A deploy must leave enough runway that a year without upgrading cannot break
# current-dated ingest.
MIN_RUNWAY_DAYS = 365


def _with_database(url: str, database: str) -> str:
    parts = urlsplit(url)
    return urlunsplit((parts.scheme, parts.netloc, f"/{database}", parts.query, parts.fragment))


def _upgrade_head(database_url: str) -> None:
    from alembic import command
    from alembic.config import Config

    config = Config(str(REPO_ROOT / "deploy" / "supabase" / "postgres" / "alembic.ini"))
    config.set_main_option("script_location", str(REPO_ROOT / "deploy" / "supabase" / "postgres" / "alembic"))
    previous = os.environ.get("ALEMBIC_DATABASE_URL")
    os.environ["ALEMBIC_DATABASE_URL"] = database_url
    try:
        command.upgrade(config, "head")
    finally:
        if previous is None:
            os.environ.pop("ALEMBIC_DATABASE_URL", None)
        else:
            os.environ["ALEMBIC_DATABASE_URL"] = previous


@pytest.fixture()
def migrated_database() -> str:
    import psycopg
    from psycopg import sql

    admin_url = os.environ["AGENT_BOM_POSTGRES_ADMIN_URL"]
    database = f"abom_runway_{uuid4().hex[:12]}"
    database_url = _with_database(admin_url, database)
    with psycopg.connect(admin_url, autocommit=True) as conn:
        conn.execute(sql.SQL("CREATE DATABASE {}").format(sql.Identifier(database)))
    try:
        _upgrade_head(database_url)
        yield database_url
    finally:
        with psycopg.connect(admin_url, autocommit=True) as conn:
            conn.execute(sql.SQL("DROP DATABASE IF EXISTS {} WITH (FORCE)").format(sql.Identifier(database)))


def test_upgrade_head_leaves_at_least_a_year_of_partition_runway(migrated_database: str) -> None:
    """Not 'a partition exists' — how far past *today* the runway reaches."""
    import psycopg

    from agent_bom.api.hub_observations_partition import observation_runway_end

    with psycopg.connect(migrated_database, autocommit=True) as conn:
        runway_end = observation_runway_end(conn)

    assert runway_end is not None, "upgrade head provisioned no observation partitions"
    remaining = runway_end - date.today()
    assert remaining >= timedelta(days=MIN_RUNWAY_DAYS), (
        f"partition runway ends {runway_end}, only {remaining.days} days past today; "
        "current-dated hub ingest will fail permanently from that date"
    )


def test_every_provisioned_partition_child_forces_tenant_isolation(migrated_database: str) -> None:
    """Children do not inherit RLS; an unprotected one is a cross-tenant hole."""
    import psycopg

    with psycopg.connect(migrated_database, autocommit=True) as conn:
        rows = conn.execute(
            """
            SELECT child.relname, child.relrowsecurity, child.relforcerowsecurity,
                   (SELECT count(*) FROM pg_policies p
                     WHERE p.tablename = child.relname
                       AND p.policyname = child.relname || '_tenant_isolation')
            FROM pg_inherits inh
            JOIN pg_class parent ON parent.oid = inh.inhparent
            JOIN pg_class child ON child.oid = inh.inhrelid
            JOIN pg_namespace n ON n.oid = parent.relnamespace
            WHERE n.nspname = current_schema() AND parent.relname = %s
            ORDER BY child.relname
            """,
            (OBSERVATIONS_TABLE,),
        ).fetchall()

    assert rows, "no observation partition children were provisioned"
    unprotected = [
        (name, enabled, forced, policies) for name, enabled, forced, policies in rows if not (enabled and forced and policies == 1)
    ]
    assert unprotected == [], f"partition children without forced tenant isolation: {unprotected}"


def test_re_running_upgrade_head_tops_the_runway_back_up(migrated_database: str) -> None:
    """The top-up rides every deploy, not just the one revision that added it."""
    import psycopg

    from agent_bom.api.hub_observations_partition import observation_runway_end

    keep = f"{OBSERVATIONS_TABLE}_y{date.today():%Ym%m}"
    with psycopg.connect(migrated_database, autocommit=True) as conn:
        children = [
            str(row[0])
            for row in conn.execute(
                """
                SELECT child.relname FROM pg_inherits inh
                JOIN pg_class parent ON parent.oid = inh.inhparent
                JOIN pg_class child ON child.oid = inh.inhrelid
                WHERE parent.relname = %s ORDER BY child.relname
                """,
                (OBSERVATIONS_TABLE,),
            ).fetchall()
        ]
        # Simulate a database whose runway has lapsed while sitting at head.
        for child in children:
            if child > keep:
                conn.execute(f"ALTER TABLE {OBSERVATIONS_TABLE} DETACH PARTITION {child}")  # noqa: S608
                conn.execute(f"DROP TABLE {child}")  # noqa: S608
        lapsed_end = observation_runway_end(conn)

    assert lapsed_end is not None and lapsed_end - date.today() < timedelta(days=MIN_RUNWAY_DAYS)

    # No revision is pending — only the per-deploy top-up can restore this.
    _upgrade_head(migrated_database)

    with psycopg.connect(migrated_database, autocommit=True) as conn:
        restored_end = observation_runway_end(conn)
    assert restored_end is not None
    assert restored_end - date.today() >= timedelta(days=MIN_RUNWAY_DAYS)
