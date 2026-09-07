"""Real PostgreSQL proof that observation partition bounds ignore session timezone."""

import os
from uuid import uuid4

import pytest

pytestmark = pytest.mark.skipif(
    not os.environ.get("AGENT_BOM_POSTGRES_URL") or not os.environ.get("AGENT_BOM_POSTGRES_ADMIN_URL"),
    reason="Postgres application and migration/admin DSNs are required",
)


@pytest.fixture
def isolated_observations():
    import psycopg
    from psycopg import sql

    from agent_bom.api.hub_observations_partition import partitioned_observations_parent_ddl

    schema = f"observation_utc_{uuid4().hex}"
    with psycopg.connect(os.environ["AGENT_BOM_POSTGRES_URL"], autocommit=True) as app:
        role, superuser, bypass = app.execute(
            "SELECT current_user, rolsuper, rolbypassrls FROM pg_roles WHERE rolname = current_user"
        ).fetchone()
        assert not superuser and not bypass
        with psycopg.connect(os.environ["AGENT_BOM_POSTGRES_ADMIN_URL"], autocommit=True) as admin:
            admin.execute(sql.SQL("CREATE SCHEMA {}").format(sql.Identifier(schema)))
            try:
                admin.execute(sql.SQL("SET search_path TO {}").format(sql.Identifier(schema)))
                admin.execute(partitioned_observations_parent_ddl())
                admin.execute(sql.SQL("GRANT USAGE ON SCHEMA {} TO {}").format(sql.Identifier(schema), sql.Identifier(role)))
                admin.execute(sql.SQL("GRANT SELECT, INSERT ON hub_findings_current_observations TO {}").format(sql.Identifier(role)))
                app.execute(sql.SQL("SET search_path TO {}").format(sql.Identifier(schema)))
                yield admin, app
            finally:
                admin.execute(sql.SQL("DROP SCHEMA {} CASCADE").format(sql.Identifier(schema)))


@pytest.mark.parametrize("session_timezone", ["UTC", "America/New_York", "Asia/Tokyo"])
def test_partition_routes_utc_month_under_any_session_timezone(isolated_observations, session_timezone):
    import psycopg

    from agent_bom.api.hub_observations_partition import create_observation_partition_ddl

    admin, app = isolated_observations
    admin.execute("SELECT set_config('TimeZone', %s, false)", (session_timezone,))
    app.execute("SELECT set_config('TimeZone', %s, false)", (session_timezone,))
    admin.execute(create_observation_partition_ddl(2026, 8))
    insert = "INSERT INTO hub_findings_current_observations VALUES (%s, %s, %s, %s) RETURNING tableoid::regclass::text"
    for index, timestamp in enumerate(
        ["2026-08-01T00:00:00Z", "2026-08-31T23:59:59.999999Z", "2026-07-31T20:00:00-04:00", "2026-09-01T08:59:59+09:00"]
    ):
        partition = app.execute(insert, ("test-tenant", "test-finding", f"scan-{index}", timestamp)).fetchone()[0]
        assert partition.split(".")[-1] == "hub_findings_current_observations_y2026m08"
    for timestamp in ["2026-07-31T23:59:59.999999Z", "2026-09-01T00:00:00Z"]:
        with pytest.raises(psycopg.errors.CheckViolation):
            app.execute(insert, ("test-tenant", "test-finding", "outside", timestamp))
    assert app.execute("SELECT count(*) FROM hub_findings_current_observations").fetchone()[0] == 4


def test_existing_non_utc_partition_is_not_silently_rewritten(isolated_observations):
    import psycopg

    from agent_bom.api.hub_observations_partition import create_observation_partition_ddl

    admin, app = isolated_observations
    admin.execute("SET timezone TO 'America/New_York'")
    admin.execute("""CREATE TABLE hub_findings_current_observations_y2026m08
        PARTITION OF hub_findings_current_observations FOR VALUES FROM ('2026-08-01') TO ('2026-09-01')""")
    app.execute("INSERT INTO hub_findings_current_observations VALUES ('test-tenant', 'finding', 'scan', '2026-08-15T00:00:00Z')")
    bounds = "SELECT pg_get_expr(relpartbound, oid) FROM pg_class WHERE oid = 'hub_findings_current_observations_y2026m08'::regclass"
    before = admin.execute(bounds).fetchone()[0]
    admin.execute(create_observation_partition_ddl(2026, 8))
    assert admin.execute(bounds).fetchone()[0] == before
    with pytest.raises(psycopg.errors.InvalidObjectDefinition):
        admin.execute(create_observation_partition_ddl(2026, 9))
    assert app.execute("SELECT count(*) FROM hub_findings_current_observations").fetchone()[0] == 1
