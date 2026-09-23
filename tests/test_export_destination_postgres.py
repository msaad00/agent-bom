"""Export destination backend selection and real Postgres durability/RLS."""

from __future__ import annotations

import os
from dataclasses import replace
from uuid import uuid4

import pytest

from agent_bom.api import export_destination_store as stores


def test_postgres_destination_factory_selects_durable_store(monkeypatch):
    monkeypatch.setenv("AGENT_BOM_POSTGRES_URL", "postgresql://fixture.invalid/control_plane")
    monkeypatch.delenv("AGENT_BOM_STORE_BACKEND", raising=False)
    marker = object()
    monkeypatch.setattr(stores, "PostgresExportDestinationStore", lambda: marker)
    monkeypatch.setattr(stores, "_DESTINATION_STORE", None)
    assert stores.get_export_destination_store() is marker


def test_postgres_destination_factory_never_falls_back_on_failure(monkeypatch):
    monkeypatch.setenv("AGENT_BOM_POSTGRES_URL", "postgresql://fixture.invalid/control_plane")
    monkeypatch.delenv("AGENT_BOM_STORE_BACKEND", raising=False)
    monkeypatch.setattr(stores, "_DESTINATION_STORE", None)

    def fail():
        raise RuntimeError("Storage unavailable")

    monkeypatch.setattr(stores, "PostgresExportDestinationStore", fail)
    with pytest.raises(RuntimeError, match="Storage unavailable"):
        stores.get_export_destination_store()
    assert stores._DESTINATION_STORE is None


@pytest.mark.skipif(not os.environ.get("AGENT_BOM_TEST_EXPORT_PG_DSN"), reason="isolated Postgres DSN required")
def test_postgres_destinations_survive_reconnect_and_enforce_rls(monkeypatch):
    from psycopg import sql
    from psycopg.errors import InsufficientPrivilege
    from psycopg_pool import ConnectionPool

    from agent_bom.api.postgres_common import reset_current_tenant, set_current_tenant

    dsn = os.environ["AGENT_BOM_TEST_EXPORT_PG_DSN"]
    role = "export_test_" + uuid4().hex[:12]
    # The test DSN must point at a disposable development database.
    monkeypatch.delenv("AGENT_BOM_POSTGRES_URL", raising=False)
    monkeypatch.delenv("AGENT_BOM_DB", raising=False)
    with ConnectionPool(dsn) as owner:
        with owner.connection() as conn:
            conn.execute(
                "DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='agent_bom_rls_maintenance') "
                "THEN CREATE ROLE agent_bom_rls_maintenance; END IF; END $$"
            )
        stores.PostgresExportDestinationStore(pool=owner)
        with owner.connection() as conn:
            conn.execute(sql.SQL("CREATE ROLE {} NOLOGIN NOSUPERUSER NOBYPASSRLS").format(sql.Identifier(role)))
            conn.execute(sql.SQL("GRANT USAGE ON SCHEMA public TO {}").format(sql.Identifier(role)))
            conn.execute(sql.SQL("GRANT SELECT, INSERT, UPDATE, DELETE ON export_destinations TO {}").format(sql.Identifier(role)))
            conn.execute(sql.SQL("GRANT SELECT ON control_plane_schema_versions TO {}").format(sql.Identifier(role)))
        monkeypatch.setenv("AGENT_BOM_POSTGRES_URL", dsn)  # schema checks only after bootstrap

        def configure(conn):
            conn.execute(sql.SQL("SET SESSION AUTHORIZATION {}").format(sql.Identifier(role)))
            conn.commit()

        record = stores.ExportDestinationRecord(
            id=uuid4().hex,
            tenant_id="tenant-a",
            kind="snowflake",
            display_name="warehouse",
            config={"database": "FINDINGS"},
            secret_encrypted="opaque-ciphertext",
            created_at="2026-09-23",
            updated_at="2026-09-23",
        )
        token = set_current_tenant("tenant-a")
        try:
            with ConnectionPool(dsn, configure=configure) as first_pool:
                first = stores.PostgresExportDestinationStore(pool=first_pool)
                first.put(record)
            with ConnectionPool(dsn, configure=configure) as second_pool:
                second = stores.PostgresExportDestinationStore(pool=second_pool)
                assert second.get("tenant-a", record.id) == record
                second.put(replace(record, status="active", last_run_status="success"))
                assert second.list_for_tenant("tenant-a")[0].last_run_status == "success"
                assert "secret_encrypted" not in second.get("tenant-a", record.id).to_public_dict()
                reset_current_tenant(token)
                token = set_current_tenant("tenant-b")
                assert second.get("tenant-a", record.id) is None  # forged predicate still blocked by RLS
                assert second.list_for_tenant("tenant-a") == []
                assert not second.delete("tenant-a", record.id)
                with pytest.raises(InsufficientPrivilege, match="row-level security"):
                    second.put(record)
                second.put(replace(record, tenant_id="tenant-b", display_name="other tenant"))
                assert second.get("tenant-b", record.id).display_name == "other tenant"
                assert second.delete("tenant-b", record.id)
                reset_current_tenant(token)
                token = set_current_tenant("tenant-a")
                assert second.delete("tenant-a", record.id)
        finally:
            reset_current_tenant(token)
            with owner.connection() as conn:
                conn.execute(sql.SQL("DROP OWNED BY {}").format(sql.Identifier(role)))
                conn.execute(sql.SQL("DROP ROLE {}").format(sql.Identifier(role)))
