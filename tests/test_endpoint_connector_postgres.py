"""Opt-in real Postgres migration, RLS, lease and retained-evidence contract."""

from __future__ import annotations

import importlib.util
import os
from pathlib import Path
from types import SimpleNamespace
from uuid import uuid4

import pytest

pytestmark = pytest.mark.skipif(not os.environ.get("ENDPOINT_TEST_POSTGRES_URL"), reason="Dedicated endpoint Postgres fixture required")


def test_migration_rls_restart_and_receipt_permissions(monkeypatch):
    from cryptography.fernet import Fernet
    from psycopg.conninfo import make_conninfo
    from psycopg.errors import InsufficientPrivilege
    from psycopg_pool import ConnectionPool

    from agent_bom.api import connection_crypto
    from agent_bom.api.postgres_common import _ensure_rls_helpers
    from agent_bom.connectors.endpoints.models import ConnectionCreate, SyncState, now
    from agent_bom.connectors.endpoints.service import create_connection
    from agent_bom.connectors.endpoints.store import EndpointStore
    from agent_bom.connectors.endpoints.transport import CollectionError
    from agent_bom.device_posture import DeviceSignal

    admin_url = os.environ["ENDPOINT_TEST_POSTGRES_URL"]
    admin = ConnectionPool(admin_url, min_size=1, max_size=2, open=True)
    with admin.connection() as db:
        db.execute("DO $$ BEGIN CREATE ROLE agent_bom_rls_maintenance NOLOGIN; EXCEPTION WHEN duplicate_object THEN NULL; END $$")
        db.execute(
            "DO $$ BEGIN CREATE ROLE agent_bom_app LOGIN PASSWORD 'endpoint-fixture'; EXCEPTION WHEN duplicate_object THEN NULL; END $$"
        )
        _ensure_rls_helpers(db)
        db.execute(
            "CREATE TABLE IF NOT EXISTS control_plane_schema_versions("
            "component TEXT PRIMARY KEY,version INTEGER NOT NULL,updated_at TIMESTAMPTZ NOT NULL)"
        )
        path = Path(__file__).parents[1] / "deploy/supabase/postgres/alembic/versions/20260927_03_endpoint_connectors.py"
        spec = importlib.util.spec_from_file_location("endpoint_migration", path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        module.op = SimpleNamespace(execute=db.execute)
        module.upgrade()
        db.execute("GRANT USAGE ON SCHEMA public TO agent_bom_app")
        db.execute("GRANT SELECT ON control_plane_schema_versions TO agent_bom_app")
        db.commit()
    app_url = os.environ.get("ENDPOINT_TEST_POSTGRES_APP_URL") or make_conninfo(
        admin_url, user="agent_bom_app", password="endpoint-fixture"
    )
    monkeypatch.setenv("AGENT_BOM_POSTGRES_URL", app_url)
    monkeypatch.setenv("AGENT_BOM_CONNECTIONS_KEY", Fernet.generate_key().decode())
    connection_crypto.reset_key_cache()
    pool_a, pool_b = ConnectionPool(app_url, min_size=1, max_size=2, open=True), ConnectionPool(app_url, min_size=1, max_size=2, open=True)
    try:
        a, b = EndpointStore(pool=pool_a), EndpointStore(pool=pool_b)
        tenant = f"tenant-{uuid4().hex}"
        conn = create_connection(
            a,
            tenant,
            ConnectionCreate(
                name="Macs",
                provider="jamf",
                account_id="acme.jamfcloud.com",
                jamf_url="https://acme.jamfcloud.com",
                client_id="fixture",
                client_secret="fixture-secret",
            ),
        )
        assert b.get(tenant, conn.id)[0] == conn
        assert b.get("other", conn.id) is None
        with b.transaction("other") as db:
            assert db.execute("SELECT id FROM endpoint_connections").fetchall() == []
        a.claim(tenant, conn.id, "a")
        with pytest.raises(CollectionError, match="already_running"):
            b.claim(tenant, conn.id, "b")
        state = SyncState(run_id=str(uuid4()), connection_id=conn.id, tenant_id=tenant, started_at=now(), updated_at=now(), device_count=1)
        signal = DeviceSignal(tenant_id=tenant, device_id="endpoint-fixture", source="jamf")
        a.checkpoint(state, [signal], "a")
        assert b.devices(tenant, conn.id, state.run_id)[0].device_id == signal.device_id
        assert b.latest(tenant, conn.id).device_count == 1
        assert b.devices("other", conn.id, state.run_id) == []
        assert len(b.history(tenant, conn.id)) == 1
        for sql in ["DELETE FROM endpoint_sync_events", "UPDATE endpoint_sync_events SET data='{}'"]:
            with pytest.raises(InsufficientPrivilege):
                with b.transaction(tenant) as db:
                    db.execute(sql)
        with pytest.raises(InsufficientPrivilege):
            with b.transaction("other") as db:
                db.execute(
                    "INSERT INTO endpoint_agent_bindings(tenant_id,device_id,agent_id,data) VALUES (%s,%s,%s,%s)",
                    (tenant, "device", "agent", "{}"),
                )
        a.release(tenant, conn.id, "a")
        b.claim(tenant, conn.id, "b")
        with pytest.raises(CollectionError, match="lease_lost"):
            a.checkpoint(state, [], "a")
    finally:
        pool_a.close()
        pool_b.close()
        admin.close()
        connection_crypto.reset_key_cache()
