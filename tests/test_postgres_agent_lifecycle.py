"""Live PostgreSQL proof for lifecycle RLS, durability and concurrent binding."""

import os
from concurrent.futures import ThreadPoolExecutor
from uuid import uuid4

import pytest

from agent_bom.api.lifecycle_store import LifecycleConflictError, PostgresLifecycleStore
from agent_bom.api.postgres_common import _tenant_connection, reset_current_tenant, set_current_tenant
from agent_bom.evidence.lifecycle import RegisterDeployment, RegisterInstance, RegisterRun
from agent_bom.evidence.scan_agent_bom import build_scan_agent_bom

pytestmark = pytest.mark.skipif(not os.environ.get("AGENT_BOM_POSTGRES_URL"), reason="requires migrated live PostgreSQL")


def test_postgres_lifecycle_rls_restart_and_concurrent_binding():
    from psycopg_pool import ConnectionPool

    from agent_bom.api.postgres_common import resolve_postgres_secret

    password = resolve_postgres_secret()
    with ConnectionPool(
        os.environ["AGENT_BOM_POSTGRES_URL"], kwargs={"password": password} if password else {}, min_size=1, max_size=4
    ) as pool:
        store = PostgresLifecycleStore(pool)
        tenant = "lifecycle-" + uuid4().hex
        token = set_current_tenant(tenant)
        result = {
            "scan_id": "s",
            "generated_at": "2026-09-26T00:00:00Z",
            "agents": [{"name": "a", "canonical_id": "a", "stable_id": "a", "agent_type": "custom", "mcp_servers": []}],
        }
        try:
            doc = build_scan_agent_bom(result, agent_id="a", tenant_id=tenant)
            captured = store.capture(tenant, doc, "operator")
            assert store.capture(tenant, doc, "operator") == captured

            def create(index):
                current = set_current_tenant(tenant)
                try:
                    return store.deployment(
                        tenant,
                        RegisterDeployment(deployment_id="d", agent_id="a", snapshot_id=captured.record_id, version=str(index)),
                        "operator",
                    ).version
                except LifecycleConflictError:
                    return "conflict"
                finally:
                    reset_current_tenant(current)

            with ThreadPoolExecutor(2) as executor:
                created = list(executor.map(create, (0, 1)))
            assert created.count("conflict") == 1
            store.instance(
                tenant, RegisterInstance(instance_id="i", deployment_id="d", identity_id="identity"), "operator", identity_agent_id="a"
            )
            run = store.run(tenant, RegisterRun(run_id="r", instance_id="i"), "operator")
            store.retire(tenant, "instance", "i", "operator")
            reopened = PostgresLifecycleStore(pool)
            assert reopened.get(tenant, "run", "r") == run
            assert reopened.snapshot(tenant, captured.record_id) == doc
            with pytest.raises(LifecycleConflictError):
                reopened.run(tenant, RegisterRun(run_id="blocked", instance_id="i"), "operator")
            # Actual application role cannot overwrite/delete a saved document.
            with _tenant_connection(pool) as conn:
                privileges = conn.execute(
                    "SELECT has_table_privilege(current_user, 'agent_bom_snapshots', 'UPDATE'), "
                    "has_table_privilege(current_user, 'agent_bom_snapshots', 'DELETE')"
                ).fetchone()
                assert privileges == (False, False)
            other = set_current_tenant("other-" + uuid4().hex)
            try:
                # Even an explicit victim tenant predicate cannot escape RLS.
                assert store.get(tenant, "run", "r") is None
                assert store.snapshot(tenant, captured.record_id) is None
            finally:
                reset_current_tenant(other)
        finally:
            reset_current_tenant(token)
