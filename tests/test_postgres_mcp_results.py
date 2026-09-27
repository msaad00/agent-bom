"""Migrated application-role proof for shared MCP result storage and tenant RLS."""

import os
from concurrent.futures import ThreadPoolExecutor
from uuid import uuid4

import pytest

from agent_bom.mcp_tools.result_store import DurableScanResultStore

pytestmark = pytest.mark.skipif(not os.environ.get("AGENT_BOM_POSTGRES_URL"), reason="requires migrated live PostgreSQL")


def test_postgres_mcp_restart_rls_and_concurrent_eviction():
    from agent_bom.api.postgres_common import _get_pool, _tenant_connection, reset_current_tenant, set_current_tenant

    tenant = "mcp-results-" + uuid4().hex

    def cache(scope=tenant):
        return DurableScanResultStore(tenant_id=scope, max_entries=3, ttl_seconds=60)

    rid = cache().put("owner", {"report": {"id": "one"}})
    assert cache().get("owner", rid) == {"report": {"id": "one"}}
    assert cache().get("rotated-token", rid) is None
    assert cache(tenant + "-other").get("owner", rid) is None
    current = set_current_tenant(tenant + "-other")
    try:
        with _tenant_connection(_get_pool()) as conn:
            # Explicit victim predicates and no predicate both remain fenced.
            assert conn.execute("SELECT result_id FROM mcp_scan_results WHERE tenant_id=%s", (tenant,)).fetchall() == []
            assert conn.execute("SELECT result_id FROM mcp_scan_results").fetchall() == []
            assert conn.execute("DELETE FROM mcp_scan_results WHERE tenant_id=%s", (tenant,)).rowcount == 0
            assert conn.execute("SELECT rolsuper, rolbypassrls FROM pg_roles WHERE rolname=current_user").fetchone() == (False, False)
        from psycopg.errors import InsufficientPrivilege

        with pytest.raises(InsufficientPrivilege), _tenant_connection(_get_pool()) as conn:
            conn.execute("INSERT INTO mcp_scan_results VALUES (%s,%s,%s,0,1,'{}')", (tenant, "forged", "owner"))
    finally:
        reset_current_tenant(current)
    with ThreadPoolExecutor(4) as executor:
        ids = list(executor.map(lambda i: cache().put("owner", {"v": i}), range(12)))
    assert sum(cache().get("owner", key) is not None for key in ids) == 3
    assert cache().get("owner", rid) is None
