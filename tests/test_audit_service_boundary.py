"""Audit writes must not construct unrelated API stores or lose tenant context."""

import json
import os
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace


def test_audit_write_stays_below_the_api_store_composition():
    code = """
import json, sys
from agent_bom.api.audit_log import InMemoryAuditLog, log_action, set_audit_log
from agent_bom.api.postgres_common import set_current_tenant, reset_current_tenant
store = InMemoryAuditLog()
set_audit_log(store)
token = set_current_tenant("boundary-tenant")
try:
    log_action("boundary.read", resource="graph")
finally:
    reset_current_tenant(token)
names = ("agent_bom.api.stores", "agent_bom.api.postgres_store", "agent_bom.api.server")
print(json.dumps({"loaded": [n for n in names if n in sys.modules], "entries": store.count(tenant_id="boundary-tenant")}))
"""
    env = {key: value for key, value in os.environ.items() if not key.startswith("AGENT_BOM_")}
    result = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, env=env, timeout=30)
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout) == {"loaded": [], "entries": 1}


def test_analytics_composition_and_audit_share_one_registry():
    from agent_bom.api import audit_log, stores
    from agent_bom.api.storage.analytics import get_analytics_store

    previous = get_analytics_store()
    previous_audit = audit_log.get_audit_log()
    rows = []
    sink = SimpleNamespace(record_audit_event=rows.append)
    try:
        stores.set_analytics_store(sink)
        audit_log.set_audit_log(audit_log.InMemoryAuditLog())
        assert stores._get_analytics_store() is get_analytics_store() is sink
        audit_log.log_action("boundary.read", tenant_id="alpha")
        assert len(rows) == 1
        assert rows[0]["tenant_id"] == "alpha"
        assert audit_log.get_audit_log().count(tenant_id="alpha") == 1
    finally:
        stores.set_analytics_store(previous)
        audit_log.set_audit_log(previous_audit)


def test_analytics_default_is_shared_across_concurrent_first_reads():
    from agent_bom.api.storage.analytics import get_analytics_store, set_analytics_store

    previous = get_analytics_store()
    try:
        set_analytics_store(None)
        with ThreadPoolExecutor(max_workers=8) as pool:
            values = list(pool.map(lambda _: get_analytics_store(), range(32)))
        assert all(value is values[0] for value in values)
    finally:
        set_analytics_store(previous)
