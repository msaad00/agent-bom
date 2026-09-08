"""Pagination totals use the same tenant, resource and time scope as audit rows."""

import pytest
from starlette.requests import Request

from agent_bom.api.audit_log import AuditEntry, InMemoryAuditLog, SQLiteAuditLog


@pytest.fixture(params=["memory", "sqlite"])
def audit_store(request, tmp_path):
    store = InMemoryAuditLog() if request.param == "memory" else SQLiteAuditLog(str(tmp_path / "audit.db"))
    for tenant, action, resource, timestamp in [
        ("alpha", "scan", "image/one", "2026-09-08T01:00:00Z"),
        ("alpha", "scan", "image/two", "2026-09-08T02:00:00Z"),
        ("alpha", "scan", "image/old", "2026-09-01T01:00:00Z"),
        ("alpha", "scan", "repo/one", "2026-09-08T01:00:00Z"),
        ("alpha", "config", "image/one", "2026-09-08T01:00:00Z"),
        ("beta", "scan", "image/one", "2026-09-08T01:00:00Z"),
    ]:
        store.append(AuditEntry(action=action, actor="operator", resource=resource, timestamp=timestamp, details={"tenant_id": tenant}))
    return store


def test_count_matches_filtered_rows_across_pages(audit_store):
    filters = dict(action="scan", resource="image/", since="2026-09-08", tenant_id="alpha")
    assert audit_store.count(**filters) == 2
    first = audit_store.list_entries(**filters, limit=1)
    second = audit_store.list_entries(**filters, limit=1, offset=1)
    assert len(first) == len(second) == 1
    assert first[0].entry_id != second[0].entry_id
    assert audit_store.count(resource="missing/", tenant_id="alpha") == 0
    assert audit_store.count(tenant_id="alpha") == 5


@pytest.mark.asyncio
async def test_api_total_retains_filters_when_page_is_empty(audit_store, monkeypatch):
    from agent_bom.api import audit_log
    from agent_bom.api.routes import enterprise

    monkeypatch.setattr(audit_log, "get_audit_log", lambda: audit_store)
    monkeypatch.setattr(enterprise, "require_request_tenant_id", lambda request: "alpha")
    response = await enterprise.list_audit_entries(
        Request({"type": "http"}), action="scan", resource="image/", since="2026-09-08", limit=1, offset=2
    )
    assert response["entries"] == []
    assert response["total"] == 2
