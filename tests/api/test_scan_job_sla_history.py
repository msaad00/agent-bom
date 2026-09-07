"""Retained scan observations anchor current finding deadlines without reviving rows."""

from datetime import datetime, timezone

import pytest
from starlette.testclient import TestClient

from agent_bom.api import stores
from agent_bom.api.compliance_hub_store import InMemoryComplianceHubStore, set_compliance_hub_store
from agent_bom.api.server import app
from agent_bom.api.store import InMemoryJobStore, SQLiteJobStore
from tests.api.test_findings_owner_sla import _completed_job, _critical_finding
from tests.auth_helpers import disable_trusted_proxy_env, enable_trusted_proxy_env, proxy_headers


@pytest.fixture(params=["memory", "sqlite"])
def scan_store(request, tmp_path):
    original = stores._store
    store = InMemoryJobStore() if request.param == "memory" else SQLiteJobStore(str(tmp_path / "jobs.db"))
    stores.set_job_store(store)
    set_compliance_hub_store(InMemoryComplianceHubStore())
    enable_trusted_proxy_env()
    yield store
    stores.set_job_store(original)
    set_compliance_hub_store(None)
    disable_trusted_proxy_env()


def job(month, *, tenant="history-tenant", target="repo-a", findings=None):
    row = _completed_job(
        tenant,
        [_critical_finding()] if findings is None else findings,
        generated_at=datetime(2026, month, 1, tzinfo=timezone.utc),
    )
    row.job_id = f"{tenant}-{target}-{month}"
    row.target = {"path": target}
    return row


def get_rows(*, tenant="history-tenant", **params):
    with TestClient(app) as client:
        client.headers.update(proxy_headers(role="analyst", tenant=tenant))
        response = client.get("/v1/findings", params={"origin": "scan", "window_days": 0, **params})
    assert response.status_code == 200
    return response.json()["findings"]


@pytest.mark.parametrize("reverse", [False, True])
def test_current_route_keeps_first_retained_observation_across_rescans(scan_store, reverse):
    rows = [job(8), job(9)]
    for row in reversed(rows) if reverse else rows:
        scan_store.put(row)
    result = get_rows()
    assert len(result) == 1
    assert result[0]["first_seen"] == "2026-08-01T00:00:00+00:00"
    assert result[0]["sla_due_at"] == "2026-08-08T00:00:00+00:00"
    assert result[0]["last_observed"] == "2026-09-01T00:00:00+00:00"


def test_empty_latest_snapshot_does_not_resurrect_historical_finding(scan_store):
    scan_store.put(job(8))
    scan_store.put(job(9, findings=[]))
    assert get_rows() == []


def test_explicit_scan_remains_snapshot_scoped(scan_store):
    old, new = job(8), job(9)
    scan_store.put(old)
    scan_store.put(new)
    result = get_rows(scan_id=new.job_id)
    assert len(result) == 1
    assert result[0]["first_seen"] == "2026-09-01T00:00:00+00:00"
    assert result[0]["sla_due_at"] == "2026-09-08T00:00:00+00:00"


@pytest.mark.parametrize("boundary", ["target", "environment", "tenant", "canonical_id"])
def test_history_never_joins_distinct_occurrences(scan_store, boundary):
    old, new = job(8), job(9)
    if boundary == "target":
        old.target = {"path": "other-repository"}
    elif boundary == "environment":
        old.result["findings"][0]["environment"] = "production"
        new.result["findings"][0]["environment"] = "development"
    elif boundary == "tenant":
        old.tenant_id = "another-tenant"
    else:
        old.result["findings"][0].update(id="another-canonical-id", canonical_id="another-canonical-id")
    scan_store.put(old)
    scan_store.put(new)
    result = get_rows()
    assert len(result) == 1
    assert result[0]["first_seen"] == "2026-09-01T00:00:00+00:00"
    assert result[0]["sla_due_at"] == "2026-09-08T00:00:00+00:00"


def test_query_window_does_not_restart_retained_history(scan_store, monkeypatch):
    from agent_bom.api import time_window

    scan_store.put(job(8))
    scan_store.put(job(9))
    monkeypatch.setattr(time_window, "window_since_iso", lambda _, **kwargs: "2026-08-31T00:00:00+00:00")
    result = get_rows(window_days=30, sort="severity")
    assert result[0]["first_seen"] == "2026-08-01T00:00:00+00:00"
    assert result[0]["sla_due_at"] == "2026-08-08T00:00:00+00:00"


@pytest.mark.parametrize("first_seen", [None, "invalid timestamp"])
def test_missing_history_does_not_use_job_completion_as_first_seen(scan_store, first_seen):
    for month in (8, 9):
        row = job(month)
        row.result["findings"][0].update(first_seen=first_seen, sla_due_at=None, sla_due_at_source="unavailable")
        scan_store.put(row)
    result = get_rows()
    assert result[0]["first_seen"] in (None, "invalid timestamp")
    assert result[0]["sla_due_at"] is None


def test_explicit_latest_deadline_is_not_replaced_by_history(scan_store):
    old, new = job(8), job(9)
    new.result["findings"][0].update(sla_due_at="2026-12-31T00:00:00+00:00", sla_due_at_source="explicit")
    scan_store.put(old)
    scan_store.put(new)
    result = get_rows()
    assert result[0]["sla_due_at"] == "2026-12-31T00:00:00+00:00"
    assert result[0]["first_seen"] == "2026-08-01T00:00:00+00:00"


@pytest.mark.parametrize("source", ["explicit", None])
@pytest.mark.parametrize("first_seen", ["2026-08-01T00:00:00+00:00", None, "invalid timestamp"])
def test_existing_assignment_survives_a_new_derived_scan_deadline(scan_store, source, first_seen):
    old, new = job(8), job(9)
    old.result["findings"][0].update(first_seen=first_seen, sla_due_at="2026-12-31T00:00:00+00:00", sla_due_at_source=source)
    scan_store.put(old)
    scan_store.put(new)
    result = get_rows()
    assert result[0]["sla_due_at"] == "2026-12-31T00:00:00+00:00"
    assert result[0]["sla_due_at_source"] == ("explicit" if source else "unknown")


def test_history_uses_existing_tenant_read_and_does_not_mutate_snapshots(scan_store, monkeypatch):
    old, new = job(8), job(9)
    scan_store.put(old)
    scan_store.put(new)
    before = [row.model_dump(mode="json") for row in scan_store.list_all(tenant_id="history-tenant")]
    calls = []
    original = scan_store.list_all

    def record_read(tenant_id=None, **kwargs):
        calls.append(tenant_id)
        return original(tenant_id=tenant_id, **kwargs)

    monkeypatch.setattr(scan_store, "list_all", record_read)
    with TestClient(app) as client:
        client.headers.update(proxy_headers(role="analyst", tenant="history-tenant"))
        calls.clear()  # Application startup restores jobs independently of this read route.
        response = client.get("/v1/findings", params={"origin": "scan", "window_days": 0})
        assert response.status_code == 200 and len(response.json()["findings"]) == 1
    assert calls == ["history-tenant"]
    assert [row.model_dump(mode="json") for row in original(tenant_id="history-tenant")] == before


def test_unqualified_legacy_identity_is_not_joined_by_display_fallback(scan_store):
    old, new = job(8), job(9)
    old.result["findings"][0].pop("canonical_id")
    scan_store.put(old)
    scan_store.put(new)
    result = get_rows()
    assert result[0]["first_seen"] == "2026-09-01T00:00:00+00:00"


def test_parent_aggregate_cannot_supply_an_earlier_leaf_observation(scan_store):
    parent, leaf = job(8), job(9)
    parent.child_job_ids = [leaf.job_id]
    scan_store.put(parent)
    scan_store.put(leaf)
    result = get_rows()
    assert len(result) == 1
    assert result[0]["first_seen"] == "2026-09-01T00:00:00+00:00"


def test_current_normalized_observation_is_not_erased_by_undated_history():
    from agent_bom.api.findings_current import current_scan_findings

    old, new = job(8), job(9)
    old.result["findings"][0].update(first_seen=None, sla_due_at="2026-12-31T00:00:00+00:00", sla_due_at_source="explicit")
    new.result["findings"][0].update(first_seen=None, sla_due_at=None)

    def normalized_rows(selected):
        return [dict(row, first_seen="2026-09-01T00:00:00+00:00") for row in selected.result["findings"]]

    rows = current_scan_findings([old, new], since=None, scan_id=None, iter_findings=normalized_rows)
    assert rows[0]["first_seen"] == "2026-09-01T00:00:00+00:00"
    assert rows[0]["sla_due_at"] == "2026-12-31T00:00:00+00:00"
