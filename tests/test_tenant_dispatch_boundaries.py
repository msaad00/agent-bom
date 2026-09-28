"""Per-tenant dispatch must not inherit global maintenance authority."""

from __future__ import annotations

import asyncio
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from agent_bom.api.postgres_common import _current_tenant, bypass_tenant_rls, is_tenant_rls_bypassed


@pytest.fixture
def maintenance_context():
    token = _current_tenant.set("outer")
    try:
        with bypass_tenant_rls(audit=False, warn=False):
            yield
            assert (_current_tenant.get(), is_tenant_rls_bypassed()) == ("outer", True)
    finally:
        _current_tenant.reset(token)


def _authority():
    return _current_tenant.get(), is_tenant_rls_bypassed()


@pytest.mark.parametrize("tenant", ["tenant-a", None, "", " \t "])
def test_connection_scan_rejects_missing_tenant_and_drops_bypass(monkeypatch, maintenance_context, tenant):
    from agent_bom.api import connection_scheduler
    from agent_bom.api.routes import cloud_connections

    seen = []

    def queue(*args, **kwargs):
        seen.append(_authority())
        return SimpleNamespace(job_id="queued")

    monkeypatch.setattr(cloud_connections, "queue_connection_scan_record", queue)
    persist = Mock(return_value=True)
    monkeypatch.setattr(connection_scheduler, "_persist_scan_outcome", persist)
    result = connection_scheduler.execute_connection_scan(SimpleNamespace(tenant_id=tenant, id="connection", provider="aws"))
    assert seen == ([("tenant-a", False)] if tenant == "tenant-a" else [])
    assert result is (tenant == "tenant-a")
    assert persist.call_count == (1 if tenant == "tenant-a" else 0)


@pytest.mark.parametrize("tenant", ["tenant-a", None, "", " \t "])
def test_event_consumer_rejects_missing_tenant_and_drops_bypass(monkeypatch, maintenance_context, tenant):
    from agent_bom.api import connection_scheduler

    seen = []
    monkeypatch.setattr(
        connection_scheduler, "_load_continuous_consumer", lambda _: (lambda: True, lambda *a, **kw: seen.append(_authority()))
    )
    connection_scheduler._consume_continuous_events(SimpleNamespace(tenant_id=tenant, id="connection", provider="aws"), Mock())
    assert seen == ([("tenant-a", False)] if tenant == "tenant-a" else [])


@pytest.mark.asyncio
async def test_side_scan_worker_isolates_each_tenant_and_invalid_target(maintenance_context):
    from agent_bom.api.side_scan_scheduler import schedule_provider_side_scans

    seen = []

    def runner(target):
        seen.append((target.tenant_id, _authority()))
        return {"status": "done"}

    targets = [SimpleNamespace(tenant_id=t, provider="gcp", target_id=str(i)) for i, t in enumerate(("tenant-a", "", "tenant-b"))]
    outcomes = await schedule_provider_side_scans(targets=targets, runner=runner, require_enabled=False)
    assert sorted(seen) == [("tenant-a", ("tenant-a", False)), ("tenant-b", ("tenant-b", False))]
    assert [row["status"] for row in outcomes] == ["done", "failed", "done"]


@pytest.mark.parametrize("tenant", ["tenant-a", None, "", " \t "])
def test_reconciliation_write_does_not_invent_tenant_or_inherit_bypass(maintenance_context, tenant):
    from agent_bom.api.scan_job_reconciliation import _put_in_job_tenant

    seen = []
    store = SimpleNamespace(put=lambda _: seen.append(_authority()))
    job = SimpleNamespace(tenant_id=tenant)
    if tenant == "tenant-a":
        _put_in_job_tenant(store, job)
        assert seen == [("tenant-a", False)]
    else:
        with pytest.raises(ValueError, match="tenant"):
            _put_in_job_tenant(store, job)
        assert seen == []


@pytest.mark.asyncio
async def test_correlation_rejects_unscoped_rows_before_lookup(monkeypatch, maintenance_context):
    from agent_bom.api import auto_correlation

    rows = [{"tenant_id": tenant, "job_id": "job"} for tenant in (None, "", " \t ", "tenant-a")]
    monkeypatch.setattr(auto_correlation, "_parent_rows", lambda *_: rows)
    seen = []

    def get(*args, **kwargs):
        seen.append((kwargs["tenant_id"], _authority()))
        return None

    await auto_correlation.reconcile_auto_correlations_once(
        SimpleNamespace(get=get), Mock(), policy=auto_correlation.AutoCorrelationPolicy()
    )
    assert seen == [("tenant-a", ("tenant-a", False))]


@pytest.mark.parametrize("graph_tenant", ["tenant-a", "foreign"])
def test_graph_write_checks_owner_before_opening_store(monkeypatch, maintenance_context, graph_tenant):
    from agent_bom.api import graph_persistence
    from agent_bom.graph.container import UnifiedGraph

    graph = UnifiedGraph(tenant_id=graph_tenant, scan_id="scan", created_at="2026-09-28T00:00:00Z")
    seen = []

    def factory():
        seen.append(_authority())
        return SimpleNamespace(latest_snapshot_id=lambda **kw: None, save_graph_streaming=lambda **kw: {"nodes": 0})

    kwargs = dict(tenant_id="tenant-a", scan_id="scan", store_factory=factory, store_backed=True, write_generation="generation")
    if graph_tenant == "tenant-a":
        graph_persistence._write_snapshot(graph, **kwargs)
        assert seen == [("tenant-a", False)]
    else:
        with pytest.raises(ValueError, match="tenant"):
            graph_persistence._write_snapshot(graph, **kwargs)
        assert seen == []


@pytest.mark.asyncio
@pytest.mark.parametrize("tenant", ["tenant-a", None, "", " \t "])
async def test_scheduled_scan_callback_drops_bypass_on_sqlite_and_restores(monkeypatch, maintenance_context, tenant):
    from agent_bom.api import scheduler

    schedule = SimpleNamespace(
        enabled=True,
        name="scheduled",
        schedule_id="schedule",
        tenant_id=tenant,
        scan_config={},
        next_run=None,
        cron_expression="0 * * * *",
    )
    seen = []
    store = SimpleNamespace(list_due=lambda _: [schedule], get=lambda *a, **kw: None)

    async def stop(_):
        raise asyncio.CancelledError

    monkeypatch.setattr(asyncio, "sleep", stop)
    monkeypatch.setattr(scheduler, "parse_cron_next", lambda *a: None)
    with pytest.raises(asyncio.CancelledError):
        await scheduler.scheduler_loop(store, lambda *a, **kw: seen.append(_authority()) or "job")
    assert seen == ([("tenant-a", False)] if tenant == "tenant-a" else [])


@pytest.mark.parametrize("tenant", [None, "", " \t ", 12])
def test_graph_service_rejects_missing_authority_before_enrichment(monkeypatch, tenant):
    from agent_bom.api import graph_persistence

    enrichment = Mock(side_effect=AssertionError("Reached enrichment without tenant authority"))
    monkeypatch.setattr(graph_persistence, "_with_cost_records", enrichment)
    with pytest.raises(ValueError, match="tenant"):
        graph_persistence.persist_graph_snapshot(SimpleNamespace(tenant_id=tenant), {}, store_factory=Mock())
    enrichment.assert_not_called()


@pytest.mark.parametrize("tenant", [None, "", " \t ", 12])
def test_direct_side_scan_rejects_missing_authority_before_lifecycle(monkeypatch, tenant):
    from agent_bom.api.side_scan_scheduler import run_scheduled_side_scan_once
    from agent_bom.cloud import side_scan_lifecycle

    create = Mock(side_effect=AssertionError("Reached lifecycle without tenant authority"))
    monkeypatch.setattr(side_scan_lifecycle, "new_side_scan_execution", create)
    with pytest.raises(ValueError, match="tenant"):
        run_scheduled_side_scan_once(SimpleNamespace(tenant_id=tenant))
    create.assert_not_called()


@pytest.mark.asyncio
async def test_tenant_scope_survives_await_and_restores_after_cancellation(maintenance_context):
    from agent_bom.api.tenant_worker import tenant_bound_context

    async def task(tenant):
        with tenant_bound_context(tenant):
            await asyncio.sleep(0)
            assert _authority() == (tenant, False)
            raise asyncio.CancelledError

    results = await asyncio.gather(task("tenant-a"), task("tenant-b"), return_exceptions=True)
    assert all(isinstance(result, asyncio.CancelledError) for result in results)


@pytest.mark.parametrize("operation", ["stale", "orphaned"])
def test_reconciliation_rejects_invalid_owner_before_mutating_shared_job(monkeypatch, operation):
    from agent_bom.api import scan_job_reconciliation, scan_queue
    from agent_bom.api.models import JobStatus

    monkeypatch.setattr(scan_queue, "distributed_scans_enabled", lambda: False)
    job = SimpleNamespace(tenant_id="", status=JobStatus.RUNNING, created_at="2020-01-01T00:00:00Z", error=None, completed_at=None)
    store = SimpleNamespace(list_all=lambda **kw: [job], put=Mock())
    with pytest.raises(ValueError, match="tenant"):
        if operation == "stale":
            scan_job_reconciliation.fail_stale_active_scan_jobs(store, timeout_seconds=1)
        else:
            scan_job_reconciliation.fail_orphaned_active_scan_jobs(store)
    assert job.status is JobStatus.RUNNING
    assert job.error is None and job.completed_at is None
    store.put.assert_not_called()


@pytest.mark.parametrize("tenant", [12, False, [], {}])
def test_side_scan_config_does_not_coerce_invalid_tenant_to_an_identity(tenant):
    from agent_bom.api.side_scan_scheduler import _coerce_target

    assert (
        _coerce_target(dict(provider="gcp", target_id="disk", account_id="account", location="region", collector_id="vm", tenant_id=tenant))
        is None
    )
