"""Guarded snapshot reads must preserve the existing enriched finding contract."""

from copy import deepcopy
from unittest.mock import Mock

import pytest

from agent_bom.api import scan_snapshot_store
from agent_bom.api.scan_snapshot import materialize_job_snapshot
from agent_bom.api.scan_snapshot_store import InMemoryScanSnapshotStore, SQLiteScanSnapshotStore
from tests.test_scan_snapshot import _job


@pytest.fixture(params=["memory", "sqlite"])
def snapshots(request, tmp_path, monkeypatch):
    store = InMemoryScanSnapshotStore() if request.param == "memory" else SQLiteScanSnapshotStore(str(tmp_path / "snapshots.db"))
    scan_snapshot_store.set_scan_snapshot_store(store)
    monkeypatch.setenv("AGENT_BOM_SCAN_SNAPSHOT_READS", "1")
    yield store
    scan_snapshot_store.set_scan_snapshot_store(None)


def put(store, job):
    meta, rows = materialize_job_snapshot(job)
    store.put_snapshot(job.tenant_id, job.job_id, meta, rows)
    return meta, rows


def read(job, legacy, attach=lambda row: row):
    from agent_bom.api.scan_snapshot_read import verified_snapshot_findings

    return verified_snapshot_findings(job, lambda: legacy, attach)


def test_matching_snapshot_is_read_and_returned_without_mutating_storage(snapshots, monkeypatch):
    job = _job()
    _, rows = put(snapshots, job)
    legacy = [{**row["payload"], "live_owner": "new-owner"} for row in rows]
    spy = Mock(wraps=snapshots.get_rows)
    monkeypatch.setattr(snapshots, "get_rows", spy)
    result = read(job, legacy, lambda row: {**row, "live_owner": "new-owner"})
    assert result == legacy and result is not legacy
    spy.assert_called_once_with(job.tenant_id, job.job_id)
    assert all("live_owner" not in row["payload"] for row in snapshots.get_rows(job.tenant_id, job.job_id))


def test_reads_default_off_and_disabled_never_access_snapshot_storage(snapshots, monkeypatch):
    job = _job()
    legacy = [{"id": "live"}]
    monkeypatch.delenv("AGENT_BOM_SCAN_SNAPSHOT_READS")
    monkeypatch.setattr(snapshots, "get_meta", Mock(side_effect=AssertionError("unexpected snapshot access")))
    assert read(job, legacy) is legacy


@pytest.mark.parametrize("reason", ["missing", "version", "count", "stale", "tenant", "order"])
def test_unusable_or_different_snapshot_returns_current_rows(snapshots, reason, caplog):
    job = _job()
    meta, rows = materialize_job_snapshot(job)
    legacy = deepcopy([row["payload"] for row in rows])
    if reason == "version":
        meta["row_schema_version"] += 1
    elif reason == "count":
        meta["row_count"] += 1
    elif reason == "stale":
        rows[0]["payload"]["title"] = "old value"
    elif reason == "order":
        rows.reverse()
    if reason != "missing":
        snapshots.put_snapshot("other-tenant" if reason == "tenant" else job.tenant_id, job.job_id, meta, rows)
    assert read(job, legacy) is legacy
    if reason in {"stale", "order"}:
        assert "outcome=mismatch" in caplog.text


def test_snapshot_error_falls_back_without_logging_exception_or_payload(snapshots, monkeypatch, caplog):
    monkeypatch.setattr(snapshots, "get_meta", Mock(side_effect=RuntimeError("password=do-not-log /private/customer")))
    legacy = [{"secret": "do-not-log"}]
    assert read(_job(), legacy) is legacy
    assert "outcome=unavailable" in caplog.text
    assert "do-not-log" not in caplog.text and "/private/customer" not in caplog.text


def test_legacy_failure_is_never_hidden_by_a_snapshot(snapshots):
    from agent_bom.api.scan_snapshot_read import verified_snapshot_findings

    job = _job()
    put(snapshots, job)
    with pytest.raises(RuntimeError, match="authoritative read failed"):
        verified_snapshot_findings(job, Mock(side_effect=RuntimeError("authoritative read failed")), lambda row: row)


def test_empty_snapshot_matches_empty_scan(snapshots):
    job = _job(result={"findings": []})
    put(snapshots, job)
    legacy = []
    result = read(job, legacy)
    assert result == [] and result is not legacy


def test_route_uses_snapshot_with_current_enrichment(snapshots, monkeypatch):
    from agent_bom.api.routes import scan

    job = _job()
    put(snapshots, job)
    spy = Mock(wraps=snapshots.get_rows)
    monkeypatch.setattr(snapshots, "get_rows", spy)
    monkeypatch.setenv("AGENT_BOM_SCAN_SNAPSHOT_READS", "0")
    expected = scan._iter_scan_findings(job)
    monkeypatch.setenv("AGENT_BOM_SCAN_SNAPSHOT_READS", "1")
    assert scan._iter_scan_findings(job) == expected
    spy.assert_called_once_with(job.tenant_id, job.job_id)
    assert all(row["last_observed"] == job.completed_at for row in expected)


@pytest.mark.parametrize("damage", ["count", "ordinal", "payload", "backend_error"])
def test_incomplete_snapshot_read_cannot_change_current_rows(snapshots, monkeypatch, damage):
    job = _job()
    put(snapshots, job)
    stored = snapshots.get_rows(job.tenant_id, job.job_id)
    legacy = deepcopy([row["payload"] for row in stored])
    if damage == "count":
        stored.pop()
    elif damage == "ordinal":
        stored[0]["ordinal"] = 7
    elif damage == "payload":
        stored[0]["payload"] = "invalid"
    if damage == "backend_error":
        monkeypatch.setattr(snapshots, "get_rows", Mock(side_effect=RuntimeError("unavailable")))
    else:
        monkeypatch.setattr(snapshots, "get_rows", lambda *_: stored)
    assert read(job, legacy) is legacy


@pytest.mark.parametrize("replacement", [True, 1.0])
def test_parity_preserves_json_value_types(snapshots, replacement):
    job = _job()
    job.result["findings"][0]["confidence"] = 1
    meta, rows = put(snapshots, job)
    legacy = deepcopy([row["payload"] for row in rows])
    rows[0]["payload"]["confidence"] = replacement
    snapshots.put_snapshot(job.tenant_id, job.job_id, meta, rows)
    assert read(job, legacy) is legacy
