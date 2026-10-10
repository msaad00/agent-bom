"""Materialized scan finding snapshots (ADR-015 phase 1: write path only)."""

from __future__ import annotations

import json
import threading
from contextlib import ExitStack
from pathlib import Path
from types import SimpleNamespace

import pytest

from agent_bom.api.models import JobStatus, ScanJob, ScanRequest
from agent_bom.api.scan_snapshot import (
    SCAN_SNAPSHOT_ROW_SCHEMA_VERSION,
    backfill_tenant_snapshots,
    finalize_with_scan_snapshot,
    main,
    materialize_job_snapshot,
)
from agent_bom.api.scan_snapshot_store import (
    InMemoryScanSnapshotStore,
    SQLiteScanSnapshotStore,
    expire_jobs_and_snapshots,
    set_scan_snapshot_store,
)
from agent_bom.api.store import InMemoryJobStore, SQLiteJobStore

_RESULT = {
    "scan_id": "scan-1",
    "generated_at": "2026-10-09T10:00:00Z",
    "findings": [
        {"id": "finding-1", "canonical_id": "canon-1", "severity": "HIGH", "title": "first", "source": "secret_scan"},
        {"id": "finding-2", "severity": "low", "title": "second", "source": "secret_scan"},
    ],
}


def _job(job_id: str = "job-1", tenant_id: str = "tenant-a", *, status: JobStatus = JobStatus.DONE, result: dict | None = None) -> ScanJob:
    return ScanJob(
        job_id=job_id,
        tenant_id=tenant_id,
        created_at="2026-10-09T09:59:00+00:00",
        completed_at="2026-10-09T10:00:05+00:00",
        request=ScanRequest(),
        status=status,
        result=dict(_RESULT) if result is None else result,
    )


def _meta(completed_at: str = "2026-10-09T10:00:05+00:00") -> dict:
    return {
        "scope_key": 'sources:["local-agents"]',
        "authority_evidence_at": completed_at,
        "authority_completed_at": completed_at,
        "authoritative": True,
        "incomplete_reasons": ["scope_partial"],
        "completed_at": completed_at,
        "created_at": completed_at,
        "row_schema_version": SCAN_SNAPSHOT_ROW_SCHEMA_VERSION,
        "row_count": 1,
        "materialized_at": completed_at,
    }


def _row(identity: str = "finding-1", canonical_id: str = "canon-1") -> dict:
    return {"finding_identity": identity, "canonical_id": canonical_id, "severity": "high", "payload": {"id": identity, "nested": {"k": 1}}}


@pytest.fixture(params=["memory", "sqlite"])
def snapshot_store(request, tmp_path: Path):
    if request.param == "memory":
        return InMemoryScanSnapshotStore()
    return SQLiteScanSnapshotStore(str(tmp_path / "snapshots.db"))


@pytest.fixture
def active_store(monkeypatch):
    monkeypatch.setenv("AGENT_BOM_SCAN_SNAPSHOTS", "1")
    store = InMemoryScanSnapshotStore()
    set_scan_snapshot_store(store)
    yield store
    set_scan_snapshot_store(None)


# ── store contract ──────────────────────────────────────────────────────────


def test_store_round_trips_meta_and_ordered_rows(snapshot_store) -> None:
    snapshot_store.put_snapshot("tenant-a", "job-1", _meta(), [_row("b", ""), _row("a")])

    meta = snapshot_store.get_meta("tenant-a")["job-1"]
    assert meta["authoritative"] is True
    assert meta["incomplete_reasons"] == ["scope_partial"]
    assert meta["row_schema_version"] == SCAN_SNAPSHOT_ROW_SCHEMA_VERSION
    assert meta["job_id"] == "job-1"
    rows = snapshot_store.get_rows("tenant-a", "job-1")
    assert [(row["ordinal"], row["finding_identity"], row["canonical_id"]) for row in rows] == [(0, "b", ""), (1, "a", "canon-1")]
    assert rows[1]["payload"] == {"id": "a", "nested": {"k": 1}}


def test_store_put_replaces_the_previous_snapshot_atomically(snapshot_store) -> None:
    snapshot_store.put_snapshot("tenant-a", "job-1", _meta(), [_row("a"), _row("b"), _row("c")])
    snapshot_store.put_snapshot("tenant-a", "job-1", {**_meta(), "authoritative": False}, [_row("z")])

    assert snapshot_store.get_meta("tenant-a")["job-1"]["authoritative"] is False
    assert [row["finding_identity"] for row in snapshot_store.get_rows("tenant-a", "job-1")] == ["z"]


def test_store_isolates_tenants_with_equal_job_ids(snapshot_store) -> None:
    snapshot_store.put_snapshot("tenant-a", "job-1", _meta(), [_row("a")])
    snapshot_store.put_snapshot("tenant-b", "job-1", _meta(), [_row("b")])

    assert [row["finding_identity"] for row in snapshot_store.get_rows("tenant-a", "job-1")] == ["a"]
    assert snapshot_store.delete_job("tenant-b", "job-1") is True
    assert snapshot_store.get_rows("tenant-b", "job-1") == []
    assert set(snapshot_store.get_meta("tenant-a")) == {"job-1"}
    assert snapshot_store.delete_tenant("tenant-a") == 1
    assert snapshot_store.get_meta("tenant-a") == {}


def test_store_meta_filters_by_job_ids(snapshot_store) -> None:
    for job_id in ("job-1", "job-2", "job-3"):
        snapshot_store.put_snapshot("tenant-a", job_id, _meta(), [])

    assert set(snapshot_store.get_meta("tenant-a", ["job-1", "job-3", "missing"])) == {"job-1", "job-3"}
    assert snapshot_store.get_meta("tenant-a", []) == {}


def test_store_expiry_is_tenant_scoped_or_global(snapshot_store) -> None:
    snapshot_store.put_snapshot("tenant-a", "old-a", _meta("2026-01-01T00:00:00+00:00"), [_row()])
    snapshot_store.put_snapshot("tenant-b", "old-b", _meta("2026-01-01T00:00:00+00:00"), [_row()])
    snapshot_store.put_snapshot("tenant-a", "new-a", _meta("2026-10-01T00:00:00+00:00"), [_row()])

    assert snapshot_store.delete_older_than("tenant-a", "2026-06-01T00:00:00+00:00") == 1
    assert set(snapshot_store.get_meta("tenant-b")) == {"old-b"}
    assert snapshot_store.delete_older_than(None, "2026-06-01T00:00:00+00:00") == 1
    assert snapshot_store.get_meta("tenant-b") == {}
    assert snapshot_store.get_rows("tenant-b", "old-b") == []
    assert set(snapshot_store.get_meta("tenant-a")) == {"new-a"}


def test_store_rejects_blank_tenant(snapshot_store) -> None:
    with pytest.raises(ValueError, match="explicit tenant_id"):
        snapshot_store.put_snapshot(" ", "job-1", _meta(), [])


# ── materializer ────────────────────────────────────────────────────────────


def test_materializer_uses_fold_metadata_and_intrinsic_rows() -> None:
    from agent_bom.api.finding_collection import collect_scan_findings
    from agent_bom.api.findings_current import finding_identity, scan_evidence_authority_key, scan_scope_key

    job = _job()
    meta, rows = materialize_job_snapshot(job)

    evidence_at, completed_at, _ = scan_evidence_authority_key(job)
    assert meta["scope_key"] == scan_scope_key(job)
    assert (meta["authority_evidence_at"], meta["authority_completed_at"]) == (evidence_at, completed_at)
    assert meta["authoritative"] is True
    assert meta["incomplete_reasons"] == []
    assert meta["row_schema_version"] == SCAN_SNAPSHOT_ROW_SCHEMA_VERSION
    assert meta["row_count"] == len(rows) == 2
    expected = collect_scan_findings(job)
    assert [row["payload"] for row in rows] == expected
    assert [row["finding_identity"] for row in rows] == [finding_identity(item) for item in expected]
    assert rows[0]["canonical_id"] == "canon-1" and rows[0]["severity"] == "high"


def test_materializer_never_reads_mutable_tenant_state(monkeypatch) -> None:
    def _forbidden(*_args, **_kwargs):
        raise AssertionError("snapshot materialization must not read mutable tenant state")

    monkeypatch.setattr("agent_bom.api.routes.scan.attach_runtime_evidence_to_finding", _forbidden)
    monkeypatch.setattr("agent_bom.api.routes.enterprise.build_tenant_triage_owner_index", _forbidden)

    _, rows = materialize_job_snapshot(_job())

    for row in rows:
        assert not {"runtime_evidence", "owner", "effective_reach_score", "suppressed"} & set(row["payload"])


def test_materializer_flags_non_authoritative_attempts() -> None:
    result = {**_RESULT, "scan_run": {"outcome": "failed"}}
    meta, _ = materialize_job_snapshot(_job(result=result))

    assert meta["authoritative"] is False
    assert "scan_failed" in meta["incomplete_reasons"]


# ── completion wiring ───────────────────────────────────────────────────────


def _ctx(job: ScanJob, *, side_effects: bool = True) -> SimpleNamespace:
    return SimpleNamespace(job=job, lock=threading.Lock(), side_effects_enabled=side_effects)


def _persist_and_compact(status: JobStatus):
    def _persist(job: ScanJob, _lock) -> tuple[object, JobStatus]:
        job.status = status
        job.result = {"_compacted": True}  # mirrors the hot-cache compaction after the durable write
        return object(), status

    return _persist


def test_completion_snapshots_a_durably_done_job_from_the_persisted_result(active_store) -> None:
    job = _job()
    _, status = finalize_with_scan_snapshot(_ctx(job), _persist_and_compact(JobStatus.DONE))

    assert status is JobStatus.DONE
    assert active_store.get_meta("tenant-a")["job-1"]["row_count"] == 2
    assert len(active_store.get_rows("tenant-a", "job-1")) == 2


@pytest.mark.parametrize(
    "status,side_effects,enabled",
    [
        (JobStatus.FAILED, True, True),  # final store write rejected: never durably DONE
        (JobStatus.CANCELLED, True, True),
        (JobStatus.DONE, False, True),  # dry-run / no-scan
        (JobStatus.DONE, True, False),  # opt-in setting off
    ],
)
def test_completion_skips_snapshot_unless_durable_done_with_side_effects(active_store, monkeypatch, status, side_effects, enabled) -> None:
    if not enabled:
        monkeypatch.setenv("AGENT_BOM_SCAN_SNAPSHOTS", "0")
    finalize_with_scan_snapshot(_ctx(_job(), side_effects=side_effects), _persist_and_compact(status))

    assert active_store.get_meta("tenant-a") == {}


def test_completion_snapshot_failure_never_changes_the_job_outcome(active_store, monkeypatch, caplog) -> None:
    def _boom(*_args, **_kwargs):
        raise RuntimeError("database at postgresql://user:secret@db unavailable")

    monkeypatch.setattr(active_store, "put_snapshot", _boom)
    job = _job()
    _, status = finalize_with_scan_snapshot(_ctx(job), _persist_and_compact(JobStatus.DONE))

    assert status is JobStatus.DONE and job.status is JobStatus.DONE
    assert "scan snapshot materialization failed" in caplog.text
    assert "secret@" not in caplog.text


def test_pipeline_finalize_writes_snapshot_after_the_job_store_write(active_store, tmp_path: Path, monkeypatch) -> None:
    from agent_bom.api import pipeline, stores
    from agent_bom.api.scan_context import ScanContext

    job_store = SQLiteJobStore(str(tmp_path / "jobs.db"))
    monkeypatch.setattr(stores, "_store", job_store)
    monkeypatch.setattr(pipeline, "_record_completion_metrics", lambda *_args: None)
    monkeypatch.setattr(pipeline, "_record_adoption", lambda *_args: None)
    order: list[str] = []
    original_put = active_store.put_snapshot

    def _put_snapshot(tenant_id, job_id, meta, rows):
        order.append("snapshot" if job_store.get(job_id, tenant_id=tenant_id).status is JobStatus.DONE else "snapshot-before-done")
        original_put(tenant_id, job_id, meta, rows)

    monkeypatch.setattr(active_store, "put_snapshot", _put_snapshot)
    job = _job()
    pipeline._finalize(ScanContext(job=job, lock=threading.Lock(), pipeline=SimpleNamespace(), repo_stack=ExitStack()))

    assert order == ["snapshot"]
    assert active_store.get_meta("tenant-a")["job-1"]["row_count"] == 2


# ── retention ───────────────────────────────────────────────────────────────


@pytest.mark.parametrize("backend", ["memory", "sqlite"])
def test_job_deletion_removes_its_snapshot(active_store, tmp_path: Path, backend: str) -> None:
    job_store = InMemoryJobStore() if backend == "memory" else SQLiteJobStore(str(tmp_path / "jobs.db"))
    for tenant in ("tenant-a", "tenant-b"):
        job_store.put(_job(tenant_id=tenant))
        active_store.put_snapshot(tenant, "job-1", _meta(), [_row()])

    assert job_store.delete("job-1", tenant_id="tenant-a") is True
    assert active_store.get_meta("tenant-a") == {}
    assert set(active_store.get_meta("tenant-b")) == {"job-1"}
    assert job_store.delete("job-1", tenant_id="tenant-a") is False


def test_job_deletion_survives_snapshot_failure(active_store, monkeypatch) -> None:
    monkeypatch.setattr(active_store, "delete_job", lambda *_args: (_ for _ in ()).throw(RuntimeError("unavailable")))
    job_store = InMemoryJobStore()
    job_store.put(_job())

    assert job_store.delete("job-1", tenant_id="tenant-a") is True
    assert job_store.get("job-1", tenant_id="tenant-a") is None


def test_ttl_cleanup_expires_snapshots_with_their_jobs(active_store) -> None:
    calls: list[int] = []
    job_store = SimpleNamespace(cleanup_expired=lambda ttl: calls.append(ttl) or 3)
    active_store.put_snapshot("tenant-a", "old", _meta("2020-01-01T00:00:00+00:00"), [_row()])
    active_store.put_snapshot("tenant-b", "fresh", _meta("2999-01-01T00:00:00+00:00"), [_row()])

    assert expire_jobs_and_snapshots(job_store, 3600) == 3
    assert calls == [3600]
    assert active_store.get_meta("tenant-a") == {}
    assert set(active_store.get_meta("tenant-b")) == {"fresh"}


# ── backfill ────────────────────────────────────────────────────────────────


def test_backfill_materializes_only_the_tenants_done_jobs(active_store) -> None:
    job_store = InMemoryJobStore()
    job_store.put(_job("done-1"))
    job_store.put(_job("done-2", result={"findings": []}))
    job_store.put(_job("failed-1", status=JobStatus.FAILED))
    job_store.put(_job("other-tenant", tenant_id="tenant-b"))

    counts = backfill_tenant_snapshots("tenant-a", job_store)

    assert counts == {"materialized": 2, "skipped": 0, "failed": 0}
    assert set(active_store.get_meta("tenant-a")) == {"done-1", "done-2"}
    assert active_store.get_meta("tenant-a")["done-2"]["row_count"] == 0
    assert active_store.get_meta("tenant-b") == {}


def test_backfill_cli_respects_the_opt_in(monkeypatch, capsys) -> None:
    monkeypatch.setenv("AGENT_BOM_SCAN_SNAPSHOTS", "0")

    assert main(["backfill", "--tenant", "tenant-a"]) == 2
    assert "AGENT_BOM_SCAN_SNAPSHOTS" in capsys.readouterr().err


def test_purge_cli_erases_one_tenant_even_when_disabled(active_store, monkeypatch, capsys) -> None:
    active_store.put_snapshot("tenant-a", "job-1", _meta(), [_row()])
    active_store.put_snapshot("tenant-b", "job-1", _meta(), [_row()])
    monkeypatch.setenv("AGENT_BOM_SCAN_SNAPSHOTS", "0")

    assert main(["purge", "--tenant", "tenant-a"]) == 0
    assert json.loads(capsys.readouterr().out) == {"action": "purge", "removed": 1, "tenant_id": "tenant-a"}
    assert set(active_store.get_meta("tenant-b")) == {"job-1"}
