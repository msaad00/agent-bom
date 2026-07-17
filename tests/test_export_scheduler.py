"""Tests for the scheduled-export store + scheduler wiring (#4040).

Covers connect-once destination persistence (secret write-only), cron-driven
due detection, cross-replica claim (CAS), and the full schedule->stream->land
path with a mocked ClickHouse client and injected destination store.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from typing import Any

from agent_bom.api.export_destination_store import (
    STATUS_ACTIVE,
    ExportDestinationRecord,
    InMemoryExportDestinationStore,
)
from agent_bom.api.export_schedule_store import ExportSchedule, InMemoryExportScheduleStore
from agent_bom.api.export_scheduler import claim_due_schedules, run_due_exports_once


def _now() -> datetime:
    return datetime(2026, 7, 16, 12, 0, tzinfo=timezone.utc)


def _destination(secret_encrypted: str = "enc-token") -> ExportDestinationRecord:
    return ExportDestinationRecord(
        id="dest-1",
        tenant_id="tenant-a",
        kind="clickhouse",
        display_name="Lake",
        config={"url": "http://ch:8123", "database": "agent_bom"},
        secret_encrypted=secret_encrypted,
        created_at="2026-07-16T00:00:00+00:00",
        updated_at="2026-07-16T00:00:00+00:00",
    )


def _schedule(**over: Any) -> ExportSchedule:
    base = dict(
        schedule_id="sched-1",
        name="nightly",
        cron_expression="0 3 * * *",
        destination_id="dest-1",
        tenant_id="tenant-a",
        next_run="2026-07-16T11:00:00+00:00",  # in the past -> due
        created_at="2026-07-16T00:00:00+00:00",
        updated_at="2026-07-16T00:00:00+00:00",
    )
    base.update(over)
    return ExportSchedule(**base)


# --------------------------------------------------------------------------
# Destination store — connect-once secret handling
# --------------------------------------------------------------------------
def test_destination_public_dict_never_leaks_the_secret():
    record = _destination(secret_encrypted="ciphertext")
    public = record.to_public_dict()
    assert "secret_encrypted" not in public
    assert public["has_secret"] is True
    assert public["config"]["url"] == "http://ch:8123"


def test_destination_store_is_tenant_scoped():
    store = InMemoryExportDestinationStore()
    store.put(_destination())
    assert store.get("tenant-a", "dest-1") is not None
    assert store.get("tenant-b", "dest-1") is None  # cross-tenant read blocked
    assert store.delete("tenant-b", "dest-1") is False
    assert store.delete("tenant-a", "dest-1") is True


# --------------------------------------------------------------------------
# Cron-driven due detection + cross-replica claim
# --------------------------------------------------------------------------
def test_claim_due_advances_next_run_and_is_won_once():
    store = InMemoryExportScheduleStore()
    store.put(_schedule())
    due_before = store.list_due(_now().isoformat())
    assert len(due_before) == 1

    won_first = claim_due_schedules(store, _now())
    assert len(won_first) == 1
    # next_run advanced to a future cron slot -> no longer due, and a second
    # replica claiming the same observed state loses.
    assert store.list_due(_now().isoformat()) == []


def test_claim_due_cross_replica_only_one_winner():
    store = InMemoryExportScheduleStore()
    store.put(_schedule())
    observed = store.get("sched-1", "tenant-a")
    assert observed is not None
    # Two replicas observed the same next_run; only the first CAS wins.
    assert store.claim_due(observed, "2026-07-17T03:00:00+00:00") is True
    assert store.claim_due(observed, "2026-07-17T03:00:00+00:00") is False


def test_disabled_schedule_is_not_claimed():
    store = InMemoryExportScheduleStore()
    store.put(_schedule(enabled=False))
    assert claim_due_schedules(store, _now()) == []


# --------------------------------------------------------------------------
# Full schedule -> stream -> land, with mocked ClickHouse + connect-once secret
# --------------------------------------------------------------------------
def test_run_due_exports_streams_to_destination_using_stored_secret(monkeypatch):
    decrypted: list[str] = []
    monkeypatch.setattr(
        "agent_bom.api.connection_crypto.decrypt_secret",
        lambda token: decrypted.append(token) or "plain-token",
    )
    captured: dict[str, Any] = {}

    def fake_run(**kwargs):
        captured.update(kwargs)
        from agent_bom.export.destinations import ExportResult

        return ExportResult(kind="clickhouse", destination_uri="clickhouse://agent_bom/findings_feed", row_count=7)

    monkeypatch.setattr("agent_bom.api.export_scheduler.run_findings_export", fake_run)

    sched_store = InMemoryExportScheduleStore()
    sched_store.put(_schedule())
    dest_store = InMemoryExportDestinationStore()
    dest_store.put(_destination(secret_encrypted="enc-token"))

    count = asyncio.run(run_due_exports_once(sched_store, dest_store, _now()))

    assert count == 1
    # Connect-once: the stored ciphertext was decrypted and the plaintext passed
    # through to the runner — never a per-run credential param.
    assert decrypted == ["enc-token"]
    assert captured["secret"] == "plain-token"
    assert captured["tenant_id"] == "tenant-a"
    assert captured["kind"] == "clickhouse"

    # Schedule run metadata + destination status persisted.
    latest = sched_store.get("sched-1", "tenant-a")
    assert latest is not None
    assert latest.last_run_status == "success"
    assert latest.last_row_count == 7
    assert dest_store.get("tenant-a", "dest-1").status == STATUS_ACTIVE


def test_run_due_exports_missing_destination_marks_error(monkeypatch):
    sched_store = InMemoryExportScheduleStore()
    sched_store.put(_schedule(destination_id="ghost"))
    dest_store = InMemoryExportDestinationStore()

    count = asyncio.run(run_due_exports_once(sched_store, dest_store, _now()))
    assert count == 1
    latest = sched_store.get("sched-1", "tenant-a")
    assert latest is not None and latest.last_run_status == "error"
