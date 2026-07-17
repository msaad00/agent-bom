"""Background scheduler that fires due findings exports (#4040).

Reuses the scan scheduler's cron engine (:func:`parse_cron_next`) to turn stored
:class:`~agent_bom.api.export_schedule_store.ExportSchedule` rows into recurring
deliveries: when a schedule is due, resolve its connect-once destination, stream
the tenant's findings, and land them at the destination on the configured
cadence.

Design mirrors the cloud-connection scheduler:

* **Opt-in, off by default.** The loop only starts when
  ``AGENT_BOM_EXPORT_SCHEDULER`` is truthy (read live), so it never runs in
  CLI/dev.
* **Cluster-safe.** Each due schedule is claimed via an atomic compare-and-swap
  on ``next_run`` (``ExportScheduleStore.claim_due``); exactly one replica fires
  a given due export.
* **Isolated + bounded.** Each export runs in a worker thread (streaming + the
  destination client are blocking) under a semaphore; one failing schedule is
  marked ``error`` and never stops the loop.
"""

from __future__ import annotations

import asyncio
import logging
import os
from datetime import datetime, timedelta, timezone

from agent_bom.api.export_destination_store import (
    ExportDestinationStore,
    get_export_destination_store,
)
from agent_bom.api.export_schedule_store import (
    ExportSchedule,
    ExportScheduleStore,
    get_export_schedule_store,
)
from agent_bom.api.scheduler import parse_cron_next
from agent_bom.export.destinations import ExportPublicationIndeterminateError, ExportResult
from agent_bom.export.runner import run_findings_export

logger = logging.getLogger(__name__)

_MAX_CONCURRENCY = 4
_POLL_SECONDS = 60


def export_scheduler_enabled() -> bool:
    """Return whether the findings-export scheduler loop is enabled (default OFF)."""
    return os.environ.get("AGENT_BOM_EXPORT_SCHEDULER", "").strip().lower() in {"1", "true", "yes", "on", "enabled"}


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _since_cutoff(schedule: ExportSchedule, now: datetime) -> str | None:
    if not schedule.since_days or schedule.since_days <= 0:
        return None
    return (now - timedelta(days=int(schedule.since_days))).isoformat()


def execute_export(
    schedule: ExportSchedule,
    store: ExportScheduleStore,
    destination_store: ExportDestinationStore,
    now: datetime,
) -> bool:
    """Run one due export and persist the outcome. Never raises.

    Resolves the connect-once destination, decrypts its single secret, streams
    the tenant's findings, and updates the schedule's run metadata. Returns
    whether the export succeeded so one bad schedule cannot sink the loop.
    """
    from agent_bom.security import sanitize_error

    record = destination_store.get(schedule.tenant_id, schedule.destination_id)
    now_iso = now.isoformat()
    if record is None:
        logger.warning("Export schedule %s references missing destination %s", schedule.schedule_id, schedule.destination_id)
        _persist_run(store, schedule, now_iso, status="error", row_count=None)
        return False

    try:
        secret = _decrypt_secret(record.secret_encrypted)
        result: ExportResult = run_findings_export(
            tenant_id=schedule.tenant_id,
            kind=record.kind,
            config=record.config,
            secret=secret,
            destination_id=record.id,
            sort=schedule.sort,
            severity=schedule.severity,
            since=_since_cutoff(schedule, now),
        )
    except ExportPublicationIndeterminateError:
        detail = "Publication status is indeterminate; verify the destination marker before retrying"
        logger.warning("Scheduled export publication is indeterminate for schedule %s", schedule.schedule_id)
        _mark_destination(destination_store, record, "indeterminate", detail)
        _persist_run(store, schedule, now_iso, status="indeterminate", row_count=None)
        return False
    except Exception as exc:  # noqa: BLE001 - destination / stream / crypto failure
        logger.warning("Scheduled export failed for schedule %s", schedule.schedule_id)
        _mark_destination(destination_store, record, "error", sanitize_error(exc))
        _persist_run(store, schedule, now_iso, status="error", row_count=None)
        return False

    _mark_destination(destination_store, record, "active", "")
    _persist_run(store, schedule, now_iso, status="success", row_count=result.row_count)
    return True


def _decrypt_secret(secret_encrypted: str) -> str | None:
    if not secret_encrypted:
        return None
    from agent_bom.api.connection_crypto import decrypt_secret

    return decrypt_secret(secret_encrypted)


def _mark_destination(store: ExportDestinationStore, record, status: str, detail: str) -> None:
    record.status = status
    record.status_detail = detail
    record.last_run_at = _now().isoformat()
    record.last_run_status = status
    store.put(record)


def _persist_run(store: ExportScheduleStore, schedule: ExportSchedule, now_iso: str, *, status: str, row_count: int | None) -> None:
    latest = store.get(schedule.schedule_id, schedule.tenant_id)
    if latest is None:
        return
    latest.last_run = now_iso
    latest.last_run_status = status
    latest.last_row_count = row_count
    latest.updated_at = now_iso
    store.put(latest)


def claim_due_schedules(store: ExportScheduleStore, now: datetime) -> list[ExportSchedule]:
    """Select due schedules and atomically claim each by advancing ``next_run``."""
    now_iso = now.isoformat()
    won: list[ExportSchedule] = []
    for schedule in store.list_due(now_iso):
        if not schedule.enabled:
            continue
        next_run = parse_cron_next(schedule.cron_expression, now)
        next_run_iso = next_run.isoformat() if next_run else None
        if store.claim_due(schedule, next_run_iso):
            won.append(schedule)
    return won


async def run_due_exports_once(
    store: ExportScheduleStore,
    destination_store: ExportDestinationStore,
    now: datetime,
    *,
    max_concurrency: int = _MAX_CONCURRENCY,
) -> int:
    """Claim and run every due export once, with bounded concurrency."""
    claimed = claim_due_schedules(store, now)
    if not claimed:
        return 0

    semaphore = asyncio.Semaphore(max(1, max_concurrency))

    async def _guarded(schedule: ExportSchedule) -> None:
        async with semaphore:
            await asyncio.to_thread(execute_export, schedule, store, destination_store, now)

    await asyncio.gather(*(_guarded(schedule) for schedule in claimed))
    return len(claimed)


async def export_scheduler_loop(
    store: ExportScheduleStore | None = None,
    destination_store: ExportDestinationStore | None = None,
    *,
    poll_seconds: int = _POLL_SECONDS,
    max_backoff: int = 900,
) -> None:
    """Background loop that fires due findings exports (API server lifespan)."""
    interval = max(1, poll_seconds)
    consecutive_failures = 0
    while True:
        try:
            sched_store = store or get_export_schedule_store()
            dest_store = destination_store or get_export_destination_store()
            count = await run_due_exports_once(sched_store, dest_store, _now())
            if count:
                logger.info("Export scheduler ran %d due findings export(s)", count)
            consecutive_failures = 0
        except asyncio.CancelledError:
            raise
        except Exception:
            consecutive_failures += 1
            backoff = min(interval * (2**consecutive_failures), max_backoff)
            logger.exception("Export scheduler loop error (attempt %d, next retry in %ds)", consecutive_failures, backoff)
            await asyncio.sleep(backoff)
            continue
        await asyncio.sleep(interval)
