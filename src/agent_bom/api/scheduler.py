"""Background scheduler for recurring scans.

Runs as an asyncio task during API server lifespan.
Checks for due schedules every 60 seconds, triggers scans.
"""

from __future__ import annotations

import logging
import os
from datetime import datetime, timedelta, timezone

logger = logging.getLogger(__name__)
_SCHEDULER_LEADER_LOCK_ID = 4_197_042_001


def _uses_postgres_schedule_store(schedule_store) -> bool:
    """Return whether schedules are backed by the clustered Postgres store."""
    return type(schedule_store).__name__ == "PostgresScheduleStore"


def validate_cron_expression(cron_expr: str) -> bool:
    """Return True when a cron expression is in the scheduler's supported subset."""
    parts = cron_expr.strip().split()
    if len(parts) != 5:
        return False

    ranges = ((0, 59), (0, 23), (1, 31), (1, 12), (0, 7))
    for spec, (min_val, max_val) in zip(parts, ranges, strict=True):
        if _expand_cron_field(spec, min_val, max_val) is None:
            return False
    return True


def _expand_cron_field(spec: str, min_val: int, max_val: int) -> set[int] | None:
    """Expand one cron field into allowed values.

    Supports standard five-field cron atoms: ``*``, ``*/N``, ``N``,
    ``A-B``, ``A-B/N``, and comma-separated lists of those atoms.
    """
    values: set[int] = set()
    for raw_token in spec.split(","):
        token = raw_token.strip()
        if not token:
            return None
        step = 1
        base = token
        if "/" in token:
            base, step_raw = token.split("/", 1)
            try:
                step = int(step_raw)
            except ValueError:
                return None
            if step <= 0:
                return None
        if base == "*":
            start, end = min_val, max_val
        elif "-" in base:
            start_raw, end_raw = base.split("-", 1)
            try:
                start, end = int(start_raw), int(end_raw)
            except ValueError:
                return None
            if start > end:
                return None
        else:
            try:
                start = end = int(base)
            except ValueError:
                return None
        if start < min_val or end > max_val:
            return None
        values.update(range(start, end + 1, step))
    return values


def parse_cron_next(cron_expr: str, after: datetime) -> datetime | None:
    """Calculate next run time from a standard five-field cron expression.

    Supports::

        minute hour day_of_month month day_of_week

    Field values may be wildcards, steps, fixed values, ranges, and lists.
    Returns None if the expression cannot be parsed or no next occurrence is
    found inside the one-year guard window.
    """
    parts = cron_expr.strip().split()
    if len(parts) != 5:
        return None
    ranges = ((0, 59), (0, 23), (1, 31), (1, 12), (0, 7))
    expanded = [_expand_cron_field(spec, min_val, max_val) for spec, (min_val, max_val) in zip(parts, ranges, strict=True)]
    if any(values is None for values in expanded):
        return None
    minutes, hours, days_of_month, months, days_of_week = [values or set() for values in expanded]
    days_of_week = {0 if value == 7 else value for value in days_of_week}

    candidate = after.replace(second=0, microsecond=0) + timedelta(minutes=1)
    for _ in range(366 * 24 * 60):
        cron_dow = (candidate.weekday() + 1) % 7
        if (
            candidate.minute in minutes
            and candidate.hour in hours
            and candidate.day in days_of_month
            and candidate.month in months
            and cron_dow in days_of_week
        ):
            return candidate
        candidate += timedelta(minutes=1)
    return None


async def scheduler_loop(
    schedule_store,
    run_scan_fn,
    interval_seconds: int = 60,
    max_backoff: int = 900,
):
    """Background loop that checks for due schedules and triggers scans.

    Uses exponential backoff on consecutive failures (up to *max_backoff*
    seconds) to avoid hammering a broken store.

    Args:
        schedule_store: ScheduleStore instance.
        run_scan_fn: Callable to trigger a scan. Receives scan_config plus
            schedule_id and tenant_id keyword metadata so persisted jobs can
            link back to the schedule that created them.
        interval_seconds: Check interval in seconds.
        max_backoff: Maximum backoff delay in seconds (default 15 min).
    """
    import asyncio

    consecutive_failures = 0
    leader_conn = None
    uses_postgres_store = _uses_postgres_schedule_store(schedule_store)
    needs_leader_lock = bool(os.environ.get("AGENT_BOM_POSTGRES_URL")) and uses_postgres_store

    def _try_acquire_postgres_leader_lock():
        if not needs_leader_lock:
            return None
        try:
            from agent_bom.api.postgres_store import _get_pool

            pool = _get_pool()
            conn = pool.getconn()
            row = conn.execute("SELECT pg_try_advisory_lock(%s)", (_SCHEDULER_LEADER_LOCK_ID,)).fetchone()
            if row and bool(row[0]):
                logger.info("Scheduler leader lock acquired")
                return conn
            pool.putconn(conn)
        except Exception:
            logger.exception("Failed to acquire scheduler leader lock")
        return None

    try:
        while True:
            try:
                if needs_leader_lock and leader_conn is None:
                    leader_conn = _try_acquire_postgres_leader_lock()
                    if leader_conn is None:
                        await asyncio.sleep(interval_seconds)
                        continue

                now = datetime.now(timezone.utc)
                now_iso = now.isoformat()
                if not uses_postgres_store:
                    due = schedule_store.list_due(now_iso)
                else:
                    from agent_bom.api.postgres_store import bypass_tenant_rls

                    with bypass_tenant_rls():
                        due = schedule_store.list_due(now_iso)

                for schedule in due:
                    if not schedule.enabled:
                        continue
                    logger.info("Triggering scheduled scan: %s (%s)", schedule.name, schedule.schedule_id)
                    try:
                        job_id = run_scan_fn(
                            schedule.scan_config,
                            schedule_id=schedule.schedule_id,
                            tenant_id=schedule.tenant_id,
                        )
                        schedule.last_run = now_iso
                        schedule.last_job_id = job_id

                        # Compute next run
                        next_run = parse_cron_next(schedule.cron_expression, now)
                        schedule.next_run = next_run.isoformat() if next_run else None
                        schedule.updated_at = now_iso
                        if not uses_postgres_store:
                            schedule_store.put(schedule)
                        else:
                            from agent_bom.api.postgres_store import bypass_tenant_rls

                            with bypass_tenant_rls():
                                schedule_store.put(schedule)
                    except Exception:
                        logger.exception("Failed to trigger scheduled scan: %s", schedule.name)

                # Success — reset backoff counter
                consecutive_failures = 0
            except Exception:
                consecutive_failures += 1
                backoff = min(interval_seconds * (2**consecutive_failures), max_backoff)
                logger.exception(
                    "Scheduler loop error (attempt %d, next retry in %ds)",
                    consecutive_failures,
                    backoff,
                )
                await asyncio.sleep(backoff)
                continue

            await asyncio.sleep(interval_seconds)
    finally:
        if leader_conn is not None:
            try:
                from agent_bom.api.postgres_store import _get_pool

                leader_conn.execute("SELECT pg_advisory_unlock(%s)", (_SCHEDULER_LEADER_LOCK_ID,))
                _get_pool().putconn(leader_conn)
            except Exception:
                logger.exception("Failed to release scheduler leader lock")
