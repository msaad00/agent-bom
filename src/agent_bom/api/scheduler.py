"""Background scheduler for recurring scans.

Runs as an asyncio task during API server lifespan.
Checks for due schedules every 60 seconds, triggers scans.
"""

from __future__ import annotations

import logging
import os
from datetime import datetime, timezone

logger = logging.getLogger(__name__)
_SCHEDULER_LEADER_LOCK_ID = 4_197_042_001


def validate_cron_expression(cron_expr: str) -> bool:
    """Return True when a cron expression is in the scheduler's supported subset."""
    parts = cron_expr.strip().split()
    if len(parts) != 5:
        return False

    ranges = ((0, 59), (0, 23), (1, 31), (1, 12), (0, 7))
    for spec, (min_val, max_val) in zip(parts, ranges, strict=True):
        if spec == "*":
            continue
        if spec.startswith("*/"):
            try:
                step = int(spec[2:])
            except ValueError:
                return False
            if step <= 0 or step > max_val:
                return False
            continue
        try:
            value = int(spec)
        except ValueError:
            return False
        if value < min_val or value > max_val:
            return False
    return True


def parse_cron_next(cron_expr: str, after: datetime) -> datetime | None:
    """Calculate next run time from a basic cron expression.

    Supports a subset of standard cron::

        minute hour day_of_month month day_of_week
        *      */6  *            *     *

    Supported field values:
    - ``*`` — every value
    - ``*/N`` — every N-th value
    - ``N``  — fixed value

    Returns None if the expression cannot be parsed.
    """
    if not validate_cron_expression(cron_expr):
        return None
    parts = cron_expr.strip().split()

    try:
        minute_spec, hour_spec, dom_spec, month_spec, dow_spec = parts

        def _next_match(spec: str, current: int, max_val: int) -> int | None:
            """Find the next matching value >= current, or None if wrapped."""
            if spec == "*":
                return current
            if spec.startswith("*/"):
                step = int(spec[2:])
                if step <= 0:
                    return None
                # Next value that is a multiple of step and >= current
                remainder = current % step
                return current if remainder == 0 else current + (step - remainder)
            # Fixed value
            val = int(spec)
            return val if val >= current else None

        # Start from the minute after 'after'
        candidate = after.replace(second=0, microsecond=0)

        # Try up to 1440 minutes (24 hours) to find next match
        for _ in range(1440):
            m = candidate.minute
            h = candidate.hour

            m_match = _next_match(minute_spec, m, 59)
            h_match = _next_match(hour_spec, h, 23)

            if m_match is not None and m_match <= 59 and h_match is not None and h_match <= 23:
                result = candidate.replace(minute=m_match, hour=h_match)
                if result > after:
                    return result

            # Advance by 1 minute
            from datetime import timedelta

            candidate += timedelta(minutes=1)

        return None
    except (ValueError, IndexError):
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
        run_scan_fn: Callable to trigger a scan (receives scan_config dict).
        interval_seconds: Check interval in seconds.
        max_backoff: Maximum backoff delay in seconds (default 15 min).
    """
    import asyncio

    consecutive_failures = 0
    leader_conn = None

    def _try_acquire_postgres_leader_lock():
        if not os.environ.get("AGENT_BOM_POSTGRES_URL"):
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
                if os.environ.get("AGENT_BOM_POSTGRES_URL") and leader_conn is None:
                    leader_conn = _try_acquire_postgres_leader_lock()
                    if leader_conn is None:
                        await asyncio.sleep(interval_seconds)
                        continue

                now = datetime.now(timezone.utc)
                now_iso = now.isoformat()
                try:
                    from agent_bom.api.postgres_store import bypass_tenant_rls
                except Exception:  # pragma: no cover - optional postgres backend
                    due = schedule_store.list_due(now_iso)
                else:
                    with bypass_tenant_rls():
                        due = schedule_store.list_due(now_iso)

                for schedule in due:
                    if not schedule.enabled:
                        continue
                    logger.info("Triggering scheduled scan: %s (%s)", schedule.name, schedule.schedule_id)
                    try:
                        job_id = run_scan_fn(schedule.scan_config)
                        schedule.last_run = now_iso
                        schedule.last_job_id = job_id

                        # Compute next run
                        next_run = parse_cron_next(schedule.cron_expression, now)
                        schedule.next_run = next_run.isoformat() if next_run else None
                        schedule.updated_at = now_iso
                        try:
                            from agent_bom.api.postgres_store import bypass_tenant_rls
                        except Exception:  # pragma: no cover - optional postgres backend
                            schedule_store.put(schedule)
                        else:
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
