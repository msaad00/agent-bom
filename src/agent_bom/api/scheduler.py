"""Background scheduler for recurring scans.

Runs as an asyncio task during API server lifespan.
Checks for due schedules every 60 seconds, triggers scans.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone

logger = logging.getLogger(__name__)


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
    parts = cron_expr.strip().split()
    if len(parts) != 5:
        return None

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
):
    """Background loop that checks for due schedules and triggers scans.

    Args:
        schedule_store: ScheduleStore instance.
        run_scan_fn: Callable to trigger a scan (receives scan_config dict).
        interval_seconds: Check interval in seconds.
    """
    import asyncio

    while True:
        try:
            now = datetime.now(timezone.utc)
            now_iso = now.isoformat()
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
                    schedule_store.put(schedule)
                except Exception:
                    logger.exception("Failed to trigger scheduled scan: %s", schedule.name)
        except Exception:
            logger.exception("Scheduler loop error")

        await asyncio.sleep(interval_seconds)
