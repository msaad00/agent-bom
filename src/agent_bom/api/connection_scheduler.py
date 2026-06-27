"""Background scheduler that re-scans due cloud connections (Phase B.2).

Phase B added an on-demand ``POST /v1/cloud/connections/{id}/scan`` path that
brokers a stored connection into a short-lived read-only role and runs the same
inventory + CIS discovery the sibling cloud routes use. This module turns that
into "connect once, keeps evaluating": a control-plane background loop that
periodically finds connections carrying a ``scan_interval_minutes`` and re-runs
the **same** broker scan path when one is due.

Design notes:

* **Opt-in, off by default.** The loop only starts when
  ``AGENT_BOM_CONNECTIONS_SCHEDULER`` is truthy (read live), so it never runs in
  CLI/dev. A connection is only eligible when it carries an interval; the field
  is null (manual-only) by default.
* **Cluster-safe.** Multiple control-plane replicas may run this loop. Each due
  connection is claimed via an atomic compare-and-swap on ``last_scan_at``
  (``ConnectionStore.claim_due_scan``): the first replica to advance the stored
  timestamp wins, every racing replica's conditional UPDATE then no-ops. Exactly
  one replica runs a given due scan. Bounded concurrency caps brokered scans.
* **Safe.** Read-only scans only. A failing connection is marked ``error`` with a
  sanitized, secret-free detail and the loop continues — one bad connection never
  stops the loop. All four providers (AWS, Azure, GCP, Snowflake) are
  broker-enabled and schedulable.
"""

from __future__ import annotations

import asyncio
import logging
import os
from datetime import datetime, timedelta, timezone

from agent_bom.api.connection_store import (
    STATUS_ACTIVE,
    STATUS_ERROR,
    CloudConnectionRecord,
    ConnectionStore,
    get_connection_store,
)
from agent_bom.config import (
    CONNECTIONS_SCHEDULER_MAX_CONCURRENCY,
    CONNECTIONS_SCHEDULER_MIN_INTERVAL_MINUTES,
    CONNECTIONS_SCHEDULER_POLL_SECONDS,
)

logger = logging.getLogger(__name__)

# Every supported provider is broker-enabled and therefore schedulable.
_SCHEDULABLE_PROVIDERS: frozenset[str] = frozenset({"aws", "azure", "gcp", "snowflake"})


def connections_scheduler_enabled() -> bool:
    """Return whether the cloud-connection scan scheduler loop is enabled.

    Read live (not import-time) so tests and operators can toggle it. Default OFF
    so the loop never runs in CLI/dev — only when an operator opts in on the
    control plane.
    """
    raw = os.environ.get("AGENT_BOM_CONNECTIONS_SCHEDULER", "")
    return raw.strip().lower() in {"1", "true", "yes", "on", "enabled"}


def _parse_iso(value: str | None) -> datetime | None:
    """Parse a stored ISO timestamp into an aware UTC datetime (tolerant)."""
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _effective_interval_minutes(record: CloudConnectionRecord) -> int | None:
    """Effective interval, clamped to the configured minimum (defensive floor)."""
    if record.scan_interval_minutes is None:
        return None
    return max(int(record.scan_interval_minutes), CONNECTIONS_SCHEDULER_MIN_INTERVAL_MINUTES)


def is_due(record: CloudConnectionRecord, now: datetime) -> bool:
    """Return whether a connection's recurring scan is due at *now*.

    Due when an interval is set and either the connection has never scanned or
    at least the (clamped) interval has elapsed since ``last_scan_at``.
    """
    interval = _effective_interval_minutes(record)
    if interval is None:
        return False
    last = _parse_iso(record.last_scan_at)
    if last is None:
        return True
    return now - last >= timedelta(minutes=interval)


def select_due_connections(store: ConnectionStore, now: datetime) -> list[CloudConnectionRecord]:
    """Return schedulable connections whose recurring scan is due at *now*."""
    return [record for record in store.list_schedulable() if is_due(record, now)]


def claim_due_connections(store: ConnectionStore, now: datetime) -> list[CloudConnectionRecord]:
    """Select due connections and atomically claim each for this replica.

    Returns only the connections this replica won. A provider with no broker is
    skipped and never claimed (defensive — all supported providers are
    broker-enabled). The claim advances ``last_scan_at`` to *now* so a racing
    replica loses the compare-and-swap and a failed scan is not retried until the
    next interval.
    """
    claimed_at = now.isoformat()
    won: list[CloudConnectionRecord] = []
    for record in select_due_connections(store, now):
        if record.provider not in _SCHEDULABLE_PROVIDERS:
            continue
        if store.claim_due_scan(record, claimed_at):
            won.append(record)
    return won


def execute_connection_scan(record: CloudConnectionRecord) -> bool:
    """Run the broker scan for a claimed connection and persist the outcome.

    Reuses the provider-dispatching scan-launch path (``_run_connection_scan``)
    and the lifecycle mutator (``_mark_connection``). On success the connection
    moves to ``active`` + a fresh ``last_scan_at``; on failure it is marked
    ``error`` with a sanitized, secret-free detail. Never raises — returns
    whether the scan succeeded so one bad connection cannot sink the loop.
    """
    # Imported lazily to avoid a route-module import at server startup time.
    from agent_bom.api.audit_log import log_action
    from agent_bom.api.routes.cloud_connections import (
        _mark_connection,
        _now,
        _run_connection_scan,
    )
    from agent_bom.security import sanitize_error

    try:
        summary = _run_connection_scan(record, record.tenant_id)
    except Exception as exc:  # noqa: BLE001 - broker / discovery / persistence failure
        detail = sanitize_error(exc)
        _mark_connection(record, status=STATUS_ERROR, status_detail=detail)
        logger.exception("Scheduled cloud connection scan failed for connection %s", record.id)
        log_action(
            "cloud_connection.scheduled_scan",
            actor="scheduler",
            resource=f"cloud-connection/{record.id}",
            tenant_id=record.tenant_id,
            provider=record.provider,
            outcome="failure",
        )
        return False

    _mark_connection(record, status=STATUS_ACTIVE, status_detail="", last_scan_at=_now())
    log_action(
        "cloud_connection.scheduled_scan",
        actor="scheduler",
        resource=f"cloud-connection/{record.id}",
        tenant_id=record.tenant_id,
        provider=record.provider,
        outcome="success",
        scan_id=summary.get("scan_id"),
    )
    return True


async def run_due_scans_once(
    store: ConnectionStore,
    now: datetime,
    *,
    max_concurrency: int = CONNECTIONS_SCHEDULER_MAX_CONCURRENCY,
) -> int:
    """Claim and run every due connection scan once, with bounded concurrency.

    Returns the number of connections this replica claimed and attempted. Each
    brokered scan runs in a worker thread (boto3 is blocking) under a semaphore
    so at most *max_concurrency* scans run at a time.
    """
    claimed = claim_due_connections(store, now)
    if not claimed:
        return 0

    semaphore = asyncio.Semaphore(max(1, max_concurrency))

    async def _guarded(record: CloudConnectionRecord) -> None:
        async with semaphore:
            await asyncio.to_thread(execute_connection_scan, record)

    await asyncio.gather(*(_guarded(record) for record in claimed))
    return len(claimed)


async def connection_scheduler_loop(
    store: ConnectionStore | None = None,
    *,
    poll_seconds: int = CONNECTIONS_SCHEDULER_POLL_SECONDS,
    max_backoff: int = 900,
) -> None:
    """Background loop that re-scans due cloud connections.

    Runs as an asyncio task during API server lifespan. Uses exponential backoff
    on consecutive failures (up to *max_backoff* seconds) so a broken store does
    not get hammered. A failure scanning one connection is isolated inside
    :func:`execute_connection_scan` and never breaks the loop.
    """
    interval = max(1, poll_seconds)
    consecutive_failures = 0
    while True:
        try:
            active_store = store or get_connection_store()
            now = datetime.now(timezone.utc)
            count = await run_due_scans_once(active_store, now)
            if count:
                logger.info("Connection scheduler ran %d due cloud-connection scan(s)", count)
            consecutive_failures = 0
        except asyncio.CancelledError:
            raise
        except Exception:
            consecutive_failures += 1
            backoff = min(interval * (2**consecutive_failures), max_backoff)
            logger.exception(
                "Connection scheduler loop error (attempt %d, next retry in %ds)",
                consecutive_failures,
                backoff,
            )
            await asyncio.sleep(backoff)
            continue
        await asyncio.sleep(interval)
