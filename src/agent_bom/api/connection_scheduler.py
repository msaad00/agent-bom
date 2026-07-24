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
* **Continuous event drain.** Each tick, *before* due full scans, connections
  with ``scan_mode=continuous`` and a provider event-queue env configured drain
  a bounded batch via ``consume_*`` (AWS/Azure/GCP). Drains run in parallel under
  the same ``CONNECTIONS_SCHEDULER_MAX_CONCURRENCY`` semaphore (one
  ``asyncio.to_thread`` per connection), with AWS ``WaitTimeSeconds=0`` on the
  scheduler path so empty queues do not stall ticks. That path stamps
  ``last_event_at`` only — full-scan cadence still goes through
  ``claim_due_scan`` / ``last_scan_at``.
* **Cluster-safe.** Multiple control-plane replicas may run this loop. Each due
  connection is claimed via an atomic compare-and-swap on ``last_scan_at``
  (``ConnectionStore.claim_due_scan``): the first replica to advance the stored
  timestamp wins, every racing replica's conditional UPDATE then no-ops. Exactly
  one replica runs a given due scan. Bounded concurrency caps brokered scans.
* **Tenant-bound.** Store *reads* run under ``bypass_tenant_rls()`` because the
  loop polls every tenant's connections, but each per-connection unit of work
  binds ``set_current_tenant(record.tenant_id)`` before touching a write path.
  On Postgres the ``WITH CHECK`` half of each tenant-isolation policy compares
  the written row against ``app.tenant_id``, so an unbound tenant makes every
  scheduled write for a non-``default`` tenant fail closed.
* **Safe.** Read-only scans only. A failing connection is marked ``error`` with
  the same curated, secret-free detail the HTTP scan route persists
  (``_safe_connection_detail``) — the broker's free-form message is never stored,
  because ``status_detail`` is returned verbatim by
  ``GET /v1/cloud/connections``. All four providers (AWS, Azure, GCP, Snowflake)
  are broker-enabled and schedulable.
* **Fail-soft per connection, fail-closed on data.** Every failure mode —
  broker, discovery, event drain, *and* persistence — is contained to the one
  connection it belongs to: the tick completes, other tenants keep scanning, and
  the loop's backoff stays reserved for a genuinely broken control plane. A
  write that cannot be persisted is never retried outside its tenant.
"""

from __future__ import annotations

import asyncio
import logging
import os
from collections.abc import Callable, Coroutine
from datetime import datetime, timedelta, timezone
from typing import Any

from agent_bom.api.connection_store import (
    STATUS_ACTIVE,
    STATUS_ERROR,
    CloudConnectionRecord,
    ConnectionStore,
    get_connection_store,
)

# ``postgres_common`` imports psycopg lazily, so this stays safe on the SQLite
# default deployment where the driver is not installed.
from agent_bom.api.postgres_common import reset_current_tenant, set_current_tenant
from agent_bom.config import (
    CONNECTIONS_SCHEDULER_MAX_CONCURRENCY,
    CONNECTIONS_SCHEDULER_MIN_INTERVAL_MINUTES,
    CONNECTIONS_SCHEDULER_POLL_SECONDS,
)

logger = logging.getLogger(__name__)

# Every supported provider is broker-enabled and therefore schedulable.
_SCHEDULABLE_PROVIDERS: frozenset[str] = frozenset({"aws", "azure", "gcp", "snowflake"})

# Provider → (event_ingest module, consume_* name). Snowflake has no consumer.
_CONTINUOUS_CONSUMERS: dict[str, tuple[str, str]] = {
    "aws": ("agent_bom.cloud.event_ingest", "consume_aws_events"),
    "azure": ("agent_bom.cloud.azure_event_ingest", "consume_azure_events"),
    "gcp": ("agent_bom.cloud.gcp_event_ingest", "consume_gcp_events"),
}


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


def _load_continuous_consumer(
    provider: str,
) -> tuple[Callable[[], bool], Callable[..., dict[str, Any]]] | None:
    """Return ``(event_ingest_enabled, consume_*)`` for *provider*, or None."""
    import importlib

    spec = _CONTINUOUS_CONSUMERS.get((provider or "").strip().lower())
    if spec is None:
        return None
    module_name, consume_name = spec
    module = importlib.import_module(module_name)
    enabled = getattr(module, "event_ingest_enabled", None)
    consume = getattr(module, consume_name, None)
    if not callable(enabled) or not callable(consume):
        return None
    return enabled, consume


def _consume_continuous_events(
    record: CloudConnectionRecord,
    store: ConnectionStore,
    *,
    wait_seconds: int = 0,
) -> None:
    """Run one connection's ``consume_*`` in a worker thread (scheduler path).

    Passes a short ``wait_seconds`` for AWS SQS so empty queues do not stall the
    tick on long-poll. Azure/GCP consumers have no WaitTimeSeconds equivalent.
    Runs with the connection's tenant bound so the consumer's ``last_event_at``
    stamp satisfies the Postgres RLS ``WITH CHECK`` clause. Never raises — one
    bad consume cannot sink the tick.
    """
    loaded = _load_continuous_consumer(record.provider)
    if loaded is None:
        return
    _enabled, consume = loaded
    kwargs: dict[str, Any] = {"tenant_id": record.tenant_id, "store": store}
    if (record.provider or "").strip().lower() == "aws":
        kwargs["wait_seconds"] = max(0, int(wait_seconds))
    token = set_current_tenant(record.tenant_id)
    try:
        consume(record, **kwargs)
    except Exception:  # noqa: BLE001 - one bad consume never sinks the tick
        logger.exception(
            "Continuous event drain failed for connection %s (provider=%s)",
            record.id,
            record.provider,
        )
    finally:
        reset_current_tenant(token)


def _select_continuous_drain_targets(store: ConnectionStore) -> list[CloudConnectionRecord]:
    """Return continuous connections whose provider event ingest is enabled.

    Never raises: a store outage while listing yields no targets so the tick
    falls through to due full scans instead of escalating the loop's backoff.
    """
    try:
        candidates = store.list_continuous()
    except Exception:  # noqa: BLE001 - a store outage never sinks the tick
        logger.exception("Listing continuous cloud connections failed")
        return []

    targets: list[CloudConnectionRecord] = []
    for record in candidates:
        loaded = _load_continuous_consumer(record.provider)
        if loaded is None:
            continue
        enabled, _consume = loaded
        try:
            if not enabled():
                continue
        except Exception:  # noqa: BLE001 - defensive; never sink the tick
            logger.exception(
                "Continuous event-ingest enabled check failed for connection %s",
                record.id,
            )
            continue
        targets.append(record)
    return targets


async def _gather_isolated(
    records: list[CloudConnectionRecord],
    task: Callable[[CloudConnectionRecord], Coroutine[Any, Any, None]],
    *,
    activity: str,
) -> None:
    """Run one *task* per record concurrently, isolating per-task failures.

    ``asyncio.gather`` without ``return_exceptions=True`` cancels the remaining
    tasks and re-raises on the first error, which would let a single connection
    abort the whole tick and drive the loop into escalating backoff for every
    tenant. Collect the results instead and log each failure against its own
    connection.
    """
    results = await asyncio.gather(*(task(record) for record in records), return_exceptions=True)
    for record, result in zip(records, results, strict=True):
        if isinstance(result, asyncio.CancelledError):
            # Shutdown, not a connection failure — let the loop unwind.
            raise result
        if isinstance(result, BaseException):
            logger.error(
                "Connection scheduler %s failed for connection %s (provider=%s)",
                activity,
                record.id,
                record.provider,
                exc_info=result,
            )


async def drain_continuous_events(
    store: ConnectionStore,
    *,
    max_concurrency: int = CONNECTIONS_SCHEDULER_MAX_CONCURRENCY,
    wait_seconds: int = 0,
) -> int:
    """Drain provider event queues for ``scan_mode=continuous`` connections.

    No-op when the scheduler flag is off. Eligible continuous connections drain
    in parallel under a semaphore (one ``asyncio.to_thread(consume_*)`` each),
    bounded by *max_concurrency* (defaults to
    ``CONNECTIONS_SCHEDULER_MAX_CONCURRENCY``). Events update ``last_event_at``
    only inside the consumer — this helper never advances ``last_scan_at``.

    Returns the number of connections for which a consume was attempted.
    """
    if not connections_scheduler_enabled():
        return 0

    targets = _select_continuous_drain_targets(store)
    if not targets:
        return 0

    semaphore = asyncio.Semaphore(max(1, max_concurrency))

    async def _guarded(record: CloudConnectionRecord) -> None:
        async with semaphore:
            await asyncio.to_thread(
                _consume_continuous_events,
                record,
                store,
                wait_seconds=wait_seconds,
            )

    await _gather_isolated(targets, _guarded, activity="continuous event drain")
    return len(targets)


def _persist_scan_outcome(
    record: CloudConnectionRecord,
    *,
    status: str,
    status_detail: str,
    outcome: str,
    last_scan_at: str | None = None,
    scan_id: str | None = None,
) -> bool:
    """Persist one scan attempt's lifecycle transition and audit entry.

    Never raises. A rejected write (database down, or an RLS ``WITH CHECK``
    refusal) is logged and reported as a failed attempt, because the exception
    handler in :func:`execute_connection_scan` is itself a write path — an
    unguarded failure there escapes the "never raises" contract and sinks the
    whole tick.
    """
    # Imported lazily to avoid a route-module import at server startup time.
    from agent_bom.api.audit_log import log_action
    from agent_bom.api.routes.cloud_connections import _mark_connection

    details: dict[str, Any] = {
        "tenant_id": record.tenant_id,
        "provider": record.provider,
        "outcome": outcome,
    }
    if scan_id is not None:
        details["scan_id"] = scan_id
    try:
        _mark_connection(
            record,
            status=status,
            status_detail=status_detail,
            last_scan_at=last_scan_at,
        )
        log_action(
            "cloud_connection.scheduled_scan",
            actor="scheduler",
            resource=f"cloud-connection/{record.id}",
            **details,
        )
    except Exception:  # noqa: BLE001 - persistence failure never sinks the tick
        logger.exception("Persisting the scheduled scan outcome failed for connection %s", record.id)
        return False
    return outcome == "success"


def execute_connection_scan(record: CloudConnectionRecord) -> bool:
    """Run the broker scan for a claimed connection and persist the outcome.

    Reuses the provider-dispatching scan-launch path (``_run_connection_scan``)
    and the lifecycle mutator (``_mark_connection``). On success the connection
    moves to ``active`` + a fresh ``last_scan_at``; on failure it is marked
    ``error`` with the same curated detail the HTTP scan route persists.

    The connection's tenant is bound for the whole unit of work — the loop runs
    outside any HTTP request, so nothing else populates the tenant contextvar
    and the scan's writes would otherwise be checked against ``default``. The
    reset lives in a ``finally`` so a raising scan cannot carry one tenant into
    the next connection's work.

    Never raises — returns whether the scan ran *and* was recorded, so one bad
    connection cannot sink the loop.
    """
    from agent_bom.api.routes.cloud_connections import (
        _now,
        _run_connection_scan,
        _safe_connection_detail,
    )

    token = set_current_tenant(record.tenant_id)
    try:
        try:
            summary = _run_connection_scan(record, record.tenant_id)
        except Exception as exc:  # noqa: BLE001 - broker / discovery / persistence failure
            logger.exception("Scheduled cloud connection scan failed for connection %s", record.id)
            _persist_scan_outcome(
                record,
                status=STATUS_ERROR,
                # ``status_detail`` is returned verbatim by
                # ``GET /v1/cloud/connections``, so it follows the HTTP scan
                # route's policy: only curated remediation text, never the
                # broker's free-form message (which can carry an ARN, an
                # account id, or the ExternalId).
                status_detail=_safe_connection_detail(exc),
                outcome="failure",
            )
            return False
        return _persist_scan_outcome(
            record,
            status=STATUS_ACTIVE,
            status_detail="",
            last_scan_at=_now(),
            outcome="success",
            scan_id=summary.get("scan_id"),
        )
    except Exception:  # noqa: BLE001 - contract: this function never raises
        logger.exception(
            "Scheduled cloud connection scan bookkeeping failed for connection %s",
            record.id,
        )
        return False
    finally:
        reset_current_tenant(token)


async def run_due_scans_once(
    store: ConnectionStore,
    now: datetime,
    *,
    max_concurrency: int = CONNECTIONS_SCHEDULER_MAX_CONCURRENCY,
) -> int:
    """Claim and run every due connection scan once, with bounded concurrency.

    Drains continuous event queues first (when the scheduler is enabled and a
    provider queue env is set), then claims due full scans. Returns the number
    of connections this replica claimed and attempted for full scans. Each
    brokered scan runs in a worker thread (boto3 is blocking) under a semaphore
    so at most *max_concurrency* scans run at a time.
    """
    # Event drain before full scans so mid-interval posture updates land first.
    # Short wait (0) so empty SQS queues do not stall the tick on long-poll.
    await drain_continuous_events(store, max_concurrency=max_concurrency, wait_seconds=0)

    claimed = claim_due_connections(store, now)
    if not claimed:
        return 0

    semaphore = asyncio.Semaphore(max(1, max_concurrency))

    async def _guarded(record: CloudConnectionRecord) -> None:
        async with semaphore:
            await asyncio.to_thread(execute_connection_scan, record)

    await _gather_isolated(claimed, _guarded, activity="scheduled scan")
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
