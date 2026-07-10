"""Distributed scan dispatch — multi-replica work-stealing for scan jobs.

In a single-node deployment a scan runs on the node that received the request
(``submit_scan_job``). In a clustered control plane that pins scan throughput to
whichever replica got the HTTP call: an idle replica cannot help a busy one.

``DistributedScanWorker`` closes that gap. When enabled, scan jobs are enqueued
to a shared Postgres dispatch queue (``PostgresJobStore.enqueue_for_dispatch``)
and every replica runs a claim-loop that pulls the oldest claimable job via
``FOR UPDATE SKIP LOCKED`` and runs it on its own local worker pool. A job
submitted to a saturated node is therefore picked up by an idle one, and a job
whose owning node dies (lease expires) is reclaimed by another. Scan throughput
scales with replica count.

The queue holds only routing metadata; the scan payload and results stay in the
RLS-protected ``scan_jobs`` table and are loaded under the job's own tenant.
"""

from __future__ import annotations

import asyncio
import logging
import os
import uuid
from typing import Any

from agent_bom.config import (
    API_SCAN_CLAIM_POLL_SECONDS,
    API_SCAN_LEASE_SECONDS,
    API_SCAN_WORKERS,
)

_logger = logging.getLogger(__name__)


def _truthy(value: str) -> bool:
    return value.strip().lower() in {"1", "true", "on", "yes", "enabled"}


def _falsy(value: str) -> bool:
    return value.strip().lower() in {"0", "false", "off", "no", "disabled"}


def distributed_scans_enabled() -> bool:
    """Whether scan jobs should be dispatched through the shared queue.

    Explicit ``AGENT_BOM_DISTRIBUTED_SCANS`` wins (on/off). Otherwise it defaults
    on exactly when the control plane is clustered (shared rate limit required or
    replicas > 1) and Postgres is configured — the same gate that makes other
    process-local control-plane state unsafe.
    """
    raw = os.environ.get("AGENT_BOM_DISTRIBUTED_SCANS", "")
    if raw and _falsy(raw):
        return False
    if not os.environ.get("AGENT_BOM_POSTGRES_URL", "").strip():
        return False
    if raw and _truthy(raw):
        return True
    try:
        from agent_bom.api.middleware import clustered_control_plane_required

        return clustered_control_plane_required()
    except Exception:  # noqa: BLE001
        return False


def store_supports_dispatch(store: object) -> bool:
    """True when the active job store exposes the dispatch-queue API."""
    return all(
        callable(getattr(store, name, None))
        for name in ("enqueue_for_dispatch", "claim_next", "renew_leases", "complete_dispatch", "requeue_expired_leases")
    )


class DistributedScanWorker:
    """Per-replica claim-loop that runs queued scan jobs on the local pool."""

    def __init__(
        self,
        store: Any,
        *,
        worker_id: str | None = None,
        lease_seconds: int = API_SCAN_LEASE_SECONDS,
        poll_seconds: int = API_SCAN_CLAIM_POLL_SECONDS,
        max_concurrent: int = API_SCAN_WORKERS,
    ) -> None:
        self._store = store
        self._worker_id = worker_id or f"{os.uname().nodename}:{os.getpid()}:{uuid.uuid4().hex[:8]}"
        self._lease = max(30, int(lease_seconds))
        self._poll = max(1, int(poll_seconds))
        self._max = max(1, int(max_concurrent))
        self._inflight: set[str] = set()
        self._stop = asyncio.Event()
        self._task: asyncio.Task | None = None

    @property
    def worker_id(self) -> str:
        return self._worker_id

    async def start(self) -> None:
        if self._task is None:
            self._stop.clear()
            self._task = asyncio.create_task(self._run(), name="distributed-scan-worker")
            _logger.info("Distributed scan worker started id=%s lease=%ss poll=%ss", self._worker_id, self._lease, self._poll)

    async def stop(self) -> None:
        self._stop.set()
        if self._task is not None:
            try:
                await asyncio.wait_for(self._task, timeout=self._poll + 5)
            except (asyncio.TimeoutError, asyncio.CancelledError):
                self._task.cancel()
            self._task = None

    async def _run(self) -> None:
        while not self._stop.is_set():
            try:
                await asyncio.to_thread(self._tick)
            except Exception:  # noqa: BLE001
                _logger.exception("Distributed scan worker tick failed id=%s", self._worker_id)
            try:
                await asyncio.wait_for(self._stop.wait(), timeout=self._poll)
            except asyncio.TimeoutError:
                pass

    def _tick(self) -> None:
        # Heartbeat in-flight leases first so a slow scan is never reclaimed by a
        # peer while this node is still actively running it.
        if self._inflight:
            self._store.renew_leases(list(self._inflight), self._lease)
        # Reclaim jobs orphaned by dead replicas (lease expired, status running).
        reclaimed = self._store.requeue_expired_leases()
        if reclaimed:
            _logger.info("Distributed scan worker reclaimed %d orphaned job(s)", reclaimed)
        # Claim up to local free capacity.
        from agent_bom.api.pipeline import submit_claimed_scan_job

        while len(self._inflight) < self._max and not self._stop.is_set():
            job = self._store.claim_next(self._worker_id, self._lease)
            if job is None:
                break
            self._inflight.add(job.job_id)
            _logger.info("Claimed scan job=%s tenant=%s worker=%s", job.job_id, job.tenant_id, self._worker_id)
            try:
                submit_claimed_scan_job(job, self._on_complete)
            except Exception:  # noqa: BLE001
                # Could not hand off locally (e.g. executor draining): drop the
                # claim so another tick/replica can reclaim it after lease expiry.
                self._inflight.discard(job.job_id)
                _logger.exception("Failed to submit claimed job=%s; will be reclaimed", job.job_id)
                break

    def _on_complete(self, job_id: str) -> None:
        self._inflight.discard(job_id)
        try:
            self._store.complete_dispatch(job_id)
        except Exception:  # noqa: BLE001
            _logger.exception("Failed to clear dispatch row job=%s", job_id)
