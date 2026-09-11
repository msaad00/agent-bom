"""Bounded export executor with durable claims, heartbeats and restart recovery."""

from __future__ import annotations

import asyncio
import logging
import os
import threading
from concurrent.futures import Future, ThreadPoolExecutor

from agent_bom.api.report_job_store import ReportClaim, ReportJobStore
from agent_bom.api.tenant_worker import run_tenant_bound, submit_tenant_bound
from agent_bom.config import API_REPORT_LEASE_SECONDS, API_REPORT_MAX_ATTEMPTS, API_REPORT_WORKERS

_logger = logging.getLogger(__name__)


class ReportWorker:
    def __init__(self, store: ReportJobStore, *, max_workers: int = 2, lease_seconds: int = 60, max_attempts: int = 3) -> None:
        if not 0 <= max_workers <= 64 or not 10 <= lease_seconds <= 86400 or not 1 <= max_attempts <= 100:
            raise ValueError("Report workers must be 0-64, lease seconds 10-86400, and max attempts 1-100")
        self.store = store
        self.capacity = max(0, max_workers)
        self.lease = max(10, lease_seconds)
        self.max_attempts = max(1, max_attempts)
        self._executor = ThreadPoolExecutor(max_workers=max(1, self.capacity), thread_name_prefix="report-export")
        self._inflight: dict[Future, tuple[ReportClaim, threading.Event]] = {}
        self._stopping = False
        self._wake = asyncio.Event()
        self._task: asyncio.Task | None = None
        self._loop: asyncio.AbstractEventLoop | None = None

    async def start(self) -> None:
        self._loop = asyncio.get_running_loop()
        self._task = asyncio.create_task(self._run(), name="report-export-claims")

    def wake(self) -> None:
        if self._loop is not None and not self._loop.is_closed():
            self._loop.call_soon_threadsafe(self._wake.set)

    async def _run(self) -> None:
        while not self._stopping:
            self._wake.clear()
            try:
                await asyncio.to_thread(self.tick)
            except Exception:  # noqa: BLE001
                # Durable state remains authoritative; never fall back to local execution.
                _logger.error("Report dispatch unavailable; queued jobs remain durable", exc_info=False)
            try:
                await asyncio.wait_for(self._wake.wait(), timeout=min(1.0, self.lease / 3))
            except asyncio.TimeoutError:
                pass

    def tick(self) -> None:
        from agent_bom.api.report_worker import run_claimed_report

        for future, (claim, lost) in list(self._inflight.items()):
            if future.done():
                try:
                    future.result()
                except Exception:  # noqa: BLE001
                    _logger.error("Report worker interrupted; claim will expire", exc_info=False)
                del self._inflight[future]
                continue
            try:
                owned = run_tenant_bound(claim.tenant_id, self.store.renew, claim, self.lease)
            except Exception:  # noqa: BLE001
                owned = False
            if not owned:
                if not lost.is_set():
                    from agent_bom.api.metrics import record_report_export

                    record_report_export("lease_lost")
                lost.set()
        while not self._stopping and len(self._inflight) < self.capacity:
            next_claim = self.store.claim_next(self.lease, self.max_attempts)
            if next_claim is None:
                break
            from agent_bom.api.metrics import record_report_export

            record_report_export("claimed")
            claim = next_claim
            lost = threading.Event()
            future = submit_tenant_bound(self._executor, claim.tenant_id, run_claimed_report, self.store, claim, lost)
            self._inflight[future] = (claim, lost)

    async def stop(self, drain_seconds: float = 25) -> None:
        self._stopping = True
        self.wake()
        if self._task:
            await self._task
        deadline = asyncio.get_running_loop().time() + max(0, drain_seconds)
        while self._inflight and asyncio.get_running_loop().time() < deadline:
            await asyncio.to_thread(self.tick)  # renew active owners while draining
            if self._inflight:
                await asyncio.sleep(0.1)
        for _claim, lost in self._inflight.values():
            lost.set()
        self._executor.shutdown(wait=False, cancel_futures=True)


_worker: ReportWorker | None = None


async def start_report_worker() -> ReportWorker:
    from agent_bom.api.report_job_store import get_report_job_store

    global _worker
    # Startup errors are fatal: a configured database must not degrade to memory.
    _worker = ReportWorker(
        get_report_job_store(),
        max_workers=int(os.environ.get("AGENT_BOM_API_REPORT_WORKERS", str(API_REPORT_WORKERS))),
        lease_seconds=int(os.environ.get("AGENT_BOM_API_REPORT_LEASE_SECONDS", str(API_REPORT_LEASE_SECONDS))),
        max_attempts=int(os.environ.get("AGENT_BOM_API_REPORT_MAX_ATTEMPTS", str(API_REPORT_MAX_ATTEMPTS))),
    )
    await _worker.start()
    return _worker


def wake_report_worker() -> None:
    if _worker:
        _worker.wake()
