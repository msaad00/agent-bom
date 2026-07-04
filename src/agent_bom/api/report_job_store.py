"""In-memory persistence for async report export jobs."""

from __future__ import annotations

import threading
from typing import Protocol

from agent_bom.api.models import ReportJob


class ReportJobStore(Protocol):
    def put(self, job: ReportJob) -> None: ...
    def get(self, job_id: str, tenant_id: str) -> ReportJob | None: ...
    def update(self, job: ReportJob) -> None: ...


class InMemoryReportJobStore:
    """Thread-safe report job store for single-replica pilots."""

    def __init__(self) -> None:
        self._jobs: dict[str, ReportJob] = {}
        self._lock = threading.Lock()

    def put(self, job: ReportJob) -> None:
        with self._lock:
            self._jobs[job.job_id] = job

    def get(self, job_id: str, tenant_id: str) -> ReportJob | None:
        with self._lock:
            job = self._jobs.get(job_id)
            if job is None or job.tenant_id != tenant_id:
                return None
            return job.model_copy(deep=True)

    def update(self, job: ReportJob) -> None:
        self.put(job)

    def list_for_tenant(self, tenant_id: str) -> list[ReportJob]:
        with self._lock:
            return [job.model_copy(deep=True) for job in self._jobs.values() if job.tenant_id == tenant_id]


_store: InMemoryReportJobStore | None = None
_store_lock = threading.Lock()


def get_report_job_store() -> InMemoryReportJobStore:
    global _store
    if _store is None:
        with _store_lock:
            if _store is None:
                _store = InMemoryReportJobStore()
    return _store


def set_report_job_store(store: InMemoryReportJobStore) -> None:
    global _store
    _store = store


def reset_report_job_store() -> None:
    global _store
    _store = None
