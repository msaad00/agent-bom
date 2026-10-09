"""Scan pipeline orchestration — ScanPipeline tracker and _run_scan_sync.

Extracted from api/server.py (Phase 4). Contains:
- ScanPipeline: structured SSE event tracker for scan progress
- _run_scan_sync: full scan pipeline runner (blocking, thread-safe)
- _sync_scan_agents_to_fleet: auto-sync discovered agents to fleet registry
- _now: UTC ISO timestamp helper
- _executor: shared ThreadPoolExecutor for scan jobs
"""

from __future__ import annotations

import ctypes
import gc
import json
import logging
import sys
import threading
import uuid
from collections.abc import Iterable
from concurrent.futures import Future, ThreadPoolExecutor
from contextlib import ExitStack
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from agent_bom.api.graph_persistence import (
    _estimate_graph_entities as _estimate_graph_entities,
)
from agent_bom.api.graph_persistence import (
    _graph_build_workspace_enabled as _graph_build_workspace_enabled,
)
from agent_bom.api.graph_persistence import (
    _graph_store_backed_build_enabled as _graph_store_backed_build_enabled,
)
from agent_bom.api.graph_persistence import (
    _persist_via_build_workspace as _persist_via_build_workspace,
)
from agent_bom.api.graph_persistence import (
    _record_graph_persistence as _record_graph_persistence,
)
from agent_bom.api.models import JobStatus, ScanJob, StepStatus
from agent_bom.api.scan_analysis_stages import (
    analyse_reachability_stage,
    attach_repo_evidence,
    attach_repo_metadata,
    build_report_stage,
    extract_packages_stage,
    scan_vulnerabilities_stage,
)
from agent_bom.api.scan_context import ScanContext, ScanStage
from agent_bom.api.scan_discovery_stages import (
    discover_agents,
    flag_blocklisted_servers,
    prepare_request,
    refresh_vulnerability_db,
)
from agent_bom.api.scan_report_support import _apply_tenant_workflow_metadata as _apply_tenant_workflow_metadata
from agent_bom.api.scan_report_support import _ast_result_for_symbol_reach as _ast_result_for_symbol_reach
from agent_bom.api.scan_report_support import _project_paths_for_symbol_reach as _project_paths_for_symbol_reach
from agent_bom.api.scan_report_support import _promote_repo_dependency_inventory as _promote_repo_dependency_inventory
from agent_bom.api.scan_report_support import _rendered_result_document as _rendered_result_document
from agent_bom.api.scan_report_support import _surface_graph_derived_findings as _surface_graph_derived_findings
from agent_bom.api.stores import (
    _compact_terminal_job_in_place,
    _get_analytics_store,
    _get_fleet_store,
    _get_graph_store,
    _get_store,
    _job_lock,
    _jobs_put,
)
from agent_bom.api.tenant_worker import run_tenant_bound
from agent_bom.config import API_SCAN_WORKER_RECYCLE_JOBS, API_SCAN_WORKERS
from agent_bom.core.tenancy import require_explicit_tenant_id
from agent_bom.security import sanitize_error, sanitize_sensitive_payload, sanitize_text

_logger = logging.getLogger(__name__)


class ScanCancelledError(Exception):
    """Raised when a running scan observes ``JobStatus.CANCELLED``."""

    def __init__(self, job_id: str) -> None:
        self.job_id = job_id
        super().__init__(f"scan cancelled: {job_id}")


def request_scan_cancellation(job: ScanJob) -> JobStatus:
    """Mark a non-terminal job cancelled under its job lock.

    Returns the resulting status. Terminal jobs are left unchanged.
    """
    lock = _job_lock(job.job_id)
    with lock:
        if job.status in {JobStatus.DONE, JobStatus.FAILED, JobStatus.CANCELLED}:
            return job.status
        job.status = JobStatus.CANCELLED
        job.progress.append("Cancellation requested")
        status = job.status
    try:
        _get_store().put(job)
    except Exception as persist_exc:  # noqa: BLE001
        _logger.warning("Failed to persist cancel for job=%s: %s", job.job_id, sanitize_text(sanitize_error(persist_exc)))
    _jobs_put(job.job_id, job, compact_terminal=False)
    return status


def _raise_if_cancelled(job: ScanJob, lock: threading.Lock) -> None:
    """Cooperative cancel checkpoint between pipeline phases."""
    with lock:
        if job.status is JobStatus.CANCELLED:
            raise ScanCancelledError(job.job_id)


# ─── Shared executor ─────────────────────────────────────────────────────────
# The scan pool is a module-level singleton so submit sites can reuse it across
# requests, but graceful shutdown in the API lifespan calls `.shutdown()` — and
# once that fires, the pool rejects further submissions with
# ``RuntimeError: cannot schedule new futures after shutdown``. In long-lived
# production processes the lifespan only fires at exit, so the effect is
# invisible. In the test suite, any test that enters a ``TestClient`` context
# manager exercises the full lifespan, leaves the global shut down, and breaks
# every subsequent test that reaches the scan path. ``get_executor()`` restores
# the pool on demand so shutdown becomes idempotent and recoverable rather than
# terminal.
_executor_lock = threading.RLock()
_executor = ThreadPoolExecutor(max_workers=max(1, API_SCAN_WORKERS))
_executor_active_jobs = 0
_executor_completed_jobs = 0
_executor_draining = False


def get_executor() -> ThreadPoolExecutor:
    """Return the shared scan executor, recreating it if a prior lifespan shut it down."""
    global _executor
    with _executor_lock:
        if _executor._shutdown and not _executor_draining:
            _executor = ThreadPoolExecutor(max_workers=max(1, API_SCAN_WORKERS))
        return _executor


def _executor_for_submission_locked() -> ThreadPoolExecutor:
    """Return an executor that can accept work while ``_executor_lock`` is held."""

    global _executor  # noqa: PLW0603
    if _executor_draining:
        raise RuntimeError("scan executor is draining during API shutdown")
    if _executor._shutdown:
        _executor = ThreadPoolExecutor(max_workers=max(1, API_SCAN_WORKERS))
    return _executor


def _recycle_executor_if_idle() -> None:
    global _executor  # noqa: PLW0603
    if API_SCAN_WORKER_RECYCLE_JOBS <= 0:
        return
    if _executor_draining or _executor_active_jobs != 0 or _executor_completed_jobs % API_SCAN_WORKER_RECYCLE_JOBS != 0:
        return
    old_executor = _executor
    _executor = ThreadPoolExecutor(max_workers=max(1, API_SCAN_WORKERS))
    old_executor.shutdown(wait=False, cancel_futures=False)
    _release_scan_memory()


def _observe_scan_future(done_future: Future | Any, *, local_job_id: str = "") -> None:
    global _executor_active_jobs, _executor_completed_jobs  # noqa: PLW0603
    try:
        exc = done_future.exception()
        if exc is not None:
            _logger.error("Unhandled API scan worker failure: %s", sanitize_text(exc))
    except Exception:  # noqa: BLE001
        _logger.error("Failed to observe API scan worker completion")
    finally:
        if local_job_id:
            from agent_bom.api.scan_queue import release_local_dispatch

            release_local_dispatch(local_job_id)
        with _executor_lock:
            _executor_active_jobs = max(0, _executor_active_jobs - 1)
            _executor_completed_jobs += 1
            _recycle_executor_if_idle()


def submit_scan_job(job: ScanJob) -> None:
    """Submit a scan job to the bounded worker pool and observe completion.

    The worker thread carries no tenant contextvar of its own, so the binding
    comes from the job — otherwise the pipeline's durable persistence
    (``PostgresJobStore.put``) writes as the default tenant and against the RLS
    ``WITH CHECK`` contract. Same requirement the claimed-job path documents.
    """
    global _executor_active_jobs  # noqa: PLW0603

    with _executor_lock:
        executor = _executor_for_submission_locked()
        _executor_active_jobs += 1
        try:
            future = executor.submit(run_tenant_bound, require_explicit_tenant_id(job.tenant_id), _run_scan_sync, job)
        except Exception:
            _executor_active_jobs = max(0, _executor_active_jobs - 1)
            raise

    future.add_done_callback(lambda done: _observe_scan_future(done, local_job_id=job.job_id))


def submit_scheduled_scan_job(loop: Any, job: ScanJob) -> None:
    """Submit a scheduler-owned scan on the shared worker pool.

    ``asyncio`` callers must not call ``get_executor()`` and then
    ``loop.run_in_executor()`` separately, because API shutdown can close the
    pool between those operations. This helper keeps the lookup and submission
    under the same lifecycle lock used by HTTP-triggered scans.

    Like ``submit_scan_job``, the worker runs bound to the job's tenant: the
    scheduler runs outside any HTTP request, so nothing else would set it.
    """

    global _executor_active_jobs  # noqa: PLW0603

    with _executor_lock:
        executor = _executor_for_submission_locked()
        _executor_active_jobs += 1
        try:
            future = loop.run_in_executor(executor, run_tenant_bound, require_explicit_tenant_id(job.tenant_id), _run_scan_sync, job)
        except Exception:
            _executor_active_jobs = max(0, _executor_active_jobs - 1)
            raise

    future.add_done_callback(_observe_scan_future)


def _run_claimed_scan_sync(job: ScanJob) -> None:
    """Run a distributed-claimed scan with the job's tenant context bound.

    The claim-loop runs outside any HTTP request, so the worker thread has no
    tenant contextvar set. Bind it from the job here so the pipeline's durable
    persistence (PostgresJobStore.put) lands under the job's own tenant and
    passes RLS WITH CHECK, instead of silently writing as the default tenant.
    """
    # A finished job can retain its queue row if dispatch cleanup failed or the
    # process stopped after persisting the result. Reclaim must not rerun it.
    if job.status not in {JobStatus.PENDING, JobStatus.RUNNING}:
        return
    run_tenant_bound(job.tenant_id, _run_scan_sync, job)


def submit_claimed_scan_job(job: ScanJob, on_complete: Any) -> None:
    """Submit a claimed (distributed) job to the local worker pool.

    Mirrors :func:`submit_scan_job` but runs the tenant-bound runner and invokes
    ``on_complete(job_id)`` after the scan finishes so the dispatcher can free
    local capacity and clear the job's dispatch-queue row.
    """
    global _executor_active_jobs  # noqa: PLW0603

    require_explicit_tenant_id(job.tenant_id)

    with _executor_lock:
        executor = _executor_for_submission_locked()
        _executor_active_jobs += 1
        try:
            future = executor.submit(_run_claimed_scan_sync, job)
        except Exception:
            _executor_active_jobs = max(0, _executor_active_jobs - 1)
            raise

    def _done(done_future: Future | Any) -> None:
        try:
            _observe_scan_future(done_future)
        finally:
            try:
                on_complete(job.job_id)
            except Exception:  # noqa: BLE001
                _logger.error("claimed scan on_complete callback failed job=%s", job.job_id)

    future.add_done_callback(_done)


def shutdown_scan_executor(*, wait: bool, cancel_futures: bool) -> None:
    """Drain or cancel the shared scan executor without racing submissions."""

    global _executor_draining  # noqa: PLW0603
    with _executor_lock:
        _executor_draining = True
        executor = _executor
    try:
        executor.shutdown(wait=wait, cancel_futures=cancel_futures)
    finally:
        with _executor_lock:
            if _executor is executor:
                _executor_draining = False


def _release_scan_memory() -> None:
    """Best-effort memory reclamation after large scan artifacts are persisted."""
    gc.collect()
    try:
        if sys.platform.startswith("linux"):
            malloc_trim = getattr(ctypes.CDLL("libc.so.6"), "malloc_trim", None)
            if malloc_trim is not None:
                malloc_trim(0)
        elif sys.platform == "darwin":
            pressure_relief = getattr(ctypes.CDLL(None), "malloc_zone_pressure_relief", None)
            if pressure_relief is not None:
                pressure_relief(None, 0)
    except Exception:  # noqa: BLE001
        pass


# ─── Constants ───────────────────────────────────────────────────────────────

PIPELINE_STEPS = ["discovery", "extraction", "scanning", "enrichment", "analysis", "output"]
PIPELINE_DAG_EVENT_SCHEMA = "agent-bom.pipeline.dag.events.v1"
PIPELINE_DAG_EDGES = [{"source": source, "target": target} for source, target in zip(PIPELINE_STEPS, PIPELINE_STEPS[1:], strict=False)]
_PIPELINE_STEP_INDEX = {step_id: index for index, step_id in enumerate(PIPELINE_STEPS)}
_PIPELINE_PREDECESSORS = {
    step_id: [edge["source"] for edge in PIPELINE_DAG_EDGES if edge["target"] == step_id] for step_id in PIPELINE_STEPS
}
_PIPELINE_SUCCESSORS = {step_id: [edge["target"] for edge in PIPELINE_DAG_EDGES if edge["source"] == step_id] for step_id in PIPELINE_STEPS}
_TERMINAL_STEP_STATUSES = {
    StepStatus.DONE.value,
    StepStatus.FAILED.value,
    StepStatus.SKIPPED.value,
}


# ─── Helpers ─────────────────────────────────────────────────────────────────


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def iter_pipeline_dag_event_records(
    progress_lines: Iterable[str],
    *,
    scan_id: str,
    tenant_id: str | None = None,
) -> list[dict[str, Any]]:
    """Return dashboard-ready DAG step records from structured progress lines.

    The API already emits JSON step progress records for SSE consumers. This
    helper keeps that wire behavior intact while giving local tests, report
    exporters, and dashboards a stable JSONL artifact shape that includes the
    scan pipeline DAG edges needed to render progress as a graph.
    """
    records: list[dict[str, Any]] = []
    for sequence, line in enumerate(progress_lines):
        try:
            event = json.loads(line)
        except (TypeError, ValueError):
            continue
        if not isinstance(event, dict) or event.get("type") != "step":
            continue
        step_id = event.get("step_id")
        status = event.get("status")
        if not isinstance(step_id, str) or step_id not in _PIPELINE_STEP_INDEX:
            continue
        if isinstance(status, StepStatus):
            status = status.value
        if not isinstance(status, str):
            continue

        emitted_at = event.get("completed_at") or event.get("started_at")
        record: dict[str, Any] = {
            "schema_version": PIPELINE_DAG_EVENT_SCHEMA,
            "type": "pipeline_dag_step",
            "event_id": f"{scan_id}:{sequence}:{step_id}:{status}",
            "scan_id": scan_id,
            "sequence": sequence,
            "emitted_at": emitted_at if isinstance(emitted_at, str) else None,
            "step": {
                "id": step_id,
                "index": _PIPELINE_STEP_INDEX[step_id],
                "status": status,
                "message": event.get("message") if isinstance(event.get("message"), str) else "",
                "started_at": event.get("started_at") if isinstance(event.get("started_at"), str) else None,
                "completed_at": event.get("completed_at") if isinstance(event.get("completed_at"), str) else None,
                "stats": event.get("stats") if isinstance(event.get("stats"), dict) else {},
                "sub_step": event.get("sub_step") if isinstance(event.get("sub_step"), str) else None,
                "progress_pct": event.get("progress_pct") if isinstance(event.get("progress_pct"), int) else None,
            },
            "dag": {
                "node_id": step_id,
                "depends_on": list(_PIPELINE_PREDECESSORS[step_id]),
                "next_steps": list(_PIPELINE_SUCCESSORS[step_id]),
                "edges": [dict(edge) for edge in PIPELINE_DAG_EDGES],
            },
            "dashboard": {
                "lane": "scan_pipeline",
                "render": "dag_step",
                "terminal": status in _TERMINAL_STEP_STATUSES,
            },
        }
        if tenant_id:
            record["tenant_id"] = tenant_id
        records.append(record)
    return records


def pipeline_dag_events_jsonl(job: ScanJob) -> str:
    """Serialize a scan job's structured pipeline events as JSONL."""
    records = iter_pipeline_dag_event_records(
        list(job.progress),
        scan_id=job.job_id,
        tenant_id=job.tenant_id,
    )
    return "\n".join(json.dumps(record, sort_keys=True) for record in records)


def _persist_graph_snapshot(
    job: ScanJob,
    report_json: dict[str, Any],
    *,
    lock: threading.Lock | None = None,
    write_generation: str = "",
) -> None:
    """Persist through the graph service using the pipeline's current store factory."""
    from agent_bom.api.graph_persistence import persist_graph_snapshot

    persist_graph_snapshot(job, report_json, store_factory=_get_graph_store, lock=lock, write_generation=write_generation)


# ─── ScanPipeline ────────────────────────────────────────────────────────────


class ScanPipeline:
    """Track scan pipeline steps and emit structured events to job.progress."""

    def __init__(self, job: ScanJob, lock: threading.Lock | None = None) -> None:
        self._job = job
        self._lock = lock
        self._steps: dict[str, dict[str, Any]] = {}
        for step_id in PIPELINE_STEPS:
            self._steps[step_id] = {
                "type": "step",
                "step_id": step_id,
                "status": StepStatus.PENDING,
                "message": f"Pending: {step_id}",
                "started_at": None,
                "completed_at": None,
                "stats": {},
                "sub_step": None,
                "progress_pct": None,
            }

    def start_step(self, step_id: str, message: str, sub_step: str | None = None) -> None:
        """Mark a step as running and emit event."""
        event = self._steps[step_id]
        event["status"] = StepStatus.RUNNING
        event["message"] = message
        event["started_at"] = _now()
        event["sub_step"] = sub_step
        self._emit(event)

    def update_step(
        self,
        step_id: str,
        message: str,
        stats: dict[str, Any] | None = None,
        progress_pct: int | None = None,
    ) -> None:
        """Update a running step with new message/stats."""
        event = self._steps[step_id]
        event["message"] = message
        if stats:
            event["stats"].update(stats)
        if progress_pct is not None:
            event["progress_pct"] = progress_pct
        self._emit(event)

    def complete_step(self, step_id: str, message: str, stats: dict[str, Any] | None = None) -> None:
        """Mark a step as done."""
        event = self._steps[step_id]
        event["status"] = StepStatus.DONE
        event["message"] = message
        event["completed_at"] = _now()
        if stats:
            event["stats"].update(stats)
        self._emit(event)

    def fail_step(self, step_id: str, message: str) -> None:
        """Mark a step as failed."""
        event = self._steps[step_id]
        event["status"] = StepStatus.FAILED
        event["message"] = message
        event["completed_at"] = _now()
        self._emit(event)

    def skip_step(self, step_id: str, message: str) -> None:
        """Mark a step as skipped."""
        event = self._steps[step_id]
        event["status"] = StepStatus.SKIPPED
        event["message"] = message
        event["completed_at"] = _now()
        self._emit(event)

    def _emit(self, event: dict[str, Any]) -> None:
        """Serialize step event to job.progress for SSE pickup (thread-safe)."""
        # Convert enum values to strings for JSON serialization
        serializable = {k: (v.value if isinstance(v, Enum) else v) for k, v in event.items()}
        line = json.dumps(sanitize_sensitive_payload(serializable))
        if self._lock:
            with self._lock:
                self._job.progress.append(line)
        else:
            self._job.progress.append(line)


# ─── Fleet sync ──────────────────────────────────────────────────────────────


def _sync_scan_agents_to_fleet(agents: list, tenant_id: str = "default") -> None:
    """Sync discovered agents from a scan into the fleet registry.

    Creates new FleetAgent entries for previously unseen agents and updates
    counts/trust scores for existing ones.  This ensures the fleet table is
    always populated after every scan — closing the gap where scan_jobs had
    data but fleet_agents stayed empty.
    """
    from agent_bom.api.fleet_store import FleetAgent, FleetLifecycleState, match_discovered_fleet_agent
    from agent_bom.fleet.trust_scoring import compute_trust_score

    store = _get_fleet_store()
    now = _now()

    # Collect all agents for a single batch upsert (atomicity)
    to_upsert: list[FleetAgent] = []

    existing_agents = store.list_by_tenant(tenant_id)
    claimed_agent_ids: set[str] = set()

    for agent in agents:
        agent_type = agent.agent_type.value if hasattr(agent.agent_type, "value") else str(agent.agent_type)
        canonical_id = _optional_str(getattr(agent, "canonical_id", ""))
        existing = match_discovered_fleet_agent(
            existing_agents,
            canonical_id=canonical_id,
            agent_type=agent_type,
            name=agent.name,
            config_path=agent.config_path or "",
            previous_canonical_ids=list(getattr(agent, "previous_canonical_ids", []) or []),
            claimed_agent_ids=claimed_agent_ids,
        )
        server_count = len(agent.mcp_servers)
        pkg_count = sum(len(s.packages) for s in agent.mcp_servers)
        cred_count = sum(len(s.credential_names) for s in agent.mcp_servers)
        vuln_count = sum(s.total_vulnerabilities for s in agent.mcp_servers)

        score, factors = compute_trust_score(agent)

        if existing:
            claimed_agent_ids.add(existing.agent_id)
            existing.canonical_id = canonical_id
            existing.name = agent.name
            existing.agent_type = agent_type
            existing.config_path = agent.config_path or ""
            existing.source_id = _optional_str(getattr(agent, "source_id", "")) or existing.source_id
            existing.device_fingerprint = _optional_str(getattr(agent, "device_fingerprint", "")) or existing.device_fingerprint
            existing.server_count = server_count
            existing.package_count = pkg_count
            existing.credential_count = cred_count
            existing.vuln_count = vuln_count
            existing.trust_score = score
            existing.trust_factors = factors
            existing.updated_at = now
            to_upsert.append(existing)
        else:
            fleet_agent = FleetAgent(
                agent_id=str(uuid.uuid4()),
                canonical_id=canonical_id,
                device_fingerprint=_optional_str(getattr(agent, "device_fingerprint", "")),
                name=agent.name,
                agent_type=agent_type,
                config_path=agent.config_path or "",
                source_id=_optional_str(getattr(agent, "source_id", "")),
                lifecycle_state=FleetLifecycleState.DISCOVERED,
                trust_score=score,
                trust_factors=factors,
                server_count=server_count,
                package_count=pkg_count,
                credential_count=cred_count,
                vuln_count=vuln_count,
                tenant_id=tenant_id,
                last_discovery=now,
                created_at=now,
                updated_at=now,
            )
            to_upsert.append(fleet_agent)

    if to_upsert:
        store.batch_put(to_upsert)


def _optional_str(value: object) -> str:
    return value if isinstance(value, str) else ""


# ─── Scan Pipeline Runner ───────────────────────────────────────────────────


def _begin_job(job: ScanJob, lock: threading.Lock) -> bool:
    """Mark the job running, or persist a cancellation that arrived before start."""
    with lock:
        if job.status is JobStatus.CANCELLED:
            job.completed_at = _now()
            job.progress.append("Scan cancelled before start")
        else:
            job.status = JobStatus.RUNNING
            job.started_at = _now()
    if job.status is not JobStatus.CANCELLED:
        return True
    try:
        _get_store().put(job)
    except Exception:  # noqa: BLE001
        pass
    _jobs_put(job.job_id, job, compact_terminal=True)
    return False


def _dispatch_connection_scan(ctx: ScanContext) -> bool:
    # Cloud-connection scans share the same durable ScanJob queue and worker
    # lifecycle as regular scans, but their evidence collector starts from a
    # tenant-scoped encrypted connection rather than local path targets.
    # Dispatch before the generic discovery pipeline so the API request never
    # performs provider I/O inline and worker reclaims keep the same job id.
    from agent_bom.api.routes.cloud_connections import (
        execute_queued_connection_scan,
        is_queued_connection_scan,
    )

    if not is_queued_connection_scan(ctx.job):
        return False
    from agent_bom.api.postgres_store import reset_current_tenant, set_current_tenant

    ctx.progress("Starting queued cloud connection scan")
    tenant_token = set_current_tenant(ctx.job.tenant_id or "default")
    try:
        execute_queued_connection_scan(ctx.job)
    finally:
        reset_current_tenant(tenant_token)
    return True


def _finish_dry_run(ctx: ScanContext) -> bool:
    req = ctx.req
    if not req.dry_run:
        return False
    pipeline = ctx.pipeline
    pipeline.start_step("discovery", "Dry run: validating scan request")
    pipeline.complete_step("discovery", "Dry run request validated")
    for step_id in ("extraction", "scanning", "enrichment", "analysis"):
        pipeline.skip_step(step_id, "Dry run")
    pipeline.skip_step("output", "Dry run completed without side effects")
    with ctx.lock:
        ctx.job.result = {
            "dry_run": True,
            "scan_skipped": True,
            "offline": req.offline,
            "no_scan": req.no_scan,
            "side_effects": "skipped",
            "would_scan": {
                "repo_url": bool(ctx.repo_url),
                "inventory": bool(req.inventory),
                "images": list(req.images),
                "kubernetes": req.k8s,
                "terraform_dirs": list(req.tf_dirs),
                "github_actions": bool(req.gha_path),
                "agent_projects": list(req.agent_projects),
                "jupyter_dirs": list(req.jupyter_dirs),
                "sbom": bool(req.sbom),
                "connectors": list(req.connectors),
                "filesystem_paths": list(req.filesystem_paths),
                "dynamic_discovery": req.dynamic_discovery,
            },
            "warnings": [],
            "scan_run": {"outcome": "complete", "issues": [], "warning_count": 0},
        }
        ctx.job.status = JobStatus.DONE
        ctx.job.completed_at = _now()
    return True


def _persist_graph_best_effort(ctx: ScanContext, report_json: dict[str, Any]) -> None:
    job, lock = ctx.job, ctx.lock
    try:
        ctx.pipeline.update_step("output", "Persisting unified graph...")
        _persist_graph_snapshot(job, report_json, lock=lock)
    except Exception as graph_exc:  # noqa: BLE001
        _logger.warning("Unified graph persistence failed: %s", sanitize_text(sanitize_error(graph_exc, generic=True)))
        _record_graph_persistence(job, status="failed", lock=lock)
        ctx.progress("Graph persistence failed; scan evidence remains available")


def _record_trend(ctx: ScanContext, report_json: dict[str, Any], *, completed_at: Any) -> None:
    from agent_bom.api.trend_comparison import scan_scope_id
    from agent_bom.api.trend_recording import record_scan_trend_best_effort

    if record_scan_trend_best_effort(
        report_json,
        tenant_id=ctx.tenant_or_default,
        scan_id=ctx.job.job_id,
        scope_id=scan_scope_id(ctx.job.request),
        completed_at=completed_at,
    ):
        ctx.progress("Posture trend recorded")


def _complete_output(ctx: ScanContext) -> bool:
    report_json = ctx.report_json
    ctx.pipeline.complete_step(
        "output",
        "Report ready",
        {"findings": len(report_json.get("findings") or report_json.get("blast_radius") or [])},
    )
    return False


def _publish_static_findings(ctx: ScanContext, ast_only_result: Any | None) -> None:
    """Report repository static findings for a scan that discovered no agents."""
    from agent_bom.models import AIBOMReport
    from agent_bom.output import to_json

    job = ctx.job
    report = AIBOMReport(agents=[], blast_radii=[], findings=[], scan_id=job.job_id, scan_run=ctx.build_scan_run(has_usable_evidence=True))
    attach_repo_evidence(ctx, report)
    if ast_only_result is not None:
        report.ai_inventory_data = report.ai_inventory_data or {}
        report.ai_inventory_data["ast_analysis"] = ast_only_result.to_dict()
    attach_repo_metadata(ctx, report)
    from agent_bom.scanners import consume_coverage_warnings

    report.coverage_warnings = consume_coverage_warnings()
    _apply_tenant_workflow_metadata(report, tenant_id=ctx.tenant_or_default)
    report_json = to_json(report)
    report_json["status"] = "findings_only"
    result_document, document_note = _rendered_result_document(job, report)
    with ctx.lock:
        job.result = report_json
        job.result_document = result_document
        if document_note:
            job.progress.append(document_note)
        job.status = JobStatus.DONE
        job.completed_at = _now()
    if ctx.side_effects_enabled:
        _persist_graph_best_effort(ctx, report_json)
        _record_trend(ctx, report_json, completed_at=job.completed_at)
    ctx.report_json = report_json
    _complete_output(ctx)


def _publish_no_agents(ctx: ScanContext) -> None:
    job = ctx.job
    scan_run = ctx.build_scan_run(has_usable_evidence=False)
    job.result = {
        "status": "no_agents_found",
        "agents": [],
        "vulnerabilities": [],
        "blast_radius": [],
        "blast_radii": [],
        "warnings": scan_run.warnings,
        "scan_run": scan_run.to_dict(),
    }
    # An empty estate still honours the requested format: the rendered
    # document carries the same "nothing discovered" outcome rather than
    # leaving the caller with a null they cannot distinguish from a bug.
    from agent_bom.models import AIBOMReport as _EmptyReport

    empty_document, empty_note = _rendered_result_document(
        job,
        _EmptyReport(agents=[], blast_radii=[], findings=[], scan_id=job.job_id, scan_run=scan_run),
    )
    job.result_document = empty_document
    if empty_note:
        job.progress.append(empty_note)
    job.status = JobStatus.DONE
    job.completed_at = _now()


def _finish_empty_estate(ctx: ScanContext) -> bool:
    if ctx.agents:
        return False
    pipeline = ctx.pipeline
    ast_only_result = _ast_result_for_symbol_reach(_project_paths_for_symbol_reach(ctx.req, extra_paths=ctx.extra_symbol_paths))
    pipeline.skip_step("extraction", "No agents to extract")
    pipeline.skip_step("scanning", "No packages to scan")
    pipeline.skip_step("enrichment", "Skipped")
    pipeline.skip_step("analysis", "Skipped")
    if ctx.has_static_repo_evidence() or ast_only_result is not None:
        _raise_if_cancelled(ctx.job, ctx.lock)
        pipeline.start_step("output", "Building report from repo static findings...")
        _publish_static_findings(ctx, ast_only_result)
    else:
        pipeline.skip_step("output", "No results")
        _publish_no_agents(ctx)
    return True


def _record_asset_tracker(ctx: ScanContext, report_json: dict[str, Any]) -> None:
    try:
        from agent_bom.asset_tracker import AssetTracker

        with AssetTracker(tenant_id=str(getattr(ctx.job, "tenant_id", None) or "default")) as tracker:
            asset_diff = tracker.record_scan(report_json)
        ctx.progress(
            "Asset tracker synced "
            f"(new={asset_diff['summary']['new_count']}, "
            f"resolved={asset_diff['summary']['resolved_count']}, "
            f"open={asset_diff['summary']['total_open']})"
        )
    except Exception as asset_exc:  # noqa: BLE001
        _logger.warning("Asset tracker persistence failed: %s", sanitize_text(asset_exc))
        ctx.progress(f"Asset tracker skipped: {sanitize_error(asset_exc)}")


def _record_local_analytics(ctx: ScanContext, report_json: dict[str, Any]) -> None:
    try:
        from agent_bom.db.local_analytics import record_scan_report_best_effort

        recorded_scan_id = record_scan_report_best_effort(
            report_json,
            source="api",
            tenant_id=str(getattr(ctx.job, "tenant_id", None) or "default"),
        )
        if recorded_scan_id:
            ctx.progress(f"Local analytics synced scan {recorded_scan_id}")
    except Exception as local_analytics_exc:  # noqa: BLE001
        _logger.debug("Local analytics persistence skipped: %s", sanitize_text(local_analytics_exc))


def _persist_results(ctx: ScanContext) -> bool:
    """Record trend, graph, asset and local-analytics evidence for a side-effecting scan."""
    if not ctx.side_effects_enabled:
        ctx.progress("Result side-effect persistence skipped by request")
        return False
    report_json = ctx.report_json
    _record_trend(ctx, report_json, completed_at=ctx.job.completed_at or report_json.get("generated_at"))
    _persist_graph_best_effort(ctx, report_json)
    _record_asset_tracker(ctx, report_json)
    _record_local_analytics(ctx, report_json)
    return False


def _sync_fleet(ctx: ScanContext) -> bool:
    """Auto-sync discovered agents to the fleet registry."""
    if not ctx.side_effects_enabled:
        return False
    try:
        _sync_scan_agents_to_fleet(ctx.agents, tenant_id=str(getattr(ctx.job, "tenant_id", None) or "default"))
    except Exception as fleet_exc:  # noqa: BLE001
        ctx.progress(f"Fleet sync skipped: {fleet_exc}")
    return False


def _record_analytics(ctx: ScanContext) -> bool:
    if not ctx.side_effects_enabled:
        return False
    try:
        from agent_bom.analytics_contract import build_scan_analytics_payload

        analytics_store = _get_analytics_store()
        analytics = build_scan_analytics_payload(ctx.report, report_json=ctx.report_json, scan_id=ctx.job.job_id, source="api")
        # Plumb the job's tenant through to analytics so the shared
        # ClickHouse cluster stays segregated per tenant at row level.
        tenant_id = str(getattr(ctx.job, "tenant_id", None) or "default")
        for agent_name, findings in analytics.agent_findings.items():
            analytics_store.record_scan(analytics.scan_id, agent_name, findings, tenant_id=tenant_id)
        analytics_store.record_scan_metadata(analytics.scan_metadata, tenant_id=tenant_id)
        for agent_name, snapshot in analytics.posture_snapshots.items():
            analytics_store.record_posture(agent_name, snapshot, tenant_id=tenant_id)
        for fleet_snapshot in analytics.fleet_snapshots:
            # The analytics builder seeds tenant_id="default" so CLI scans
            # without a request context keep working. When a real job is
            # on the wire we override with the authed tenant so dashboards
            # see the finding in the right column.
            fleet_snapshot["tenant_id"] = tenant_id
            analytics_store.record_fleet_snapshot(fleet_snapshot)
        for control in analytics.compliance_controls:
            analytics_store.record_compliance_control(control, tenant_id=tenant_id)
        analytics_store.record_cis_benchmark_checks(analytics.cis_benchmark_checks, tenant_id=tenant_id)
    except Exception as analytics_exc:  # noqa: BLE001
        _logger.warning("API ClickHouse analytics persistence failed: %s", sanitize_text(analytics_exc))
        ctx.progress(f"Analytics sync skipped: {sanitize_error(analytics_exc)}")
    return False


SCAN_STAGES: tuple[ScanStage, ...] = (
    ScanStage("connection_scan", _dispatch_connection_scan),
    ScanStage("prepare_request", prepare_request),
    ScanStage("dry_run", _finish_dry_run),
    ScanStage("refresh_vulnerability_db", refresh_vulnerability_db),
    ScanStage("discover_agents", discover_agents),
    ScanStage("empty_estate", _finish_empty_estate),
    ScanStage("flag_blocklisted_servers", flag_blocklisted_servers),
    ScanStage("extract_packages", extract_packages_stage, check_cancelled=True),
    ScanStage("scan_vulnerabilities", scan_vulnerabilities_stage, check_cancelled=True),
    ScanStage("analyse_reachability", analyse_reachability_stage, check_cancelled=True),
    ScanStage("build_report", build_report_stage, check_cancelled=True),
    ScanStage("persist_results", _persist_results),
    ScanStage("complete_output", _complete_output),
    ScanStage("sync_fleet", _sync_fleet),
    ScanStage("record_analytics", _record_analytics),
)
"""The scan pipeline, in order. A stage returning ``True`` completes the job."""


def _handle_cancelled(ctx: ScanContext) -> None:
    with ctx.lock:
        ctx.job.status = JobStatus.CANCELLED
        ctx.job.error = None
        ctx.job.progress.append("Scan cancelled")
    for step_id in PIPELINE_STEPS:
        if ctx.pipeline._steps[step_id]["status"] == StepStatus.RUNNING:
            ctx.pipeline.skip_step(step_id, "Cancelled")
            break


def _failed_scan_result(safe_error: str) -> dict[str, Any]:
    return {
        "scan_run": {
            "outcome": "failed",
            "issues": [
                {
                    "code": "scan_failed",
                    "stage": "pipeline",
                    "source": "api",
                    "message": safe_error,
                    "severity": "error",
                    "affects_coverage": True,
                }
            ],
            "warning_count": 1,
        },
        "warnings": [safe_error],
    }


def _handle_failure(ctx: ScanContext, exc: Exception) -> None:
    job = ctx.job
    safe_error = sanitize_error(exc)
    with ctx.lock:
        if job.status is JobStatus.CANCELLED:
            job.progress.append("Scan cancelled during failure handling")
        else:
            job.status = JobStatus.FAILED
            job.error = safe_error
            job.result = _failed_scan_result(safe_error)
    if job.status is JobStatus.CANCELLED:
        return
    # Mark whichever step was running as failed
    for step_id in PIPELINE_STEPS:
        if ctx.pipeline._steps[step_id]["status"] == StepStatus.RUNNING:
            ctx.pipeline.fail_step(step_id, sanitize_error(exc))
            break
    else:
        ctx.progress(f"Error: {sanitize_error(exc)}")


def _persist_final_state(job: ScanJob, lock: threading.Lock) -> tuple[Any, JobStatus]:
    with lock:
        job.completed_at = _now()
        terminal_status = job.status
    # Persist final state
    store = _get_store()
    try:
        store.put(job)
    except Exception as persist_exc:  # noqa: BLE001
        # Persistence is the durability boundary. If the store rejects the
        # final write, this result only ever existed in this process's
        # memory: it will not survive a restart and will never reach the
        # compliance/graph reads that load from the store. Reporting it as a
        # clean success would be a lie, so surface the failure on the job
        # the caller polls rather than swallowing it in a finally block.
        _logger.error("Scan result persistence failed job=%s: %s", job.job_id, sanitize_text(persist_exc))
        with lock:
            job.status = JobStatus.FAILED
            job.error = f"result not persisted: {sanitize_error(persist_exc)}"
            job.progress.append(f"Persistence failed: {sanitize_error(persist_exc)}")
            terminal_status = job.status
    # Default to "retains in memory" so a store that does not declare the
    # attribute (e.g. test mocks, third-party plugins) keeps a usable job
    # result for the caller. Durable stores that fully serialize on put()
    # opt in to in-place compaction by setting
    # ``retains_job_objects_in_memory = False`` explicitly — see
    # SQLiteJobStore, PostgresJobStore, SnowflakeJobStore.
    if not bool(getattr(store, "retains_job_objects_in_memory", True)):
        _compact_terminal_job_in_place(job)
    _jobs_put(job.job_id, job, compact_terminal=True)
    return store, terminal_status


def _refresh_batch_parent(job: ScanJob) -> None:
    if not job.parent_job_id:
        return
    try:
        from agent_bom.api.scan_batches import refresh_batch_parent

        refresh_batch_parent(job.parent_job_id, tenant_id=job.tenant_id or "default")
    except Exception:  # noqa: BLE001
        _logger.error("Failed to refresh scan batch parent job=%s child=%s", job.parent_job_id, job.job_id)


def _record_completion_metrics(store: Any, terminal_status: JobStatus) -> None:
    # Update operator-visible scan metrics. The active gauge feeds
    # the KEDA scaler in deploy/helm/agent-bom; the completion
    # counter feeds dashboards + alerting on failure rate.
    try:
        from agent_bom.api import metrics as _api_metrics
        from agent_bom.api.scan_job_reconciliation import reconcile_scan_jobs_active

        reconcile_scan_jobs_active(store)
        _api_metrics.record_scan_completion(str(terminal_status))
    except Exception:  # noqa: BLE001
        # Metrics must never break the scan path. Swallow all errors.
        pass


def _record_adoption(job: ScanJob, terminal_status: JobStatus) -> None:
    if terminal_status not in {JobStatus.DONE, JobStatus.FAILED}:
        return
    from agent_bom.db.adoption_events import record_scan_completion_best_effort

    outcome = "failed" if terminal_status is JobStatus.FAILED else "complete"
    scan_run_payload = job.result.get("scan_run", {}) if isinstance(job.result, dict) else {}
    if terminal_status is JobStatus.DONE and isinstance(scan_run_payload, dict) and scan_run_payload.get("outcome") == "partial":
        outcome = "partial"
    record_scan_completion_best_effort(
        channel="control_plane",
        outcome=outcome,
        artifact_type="json" if terminal_status is JobStatus.DONE else None,
    )


def _finalize(ctx: ScanContext) -> None:
    ctx.repo_stack.close()
    store, terminal_status = _persist_final_state(ctx.job, ctx.lock)
    _refresh_batch_parent(ctx.job)
    _release_scan_memory()
    _record_completion_metrics(store, terminal_status)
    _record_adoption(ctx.job, terminal_status)


def _run_scan_sync(job: ScanJob) -> None:
    """Run the full scan pipeline in a thread (blocking). Updates job in-place."""
    lock = _job_lock(job.job_id)
    if not _begin_job(job, lock):
        return
    ctx = ScanContext(job=job, lock=lock, pipeline=ScanPipeline(job, lock), repo_stack=ExitStack())
    try:
        for stage in SCAN_STAGES:
            if stage.check_cancelled:
                _raise_if_cancelled(job, lock)
            if stage.run(ctx):
                return
    except ScanCancelledError:
        _handle_cancelled(ctx)
    except Exception as exc:  # noqa: BLE001
        _handle_failure(ctx, exc)
    finally:
        _finalize(ctx)
