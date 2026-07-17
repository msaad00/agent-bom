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
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from agent_bom import __version__
from agent_bom.api.models import JobStatus, ScanJob, StepStatus
from agent_bom.api.stores import (
    _compact_terminal_job_in_place,
    _get_analytics_store,
    _get_fleet_store,
    _get_graph_store,
    _get_store,
    _job_lock,
    _jobs_put,
)
from agent_bom.config import API_SCAN_WORKER_RECYCLE_JOBS, API_SCAN_WORKERS
from agent_bom.security import sanitize_error

_logger = logging.getLogger(__name__)

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


def _observe_scan_future(done_future: Future | Any) -> None:
    global _executor_active_jobs, _executor_completed_jobs  # noqa: PLW0603
    try:
        exc = done_future.exception()
        if exc is not None:
            _logger.error("Unhandled API scan worker failure", exc_info=(type(exc), exc, exc.__traceback__))
    except Exception:  # noqa: BLE001
        _logger.exception("Failed to observe API scan worker completion")
    finally:
        with _executor_lock:
            _executor_active_jobs = max(0, _executor_active_jobs - 1)
            _executor_completed_jobs += 1
            _recycle_executor_if_idle()


def submit_scan_job(job: ScanJob) -> None:
    """Submit a scan job to the bounded worker pool and observe completion."""
    global _executor_active_jobs  # noqa: PLW0603

    with _executor_lock:
        executor = _executor_for_submission_locked()
        _executor_active_jobs += 1
        try:
            future = executor.submit(_run_scan_sync, job)
        except Exception:
            _executor_active_jobs = max(0, _executor_active_jobs - 1)
            raise

    future.add_done_callback(_observe_scan_future)


def submit_scheduled_scan_job(loop: Any, job: ScanJob) -> None:
    """Submit a scheduler-owned scan on the shared worker pool.

    ``asyncio`` callers must not call ``get_executor()`` and then
    ``loop.run_in_executor()`` separately, because API shutdown can close the
    pool between those operations. This helper keeps the lookup and submission
    under the same lifecycle lock used by HTTP-triggered scans.
    """

    global _executor_active_jobs  # noqa: PLW0603

    with _executor_lock:
        executor = _executor_for_submission_locked()
        _executor_active_jobs += 1
        try:
            future = loop.run_in_executor(executor, _run_scan_sync, job)
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
    from agent_bom.api.postgres_store import reset_current_tenant, set_current_tenant

    token = set_current_tenant(job.tenant_id or "default")
    try:
        _run_scan_sync(job)
    finally:
        reset_current_tenant(token)


def submit_claimed_scan_job(job: ScanJob, on_complete: Any) -> None:
    """Submit a claimed (distributed) job to the local worker pool.

    Mirrors :func:`submit_scan_job` but runs the tenant-bound runner and invokes
    ``on_complete(job_id)`` after the scan finishes so the dispatcher can free
    local capacity and clear the job's dispatch-queue row.
    """
    global _executor_active_jobs  # noqa: PLW0603

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
                _logger.exception("claimed scan on_complete callback failed job=%s", job.job_id)

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
) -> None:
    """Persist the unified graph snapshot produced by a completed scan.

    Persistence is best-effort: graph failures should not fail the scan job.
    This path also evaluates graph deltas against the tenant's previous
    snapshot so current-state views, diff views, alert delivery, and OCSF
    export all derive from the same persisted graph state.
    """
    from agent_bom.graph.builder import build_unified_graph_from_report
    from agent_bom.graph.delta_digest import compute_delta_alerts_from_digest
    from agent_bom.graph.webhooks import dispatch_delta_alerts

    tenant_id = job.tenant_id or "default"
    scan_id = report_json.get("scan_id") or job.job_id
    graph = build_unified_graph_from_report(report_json, scan_id=scan_id, tenant_id=tenant_id)

    from agent_bom.api.postgres_store import reset_current_tenant, set_current_tenant

    tenant_token = set_current_tenant(tenant_id)
    try:
        prior_digest = None
        graph_store = _get_graph_store()
        previous_scan_id = graph_store.latest_snapshot_id(tenant_id=tenant_id)
        if previous_scan_id and previous_scan_id != scan_id:
            # Bounded prior-snapshot digest instead of a second full UnifiedGraph
            # load — keeps peak RSS decoupled from the prior graph size (#4055/#4075).
            prior_digest = graph_store.prior_delta_digest(tenant_id=tenant_id, scan_id=previous_scan_id)
        # Persist via the streamed write path (node/edge iterables) so the write
        # never buffers a second copy of the graph; counts come from the store's
        # running tally, not len(graph.*).
        counts = graph_store.save_graph_streaming(
            scan_id=graph.scan_id,
            tenant_id=graph.tenant_id,
            nodes=graph.nodes.values(),
            edges=graph.edges,
            attack_paths=graph.attack_paths,
            interaction_risks=graph.interaction_risks,
            analysis_status=graph.analysis_status,
            created_at=graph.created_at,
        )
    finally:
        reset_current_tenant(tenant_token)

    node_count = counts.get("nodes", len(graph.nodes))
    edge_count = counts.get("edges", len(graph.edges))
    alerts = compute_delta_alerts_from_digest(prior_digest, graph)
    delivery = dispatch_delta_alerts(alerts, product_version=__version__, tenant_id=tenant_id) if alerts else None
    _logger.info(
        "Graph persisted for scan=%s tenant=%s nodes=%d edges=%d delta_alerts=%d delta_delivered=%d",
        scan_id,
        tenant_id,
        node_count,
        edge_count,
        len(alerts),
        delivery["delivered"] if delivery else 0,
    )
    if lock:
        with lock:
            job.progress.append(f"Graph persisted: {node_count} nodes, {edge_count} edges")
            if alerts:
                job.progress.append(f"Graph delta alerts: {len(alerts)}")
                if delivery and delivery["configured"]:
                    summary = (
                        f"Graph delta delivery: {delivery['delivered']}/{delivery['attempted']} "
                        f"via {delivery['outbound_channels']} outbound channel(s)"
                    )
                    job.progress.append(summary)
                else:
                    job.progress.append(f"Graph delta export ready: {delivery['ocsf_event_count'] if delivery else 0} OCSF event(s)")


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
        self._emit(event)

    def _emit(self, event: dict[str, Any]) -> None:
        """Serialize step event to job.progress for SSE pickup (thread-safe)."""
        # Convert enum values to strings for JSON serialization
        serializable = {k: (v.value if isinstance(v, Enum) else v) for k, v in event.items()}
        line = json.dumps(serializable)
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
    from agent_bom.api.fleet_store import FleetAgent, FleetLifecycleState
    from agent_bom.fleet.trust_scoring import compute_trust_score

    store = _get_fleet_store()
    now = _now()

    # Collect all agents for a single batch upsert (atomicity)
    to_upsert: list[FleetAgent] = []

    # Key by canonical_id so two fleet agents that share a bare name (distinct
    # source_ids) are not collapsed into a single index slot; fall back to name
    # only for legacy records without a canonical_id.
    existing_by_id = {(fleet_agent.canonical_id or fleet_agent.name): fleet_agent for fleet_agent in store.list_by_tenant(tenant_id)}

    for agent in agents:
        existing = existing_by_id.get(getattr(agent, "canonical_id", "") or agent.name)
        server_count = len(agent.mcp_servers)
        pkg_count = sum(len(s.packages) for s in agent.mcp_servers)
        cred_count = sum(len(s.credential_names) for s in agent.mcp_servers)
        vuln_count = sum(s.total_vulnerabilities for s in agent.mcp_servers)

        score, factors = compute_trust_score(agent)

        if existing:
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
                canonical_id=_optional_str(getattr(agent, "canonical_id", "")),
                device_fingerprint=_optional_str(getattr(agent, "device_fingerprint", "")),
                name=agent.name,
                agent_type=agent.agent_type.value if hasattr(agent.agent_type, "value") else str(agent.agent_type),
                config_path=agent.config_path or "",
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


def _project_paths_for_symbol_reach(req: Any, *, extra_paths: Iterable[str] | None = None) -> list[str]:
    """Collect scan-target paths that may contain Python source for symbol reach."""
    paths: list[str] = []
    seen: set[str] = set()
    for raw in (
        list(getattr(req, "agent_projects", []) or [])
        + list(getattr(req, "filesystem_paths", []) or [])
        + list(getattr(req, "jupyter_dirs", []) or [])
        + ([req.gha_path] if getattr(req, "gha_path", None) else [])
        + list(extra_paths or [])
    ):
        if raw and raw not in seen:
            seen.add(raw)
            paths.append(raw)
    return paths


def _ast_result_for_symbol_reach(paths: Iterable[str]) -> Any | None:
    """Best-effort AST symbol-reach for API pipeline parity with CLI --project."""
    from pathlib import Path

    from agent_bom.ast_analyzer import analyze_project, project_has_analyzable_sources
    from agent_bom.ast_models import ASTAnalysisResult

    merged: ASTAnalysisResult | None = None
    for raw in paths:
        project = Path(raw)
        try:
            if not project_has_analyzable_sources(project):
                continue
        except OSError as path_exc:
            _logger.debug("AST symbol-reach path skipped for %s: %s", raw, sanitize_error(path_exc))
            continue
        try:
            result = analyze_project(project)
        except Exception as ast_exc:  # noqa: BLE001
            _logger.debug("AST symbol-reach analysis skipped for %s: %s", raw, sanitize_error(ast_exc))
            continue
        if merged is None:
            merged = result
        elif result.dependency_symbol_reach:
            merged.dependency_symbol_reach.extend(result.dependency_symbol_reach)
    return merged


def _promote_repo_dependency_inventory(report: Any, ai_inventory: dict[str, Any]) -> None:
    """Lift nested API dependency inventory to top-level for graph overlay parity with CLI."""
    if getattr(report, "project_inventory_data", None):
        return
    nested = ai_inventory.get("dependency_inventory")
    if isinstance(nested, dict) and nested:
        report.project_inventory_data = nested


def _run_scan_sync(job: ScanJob) -> None:
    """Run the full scan pipeline in a thread (blocking). Updates job in-place."""
    from contextlib import ExitStack

    lock = _job_lock(job.job_id)
    with lock:
        job.status = JobStatus.RUNNING
        job.started_at = _now()
    pipeline = ScanPipeline(job, lock)
    repo_stack = ExitStack()

    try:
        from agent_bom.discovery import discover_all
        from agent_bom.output import to_json
        from agent_bom.parsers import extract_packages
        from agent_bom.scanners import scan_agents_sync
        from agent_bom.security import validate_path

        req = job.request
        agents: list[Any] = []
        warnings_all: list[str] = []
        side_effects_enabled = not (req.dry_run or req.no_scan)
        effective_agent_projects = list(req.agent_projects)
        effective_tf_dirs = list(req.tf_dirs)
        effective_gha_path = req.gha_path
        extra_symbol_paths: list[str] = []

        repo_url = (req.repo_url or "").strip()
        skill_audit_data: dict | None = None
        iac_findings_data: dict | None = None
        repo_ai_inventory_data: dict | None = None
        repo_sast_data: dict | None = None
        if repo_url:
            from agent_bom.repo_scan import RepoScanError, clone_repository

            pipeline.start_step("discovery", f"Cloning repository: {repo_url}")
            try:
                cloned_dir = repo_stack.enter_context(clone_repository(repo_url, token_env="AGENT_BOM_REPO_SCAN_TOKEN"))
            except RepoScanError as exc:
                raise RuntimeError(sanitize_error(exc, generic=True)) from exc
            cloned_path = str(cloned_dir)
            effective_agent_projects = [cloned_path]
            effective_tf_dirs = [cloned_path]
            effective_gha_path = effective_gha_path or cloned_path
            extra_symbol_paths.append(cloned_path)
            pipeline.update_step("discovery", f"Repository cloned for static scan: {repo_url}")
            from agent_bom.api.repo_tree_scan import scan_cloned_repo_tree

            repo_tree_result = scan_cloned_repo_tree(
                cloned_path,
                agents=agents,
                warnings=warnings_all,
                update_progress=lambda message: pipeline.update_step("discovery", message),
                offline=req.offline,
            )
            skill_audit_data = repo_tree_result.skill_audit_data
            iac_findings_data = repo_tree_result.iac_findings_data
            repo_ai_inventory_data = repo_tree_result.ai_inventory_data
            repo_sast_data = repo_tree_result.sast_data
        path_fields = (
            ([req.inventory] if req.inventory else [])
            + req.tf_dirs
            + ([req.gha_path] if req.gha_path else [])
            + req.agent_projects
            + req.jupyter_dirs
            + ([req.sbom] if req.sbom else [])
            + req.filesystem_paths
        )
        if not repo_url:
            for p in path_fields:
                validate_path(p, must_exist=True)

        if req.dry_run:
            pipeline.start_step("discovery", "Dry run: validating scan request")
            pipeline.complete_step("discovery", "Dry run request validated")
            pipeline.skip_step("extraction", "Dry run")
            pipeline.skip_step("scanning", "Dry run")
            pipeline.skip_step("enrichment", "Dry run")
            pipeline.skip_step("analysis", "Dry run")
            pipeline.skip_step("output", "Dry run completed without side effects")
            with lock:
                job.result = {
                    "dry_run": True,
                    "scan_skipped": True,
                    "offline": req.offline,
                    "no_scan": req.no_scan,
                    "side_effects": "skipped",
                    "would_scan": {
                        "repo_url": bool(repo_url),
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
                }
                job.status = JobStatus.DONE
                job.completed_at = _now()
            return

        if req.auto_update_db and not req.offline and not req.no_scan:
            try:
                from agent_bom.db.schema import db_freshness_days
                from agent_bom.db.sync import sync_db

                source_list = [s.strip() for s in req.db_sources.split(",") if s.strip()] if req.db_sources else None
                freshness = db_freshness_days()
                if freshness is None or freshness >= 1 or source_list:
                    sync_db(sources=source_list)
            except Exception as db_exc:  # noqa: BLE001
                _logger.warning("API auto DB refresh failed: %s", sanitize_error(db_exc))
                warnings_all.append(f"Auto DB refresh skipped: {sanitize_error(db_exc)}")

        # ── Discovery phase ──
        if repo_url:
            pipeline.start_step("discovery", "Discovering MCP configs in cloned repository...")
            local_agents = discover_all(
                project_dir=cloned_path,
                dynamic=req.dynamic_discovery,
                dynamic_max_depth=req.dynamic_max_depth,
            )
        else:
            pipeline.start_step("discovery", "Discovering local MCP configurations...")
            local_agents = discover_all(
                dynamic=req.dynamic_discovery,
                dynamic_max_depth=req.dynamic_max_depth,
            )
        agents.extend(local_agents)

        if req.inventory:
            pipeline.update_step("discovery", f"Loading inventory: {req.inventory}")
            from agent_bom.cli._common import _build_agents_from_inventory
            from agent_bom.inventory import load_inventory

            try:
                inv_data = load_inventory(req.inventory)
            except (OSError, RuntimeError, ValueError) as parse_err:
                raise RuntimeError(f"Failed to load inventory file: {parse_err}") from parse_err
            agents.extend(_build_agents_from_inventory(inv_data, req.inventory))

        for image_ref in req.images:
            pipeline.update_step("discovery", f"Scanning image: {image_ref}")
            from agent_bom.image import scan_image
            from agent_bom.models import Agent, AgentType, MCPServer, ServerSurface, TransportType

            try:
                img_packages, _strategy = scan_image(image_ref)
                agents.append(
                    Agent(
                        name=f"image:{image_ref}",
                        agent_type=AgentType.CUSTOM,
                        config_path=f"docker://{image_ref}",
                        source="image",
                        mcp_servers=[
                            MCPServer(
                                name=image_ref,
                                command="docker",
                                args=["run", image_ref],
                                transport=TransportType.STDIO,
                                packages=img_packages,
                                surface=ServerSurface.CONTAINER_IMAGE,
                            )
                        ],
                    )
                )
            except Exception as img_exc:  # noqa: BLE001
                warnings_all.append(f"Image scan error for {image_ref}: {sanitize_error(img_exc)}")

        if req.k8s:
            pipeline.update_step("discovery", "Scanning Kubernetes pods...")
            from agent_bom.k8s import discover_images

            k8s_records = discover_images(namespace=req.k8s_namespace or "default")
            for img, _pod, _ctr in k8s_records:
                from agent_bom.image import scan_image
                from agent_bom.models import Agent, AgentType, MCPServer, ServerSurface, TransportType

                try:
                    img_packages, _strategy = scan_image(img)
                    agents.append(
                        Agent(
                            name=f"image:{img}",
                            agent_type=AgentType.CUSTOM,
                            config_path=f"docker://{img}",
                            source="kubernetes-image",
                            mcp_servers=[
                                MCPServer(
                                    name=img,
                                    command="docker",
                                    args=["run", img],
                                    transport=TransportType.STDIO,
                                    packages=img_packages,
                                    surface=ServerSurface.CONTAINER_IMAGE,
                                )
                            ],
                        )
                    )
                except Exception as img_exc:  # noqa: BLE001
                    warnings_all.append(f"Kubernetes image scan error for {img}: {sanitize_error(img_exc)}")

        for tf_dir in effective_tf_dirs:
            pipeline.update_step("discovery", f"Scanning Terraform: {tf_dir}")
            from agent_bom.terraform import scan_terraform_dir

            tf_agents, tf_warnings = scan_terraform_dir(tf_dir)
            agents.extend(tf_agents)
            warnings_all.extend(tf_warnings)

        if effective_gha_path:
            pipeline.update_step("discovery", f"Scanning GitHub Actions: {effective_gha_path}")
            from agent_bom.github_actions import scan_github_actions

            gha_agents, gha_warnings = scan_github_actions(effective_gha_path)
            agents.extend(gha_agents)
            warnings_all.extend(gha_warnings)

        for ap in effective_agent_projects:
            pipeline.update_step("discovery", f"Scanning Python agent project: {ap}")
            from agent_bom.python_agents import scan_python_agents

            py_agents, py_warnings = scan_python_agents(ap)
            agents.extend(py_agents)
            warnings_all.extend(py_warnings)

        for jdir in req.jupyter_dirs:
            pipeline.update_step("discovery", f"Scanning Jupyter notebooks: {jdir}")
            from agent_bom.jupyter import scan_jupyter_notebooks

            j_agents, j_warnings = scan_jupyter_notebooks(jdir)
            agents.extend(j_agents)
            warnings_all.extend(j_warnings)

        if req.sbom:
            pipeline.update_step("discovery", f"Ingesting SBOM: {req.sbom}")
            from agent_bom.sbom import load_sbom

            sbom_packages, _fmt, _sbom_name = load_sbom(req.sbom)
            if sbom_packages:
                from agent_bom.models import Agent, AgentType, MCPServer, ServerSurface

                sbom_server = MCPServer(name=f"sbom:{req.sbom}", surface=ServerSurface.SBOM)
                sbom_server.packages = sbom_packages
                sbom_agent = Agent(
                    name=f"sbom:{req.sbom}",
                    agent_type=AgentType.CUSTOM,
                    config_path=req.sbom,
                    mcp_servers=[sbom_server],
                )
                agents.append(sbom_agent)

        if req.external_scan:
            pipeline.update_step("discovery", f"Ingesting external scan: {req.external_scan}")
            import json as _json
            from pathlib import Path as _Path

            from agent_bom.models import Agent, AgentType, MCPServer, ServerSurface, TransportType
            from agent_bom.parsers.external_scanners import detect_and_parse

            try:
                with open(req.external_scan) as _ext_f:
                    _ext_data = _json.load(_ext_f)
                _ext_packages = detect_and_parse(_ext_data)
                _ext_resource_name = _Path(req.external_scan).stem
                _ext_server = MCPServer(
                    name=_ext_resource_name,
                    command="external-scan",
                    args=[req.external_scan],
                    transport=TransportType.STDIO,
                    packages=_ext_packages,
                    surface=ServerSurface.EXTERNAL_SCAN,
                )
                _ext_agent = Agent(
                    name=f"external-scan:{_ext_resource_name}",
                    agent_type=AgentType.CUSTOM,
                    config_path=req.external_scan,
                    source="external-scan",
                    mcp_servers=[_ext_server],
                )
                agents.append(_ext_agent)
            except (OSError, ValueError, _json.JSONDecodeError) as ext_exc:
                warnings_all.append(f"External scan error: {sanitize_error(ext_exc)}")

        for connector_name in req.connectors:
            pipeline.update_step("discovery", f"Discovering from connector: {connector_name}")
            try:
                from agent_bom.connectors import discover_from_connector

                con_agents, con_warnings = discover_from_connector(connector_name)
                agents.extend(con_agents)
                warnings_all.extend(con_warnings)
            except Exception as con_exc:  # noqa: BLE001
                warnings_all.append(f"{connector_name} connector error: {con_exc}")

        for fs_path in req.filesystem_paths:
            pipeline.update_step("discovery", f"Scanning filesystem: {fs_path}")
            try:
                from agent_bom.filesystem import scan_filesystem
                from agent_bom.models import Agent, AgentType, MCPServer, ServerSurface

                fs_pkgs, fs_strat = scan_filesystem(fs_path)
                if fs_pkgs:
                    from pathlib import Path as _Path

                    fs_server = MCPServer(name=f"fs:{fs_path}", surface=ServerSurface.FILESYSTEM)
                    fs_server.packages = fs_pkgs
                    fs_agent = Agent(
                        name=f"filesystem:{_Path(fs_path).name}",
                        agent_type=AgentType.CUSTOM,
                        config_path=fs_path,
                        source="filesystem",
                        mcp_servers=[fs_server],
                    )
                    agents.append(fs_agent)
            except Exception as fs_exc:  # noqa: BLE001
                warnings_all.append(f"Filesystem scan error for {fs_path}: {fs_exc}")

        pipeline.complete_step("discovery", f"Found {len(agents)} agent(s)", {"agents": len(agents)})

        # ── Scope filtering (pre-extraction) ──
        if req.scope_agents or req.scope_servers or req.exclude_agents or req.exclude_servers:
            import fnmatch

            pre_filter = len(agents)
            if req.scope_agents:
                agents = [a for a in agents if any(fnmatch.fnmatch(a.name, pat) for pat in req.scope_agents)]
            if req.exclude_agents:
                agents = [a for a in agents if not any(fnmatch.fnmatch(a.name, pat) for pat in req.exclude_agents)]
            if req.scope_servers or req.exclude_servers:
                for agent in agents:
                    if req.scope_servers:
                        agent.mcp_servers = [s for s in agent.mcp_servers if any(fnmatch.fnmatch(s.name, pat) for pat in req.scope_servers)]
                    if req.exclude_servers:
                        agent.mcp_servers = [
                            s for s in agent.mcp_servers if not any(fnmatch.fnmatch(s.name, pat) for pat in req.exclude_servers)
                        ]
            filtered_count = pre_filter - len(agents)
            if filtered_count:
                pipeline.update_step("discovery", f"Scope filter removed {filtered_count} agent(s)")

        if not agents:
            if (
                skill_audit_data is not None
                or iac_findings_data is not None
                or repo_ai_inventory_data is not None
                or repo_sast_data is not None
            ):
                pipeline.skip_step("extraction", "No agents to extract")
                pipeline.skip_step("scanning", "No packages to scan")
                pipeline.skip_step("enrichment", "Skipped")
                pipeline.skip_step("analysis", "Skipped")
                pipeline.start_step("output", "Building report from repo static findings...")
                from agent_bom.models import AIBOMReport
                from agent_bom.output import to_json

                report = AIBOMReport(agents=[], blast_radii=[], findings=[], scan_id=job.job_id)
                if skill_audit_data is not None:
                    report.skill_audit_data = skill_audit_data
                if iac_findings_data is not None:
                    report.iac_findings_data = iac_findings_data
                if repo_ai_inventory_data is not None:
                    report.ai_inventory_data = repo_ai_inventory_data
                    _promote_repo_dependency_inventory(report, repo_ai_inventory_data)
                if repo_sast_data is not None:
                    report.sast_data = repo_sast_data
                report_json = to_json(report)
                report_json["warnings"] = warnings_all
                report_json["status"] = "findings_only"
                with lock:
                    job.result = report_json
                    job.status = JobStatus.DONE
                    job.completed_at = _now()
                if side_effects_enabled:
                    try:
                        pipeline.update_step("output", "Persisting unified graph...")
                        _persist_graph_snapshot(job, report_json, lock=lock)
                    except Exception as graph_exc:  # noqa: BLE001
                        _logger.warning("Unified graph persistence failed: %s", graph_exc)
                        with lock:
                            job.progress.append(f"Graph persistence skipped: {sanitize_error(graph_exc)}")
                pipeline.complete_step("output", "Report ready")
                return

            pipeline.skip_step("extraction", "No agents to extract")
            pipeline.skip_step("scanning", "No packages to scan")
            pipeline.skip_step("enrichment", "Skipped")
            pipeline.skip_step("analysis", "Skipped")
            pipeline.skip_step("output", "No results")
            job.result = {
                "status": "no_agents_found",
                "agents": [],
                "vulnerabilities": [],
                "blast_radius": [],
                "blast_radii": [],
                "warnings": warnings_all,
            }
            job.status = JobStatus.DONE
            job.completed_at = _now()
            return

        from agent_bom.mcp_blocklist import flag_blocklisted_mcp_servers

        blocked_servers = flag_blocklisted_mcp_servers(agents)
        if blocked_servers:
            pipeline.update_step("discovery", f"MCP blocklist flagged {blocked_servers} server(s)")

        # ── Extraction phase ──
        pipeline.start_step("extraction", f"Extracting packages from {len(agents)} agent(s)...")
        total_pkgs = 0
        for agent in agents:
            for server in agent.mcp_servers:
                if server.security_blocked:
                    continue  # Don't extract packages from security-blocked servers
                if not server.packages:
                    server.packages = extract_packages(
                        server,
                        resolve_transitive=True,  # Match CLI behavior — resolve full dep tree
                        max_depth=3,
                    )
                total_pkgs += len(server.packages)
        pipeline.complete_step("extraction", f"Extracted {total_pkgs} packages", {"packages": total_pkgs})

        # ── Scanning phase ──
        blast_radii = []
        effective_enrich = bool(req.enrich and not req.offline)
        if req.no_scan:
            pipeline.skip_step("scanning", "Vulnerability scanning skipped by request")
            warnings_all.append("Vulnerability scanning skipped by request")
        else:
            if req.offline:
                scan_message = f"Scanning {total_pkgs} packages against the local vulnerability DB only..."
            else:
                scan_message = (
                    f"Scanning {total_pkgs} packages via OSV.dev with vulnerability enrichment..."
                    if effective_enrich
                    else f"Scanning {total_pkgs} packages via OSV.dev..."
                )
            pipeline.start_step("scanning", scan_message)
            try:
                blast_radii = scan_agents_sync(agents, enable_enrichment=effective_enrich, offline=req.offline, compliance_enabled=True)
            except Exception as scan_exc:  # noqa: BLE001
                safe_scan_error = sanitize_error(scan_exc)
                if req.offline:
                    _logger.warning("Offline scan phase error: %s", safe_scan_error)
                    pipeline.update_step("scanning", f"Offline scan error: {safe_scan_error}")
                    warnings_all.append(f"Offline CVE scanning failed: {safe_scan_error}")
                    blast_radii = []
                else:
                    # Log but don't crash — return what we have with warning
                    _logger.warning("Scan phase error (retrying without enrichment): %s", safe_scan_error)
                    pipeline.update_step("scanning", f"Scan error: {safe_scan_error} — retrying without enrichment")
                    try:
                        blast_radii = scan_agents_sync(agents, enable_enrichment=False, offline=False, compliance_enabled=True)
                    except Exception as retry_exc:  # noqa: BLE001
                        _logger.error("Scan retry also failed: %s", sanitize_error(retry_exc))
                        blast_radii = []
                        warnings_all.append(f"CVE scanning failed: {sanitize_error(retry_exc)}")
            total_vulns = sum(len(p.vulnerabilities) for a in agents for s in a.mcp_servers for p in s.packages)
            if total_pkgs > 0 and total_vulns == 0 and not blast_radii and not req.offline:
                warnings_all.append(
                    f"Scanned {total_pkgs} packages but found 0 vulnerabilities. This may indicate a network issue reaching OSV.dev."
                )
            pipeline.complete_step("scanning", f"Found {total_vulns} vulnerabilities", {"vulnerabilities": total_vulns})

        if req.no_scan:
            total_vulns = 0
        elif req.offline and req.enrich:
            warnings_all.append("Enrichment skipped because offline mode was requested")

        if req.no_scan:
            pipeline.skip_step("enrichment", "Vulnerability scanning skipped")
        elif effective_enrich:
            # Enrichment is executed inside scan_agents_sync, alongside the
            # vulnerability query. Emit a terminal event only so SSE timing does
            # not claim a separate enrichment phase ran after scanning.
            pipeline.complete_step(
                "enrichment",
                "Enrichment completed during scanning",
                {"executed_in_step": "scanning"},
            )
        else:
            pipeline.skip_step("enrichment", "Enrichment not requested")

        # ── Severity filtering (post-scan) ──
        if req.min_severity:
            _sev_order = {"low": 1, "medium": 2, "high": 3, "critical": 4}
            _min = _sev_order.get(req.min_severity.lower(), 0)
            blast_radii = [br for br in blast_radii if _sev_order.get(br.vulnerability.severity.value.lower(), 0) >= _min]

        try:
            from agent_bom.api.stores import _get_exception_store
            from agent_bom.suppression_rules import apply_tenant_suppression_rules

            suppression = (
                {"suppressed": 0}
                if req.no_scan
                else apply_tenant_suppression_rules(blast_radii, _get_exception_store(), tenant_id=job.tenant_id or "default")
            )
            if suppression["suppressed"]:
                warnings_all.append(f"{suppression['suppressed']} finding(s) suppressed by tenant feedback/rules")
        except Exception as exc:  # noqa: BLE001
            _logger.warning("Tenant suppression-rule evaluation skipped: %s", sanitize_error(exc))
            warnings_all.append("Tenant suppression-rule evaluation skipped")

        # ── Analysis phase ──
        pipeline.start_step("analysis", "Computing blast radius...")
        # Surface graph-walk reachability onto each blast-radius row before
        # the report is built so the JSON payload (and risk_score) reflects
        # whether each vulnerable package is actually reachable from an
        # agent entrypoint, not just present in the dependency closure.
        try:
            from agent_bom.graph.blast_reach import (
                apply_dependency_reachability_to_blast_radii,
                apply_symbol_reachability_to_blast_radii,
            )

            stamped = apply_dependency_reachability_to_blast_radii(blast_radii, agents, rescore=True)
            if stamped:
                with lock:
                    job.progress.append(f"Reachability: stamped {stamped} blast-radius row(s) with graph-walk evidence")
            _ast_for_reach = _ast_result_for_symbol_reach(_project_paths_for_symbol_reach(req, extra_paths=extra_symbol_paths))
            if _ast_for_reach is not None:
                sym_stamped = apply_symbol_reachability_to_blast_radii(blast_radii, _ast_for_reach)
                if sym_stamped:
                    with lock:
                        job.progress.append(f"Symbol reachability: stamped {sym_stamped} blast-radius row(s) with function-level evidence")
        except Exception as reach_exc:  # noqa: BLE001
            _logger.warning("Reachability surfacing skipped: %s", sanitize_error(reach_exc))
        pipeline.complete_step("analysis", f"Computed {len(blast_radii)} blast radius entries", {"blast_radius": len(blast_radii)})

        # ── Output phase ──
        pipeline.start_step("output", "Building report...")
        from agent_bom.a2a_auth_posture import evaluate_a2a_auth_posture
        from agent_bom.finding import blast_radius_to_finding
        from agent_bom.mcp_auth_posture import evaluate_mcp_auth_posture
        from agent_bom.mcp_blocklist import blocklist_findings_for_agents
        from agent_bom.models import AIBOMReport

        report_findings = [blast_radius_to_finding(br) for br in blast_radii]
        report_findings.extend(blocklist_findings_for_agents(agents))
        try:
            report_findings.extend(evaluate_a2a_auth_posture(agents))
        except Exception as a2a_exc:  # noqa: BLE001
            _logger.warning("A2A auth posture evaluation skipped: %s", sanitize_error(a2a_exc))
        try:
            report_findings.extend(evaluate_mcp_auth_posture(agents))
        except Exception as mcp_auth_exc:  # noqa: BLE001
            _logger.warning("MCP auth posture evaluation skipped: %s", sanitize_error(mcp_auth_exc))
        report = AIBOMReport(agents=agents, blast_radii=blast_radii, findings=report_findings, scan_id=job.job_id)
        if skill_audit_data is not None:
            report.skill_audit_data = skill_audit_data
        if iac_findings_data is not None:
            report.iac_findings_data = iac_findings_data
        if repo_ai_inventory_data is not None:
            report.ai_inventory_data = repo_ai_inventory_data
            _promote_repo_dependency_inventory(report, repo_ai_inventory_data)
        if repo_sast_data is not None:
            report.sast_data = repo_sast_data
        if req.vex:
            from agent_bom.vex import apply_vex, load_vex
            from agent_bom.vex import to_serializable as vex_to_serializable

            try:
                _vex_doc = load_vex(req.vex)
            except ValueError as vex_exc:
                raise RuntimeError(f"Failed to load VEX file: {vex_exc}") from vex_exc
            _vex_count = apply_vex(report, _vex_doc)
            report.vex_data = vex_to_serializable(_vex_doc)
            report.findings = [blast_radius_to_finding(br) for br in blast_radii]
            with lock:
                job.progress.append(f"VEX applied: {_vex_count} vulnerabilities updated from {req.vex}")
        try:
            from agent_bom.scanners import consume_coverage_warnings

            _coverage_warnings = consume_coverage_warnings()
            if _coverage_warnings:
                report.coverage_warnings = _coverage_warnings
        except Exception as cov_exc:  # noqa: BLE001
            _logger.debug("coverage-warning attach skipped: %s", sanitize_error(cov_exc))

        # Opt-in estate enrichment (cloud inventory + NHI discovery). Default
        # OFF: no-op and no network I/O unless the per-provider env flags are
        # set; the graph builder consumes the attached blocks. Never raises.
        try:
            from agent_bom.scan_enrichment import enrich_report_with_estate_discovery

            enrich_report_with_estate_discovery(report)
        except Exception as enrich_exc:  # noqa: BLE001
            _logger.warning("Estate enrichment skipped: %s", sanitize_error(enrich_exc))

        report_json = to_json(report)
        report_json["warnings"] = warnings_all
        with lock:
            job.result = report_json
            job.status = JobStatus.DONE

        if side_effects_enabled:
            try:
                pipeline.update_step("output", "Persisting unified graph...")
                _persist_graph_snapshot(job, report_json, lock=lock)
            except Exception as graph_exc:  # noqa: BLE001
                _logger.warning("Unified graph persistence failed: %s", graph_exc)
                with lock:
                    job.progress.append(f"Graph persistence skipped: {sanitize_error(graph_exc)}")

            try:
                from agent_bom.asset_tracker import AssetTracker

                with AssetTracker(tenant_id=str(getattr(job, "tenant_id", None) or "default")) as tracker:
                    asset_diff = tracker.record_scan(report_json)
                with lock:
                    job.progress.append(
                        "Asset tracker synced "
                        f"(new={asset_diff['summary']['new_count']}, "
                        f"resolved={asset_diff['summary']['resolved_count']}, "
                        f"open={asset_diff['summary']['total_open']})"
                    )
            except Exception as asset_exc:  # noqa: BLE001
                _logger.warning("Asset tracker persistence failed: %s", asset_exc)
                with lock:
                    job.progress.append(f"Asset tracker skipped: {sanitize_error(asset_exc)}")

            try:
                from agent_bom.db.local_analytics import record_scan_report_best_effort

                recorded_scan_id = record_scan_report_best_effort(
                    report_json,
                    source="api",
                    tenant_id=str(getattr(job, "tenant_id", None) or "default"),
                )
                if recorded_scan_id:
                    with lock:
                        job.progress.append(f"Local analytics synced scan {recorded_scan_id}")
            except Exception as local_analytics_exc:  # noqa: BLE001
                _logger.debug("Local analytics persistence skipped: %s", local_analytics_exc)
        else:
            with lock:
                job.progress.append("Result side-effect persistence skipped by request")

        pipeline.complete_step("output", "Report ready")

        # Auto-sync discovered agents to fleet registry
        if side_effects_enabled:
            try:
                _sync_scan_agents_to_fleet(agents, tenant_id=str(getattr(job, "tenant_id", None) or "default"))
            except Exception as fleet_exc:  # noqa: BLE001
                with lock:
                    job.progress.append(f"Fleet sync skipped: {fleet_exc}")

        if side_effects_enabled:
            try:
                from agent_bom.analytics_contract import build_scan_analytics_payload

                analytics_store = _get_analytics_store()
                analytics = build_scan_analytics_payload(report, report_json=report_json, scan_id=job.job_id, source="api")
                # Plumb the job's tenant through to analytics so the shared
                # ClickHouse cluster stays segregated per tenant at row level.
                tenant_id = str(getattr(job, "tenant_id", None) or "default")
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
                _logger.warning("API ClickHouse analytics persistence failed: %s", analytics_exc)
                with lock:
                    job.progress.append(f"Analytics sync skipped: {sanitize_error(analytics_exc)}")

    except Exception as exc:  # noqa: BLE001
        with lock:
            job.status = JobStatus.FAILED
            job.error = sanitize_error(exc)
        # Mark whichever step was running as failed
        for step_id in PIPELINE_STEPS:
            if pipeline._steps[step_id]["status"] == StepStatus.RUNNING:
                pipeline.fail_step(step_id, sanitize_error(exc))
                break
        else:
            with lock:
                job.progress.append(f"Error: {sanitize_error(exc)}")
    finally:
        repo_stack.close()
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
            _logger.error("Scan result persistence failed job=%s: %s", job.job_id, persist_exc)
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
        if job.parent_job_id:
            try:
                from agent_bom.api.scan_batches import refresh_batch_parent

                refresh_batch_parent(job.parent_job_id, tenant_id=job.tenant_id or "default")
            except Exception:  # noqa: BLE001
                _logger.exception("Failed to refresh scan batch parent job=%s child=%s", job.parent_job_id, job.job_id)
        _release_scan_memory()
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
