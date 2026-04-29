"""Scan pipeline orchestration — ScanPipeline tracker and _run_scan_sync.

Extracted from api/server.py (Phase 4). Contains:
- ScanPipeline: structured SSE event tracker for scan progress
- _run_scan_sync: full scan pipeline runner (blocking, thread-safe)
- _sync_scan_agents_to_fleet: auto-sync discovered agents to fleet registry
- _now: UTC ISO timestamp helper
- _executor: shared ThreadPoolExecutor for scan jobs
"""

from __future__ import annotations

import logging
import os
import threading
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from agent_bom import __version__
from agent_bom.api.models import JobStatus, ScanJob, StepStatus
from agent_bom.api.stores import _get_analytics_store, _get_fleet_store, _get_graph_store, _get_store, _job_lock
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
_executor_lock = threading.Lock()
_executor = ThreadPoolExecutor(max_workers=min(8, (os.cpu_count() or 4) + 2))


def get_executor() -> ThreadPoolExecutor:
    """Return the shared scan executor, recreating it if a prior lifespan shut it down."""
    global _executor
    with _executor_lock:
        if _executor._shutdown:
            _executor = ThreadPoolExecutor(max_workers=min(8, (os.cpu_count() or 4) + 2))
        return _executor


# ─── Constants ───────────────────────────────────────────────────────────────

PIPELINE_STEPS = ["discovery", "extraction", "scanning", "enrichment", "analysis", "output"]


# ─── Helpers ─────────────────────────────────────────────────────────────────


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


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
    from agent_bom.graph.webhooks import compute_delta_alerts, dispatch_delta_alerts

    tenant_id = job.tenant_id or "default"
    scan_id = report_json.get("scan_id") or job.job_id
    graph = build_unified_graph_from_report(report_json, scan_id=scan_id, tenant_id=tenant_id)

    previous_graph = None
    graph_store = _get_graph_store()
    previous_scan_id = graph_store.latest_snapshot_id(tenant_id=tenant_id)
    if previous_scan_id and previous_scan_id != scan_id:
        previous_graph = graph_store.load_graph(tenant_id=tenant_id, scan_id=previous_scan_id)
    graph_store.save_graph(graph)

    alerts = compute_delta_alerts(previous_graph, graph)
    delivery = dispatch_delta_alerts(alerts, product_version=__version__) if alerts else None
    _logger.info(
        "Graph persisted for scan=%s tenant=%s nodes=%d edges=%d delta_alerts=%d delta_delivered=%d",
        scan_id,
        tenant_id,
        len(graph.nodes),
        len(graph.edges),
        len(alerts),
        delivery["delivered"] if delivery else 0,
    )
    if lock:
        with lock:
            job.progress.append(f"Graph persisted: {len(graph.nodes)} nodes, {len(graph.edges)} edges")
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
        import json as _json_mod

        # Convert enum values to strings for JSON serialization
        serializable = {k: (v.value if isinstance(v, Enum) else v) for k, v in event.items()}
        line = _json_mod.dumps(serializable)
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

    existing_by_name = {agent.name: agent for agent in store.list_by_tenant(tenant_id)}

    for agent in agents:
        existing = existing_by_name.get(agent.name)
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


# ─── Scan Pipeline Runner ───────────────────────────────────────────────────


def _run_scan_sync(job: ScanJob) -> None:
    """Run the full scan pipeline in a thread (blocking). Updates job in-place."""
    lock = _job_lock(job.job_id)
    with lock:
        job.status = JobStatus.RUNNING
        job.started_at = _now()
    pipeline = ScanPipeline(job, lock)

    try:
        from agent_bom.discovery import discover_all
        from agent_bom.output import to_json
        from agent_bom.parsers import extract_packages
        from agent_bom.scanners import scan_agents_sync
        from agent_bom.security import validate_path

        req = job.request
        agents = []
        warnings_all: list[str] = []

        # ── Path validation (prevent path traversal via API) ──
        path_fields = (
            ([req.inventory] if req.inventory else [])
            + req.tf_dirs
            + ([req.gha_path] if req.gha_path else [])
            + req.agent_projects
            + req.jupyter_dirs
            + ([req.sbom] if req.sbom else [])
            + req.filesystem_paths
        )
        for p in path_fields:
            validate_path(p, must_exist=True)

        # ── Discovery phase ──
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

        for tf_dir in req.tf_dirs:
            pipeline.update_step("discovery", f"Scanning Terraform: {tf_dir}")
            from agent_bom.terraform import scan_terraform_dir

            tf_agents, tf_warnings = scan_terraform_dir(tf_dir)
            agents.extend(tf_agents)
            warnings_all.extend(tf_warnings)

        if req.gha_path:
            pipeline.update_step("discovery", f"Scanning GitHub Actions: {req.gha_path}")
            from agent_bom.github_actions import scan_github_actions

            gha_agents, gha_warnings = scan_github_actions(req.gha_path)
            agents.extend(gha_agents)
            warnings_all.extend(gha_warnings)

        for ap in req.agent_projects:
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
            pipeline.skip_step("extraction", "No agents to extract")
            pipeline.skip_step("scanning", "No packages to scan")
            pipeline.skip_step("enrichment", "Skipped")
            pipeline.skip_step("analysis", "Skipped")
            pipeline.skip_step("output", "No results")
            job.result = {"agents": [], "vulnerabilities": [], "blast_radius": [], "warnings": warnings_all}
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
        scan_message = (
            f"Scanning {total_pkgs} packages via OSV.dev with vulnerability enrichment..."
            if req.enrich
            else f"Scanning {total_pkgs} packages via OSV.dev..."
        )
        pipeline.start_step("scanning", scan_message)
        try:
            blast_radii = scan_agents_sync(agents, enable_enrichment=req.enrich, offline=False)
        except Exception as scan_exc:  # noqa: BLE001
            # Log but don't crash — return what we have with warning
            _logger.warning("Scan phase error (retrying without enrichment): %s", scan_exc)
            pipeline.update_step("scanning", f"Scan error: {sanitize_error(scan_exc)} — retrying without enrichment")
            try:
                blast_radii = scan_agents_sync(agents, enable_enrichment=False, offline=False)
            except Exception as retry_exc:  # noqa: BLE001
                _logger.error("Scan retry also failed: %s", retry_exc)
                blast_radii = []
                warnings_all.append(f"CVE scanning failed: {sanitize_error(retry_exc)}")
        total_vulns = sum(len(p.vulnerabilities) for a in agents for s in a.mcp_servers for p in s.packages)
        if total_pkgs > 0 and total_vulns == 0 and not blast_radii:
            warnings_all.append(
                f"Scanned {total_pkgs} packages but found 0 vulnerabilities. This may indicate a network issue reaching OSV.dev."
            )
        pipeline.complete_step("scanning", f"Found {total_vulns} vulnerabilities", {"vulnerabilities": total_vulns})

        # ── Severity filtering (post-scan) ──
        if req.min_severity:
            _sev_order = {"low": 1, "medium": 2, "high": 3, "critical": 4}
            _min = _sev_order.get(req.min_severity.lower(), 0)
            blast_radii = [br for br in blast_radii if _sev_order.get(br.vulnerability.severity.value.lower(), 0) >= _min]

        try:
            from agent_bom.api.stores import _get_exception_store
            from agent_bom.suppression_rules import apply_tenant_suppression_rules

            suppression = apply_tenant_suppression_rules(blast_radii, _get_exception_store(), tenant_id=job.tenant_id or "default")
            if suppression["suppressed"]:
                warnings_all.append(f"{suppression['suppressed']} finding(s) suppressed by tenant feedback/rules")
        except Exception as exc:  # noqa: BLE001
            _logger.warning("Tenant suppression-rule evaluation skipped: %s", sanitize_error(exc))
            warnings_all.append("Tenant suppression-rule evaluation skipped")

        # ── Enrichment phase ──
        if req.enrich:
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

        # ── Analysis phase ──
        pipeline.start_step("analysis", "Computing blast radius...")
        # Surface graph-walk reachability onto each blast-radius row before
        # the report is built so the JSON payload (and risk_score) reflects
        # whether each vulnerable package is actually reachable from an
        # agent entrypoint, not just present in the dependency closure.
        try:
            from agent_bom.graph.blast_reach import (
                apply_dependency_reachability_to_blast_radii,
            )

            stamped = apply_dependency_reachability_to_blast_radii(blast_radii, agents, rescore=True)
            if stamped:
                with lock:
                    job.progress.append(f"Reachability: stamped {stamped} blast-radius row(s) with graph-walk evidence")
        except Exception as reach_exc:  # noqa: BLE001
            _logger.warning("Reachability surfacing skipped: %s", sanitize_error(reach_exc))
        pipeline.complete_step("analysis", f"Computed {len(blast_radii)} blast radius entries", {"blast_radius": len(blast_radii)})

        # ── Output phase ──
        pipeline.start_step("output", "Building report...")
        from agent_bom.finding import blast_radius_to_finding
        from agent_bom.mcp_blocklist import blocklist_findings_for_agents
        from agent_bom.models import AIBOMReport

        report_findings = [blast_radius_to_finding(br) for br in blast_radii]
        report_findings.extend(blocklist_findings_for_agents(agents))
        report = AIBOMReport(agents=agents, blast_radii=blast_radii, findings=report_findings, scan_id=job.job_id)
        report_json = to_json(report)
        report_json["warnings"] = warnings_all
        with lock:
            job.result = report_json
            job.status = JobStatus.DONE

        try:
            pipeline.update_step("output", "Persisting unified graph...")
            _persist_graph_snapshot(job, report_json, lock=lock)
        except Exception as graph_exc:  # noqa: BLE001
            _logger.warning("Unified graph persistence failed: %s", graph_exc)
            with lock:
                job.progress.append(f"Graph persistence skipped: {sanitize_error(graph_exc)}")

        try:
            from agent_bom.asset_tracker import AssetTracker

            tracker = AssetTracker(tenant_id=str(getattr(job, "tenant_id", None) or "default"))
            asset_diff = tracker.record_scan(report_json)
            tracker.close()
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

        pipeline.complete_step("output", "Report ready")

        # Auto-sync discovered agents to fleet registry
        try:
            _sync_scan_agents_to_fleet(agents, tenant_id=str(getattr(job, "tenant_id", None) or "default"))
        except Exception as fleet_exc:  # noqa: BLE001
            with lock:
                job.progress.append(f"Fleet sync skipped: {fleet_exc}")

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
        with lock:
            job.completed_at = _now()
            terminal_status = job.status
        # Persist final state
        store = _get_store()
        store.put(job)
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
