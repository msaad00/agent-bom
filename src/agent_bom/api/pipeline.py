"""Scan pipeline orchestration — ScanPipeline tracker and _run_scan_sync.

Extracted from api/server.py (Phase 4). Contains:
- ScanPipeline: structured SSE event tracker for scan progress
- _run_scan_sync: full scan pipeline runner (blocking, thread-safe)
- _sync_scan_agents_to_fleet: auto-sync discovered agents to fleet registry
- _now: UTC ISO timestamp helper
"""

from __future__ import annotations

import threading
import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from agent_bom.api.models import JobStatus, ScanJob, StepStatus
from agent_bom.api.stores import _get_fleet_store, _get_store, _job_lock
from agent_bom.security import sanitize_error

# ─── Constants ───────────────────────────────────────────────────────────────

PIPELINE_STEPS = ["discovery", "extraction", "scanning", "enrichment", "analysis", "output"]


# ─── Helpers ─────────────────────────────────────────────────────────────────


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


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
        stats: dict[str, int] | None = None,
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

    def complete_step(self, step_id: str, message: str, stats: dict[str, int] | None = None) -> None:
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


def _sync_scan_agents_to_fleet(agents: list) -> None:
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

    for agent in agents:
        existing = store.get_by_name(agent.name)
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
            import json as _json

            from agent_bom.models import Agent, AgentType, MCPServer

            try:
                with open(req.inventory) as _f:
                    inv_data = _json.load(_f)
            except (_json.JSONDecodeError, OSError) as parse_err:
                raise RuntimeError(f"Failed to load inventory file: {parse_err}") from parse_err
            for agent_data in inv_data.get("agents", []):
                servers = []
                for s in agent_data.get("mcp_servers", []):
                    servers.append(
                        MCPServer(
                            name=s.get("name", "unknown"),
                            command=s.get("command", ""),
                            args=s.get("args", []),
                            env=s.get("env", {}),
                        )
                    )
                agents.append(
                    Agent(
                        name=agent_data.get("name", "unknown"),
                        agent_type=AgentType.CUSTOM,
                        config_path=req.inventory,
                        mcp_servers=servers,
                    )
                )

        for image_ref in req.images:
            pipeline.update_step("discovery", f"Scanning image: {image_ref}")
            from agent_bom.image import scan_image

            img_agents, img_warnings = scan_image(image_ref)
            agents.extend(img_agents)  # type: ignore[arg-type]
            warnings_all.extend(img_warnings)

        if req.k8s:
            pipeline.update_step("discovery", "Scanning Kubernetes pods...")
            from agent_bom.k8s import discover_images

            k8s_records = discover_images(namespace=req.k8s_namespace or "default")
            for img, _pod, _ctr in k8s_records:
                from agent_bom.image import scan_image

                k8s_agents, k8s_warns = scan_image(img)
                agents.extend(k8s_agents)  # type: ignore[arg-type]
                warnings_all.extend(k8s_warns)

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
                from agent_bom.models import Agent, AgentType, MCPServer

                sbom_server = MCPServer(name=f"sbom:{req.sbom}")
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
                from agent_bom.models import Agent, AgentType, MCPServer

                fs_pkgs, fs_strat = scan_filesystem(fs_path)
                if fs_pkgs:
                    from pathlib import Path as _Path

                    fs_server = MCPServer(name=f"fs:{fs_path}")
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

        # ── Extraction phase ──
        pipeline.start_step("extraction", f"Extracting packages from {len(agents)} agent(s)...")
        total_pkgs = 0
        for agent in agents:
            for server in agent.mcp_servers:
                if server.security_blocked:
                    continue  # Don't extract packages from security-blocked servers
                if not server.packages:
                    server.packages = extract_packages(server)
                total_pkgs += len(server.packages)
        pipeline.complete_step("extraction", f"Extracted {total_pkgs} packages", {"packages": total_pkgs})

        # ── Scanning phase ──
        pipeline.start_step("scanning", "Querying OSV.dev for CVEs...")
        blast_radii = scan_agents_sync(agents, enable_enrichment=req.enrich)
        total_vulns = sum(len(p.vulnerabilities) for a in agents for s in a.mcp_servers for p in s.packages)
        pipeline.complete_step("scanning", f"Found {total_vulns} vulnerabilities", {"vulnerabilities": total_vulns})

        # ── Severity filtering (post-scan) ──
        if req.min_severity:
            _sev_order = {"low": 1, "medium": 2, "high": 3, "critical": 4}
            _min = _sev_order.get(req.min_severity.lower(), 0)
            blast_radii = [br for br in blast_radii if _sev_order.get(br.vulnerability.severity.value.lower(), 0) >= _min]

        # ── Enrichment phase ──
        if req.enrich:
            pipeline.start_step("enrichment", "Enriching with NVD CVSS, EPSS, CISA KEV...")
            # Enrichment happens inside scan_agents_sync, so just mark done
            pipeline.complete_step("enrichment", "Enrichment complete")
        else:
            pipeline.skip_step("enrichment", "Enrichment not requested")

        # ── Analysis phase ──
        pipeline.start_step("analysis", "Computing blast radius...")
        pipeline.complete_step("analysis", f"Computed {len(blast_radii)} blast radius entries", {"blast_radius": len(blast_radii)})

        # ── Output phase ──
        pipeline.start_step("output", "Building report...")
        from agent_bom.models import AIBOMReport

        report = AIBOMReport(agents=agents, blast_radii=blast_radii)
        report_json = to_json(report)
        report_json["warnings"] = warnings_all
        with lock:
            job.result = report_json
            job.status = JobStatus.DONE
        pipeline.complete_step("output", "Report ready")

        # Auto-sync discovered agents to fleet registry
        try:
            _sync_scan_agents_to_fleet(agents)
        except Exception as fleet_exc:  # noqa: BLE001
            with lock:
                job.progress.append(f"Fleet sync skipped: {fleet_exc}")

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
        # Persist final state
        _get_store().put(job)
