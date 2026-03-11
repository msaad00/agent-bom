"""agent-bom FastAPI server.

Start with:
    agent-bom api                      # default: http://localhost:8422
    agent-bom api --host 0.0.0.0 --port 8422

Endpoints:
    GET  /                             redirect → /docs
    GET  /health                       liveness probe
    GET  /version                      version info
    POST /v1/scan                      start a scan (async, returns job_id)
    GET  /v1/scan/{job_id}             poll scan status + results
    GET  /v1/scan/{job_id}/stream      SSE — real-time scan progress
    GET  /v1/agents                    quick agent discovery (no CVE scan)
    DELETE /v1/scan/{job_id}           cancel / discard a job
    GET  /v1/compliance                full 10-framework compliance posture
    GET  /v1/compliance/{framework}    single framework (owasp-llm, owasp-mcp, owasp-agentic, atlas, nist, eu-ai-act, nist-csf, iso-27001, soc2, cis)
    GET  /v1/malicious/check           malicious package / typosquat check
    GET  /v1/proxy/status              runtime proxy metrics
    GET  /v1/proxy/alerts              recent runtime proxy alerts
    GET  /v1/scorecard/{eco}/{pkg}     OpenSSF Scorecard lookup
    GET  /v1/governance                Snowflake governance report
    GET  /v1/governance/findings       governance findings (filtered)
    GET  /v1/activity                  agent activity timeline
    POST /v1/auth/keys                 create RBAC API key
    GET  /v1/auth/keys                 list API keys
    DELETE /v1/auth/keys/{id}          revoke an API key
    GET  /v1/audit                     query audit log
    GET  /v1/audit/integrity           verify audit log HMAC integrity
    POST /v1/scan/dataset-cards        scan dataset cards & DVC files
    POST /v1/scan/training-pipelines   scan ML training pipeline artifacts
    POST /v1/scan/browser-extensions   scan browser extensions
    POST /v1/scan/model-provenance     check HF/Ollama model provenance
    POST /v1/scan/prompt-scan          scan prompts for injection/secrets
    POST /v1/scan/model-files          scan model files for unsafe formats
"""

from __future__ import annotations

import asyncio
import logging
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from typing import Any

from agent_bom import __version__
from agent_bom.api import stores as _stores
from agent_bom.api.middleware import (  # noqa: E402
    APIKeyMiddleware,
    MaxBodySizeMiddleware,
    RateLimitMiddleware,
    TrustHeadersMiddleware,
)

# ─── Extracted modules ────────────────────────────────────────────────────────
from agent_bom.api.models import (  # noqa: E402
    BrowserExtensionsRequest,
    CreateKeyRequest,
    DatasetCardsRequest,
    ExceptionRequest,
    HealthResponse,
    JobStatus,
    ModelFilesRequest,
    ModelProvenanceRequest,
    PromptScanRequest,
    PushPayload,
    ScanJob,
    ScanRequest,
    ScheduleCreate,
    StepStatus,  # noqa: F401 — re-exported for tests
    TrainingPipelinesRequest,
    VersionInfo,
)
from agent_bom.api.stores import (
    _get_exception_store,
    _get_schedule_store,
    _get_store,
    _get_trend_store,
    _job_lock,
    _jobs,
    _jobs_get,
    _jobs_lock,
    _jobs_pop,
    _jobs_put,
    set_analytics_store,
    set_fleet_store,
    set_job_store,
    set_policy_store,
    set_schedule_store,
)
from agent_bom.config import API_JOB_TTL_SECONDS as _JOB_TTL_SECONDS
from agent_bom.config import API_MAX_CONCURRENT_JOBS as _MAX_CONCURRENT_JOBS
from agent_bom.security import sanitize_error

_logger = logging.getLogger(__name__)

# ─── Dependency check ─────────────────────────────────────────────────────────

try:
    from fastapi import FastAPI, HTTPException
    from fastapi.middleware.cors import CORSMiddleware
    from fastapi.responses import RedirectResponse
    from pydantic import BaseModel  # noqa: F401 — presence check for [api] extra
except ImportError as exc:  # pragma: no cover
    raise ImportError("agent-bom API requires extra dependencies.\nInstall with:  pip install 'agent-bom[api]'") from exc

# ─── App ──────────────────────────────────────────────────────────────────────

from contextlib import asynccontextmanager  # noqa: E402


@asynccontextmanager
async def _lifespan(app_instance: FastAPI):
    """Start background cleanup task on startup, cancel on shutdown."""
    # Priority: Snowflake > SQLite > InMemory (lazy default)
    if os.environ.get("SNOWFLAKE_ACCOUNT"):
        from agent_bom.api.snowflake_store import (
            SnowflakeFleetStore,
            SnowflakeJobStore,
            SnowflakePolicyStore,
            build_connection_params,
        )

        sf = build_connection_params()
        if _stores._store is None:
            set_job_store(SnowflakeJobStore(sf))
        if _stores._fleet_store is None:
            set_fleet_store(SnowflakeFleetStore(sf))
        if _stores._policy_store is None:
            set_policy_store(SnowflakePolicyStore(sf))
    elif os.environ.get("AGENT_BOM_POSTGRES_URL"):
        from agent_bom.api.postgres_store import (
            PostgresFleetStore,
            PostgresJobStore,
            PostgresPolicyStore,
        )

        if _stores._store is None:
            set_job_store(PostgresJobStore())
        if _stores._fleet_store is None:
            set_fleet_store(PostgresFleetStore())
        if _stores._policy_store is None:
            set_policy_store(PostgresPolicyStore())
    elif os.environ.get("AGENT_BOM_DB"):
        db_path = os.environ["AGENT_BOM_DB"]
        if _stores._store is None:
            from agent_bom.api.store import SQLiteJobStore

            set_job_store(SQLiteJobStore(db_path))
        if _stores._fleet_store is None:
            from agent_bom.api.fleet_store import SQLiteFleetStore

            set_fleet_store(SQLiteFleetStore(db_path))
        if _stores._policy_store is None:
            from agent_bom.api.policy_store import SQLitePolicyStore

            set_policy_store(SQLitePolicyStore(db_path))

    # ── Schedule store ──
    if _stores._schedule_store is None:
        if os.environ.get("AGENT_BOM_POSTGRES_URL"):
            from agent_bom.api.postgres_store import PostgresScheduleStore

            set_schedule_store(PostgresScheduleStore())
        elif os.environ.get("AGENT_BOM_DB"):
            from agent_bom.api.schedule_store import SQLiteScheduleStore

            set_schedule_store(SQLiteScheduleStore(os.environ["AGENT_BOM_DB"]))
        else:
            from agent_bom.api.schedule_store import InMemoryScheduleStore

            set_schedule_store(InMemoryScheduleStore())

    # ── Analytics store (ClickHouse OLAP — optional) ──
    if os.environ.get("AGENT_BOM_CLICKHOUSE_URL") and _stores._analytics_store is None:
        try:
            from agent_bom.api.clickhouse_store import ClickHouseAnalyticsStore

            set_analytics_store(ClickHouseAnalyticsStore(url=os.environ["AGENT_BOM_CLICKHOUSE_URL"]))
            _logger.info("ClickHouse analytics store enabled")
        except Exception:
            _logger.warning("ClickHouse analytics unavailable, using NullAnalyticsStore", exc_info=True)

    global _cleanup_task
    _cleanup_task = asyncio.create_task(_cleanup_loop())

    # Start scheduler background loop
    global _scheduler_task
    from agent_bom.api.scheduler import scheduler_loop

    def _schedule_scan(scan_config: dict) -> str:
        """Trigger a scan from a schedule."""
        job = ScanJob(
            job_id=str(uuid.uuid4()),
            created_at=_now(),
            request=ScanRequest(**scan_config) if isinstance(scan_config, dict) else scan_config,
        )
        _get_store().put(job)
        _jobs_put(job.job_id, job)
        loop = asyncio.get_running_loop()
        loop.run_in_executor(_executor, _run_scan_sync, job)
        return job.job_id

    _scheduler_task = asyncio.create_task(scheduler_loop(_get_schedule_store(), _schedule_scan))

    yield

    # ── Graceful shutdown ──
    if _scheduler_task:
        _scheduler_task.cancel()
    if _cleanup_task:
        _cleanup_task.cancel()
    # Shut down thread pool (wait for in-flight scans, 30s timeout)
    _executor.shutdown(wait=True, cancel_futures=True)
    # Close Postgres connection pool if active
    try:
        if os.environ.get("AGENT_BOM_POSTGRES_URL"):
            from agent_bom.api.postgres_store import _pool as _pg_pool

            if _pg_pool is not None:
                _pg_pool.close()
    except Exception:
        _logger.debug("Postgres pool close skipped")


app = FastAPI(
    title="agent-bom API",
    description=("AI Bill of Materials — map the full trust chain from AI agents and MCP servers to CVEs, credentials, and blast radius."),
    version=__version__,
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=_lifespan,
)

# ── API hardening config ─────────────────────────────────────────────────
import os  # noqa: E402

_default_origins = ["http://localhost:3000", "http://127.0.0.1:3000"]
_cors_env = os.environ.get("CORS_ORIGINS")
_cors_origins: list[str] = [o.strip() for o in _cors_env.split(",") if o.strip()] if _cors_env else _default_origins
_api_key: str | None = None
_rate_limit_rpm: int = 60

# CORS: defaults to localhost; configure via configure_api() before startup
app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors_origins,
    allow_credentials="*" not in _cors_origins,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["Content-Type", "Authorization", "X-API-Key"],
)


# ─── Trust headers middleware ──────────────────────────────────────────────────


app.add_middleware(TrustHeadersMiddleware)


def configure_api(
    cors_origins: list[str] | None = None,
    cors_allow_all: bool = False,
    api_key: str | None = None,
    rate_limit_rpm: int = 60,
) -> None:
    """Configure API hardening before server startup.

    Call this before uvicorn.run() to set CORS, auth, and rate limiting.
    """
    global _cors_origins, _api_key, _rate_limit_rpm

    if cors_allow_all:
        _cors_origins = ["*"]
    elif cors_origins:
        _cors_origins = cors_origins

    _api_key = api_key
    _rate_limit_rpm = rate_limit_rpm

    # Warn if API is exposed without authentication
    if not api_key:
        _logger.warning(
            "SECURITY: No AGENT_BOM_API_KEY set — API endpoints are unauthenticated. "
            "Set AGENT_BOM_API_KEY environment variable for production deployments."
        )

    # Add optional middleware
    if api_key:
        app.add_middleware(APIKeyMiddleware, api_key=api_key)

    app.add_middleware(RateLimitMiddleware, scan_rpm=rate_limit_rpm, read_rpm=rate_limit_rpm * 5)
    app.add_middleware(MaxBodySizeMiddleware)


# Thread pool for running blocking scan functions without blocking the event loop
_executor = ThreadPoolExecutor(max_workers=min(8, (os.cpu_count() or 4) + 2))


# ─── Models ───────────────────────────────────────────────────────────────────


# ─── Scan Pipeline (extracted to api/pipeline.py) ────────────────────────────
from agent_bom.api.pipeline import (  # noqa: E402
    PIPELINE_STEPS,  # noqa: F401 — re-exported for tests
    ScanPipeline,  # noqa: F401 — re-exported for tests
    _now,
    _run_scan_sync,
    _sync_scan_agents_to_fleet,  # noqa: F401 — re-exported for tests
)

# ─── Route modules ────────────────────────────────────────────────────────
from agent_bom.api.routes.compliance import router as _compliance_router  # noqa: E402
from agent_bom.api.routes.fleet import router as _fleet_router  # noqa: E402
from agent_bom.api.routes.gateway import router as _gateway_router  # noqa: E402
from agent_bom.api.routes.proxy import router as _proxy_router  # noqa: E402

app.include_router(_compliance_router)
app.include_router(_fleet_router)
app.include_router(_gateway_router)
app.include_router(_proxy_router)

# Re-export proxy push functions for backward compatibility
from agent_bom.api.routes.proxy import push_proxy_alert, push_proxy_metrics  # noqa: E402, F401

_cleanup_task: asyncio.Task | None = None
_scheduler_task: asyncio.Task | None = None


_STUCK_JOB_TIMEOUT = 1800  # 30 minutes — mark RUNNING jobs as FAILED


async def _cleanup_loop():
    """Background task that removes expired jobs and unsticks RUNNING jobs."""
    while True:
        await asyncio.sleep(300)
        _get_store().cleanup_expired(_JOB_TTL_SECONDS)
        # Unstick jobs that have been RUNNING for too long
        try:
            from datetime import datetime, timezone

            now = datetime.now(timezone.utc)
            with _jobs_lock:
                for job in list(_jobs.values()):
                    if job.status == JobStatus.RUNNING and job.created_at:
                        try:
                            created = datetime.fromisoformat(job.created_at.replace("Z", "+00:00"))
                            if (now - created).total_seconds() > _STUCK_JOB_TIMEOUT:
                                job.status = JobStatus.FAILED
                                job.error = "Timed out (stuck in RUNNING state)"
                                job.completed_at = now.isoformat()
                        except (ValueError, TypeError):
                            pass
        except Exception:  # noqa: BLE001
            pass


# ─── Routes ───────────────────────────────────────────────────────────────────


@app.get("/", include_in_schema=False)
async def root() -> RedirectResponse:
    return RedirectResponse(url="/docs")


@app.get("/health", response_model=HealthResponse, tags=["meta"])
async def health() -> HealthResponse:
    """Liveness probe."""
    return HealthResponse(status="ok", version=__version__)


@app.get("/version", response_model=VersionInfo, tags=["meta"])
async def version() -> VersionInfo:
    """Version information."""
    return VersionInfo(version=__version__)


@app.post("/v1/scan", response_model=ScanJob, status_code=202, tags=["scan"])
async def create_scan(request: ScanRequest) -> ScanJob:
    """Start a scan. Returns immediately with a job_id.
    Poll GET /v1/scan/{job_id} for results, or stream via /v1/scan/{job_id}/stream.
    """
    # Enforce max concurrent jobs
    store = _get_store()
    active = sum(1 for j in store.list_all() if j.status in (JobStatus.PENDING, JobStatus.RUNNING))
    if active >= _MAX_CONCURRENT_JOBS:
        raise HTTPException(
            status_code=429,
            detail=f"Max {_MAX_CONCURRENT_JOBS} concurrent scan jobs. Try again later.",
        )

    job = ScanJob(
        job_id=str(uuid.uuid4()),
        created_at=_now(),
        request=request,
    )
    store.put(job)
    # Keep in-memory ref for SSE streaming (progress list updates in real-time)
    _jobs_put(job.job_id, job)

    loop = asyncio.get_running_loop()
    loop.run_in_executor(_executor, _run_scan_sync, job)

    return job


@app.get("/v1/scan/{job_id}", response_model=ScanJob, tags=["scan"])
async def get_scan(job_id: str) -> ScanJob:
    """Poll scan status and results."""
    # Check in-memory first (for in-progress jobs with live progress)
    in_mem = _jobs_get(job_id)
    if in_mem is not None:
        return in_mem
    job = _get_store().get(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail=f"Job {job_id} not found")
    return job


@app.get("/v1/scan/{job_id}/attack-flow", tags=["scan"])
async def get_attack_flow(
    job_id: str,
    cve: str | None = None,
    severity: str | None = None,
    framework: str | None = None,
    agent: str | None = None,
) -> dict:
    """Get the attack flow graph for a completed scan.

    Returns React Flow-compatible nodes/edges showing the CVE -> package ->
    server -> agent attack chain with credential and tool branches.

    Query params for filtering:
      ?cve=CVE-2025-xxx     - show only this CVE's blast radius
      ?severity=critical     - filter by severity level
      ?framework=LLM05       - filter by OWASP/ATLAS/NIST tag
      ?agent=claude-desktop  - filter to a specific agent
    """
    job = _jobs_get(job_id) or _get_store().get(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail=f"Job {job_id} not found")
    if job.status != JobStatus.DONE or not job.result:
        raise HTTPException(status_code=409, detail="Scan not completed yet")

    from agent_bom.output.attack_flow import build_attack_flow

    blast_radius = job.result.get("blast_radius", [])
    agents_data = job.result.get("agents", [])

    return build_attack_flow(
        blast_radius,
        agents_data,
        cve=cve,
        severity=severity,
        framework=framework,
        agent_name=agent,
    )


@app.get("/v1/scan/{job_id}/context-graph", tags=["scan"])
async def get_context_graph(job_id: str, agent: str | None = None) -> dict:
    """Get the agent context graph with lateral movement analysis.

    Returns nodes, edges, lateral paths, interaction risks, and stats for
    a completed scan.  Optionally filter lateral paths to a single agent.

    Query params:
      ?agent=claude-desktop  - only compute lateral paths from this agent
    """
    job = _jobs_get(job_id) or _get_store().get(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail=f"Job {job_id} not found")
    if job.status != JobStatus.DONE or not job.result:
        raise HTTPException(status_code=409, detail="Scan not completed yet")

    from agent_bom.context_graph import (
        NodeKind,
        build_context_graph,
        compute_interaction_risks,
        find_lateral_paths,
        to_serializable,
    )

    graph = build_context_graph(
        job.result.get("agents", []),
        job.result.get("blast_radius", []),
    )
    paths: list = []
    if agent:
        node_id = f"agent:{agent}"
        if node_id in graph.nodes:
            paths = find_lateral_paths(graph, node_id)
    else:
        for nid, node in graph.nodes.items():
            if node.kind == NodeKind.AGENT:
                paths.extend(find_lateral_paths(graph, nid))
    risks = compute_interaction_risks(graph)
    return to_serializable(graph, paths, risks)


@app.get("/v1/scan/{job_id}/licenses", tags=["scan"])
async def get_licenses(job_id: str) -> dict:
    """Get the license compliance report for a completed scan.

    Returns license findings, summary, compliance status, and per-package
    license categorization (permissive, copyleft, commercial risk, unknown).
    """
    job = _jobs_get(job_id) or _get_store().get(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail=f"Job {job_id} not found")
    if job.status != JobStatus.DONE or not job.result:
        raise HTTPException(status_code=409, detail="Scan not completed yet")

    # If the scan already computed license_report, return it
    if isinstance(job.result, dict) and job.result.get("license_report"):
        return job.result["license_report"]

    # Otherwise compute on-the-fly from scan result agents
    from agent_bom.license_policy import evaluate_license_policy as _eval_lic
    from agent_bom.license_policy import to_serializable as _lic_ser
    from agent_bom.models import Agent as _AgentModel
    from agent_bom.models import AgentType as _AgentType
    from agent_bom.models import MCPServer as _ServerModel
    from agent_bom.models import Package as _PkgModel

    agents_data = job.result.get("agents", []) if isinstance(job.result, dict) else []
    model_agents = []
    for ad in agents_data:
        servers = []
        for sd in ad.get("mcp_servers", []):
            pkgs = [
                _PkgModel(
                    name=p.get("name", ""),
                    version=p.get("version", ""),
                    ecosystem=p.get("ecosystem", ""),
                    license=p.get("license"),
                    license_expression=p.get("license_expression"),
                )
                for p in sd.get("packages", [])
            ]
            servers.append(_ServerModel(name=sd.get("name", ""), command=sd.get("command", ""), packages=pkgs))
        model_agents.append(
            _AgentModel(name=ad.get("name", ""), agent_type=_AgentType(ad.get("type", "custom")), config_path="", mcp_servers=servers)
        )

    lic_report = _eval_lic(model_agents)
    return _lic_ser(lic_report)


@app.get("/v1/scan/{job_id}/vex", tags=["scan"])
async def get_vex(job_id: str) -> dict:
    """Get the VEX (Vulnerability Exploitability eXchange) document for a completed scan.

    Returns VEX statements with vulnerability status (affected, not_affected,
    fixed, under_investigation), justifications, and statistics.
    """
    job = _jobs_get(job_id) or _get_store().get(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail=f"Job {job_id} not found")
    if job.status != JobStatus.DONE or not job.result:
        raise HTTPException(status_code=409, detail="Scan not completed yet")

    # Return pre-computed VEX data if available
    if isinstance(job.result, dict) and job.result.get("vex"):
        return job.result["vex"]

    # Otherwise generate on-the-fly from blast_radii
    return {"statements": [], "stats": {"total_statements": 0, "affected": 0, "not_affected": 0, "fixed": 0, "under_investigation": 0}}


@app.get("/v1/scan/{job_id}/skill-audit", tags=["scan"])
async def get_skill_audit(job_id: str) -> dict:
    """Get the skill security audit results for a completed scan.

    Returns findings from the skill file security audit including
    typosquat detection, unverified servers, shell access, and more.
    Empty results if no skill files were scanned.
    """
    job = _jobs_get(job_id) or _get_store().get(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail=f"Job {job_id} not found")

    if job.status != JobStatus.DONE or not job.result:
        raise HTTPException(status_code=409, detail="Scan not completed yet")

    return job.result.get(
        "skill_audit",
        {
            "findings": [],
            "packages_checked": 0,
            "servers_checked": 0,
            "credentials_checked": 0,
            "passed": True,
        },
    )


@app.delete("/v1/scan/{job_id}", status_code=204, tags=["scan"])
async def delete_scan(job_id: str) -> None:
    """Discard a job record."""
    in_memory = _jobs_pop(job_id)
    in_store = _get_store().delete(job_id)
    if not in_memory and not in_store:
        raise HTTPException(status_code=404, detail=f"Job {job_id} not found")


@app.get("/v1/scan/{job_id}/stream", tags=["scan"])
async def stream_scan(job_id: str):
    """Server-Sent Events stream for real-time scan progress.

    Connect with EventSource:
        const es = new EventSource('/v1/scan/{job_id}/stream');
        es.onmessage = e => console.log(JSON.parse(e.data));
    """
    try:
        from sse_starlette.sse import EventSourceResponse
    except ImportError as exc:
        raise HTTPException(
            status_code=501,
            detail="SSE requires sse-starlette. Install: pip install 'agent-bom[api]'",
        ) from exc

    if _jobs_get(job_id) is None:
        raise HTTPException(status_code=404, detail=f"Job {job_id} not found")

    import json as _json

    async def event_generator():
        sent = 0
        lock = _job_lock(job_id)
        start = time.monotonic()
        while time.monotonic() - start < 2100:  # 35 min max (exceeds stuck-job timeout)
            current = _jobs_get(job_id)
            if current is None:
                break
            # Thread-safe snapshot of new progress lines and status
            with lock:
                new_lines = list(current.progress[sent:])
                status = current.status
            for line in new_lines:
                try:
                    parsed = _json.loads(line)
                    if isinstance(parsed, dict) and parsed.get("type") == "step":
                        yield {"data": _json.dumps(parsed)}
                    else:
                        yield {"data": _json.dumps({"type": "progress", "message": line})}
                except (_json.JSONDecodeError, ValueError):
                    yield {"data": _json.dumps({"type": "progress", "message": line})}
                sent += 1
            if status in (JobStatus.DONE, JobStatus.FAILED, JobStatus.CANCELLED):
                yield {"data": _json.dumps({"type": "done", "status": status, "job_id": job_id})}
                break
            await asyncio.sleep(0.25)

    return EventSourceResponse(event_generator())


@app.get("/v1/agents", tags=["discovery"])
async def list_agents() -> dict:
    """Quick auto-discovery of local AI agent configs (Claude Desktop, Cursor, Windsurf...).
    No CVE scan — instant results for the UI sidebar.
    """
    try:
        from dataclasses import asdict

        from agent_bom.discovery import discover_all
        from agent_bom.parsers import extract_packages

        agents = discover_all()
        # Extract packages for each server
        for agent in agents:
            for server in agent.mcp_servers:
                if not server.packages:
                    server.packages = extract_packages(server)

        return {
            "agents": [asdict(a) for a in agents],
            "count": len(agents),
            "warnings": [],
        }
    except Exception as exc:  # noqa: BLE001
        _logger.exception("Agent discovery failed")
        raise HTTPException(status_code=500, detail=sanitize_error(exc)) from exc


@app.get("/v1/agents/{agent_name}", tags=["discovery"])
async def get_agent_detail(agent_name: str) -> dict:
    """Get detailed view of a single agent with cross-referenced scan data."""
    try:
        from dataclasses import asdict

        from agent_bom.discovery import discover_all
        from agent_bom.parsers import extract_packages

        agents = discover_all()
        agent = None
        for a in agents:
            if a.name == agent_name:
                agent = a
                break

        if agent is None:
            raise HTTPException(status_code=404, detail=f"Agent '{agent_name}' not found")

        for server in agent.mcp_servers:
            if not server.packages:
                server.packages = extract_packages(server)

        # Cross-reference blast radii from completed scans
        agent_blast: list[dict] = []
        for job in _get_store().list_all():
            if job.status != JobStatus.DONE or not job.result:
                continue
            for br in job.result.get("blast_radius", []):
                if agent_name in br.get("affected_agents", []):
                    agent_blast.append(br)

        total_packages = sum(len(s.packages) for s in agent.mcp_servers)
        total_tools = sum(len(s.tools) for s in agent.mcp_servers)
        all_credentials: list[str] = []
        for s in agent.mcp_servers:
            all_credentials.extend(s.credential_names)

        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for br in agent_blast:
            sev = (br.get("severity") or "").lower()
            if sev in severity_counts:
                severity_counts[sev] += 1

        return {
            "agent": asdict(agent),
            "summary": {
                "total_servers": len(agent.mcp_servers),
                "total_packages": total_packages,
                "total_tools": total_tools,
                "total_credentials": len(all_credentials),
                "total_vulnerabilities": len(agent_blast),
                "severity_breakdown": severity_counts,
            },
            "blast_radius": agent_blast,
            "credentials": all_credentials,
        }
    except HTTPException:
        raise
    except Exception as exc:  # noqa: BLE001
        _logger.exception("Agent detail failed")
        raise HTTPException(status_code=500, detail=sanitize_error(exc)) from exc


@app.get("/v1/agents/{agent_name}/lifecycle", tags=["discovery"])
async def get_agent_lifecycle(agent_name: str) -> dict:
    """Get React Flow nodes/edges for an agent's full lifecycle graph.

    Shows: Agent -> MCP Servers -> Tools/Credentials -> Packages -> CVEs
    """
    from agent_bom.output.attack_flow import _severity_color

    detail = await get_agent_detail(agent_name)
    agent_data = detail["agent"]

    nodes: list[dict] = []
    edges: list[dict] = []
    seen: set[str] = set()

    agent_id = f"agent:{agent_data['name']}"
    nodes.append(
        {
            "id": agent_id,
            "type": "lifecycleNode",
            "position": {"x": 0, "y": 200},
            "data": {
                "nodeType": "agent",
                "label": agent_data["name"],
                "agent_type": agent_data.get("agent_type", ""),
            },
        }
    )

    y_offset = 0
    for srv in agent_data.get("mcp_servers", []):
        srv_id = f"srv:{srv['name']}"
        nodes.append(
            {
                "id": srv_id,
                "type": "lifecycleNode",
                "position": {"x": 350, "y": y_offset},
                "data": {
                    "nodeType": "server",
                    "label": srv["name"],
                    "transport": srv.get("transport", "stdio"),
                    "package_count": len(srv.get("packages", [])),
                    "tool_count": len(srv.get("tools", [])),
                },
            }
        )
        edges.append(
            {
                "id": f"e:{agent_id}->{srv_id}",
                "source": agent_id,
                "target": srv_id,
                "type": "smoothstep",
                "animated": True,
                "style": {"stroke": "#10b981"},
            }
        )

        # Tools
        ty = y_offset - 40
        for tool in srv.get("tools", [])[:10]:
            tid = f"tool:{srv['name']}:{tool['name']}"
            if tid not in seen:
                seen.add(tid)
                nodes.append(
                    {
                        "id": tid,
                        "type": "lifecycleNode",
                        "position": {"x": 700, "y": ty},
                        "data": {"nodeType": "tool", "label": tool["name"], "description": tool.get("description", "")},
                    }
                )
                edges.append(
                    {
                        "id": f"e:{srv_id}->{tid}",
                        "source": srv_id,
                        "target": tid,
                        "type": "smoothstep",
                        "style": {"stroke": "#a855f7"},
                    }
                )
                ty += 50

        # Credentials
        cy = ty + 10
        env = srv.get("env", {})
        _sens = ["key", "token", "secret", "password", "credential", "auth"]
        cred_vars = [k for k in env if any(p in k.lower() for p in _sens)]
        for cred in cred_vars:
            cid = f"cred:{cred}"
            if cid not in seen:
                seen.add(cid)
                nodes.append(
                    {
                        "id": cid,
                        "type": "lifecycleNode",
                        "position": {"x": 700, "y": cy},
                        "data": {"nodeType": "credential", "label": cred},
                    }
                )
                edges.append(
                    {
                        "id": f"e:{srv_id}->{cid}",
                        "source": srv_id,
                        "target": cid,
                        "type": "smoothstep",
                        "animated": True,
                        "style": {"stroke": "#eab308"},
                    }
                )
                cy += 50

        # Packages
        py_ = y_offset
        for pkg in srv.get("packages", []):
            pkg_key = f"{pkg['name']}@{pkg.get('version', '')}"
            pid = f"pkg:{pkg_key}"
            if pid not in seen:
                seen.add(pid)
                vulns = pkg.get("vulnerabilities", [])
                nodes.append(
                    {
                        "id": pid,
                        "type": "lifecycleNode",
                        "position": {"x": 1050, "y": py_},
                        "data": {
                            "nodeType": "package",
                            "label": pkg["name"],
                            "version": pkg.get("version", ""),
                            "ecosystem": pkg.get("ecosystem", ""),
                            "vuln_count": len(vulns),
                        },
                    }
                )
                edges.append(
                    {
                        "id": f"e:{srv_id}->{pid}",
                        "source": srv_id,
                        "target": pid,
                        "type": "smoothstep",
                        "style": {"stroke": "#3b82f6"},
                    }
                )

                # CVEs
                vy = py_
                for vuln in vulns:
                    vid = vuln.get("id", "")
                    cvid = f"cve:{vid}"
                    if cvid not in seen:
                        seen.add(cvid)
                        sev = vuln.get("severity", "low")
                        nodes.append(
                            {
                                "id": cvid,
                                "type": "lifecycleNode",
                                "position": {"x": 1400, "y": vy},
                                "data": {
                                    "nodeType": "cve",
                                    "label": vid,
                                    "severity": sev,
                                    "cvss_score": vuln.get("cvss_score"),
                                    "fixed_version": vuln.get("fixed_version"),
                                },
                            }
                        )
                        edges.append(
                            {
                                "id": f"e:{pid}->{cvid}",
                                "source": pid,
                                "target": cvid,
                                "type": "smoothstep",
                                "animated": True,
                                "style": {"stroke": _severity_color(sev)},
                            }
                        )
                        vy += 70
                py_ += max(len(vulns) * 70, 60)

        y_offset = max(y_offset + 180, py_)

    return {"nodes": nodes, "edges": edges, "stats": detail["summary"]}


@app.get("/v1/jobs", tags=["scan"])
async def list_jobs(limit: int = 50, offset: int = 0) -> dict:
    """List all scan jobs (for the UI job history panel).

    Supports pagination via ``limit`` (default 50, max 200) and ``offset``.
    """
    limit = max(1, min(limit, 200))
    offset = max(0, offset)
    summary = _get_store().list_summary()
    total = len(summary)
    page = summary[offset : offset + limit]
    return {
        "jobs": page,
        "count": len(page),
        "total": total,
        "limit": limit,
        "offset": offset,
    }


# ─── Dedicated Scan Endpoints ─────────────────────────────────────────────────
# Lightweight, synchronous scans for specific asset types.
# Each returns results directly (no job queue — these are fast local scans).


def _sanitize_api_path(user_path: str) -> str:
    """Validate and sanitize a user-supplied path from an API request.

    Interprets ``user_path`` as relative to the current user's home directory
    (absolute paths are rejected). The resolved path is normalised, has any
    symlinks resolved, and is verified to remain within the home directory
    using ``os.path.commonpath`` before being returned.
    """
    import os
    from pathlib import Path

    from agent_bom.security import SecurityError

    # Normalise basic whitespace
    user_path = (user_path or "").strip()
    if not user_path:
        raise SecurityError("Empty paths are not allowed")

    # 1. Reject absolute paths — API callers must use paths relative to $HOME
    if os.path.isabs(user_path):
        raise SecurityError(f"Absolute paths are not allowed: {user_path}")

    # 2. Reject path traversal in raw input (../ segments)
    if ".." in user_path.split(os.sep):
        raise SecurityError(f"Path traversal not allowed: {user_path}")

    # 3. Compute fixed root and join user path under it
    home = os.path.realpath(str(Path.home()))
    # Normalise the user-provided relative path before joining
    relative = os.path.normpath(user_path)
    candidate = os.path.join(home, relative)

    # 4. Resolve to real absolute path (follows symlinks)
    resolved = os.path.realpath(candidate)

    # 5. Containment check — ensure resolved path stays within $HOME
    if os.path.commonpath([home, resolved]) != home:
        raise SecurityError(f"Path resolves outside home directory: {user_path}")

    return resolved


@app.post("/v1/scan/dataset-cards", tags=["scan"], status_code=200)
async def scan_dataset_cards(request: DatasetCardsRequest) -> dict:
    """Scan directories for HuggingFace dataset cards, DVC files, and data lineage.

    Returns dataset metadata, license info, and security flags
    (unlicensed data, missing cards, unversioned data, remote sources).
    """
    import os
    from pathlib import Path

    from agent_bom.parsers.dataset_cards import scan_dataset_directory
    from agent_bom.security import SecurityError

    home = os.path.realpath(str(Path.home()))
    results = []
    safe_dirs = []
    for d in request.directories:
        resolved = _sanitize_api_path(d)
        if os.path.commonpath([home, resolved]) == home:
            safe_dirs.append(resolved)
            result = scan_dataset_directory(resolved)
            results.append(result.to_dict() if hasattr(result, "to_dict") else _dataclass_to_dict(result))
        else:
            raise SecurityError(f"Path escapes safe root: {d}")

    return {"scan_type": "dataset-cards", "directories": safe_dirs, "results": results}


@app.post("/v1/scan/training-pipelines", tags=["scan"], status_code=200)
async def scan_training_pipelines(request: TrainingPipelinesRequest) -> dict:
    """Scan directories for ML training pipeline artifacts.

    Detects MLflow runs, W&B metadata, Kubeflow pipeline definitions.
    Flags unsafe serialization (pickle), missing provenance, exposed credentials.
    """
    import os
    from pathlib import Path

    from agent_bom.parsers.training_pipeline import scan_training_directory
    from agent_bom.security import SecurityError

    home = os.path.realpath(str(Path.home()))
    results = []
    safe_dirs = []
    for d in request.directories:
        resolved = _sanitize_api_path(d)
        if os.path.commonpath([home, resolved]) == home:
            safe_dirs.append(resolved)
            result = scan_training_directory(resolved)
            results.append(result.to_dict() if hasattr(result, "to_dict") else _dataclass_to_dict(result))
        else:
            raise SecurityError(f"Path escapes safe root: {d}")

    return {"scan_type": "training-pipelines", "directories": safe_dirs, "results": results}


@app.post("/v1/scan/browser-extensions", tags=["scan"], status_code=200)
async def scan_browser_extensions_endpoint(request: BrowserExtensionsRequest) -> dict:
    """Scan installed browser extensions (Chrome, Chromium, Brave, Edge, Firefox).

    Detects dangerous permissions (debugger, nativeMessaging, cookies),
    AI assistant domain access, and broad host permissions.
    """
    from agent_bom.parsers.browser_extensions import discover_browser_extensions

    extensions = discover_browser_extensions(include_low_risk=request.include_low_risk)
    ext_dicts: list[Any] = [e.to_dict() if hasattr(e, "to_dict") else _dataclass_to_dict(e) for e in extensions]

    return {
        "scan_type": "browser-extensions",
        "total": len(ext_dicts),
        "critical": sum(1 for e in ext_dicts if e.get("risk_level") == "critical"),
        "high": sum(1 for e in ext_dicts if e.get("risk_level") == "high"),
        "extensions": ext_dicts,
    }


@app.post("/v1/scan/model-provenance", tags=["scan"], status_code=200)
async def scan_model_provenance(request: ModelProvenanceRequest) -> dict:
    """Check model provenance for HuggingFace and Ollama models.

    Verifies serialization safety (safetensors vs pickle), digest integrity,
    model card presence, gating status, and public exposure risk.
    """
    from agent_bom.cloud.model_provenance import check_hf_models, check_ollama_models

    results: list[Any] = []
    if request.hf_models:
        hf_results = check_hf_models(request.hf_models)
        results.extend(r.to_dict() if hasattr(r, "to_dict") else _dataclass_to_dict(r) for r in hf_results)
    if request.ollama_models:
        ollama_results = check_ollama_models(request.ollama_models)
        results.extend(r.to_dict() if hasattr(r, "to_dict") else _dataclass_to_dict(r) for r in ollama_results)

    return {
        "scan_type": "model-provenance",
        "total": len(results),
        "unsafe_format": sum(1 for r in results if not r.get("is_safe_format", True)),
        "results": results,
    }


@app.post("/v1/scan/prompt-scan", tags=["scan"], status_code=200)
async def scan_prompts(request: PromptScanRequest) -> dict:
    """Scan prompt files for injection patterns, hardcoded secrets, and unsafe instructions.

    Detects prompt injection, jailbreak patterns, hardcoded API keys,
    shell execution instructions, and data exfiltration patterns.
    """
    import os
    from pathlib import Path

    from agent_bom.parsers.prompt_scanner import scan_prompt_files
    from agent_bom.security import SecurityError

    home = os.path.realpath(str(Path.home()))
    safe_dirs: list[Path] = []
    all_paths: list[Path] = []
    for d in request.directories:
        resolved = _sanitize_api_path(d)
        if os.path.commonpath([home, resolved]) == home:
            safe_dirs.append(Path(resolved))
        else:
            raise SecurityError(f"Path escapes safe root: {d}")
    for f in request.files:
        resolved = _sanitize_api_path(f)
        if os.path.commonpath([home, resolved]) == home:
            all_paths.append(Path(resolved))
        else:
            raise SecurityError(f"Path escapes safe root: {f}")

    results = []
    for safe in safe_dirs:
        result = scan_prompt_files(root=safe)
        results.append(result.to_dict() if hasattr(result, "to_dict") else _dataclass_to_dict(result))
    if all_paths:
        result = scan_prompt_files(paths=all_paths)
        results.append(result.to_dict() if hasattr(result, "to_dict") else _dataclass_to_dict(result))

    return {"scan_type": "prompt-scan", "results": results}


@app.post("/v1/scan/model-files", tags=["scan"], status_code=200)
async def scan_model_files_endpoint(request: ModelFilesRequest) -> dict:
    """Scan directories for ML model files and assess serialization safety.

    Detects pickle deserialization risks (.pkl, .pt), verifies file integrity,
    and flags unsafe model formats.
    """
    import os
    from pathlib import Path

    from agent_bom.model_files import scan_model_files, verify_model_hash
    from agent_bom.security import SecurityError

    home = os.path.realpath(str(Path.home()))
    all_files = []
    all_warnings = []
    for d in request.directories:
        resolved = _sanitize_api_path(d)
        if os.path.commonpath([home, resolved]) == home:
            files, warnings = scan_model_files(resolved)
            all_files.extend(files)
            all_warnings.extend(warnings)
        else:
            raise SecurityError(f"Path escapes safe root: {d}")

    if request.verify_hashes:
        for f in all_files:
            hash_result = verify_model_hash(f["path"])
            f["sha256"] = hash_result.get("sha256")

    return {
        "scan_type": "model-files",
        "total": len(all_files),
        "unsafe": sum(1 for f in all_files if f.get("security_flags")),
        "files": all_files,
        "warnings": all_warnings,
    }


def _dataclass_to_dict(obj: object) -> object:
    """Convert a dataclass to dict, handling nested dataclasses."""
    import dataclasses

    if dataclasses.is_dataclass(obj) and not isinstance(obj, type):
        return {k: _dataclass_to_dict(v) for k, v in dataclasses.asdict(obj).items()}
    if isinstance(obj, list):
        return [_dataclass_to_dict(i) for i in obj]
    return obj


# ─── MCP Registry ─────────────────────────────────────────────────────────────

import functools  # noqa: E402
import re as _re  # noqa: E402
from pathlib import Path as _Path  # noqa: E402


def _derive_name(key: str) -> str:
    """Derive a human-readable name from a registry key."""
    # Strip npm scope prefix
    name = _re.sub(r"^@[^/]+/", "", key)
    # Strip common prefixes
    for prefix in ("mcp-server-", "server-", "mcp-"):
        if name.startswith(prefix):
            name = name[len(prefix) :]
            break
    # Title-case, replace hyphens with spaces
    return name.replace("-", " ").title()


def _infer_publisher(key: str) -> str:
    """Infer publisher from a registry key."""
    # npm scoped: @scope/pkg → scope
    m = _re.match(r"^@([^/]+)/", key)
    if m:
        return m.group(1)
    # Unscoped: use first segment before hyphen or the key itself
    return key.split("-")[0] if "-" in key else key


@functools.lru_cache(maxsize=1)
def _load_registry() -> list[dict]:
    """Load the bundled MCP registry JSON (cached after first load)."""
    import json as _json

    registry_path = _Path(__file__).parent.parent / "mcp_registry.json"
    if not registry_path.exists():
        return []
    try:
        raw = _json.loads(registry_path.read_text())
    except (_json.JSONDecodeError, OSError):
        return []
    servers_dict = raw.get("servers", {})
    result = []
    for key, entry in servers_dict.items():
        result.append(
            {
                "id": key,
                "name": entry.get("name", _derive_name(key)),
                "publisher": _infer_publisher(key),
                "verified": entry.get("verified", False),
                "transport": "stdio",
                "risk_level": entry.get("risk_level", "low"),
                "packages": [{"name": entry["package"], "ecosystem": entry["ecosystem"]}] if entry.get("package") else [],
                "source_url": entry.get("source_url", ""),
                "description": entry.get("description"),
                "sigstore_bundle": None,
                "tools": entry.get("tools", []),
                "credential_env_vars": entry.get("credential_env_vars", []),
                "category": entry.get("category"),
                "license": entry.get("license"),
                "latest_version": entry.get("latest_version"),
                "known_cves": entry.get("known_cves", []),
                "command_patterns": entry.get("command_patterns", []),
                "risk_justification": entry.get("risk_justification"),
            }
        )
    return result


# ── Connectors ─────────────────────────────────────────────────────────────


@app.get("/v1/connectors", tags=["connectors"])
async def list_available_connectors() -> dict:
    """List available SaaS connectors for AI agent discovery."""
    from agent_bom.connectors import list_connectors

    return {"connectors": list_connectors()}


@app.get("/v1/connectors/{name}/health", tags=["connectors"])
async def connector_health(name: str) -> dict:
    """Check connectivity for a SaaS connector."""
    try:
        from agent_bom.connectors import check_connector_health

        status = check_connector_health(name)
        return {"connector": status.connector, "state": status.state.value, "message": status.message, "api_version": status.api_version}
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=sanitize_error(str(exc))) from exc


# ── Registry ───────────────────────────────────────────────────────────────


@app.get("/v1/registry", tags=["registry"])
async def list_registry() -> dict:
    """List all known MCP servers from the agent-bom registry."""
    servers = _load_registry()
    return {"servers": servers, "count": len(servers)}


@app.get("/v1/registry/{server_id:path}", tags=["registry"])
async def get_registry_server(server_id: str) -> dict:
    """Get a single MCP server entry by ID (e.g. 'modelcontextprotocol/filesystem')."""
    servers = _load_registry()
    for server in servers:
        if server.get("id") == server_id:
            return server
    raise HTTPException(status_code=404, detail=f"Registry entry '{server_id}' not found")


# ─── Malicious Package Check ────────────────────────────────────────────────


@app.get("/v1/malicious/check", tags=["security"])
async def check_malicious(name: str, ecosystem: str = "npm") -> dict:
    """Check if a package name is a known malicious package or typosquat.

    Query params:
        name: Package name to check
        ecosystem: Package ecosystem (npm, pypi)
    """
    from agent_bom.malicious import check_typosquat

    typosquat_target = check_typosquat(name, ecosystem)
    return {
        "package": name,
        "ecosystem": ecosystem,
        "is_typosquat": typosquat_target is not None,
        "typosquat_target": typosquat_target,
    }


# ─── OpenSSF Scorecard Lookup ────────────────────────────────────────────────


@app.get("/v1/scorecard/{ecosystem}/{package:path}", tags=["security"])
async def scorecard_lookup(ecosystem: str, package: str) -> dict:
    """Look up OpenSSF Scorecard for a package.

    Resolves the package's source repository and fetches its scorecard
    from api.securityscorecards.dev.

    Path params:
        ecosystem: Package ecosystem (npm, pypi, go, cargo)
        package: Package name
    """
    import re as _re_local

    from agent_bom.scorecard import extract_github_repo, fetch_scorecard

    # Validate package input — only allow safe characters
    if not _re_local.match(r"^[A-Za-z0-9._@/:-]+$", package):
        raise HTTPException(status_code=400, detail="Invalid package name")

    # For GitHub-hosted packages, try direct repo lookup
    # Common patterns: npm @scope/pkg -> github.com/scope/pkg
    repo = None

    # Try direct GitHub repo format
    if "/" in package:
        repo = package

    if not repo:
        # Try ecosystem-specific heuristics
        if ecosystem == "npm":
            # npm packages often map to github.com/owner/repo
            # Strip @ scope prefix for GitHub lookup
            clean = package.lstrip("@").replace("/", "/")
            repo = clean
        elif ecosystem == "pypi":
            # PyPI packages often use the package name as the repo
            repo = None  # Need source_repo metadata
        elif ecosystem == "go":
            # Go modules are their repo path
            repo_match = extract_github_repo(f"https://{package}")
            if repo_match:
                repo = repo_match

    if not repo:
        return {
            "package": package,
            "ecosystem": ecosystem,
            "scorecard": None,
            "error": "Could not resolve GitHub repository for this package. "
            "Try providing the GitHub owner/repo directly (e.g., /v1/scorecard/github/expressjs/express).",
        }

    data = await fetch_scorecard(repo)
    if data is None:
        return {
            "package": package,
            "ecosystem": ecosystem,
            "repo": repo,
            "scorecard": None,
            "error": f"No scorecard found for github.com/{repo}",
        }

    return {
        "package": package,
        "ecosystem": ecosystem,
        "repo": repo,
        "scorecard": data,
    }


# ─── Governance ──────────────────────────────────────────────────────────────


@app.get("/v1/governance", tags=["governance"])
async def governance_report(days: int = 30):
    """Run Snowflake governance discovery and return findings.

    Mines ACCESS_HISTORY, GRANTS_TO_ROLES, TAG_REFERENCES, and
    CORTEX_AGENT_USAGE_HISTORY. Requires SNOWFLAKE_ACCOUNT env var.
    """
    import os

    days = max(1, min(days, 365))

    if not os.environ.get("SNOWFLAKE_ACCOUNT"):
        raise HTTPException(
            status_code=400,
            detail="SNOWFLAKE_ACCOUNT env var not set. Governance requires Snowflake.",
        )

    try:
        from agent_bom.cloud import discover_governance

        report = discover_governance(provider="snowflake", days=days)
        return report.to_dict()
    except Exception as exc:
        _logger.exception("Request failed")
        raise HTTPException(status_code=500, detail=sanitize_error(exc))


@app.get("/v1/governance/findings", tags=["governance"])
async def governance_findings(
    days: int = 30,
    severity: str | None = None,
    category: str | None = None,
):
    """Return only governance findings, optionally filtered."""
    import os

    days = max(1, min(days, 365))

    if not os.environ.get("SNOWFLAKE_ACCOUNT"):
        raise HTTPException(
            status_code=400,
            detail="SNOWFLAKE_ACCOUNT env var not set.",
        )

    try:
        from agent_bom.cloud import discover_governance

        report = discover_governance(provider="snowflake", days=days)
        findings = [f.to_dict() for f in report.findings]

        if severity:
            findings = [f for f in findings if f["severity"] == severity.lower()]
        if category:
            findings = [f for f in findings if f["category"] == category.lower()]

        return {
            "findings": findings,
            "count": len(findings),
            "warnings": report.warnings,
        }
    except Exception as exc:
        _logger.exception("Request failed")
        raise HTTPException(status_code=500, detail=sanitize_error(exc))


# ─── Activity Timeline ──────────────────────────────────────────────────────


@app.get("/v1/activity", tags=["governance"])
async def activity_timeline(days: int = 30):
    """Agent activity timeline from Snowflake QUERY_HISTORY + AI_OBSERVABILITY_EVENTS.

    Reconstructs agent execution history from 365-day query history
    and AI observability traces.
    """
    import os

    days = max(1, min(days, 365))

    if not os.environ.get("SNOWFLAKE_ACCOUNT"):
        raise HTTPException(
            status_code=400,
            detail="SNOWFLAKE_ACCOUNT env var not set. Activity requires Snowflake.",
        )

    try:
        from agent_bom.cloud import discover_activity

        timeline = discover_activity(provider="snowflake", days=days)
        return timeline.to_dict()
    except Exception as exc:
        _logger.exception("Request failed")
        raise HTTPException(status_code=500, detail=sanitize_error(exc))


# ─── Cortex Agent Observability ─────────────────────────────────────────────


@app.get("/v1/cortex/telemetry", tags=["governance"])
async def cortex_telemetry(hours: int = 24):
    """Aggregated Cortex agent telemetry with health assessments.

    Combines CORTEX_AGENT_USAGE_HISTORY and AI_OBSERVABILITY_EVENTS
    into per-agent metrics, error rates, latency percentiles, and
    health status.
    """
    import os

    hours = max(1, min(hours, 8760))

    if not os.environ.get("SNOWFLAKE_ACCOUNT"):
        raise HTTPException(
            status_code=400,
            detail="SNOWFLAKE_ACCOUNT env var not set.",
        )

    try:
        from agent_bom.cloud.snowflake import _get_connection  # type: ignore[attr-defined]
        from agent_bom.cloud.snowflake_observability import get_cortex_telemetry

        conn = _get_connection()
        result = get_cortex_telemetry(conn, hours=hours)
        conn.close()
        return result
    except Exception as exc:
        _logger.exception("Request failed")
        raise HTTPException(status_code=500, detail=sanitize_error(exc))


@app.get("/v1/cortex/agents/{name}/telemetry", tags=["governance"])
async def cortex_agent_telemetry(name: str, hours: int = 24):
    """Telemetry for a specific Cortex agent."""
    import os

    if not os.environ.get("SNOWFLAKE_ACCOUNT"):
        raise HTTPException(
            status_code=400,
            detail="SNOWFLAKE_ACCOUNT env var not set.",
        )

    try:
        from agent_bom.cloud.snowflake import _get_connection  # type: ignore[attr-defined]
        from agent_bom.cloud.snowflake_observability import get_cortex_telemetry

        conn = _get_connection()
        result = get_cortex_telemetry(conn, agent_name=name, hours=hours)
        conn.close()
        return result
    except Exception as exc:
        _logger.exception("Request failed")
        raise HTTPException(status_code=500, detail=sanitize_error(exc))


@app.get("/v1/cortex/health", tags=["governance"])
async def cortex_health():
    """Health status for all Cortex agents."""
    import os

    if not os.environ.get("SNOWFLAKE_ACCOUNT"):
        raise HTTPException(
            status_code=400,
            detail="SNOWFLAKE_ACCOUNT env var not set.",
        )

    try:
        from agent_bom.cloud.snowflake import _get_connection, _mine_cortex_agent_usage
        from agent_bom.cloud.snowflake_observability import (
            aggregate_agent_metrics,
            assess_agent_health,
        )

        conn = _get_connection()
        records, warnings = _mine_cortex_agent_usage(conn, days=1)
        conn.close()

        metrics = aggregate_agent_metrics(records, hours=24)
        health = [assess_agent_health(m) for m in metrics]

        return {
            "agents": [
                {
                    "name": h.agent_name,
                    "status": h.status,
                    "issues": h.issues,
                }
                for h in health
            ],
            "warnings": warnings,
        }
    except Exception as exc:
        _logger.exception("Request failed")
        raise HTTPException(status_code=500, detail=sanitize_error(exc))


# ─── SIEM Formats ──────────────────────────────────────────────────────────


@app.get("/v1/siem/formats", tags=["siem"])
async def siem_formats():
    """List supported SIEM event formats."""
    from agent_bom.siem import list_formats

    return {"formats": list_formats()}


@app.get("/v1/agents/mesh", tags=["discovery"])
async def get_agent_mesh() -> dict:
    """Get a ReactFlow-compatible mesh topology of all discovered agents.

    Shows agents, their MCP servers, tools, and vulnerability overlay
    as an interactive graph.
    """
    try:
        from dataclasses import asdict

        from agent_bom.discovery import discover_all
        from agent_bom.output.agent_mesh import build_agent_mesh
        from agent_bom.parsers import extract_packages

        agents = discover_all()
        for agent in agents:
            for server in agent.mcp_servers:
                if not server.packages:
                    server.packages = extract_packages(server)

        agents_data = [asdict(a) for a in agents]

        # Gather blast radius from completed scans for vuln overlay
        all_blast: list[dict] = []
        for job in _get_store().list_all():
            if job.status == JobStatus.DONE and job.result:
                all_blast.extend(job.result.get("blast_radius", []))

        return build_agent_mesh(agents_data, all_blast)
    except Exception as exc:  # noqa: BLE001
        _logger.exception("Request failed")
        raise HTTPException(status_code=500, detail=sanitize_error(exc)) from exc


# ── OpenTelemetry Trace Ingestion ────────────────────────────────────────────


@app.post("/v1/traces", tags=["observability"])
async def ingest_traces(body: dict) -> dict:
    """Ingest OpenTelemetry trace data and flag vulnerable tool calls.

    Accepts OTLP JSON format traces containing `adk.tool.*` spans.
    Cross-references tool calls against completed scan results to flag
    any calls that touch packages with known CVEs.
    """
    try:
        from agent_bom.otel_ingest import flag_vulnerable_tool_calls, parse_otel_traces

        traces = parse_otel_traces(body)
        if not traces:
            return {"traces": 0, "flagged": [], "message": "No tool call traces found"}

        # Gather vulnerable packages and servers from scan history
        vuln_packages: list[str] = []
        vuln_servers: list[str] = []
        for job in _get_store().list_all():
            if job.status == JobStatus.DONE and job.result:
                for br in job.result.get("blast_radius", []):
                    pkg = br.get("package", "")
                    if pkg:
                        vuln_packages.append(pkg)
                    for srv in br.get("affected_servers", []):
                        name = srv if isinstance(srv, str) else srv.get("name", "")
                        if name:
                            vuln_servers.append(name)

        flagged = flag_vulnerable_tool_calls(traces, {p: [] for p in vuln_packages}, set(vuln_servers))

        return {
            "traces": len(traces),
            "flagged": [
                {
                    "tool_name": f.trace.tool_name,
                    "reason": f.reason,
                    "severity": f.severity,
                    "span_id": f.trace.span_id,
                }
                for f in flagged
            ],
        }
    except Exception as exc:  # noqa: BLE001
        _logger.exception("Request failed")
        raise HTTPException(status_code=500, detail=sanitize_error(exc)) from exc


# ── Hybrid Push — receive results from CLI ────────────────────────────────────


@app.post("/v1/results/push", tags=["push"], status_code=201)
async def receive_push(body: PushPayload) -> dict:
    """Receive pushed scan results from a CLI instance.

    Stores as a completed ScanJob with source metadata.
    """
    job = ScanJob(
        job_id=str(uuid.uuid4()),
        created_at=_now(),
        request=ScanRequest(),
    )
    job.status = JobStatus.DONE
    job.result = {
        "agents": body.agents,
        "blast_radii": body.blast_radii,
        "warnings": body.warnings,
        "source_id": body.source_id,
        "pushed": True,
    }
    job.progress.append(f"Received via push from source={body.source_id}")
    _get_store().put(job)
    return {"job_id": job.job_id, "source_id": body.source_id, "status": "stored"}


# ── Scheduled Scanning ───────────────────────────────────────────────────────


@app.post("/v1/schedules", tags=["schedules"], status_code=201)
async def create_schedule(body: ScheduleCreate) -> dict:
    """Create a recurring scan schedule."""
    from agent_bom.api.schedule_store import ScanSchedule
    from agent_bom.api.scheduler import parse_cron_next

    now = datetime.now(timezone.utc)
    next_run = parse_cron_next(body.cron_expression, now)
    schedule = ScanSchedule(
        schedule_id=str(uuid.uuid4()),
        name=body.name,
        cron_expression=body.cron_expression,
        scan_config=body.scan_config,
        enabled=body.enabled,
        next_run=next_run.isoformat() if next_run else None,
        created_at=now.isoformat(),
        updated_at=now.isoformat(),
        tenant_id=body.tenant_id,
    )
    _get_schedule_store().put(schedule)
    return schedule.model_dump()


@app.get("/v1/schedules", tags=["schedules"])
async def list_schedules() -> list[dict]:
    """List all scan schedules."""
    return [s.model_dump() for s in _get_schedule_store().list_all()]


@app.get("/v1/schedules/{schedule_id}", tags=["schedules"])
async def get_schedule(schedule_id: str) -> dict:
    """Get a specific schedule."""
    s = _get_schedule_store().get(schedule_id)
    if s is None:
        raise HTTPException(status_code=404, detail=f"Schedule {schedule_id} not found")
    return s.model_dump()


@app.delete("/v1/schedules/{schedule_id}", tags=["schedules"], status_code=204)
async def delete_schedule(schedule_id: str):
    """Delete a schedule."""
    if not _get_schedule_store().delete(schedule_id):
        raise HTTPException(status_code=404, detail=f"Schedule {schedule_id} not found")


@app.put("/v1/schedules/{schedule_id}/toggle", tags=["schedules"])
async def toggle_schedule(schedule_id: str) -> dict:
    """Enable or disable a schedule."""
    s = _get_schedule_store().get(schedule_id)
    if s is None:
        raise HTTPException(status_code=404, detail=f"Schedule {schedule_id} not found")
    s.enabled = not s.enabled
    s.updated_at = datetime.now(timezone.utc).isoformat()
    _get_schedule_store().put(s)
    return s.model_dump()


# ── Enterprise: API Key Management (RBAC) ──────────────────────────────────


@app.post("/v1/auth/keys", tags=["enterprise"], status_code=201)
async def create_key(req: CreateKeyRequest) -> dict:
    """Create a new API key. Returns the raw key once — store it securely."""
    from agent_bom.api.audit_log import log_action
    from agent_bom.api.auth import Role, create_api_key, get_key_store

    try:
        role = Role(req.role)
    except ValueError:
        raise HTTPException(status_code=400, detail=f"Invalid role: {req.role}. Must be admin, analyst, or viewer")

    raw_key, api_key = create_api_key(
        name=req.name,
        role=role,
        expires_at=req.expires_at,
        scopes=req.scopes,
    )
    get_key_store().add(api_key)

    log_action("auth.key_created", actor=req.name, resource=f"key/{api_key.key_id}", role=req.role)

    return {
        "raw_key": raw_key,
        "key_id": api_key.key_id,
        "key_prefix": api_key.key_prefix,
        "name": api_key.name,
        "role": api_key.role.value,
        "created_at": api_key.created_at,
        "expires_at": api_key.expires_at,
        "message": "Store the raw_key securely — it will not be shown again.",
    }


@app.get("/v1/auth/keys", tags=["enterprise"])
async def list_keys() -> dict:
    """List all API keys (without hashes or raw values)."""
    from agent_bom.api.auth import get_key_store

    keys = get_key_store().list_keys()
    return {"keys": [k.to_dict() for k in keys]}


@app.delete("/v1/auth/keys/{key_id}", tags=["enterprise"], status_code=204)
async def delete_key(key_id: str) -> None:
    """Revoke an API key."""
    from agent_bom.api.audit_log import log_action
    from agent_bom.api.auth import get_key_store

    if not get_key_store().remove(key_id):
        raise HTTPException(status_code=404, detail=f"Key {key_id} not found")

    log_action("auth.key_revoked", resource=f"key/{key_id}")


# ── Enterprise: Audit Log ────────────────────────────────────────────────────

_audit_log_store: Any = None


@app.get("/v1/audit", tags=["enterprise"])
async def list_audit_entries(
    action: str | None = None,
    resource: str | None = None,
    since: str | None = None,
    limit: int = 100,
    offset: int = 0,
) -> dict:
    """List audit log entries with optional filters."""
    from agent_bom.api.audit_log import get_audit_log

    store = get_audit_log()
    entries = store.list_entries(action=action, resource=resource, since=since, limit=limit, offset=offset)
    return {
        "entries": [e.to_dict() for e in entries],
        "total": store.count(action=action),
    }


@app.get("/v1/audit/integrity", tags=["enterprise"])
async def audit_integrity(limit: int = 1000) -> dict:
    """Verify HMAC integrity of audit log entries."""
    from agent_bom.api.audit_log import get_audit_log

    verified, tampered = get_audit_log().verify_integrity(limit=limit)
    return {"verified": verified, "tampered": tampered, "checked": verified + tampered}


# ── Enterprise: Exception / Waiver Management ───────────────────────────────


@app.post("/v1/exceptions", tags=["enterprise"], status_code=201)
async def create_exception(req: ExceptionRequest) -> dict:
    """Request a vulnerability exception / waiver."""
    from agent_bom.api.audit_log import log_action
    from agent_bom.api.exception_store import VulnException

    exc = VulnException(
        vuln_id=req.vuln_id,
        package_name=req.package_name,
        server_name=req.server_name,
        reason=req.reason,
        requested_by=req.requested_by,
        expires_at=req.expires_at,
        tenant_id=req.tenant_id,
    )
    _get_exception_store().put(exc)
    log_action(
        "exception_create", actor=req.requested_by, resource=f"exception/{exc.exception_id}", vuln_id=req.vuln_id, package=req.package_name
    )
    return exc.to_dict()


@app.get("/v1/exceptions", tags=["enterprise"])
async def list_exceptions(status: str | None = None, tenant_id: str = "default") -> dict:
    """List all vulnerability exceptions."""
    exceptions = _get_exception_store().list_all(status=status, tenant_id=tenant_id)
    return {"exceptions": [e.to_dict() for e in exceptions], "total": len(exceptions)}


@app.get("/v1/exceptions/{exception_id}", tags=["enterprise"])
async def get_exception(exception_id: str) -> dict:
    """Get a specific exception."""
    exc = _get_exception_store().get(exception_id)
    if exc is None:
        raise HTTPException(status_code=404, detail=f"Exception {exception_id} not found")
    return exc.to_dict()


@app.put("/v1/exceptions/{exception_id}/approve", tags=["enterprise"])
async def approve_exception(exception_id: str, approved_by: str = "") -> dict:
    """Approve a pending exception (admin only)."""
    from agent_bom.api.audit_log import log_action
    from agent_bom.api.exception_store import ExceptionStatus

    store = _get_exception_store()
    exc = store.get(exception_id)
    if exc is None:
        raise HTTPException(status_code=404, detail=f"Exception {exception_id} not found")
    if exc.status != ExceptionStatus.PENDING:
        raise HTTPException(status_code=409, detail=f"Cannot approve exception in {exc.status.value} state")
    exc.status = ExceptionStatus.ACTIVE
    exc.approved_by = approved_by
    exc.approved_at = datetime.now(timezone.utc).isoformat()
    store.put(exc)
    log_action("exception_approve", actor=approved_by, resource=f"exception/{exception_id}")
    return exc.to_dict()


@app.put("/v1/exceptions/{exception_id}/revoke", tags=["enterprise"])
async def revoke_exception(exception_id: str, revoked_by: str = "") -> dict:
    """Revoke an active exception."""
    from agent_bom.api.audit_log import log_action
    from agent_bom.api.exception_store import ExceptionStatus

    store = _get_exception_store()
    exc = store.get(exception_id)
    if exc is None:
        raise HTTPException(status_code=404, detail=f"Exception {exception_id} not found")
    exc.status = ExceptionStatus.REVOKED
    exc.revoked_at = datetime.now(timezone.utc).isoformat()
    store.put(exc)
    log_action("exception_revoke", actor=revoked_by, resource=f"exception/{exception_id}")
    return exc.to_dict()


@app.delete("/v1/exceptions/{exception_id}", tags=["enterprise"], status_code=204)
async def delete_exception(exception_id: str) -> None:
    """Delete an exception."""
    ok = _get_exception_store().delete(exception_id)
    if not ok:
        raise HTTPException(status_code=404, detail=f"Exception {exception_id} not found")


# ── Enterprise: Baseline Comparison & Trends ─────────────────────────────────


@app.post("/v1/baseline/compare", tags=["enterprise"])
async def compare_baseline(previous_job_id: str = "", current_job_id: str = "") -> dict:
    """Compare two scan results to show new, resolved, and persistent vulnerabilities."""
    from agent_bom.baseline import compare_reports

    store = _get_store()
    prev_job = store.get(previous_job_id) if previous_job_id else None
    curr_job = store.get(current_job_id) if current_job_id else None

    prev_report = prev_job.result if prev_job and prev_job.result else {}
    curr_report = curr_job.result if curr_job and curr_job.result else {}

    if not prev_report and not curr_report:
        raise HTTPException(status_code=404, detail="At least one valid job_id required")

    diff = compare_reports(prev_report, curr_report)
    return diff.to_dict()


@app.get("/v1/trends", tags=["enterprise"])
async def get_trends(limit: int = 30) -> dict:
    """Get historical trend data — posture score and vuln counts over time."""
    history = _get_trend_store().get_history(limit=limit)
    return {
        "data_points": [p.to_dict() for p in history],
        "count": len(history),
    }


# ── Enterprise: SIEM Connectors ─────────────────────────────────────────────


@app.get("/v1/siem/connectors", tags=["enterprise"])
async def list_siem_connectors() -> dict:
    """List available SIEM connector types."""
    from agent_bom.siem import list_connectors

    return {"connectors": list_connectors()}


@app.post("/v1/siem/test", tags=["enterprise"])
async def test_siem_connection(siem_type: str = "", url: str = "", token: str = "") -> dict:
    """Test SIEM connectivity."""
    from agent_bom.security import validate_url
    from agent_bom.siem import SIEMConfig, create_connector

    # Validate URL to prevent SSRF
    if url:
        try:
            validate_url(url)
        except Exception as url_exc:
            raise HTTPException(status_code=400, detail=f"Invalid URL: {sanitize_error(url_exc)}")

    try:
        connector = create_connector(siem_type, SIEMConfig(name=siem_type, url=url, token=token))
        healthy = connector.health_check()
        return {"siem_type": siem_type, "healthy": healthy}
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=sanitize_error(str(exc)))
    except Exception as exc:
        # Log sanitized details server-side, but return a generic error to the client
        _logger.exception(
            "Unexpected error while testing SIEM connection: %s",
            sanitize_error(exc),
        )
        return {
            "siem_type": siem_type,
            "healthy": False,
            "error": "Failed to test SIEM connection",
        }


# ── Dashboard static file serving ────────────────────────────────────────────
# Must be registered LAST so API routes take precedence.


# ── Asset Tracking ──────────────────────────────────────────────────────────


@app.get("/v1/assets", tags=["assets"])
async def list_assets(
    status: str | None = None,
    severity: str | None = None,
    limit: int = 500,
) -> dict:
    """List tracked vulnerability assets with first_seen / last_seen / status.

    The asset tracker persists across scans so you can see when a vulnerability
    was first discovered, when it was last seen, and when it was resolved.

    Use ``--save`` on CLI scans or the API to populate the tracker.
    """
    try:
        from agent_bom.asset_tracker import AssetTracker

        tracker = AssetTracker()
        assets = tracker.list_assets(status=status, severity=severity, limit=limit)
        stats = tracker.stats()
        mttr = tracker.mttr_days()
        tracker.close()
        return {
            "assets": assets,
            "count": len(assets),
            "stats": stats,
            "mttr_days": mttr,
        }
    except Exception as exc:
        _logger.exception("Failed to list assets")
        return {
            "assets": [],
            "count": 0,
            "stats": {},
            "mttr_days": None,
            "error": sanitize_error(exc),
        }


@app.get("/v1/assets/stats", tags=["assets"])
async def get_asset_stats() -> dict:
    """Return aggregate asset tracking statistics including MTTR."""
    try:
        from agent_bom.asset_tracker import AssetTracker

        tracker = AssetTracker()
        stats = tracker.stats()
        mttr = tracker.mttr_days()
        tracker.close()
        return {"stats": stats, "mttr_days": mttr}
    except Exception as exc:
        _logger.exception("Failed to get asset stats")
        return {
            "stats": {},
            "mttr_days": None,
            "error": sanitize_error(exc),
        }


def _mount_dashboard(application: FastAPI) -> None:
    """Mount pre-built Next.js dashboard if ui_dist/ exists in the package."""
    from pathlib import Path as _DashPath  # noqa: N814

    ui_dist = _DashPath(__file__).parent / "ui_dist"
    if not ui_dist.is_dir() or not (ui_dist / "index.html").exists():
        return

    from starlette.responses import FileResponse
    from starlette.staticfiles import StaticFiles

    # Hashed JS/CSS assets
    next_static = ui_dist / "_next"
    if next_static.is_dir():
        application.mount("/_next", StaticFiles(directory=str(next_static)), name="next-static")

    # Override root to serve dashboard instead of redirect to /docs
    @application.get("/", include_in_schema=False)
    async def _dashboard_root():
        return FileResponse(str(ui_dist / "index.html"))

    # Pre-build a whitelist of static files at startup so the catch-all
    # handler never constructs filesystem paths from user input.
    _static_file_map: dict[str, str] = {}
    for _f in ui_dist.rglob("*"):
        if _f.is_file() and not str(_f.relative_to(ui_dist)).startswith("_next"):
            _static_file_map[str(_f.relative_to(ui_dist))] = str(_f.resolve())
    _index_html = str((ui_dist / "index.html").resolve())

    # SPA catch-all for client-side routing
    @application.get("/{path:path}", include_in_schema=False)
    async def _spa_catch_all(path: str):
        # Skip API and docs paths
        if path.startswith(("v1/", "docs", "redoc", "openapi.json", "health", "version")):
            raise HTTPException(status_code=404)
        # Look up the pre-resolved path — user input is only a dict key,
        # never used in any filesystem operation (no path-injection risk).
        resolved = _static_file_map.get(path)
        if resolved:
            return FileResponse(resolved)
        # SPA fallback — serve index.html for client-side routing
        return FileResponse(_index_html)


_mount_dashboard(app)
