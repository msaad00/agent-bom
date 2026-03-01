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
    GET  /v1/compliance                full 6-framework compliance posture
    GET  /v1/compliance/{framework}    single framework (owasp-llm, owasp-mcp, atlas, nist, owasp-agentic, eu-ai-act)
    GET  /v1/malicious/check           malicious package / typosquat check
    GET  /v1/proxy/status              runtime proxy metrics
    GET  /v1/proxy/alerts              recent runtime proxy alerts
    GET  /v1/scorecard/{eco}/{pkg}     OpenSSF Scorecard lookup
    GET  /v1/governance                Snowflake governance report
    GET  /v1/governance/findings       governance findings (filtered)
    GET  /v1/activity                  agent activity timeline
"""

from __future__ import annotations

import asyncio
import logging
import secrets
import time
import uuid
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from agent_bom import __version__
from agent_bom.security import sanitize_error

_logger = logging.getLogger(__name__)

# ─── Dependency check ─────────────────────────────────────────────────────────

try:
    from fastapi import FastAPI, HTTPException
    from fastapi.middleware.cors import CORSMiddleware
    from fastapi.responses import RedirectResponse
    from pydantic import BaseModel
except ImportError as exc:  # pragma: no cover
    raise ImportError("agent-bom API requires extra dependencies.\nInstall with:  pip install 'agent-bom[api]'") from exc

# ─── App ──────────────────────────────────────────────────────────────────────

from contextlib import asynccontextmanager  # noqa: E402


@asynccontextmanager
async def _lifespan(app_instance: FastAPI):
    """Start background cleanup task on startup, cancel on shutdown."""
    # Priority: Snowflake > SQLite > InMemory (lazy default)
    if _os.environ.get("SNOWFLAKE_ACCOUNT"):
        from agent_bom.api.snowflake_store import (
            SnowflakeFleetStore,
            SnowflakeJobStore,
            SnowflakePolicyStore,
            build_connection_params,
        )

        sf = build_connection_params()
        if _store is None:
            set_job_store(SnowflakeJobStore(sf))
        if _fleet_store is None:
            set_fleet_store(SnowflakeFleetStore(sf))
        if _policy_store is None:
            set_policy_store(SnowflakePolicyStore(sf))
    elif _os.environ.get("AGENT_BOM_DB"):
        db_path = _os.environ["AGENT_BOM_DB"]
        if _store is None:
            from agent_bom.api.store import SQLiteJobStore

            set_job_store(SQLiteJobStore(db_path))
        if _fleet_store is None:
            from agent_bom.api.fleet_store import SQLiteFleetStore

            set_fleet_store(SQLiteFleetStore(db_path))
        if _policy_store is None:
            from agent_bom.api.policy_store import SQLitePolicyStore

            set_policy_store(SQLitePolicyStore(db_path))

    global _cleanup_task
    _cleanup_task = asyncio.create_task(_cleanup_loop())
    yield
    if _cleanup_task:
        _cleanup_task.cancel()


app = FastAPI(
    title="agent-bom API",
    description=("AI Bill of Materials — map the full trust chain from AI agents and MCP servers to CVEs, credentials, and blast radius."),
    version=__version__,
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=_lifespan,
)

# ── API hardening config ─────────────────────────────────────────────────
import os as _os  # noqa: E402

_default_origins = ["http://localhost:3000", "http://127.0.0.1:3000"]
_cors_env = _os.environ.get("CORS_ORIGINS")
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

from starlette.middleware.base import BaseHTTPMiddleware  # noqa: E402
from starlette.requests import Request as StarletteRequest  # noqa: E402
from starlette.responses import JSONResponse  # noqa: E402
from starlette.types import ASGIApp  # noqa: E402


class TrustHeadersMiddleware(BaseHTTPMiddleware):
    """Add read-only + no-credential-storage trust headers to every response."""

    async def dispatch(self, request: StarletteRequest, call_next):
        response = await call_next(request)
        response.headers["X-Agent-Bom-Read-Only"] = "true"
        response.headers["X-Agent-Bom-No-Credential-Storage"] = "true"
        response.headers["X-Agent-Bom-Version"] = __version__
        return response


app.add_middleware(TrustHeadersMiddleware)


class APIKeyMiddleware(BaseHTTPMiddleware):
    """Optional API key authentication via Bearer token or X-API-Key header."""

    _EXEMPT_PATHS = {"/", "/health", "/version", "/docs", "/redoc", "/openapi.json"}

    def __init__(self, app: ASGIApp, api_key: str):
        super().__init__(app)
        self._api_key = api_key

    async def dispatch(self, request: StarletteRequest, call_next):
        if request.url.path in self._EXEMPT_PATHS:
            return await call_next(request)

        # Check Authorization: Bearer <key>
        auth = request.headers.get("authorization", "")
        if auth.startswith("Bearer ") and secrets.compare_digest(auth[7:], self._api_key):
            return await call_next(request)

        # Check X-API-Key header
        header_key = request.headers.get("x-api-key", "")
        if header_key and secrets.compare_digest(header_key, self._api_key):
            return await call_next(request)

        return JSONResponse(
            status_code=401, content={"detail": "Unauthorized — provide API key via Authorization: Bearer <key> or X-API-Key header"}
        )


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Per-IP sliding window rate limiter with bounded memory."""

    _MAX_ENTRIES = 10_000

    def __init__(self, app: ASGIApp, scan_rpm: int = 60, read_rpm: int = 300):
        super().__init__(app)
        self._scan_rpm = scan_rpm
        self._read_rpm = read_rpm
        self._window = 60
        self._hits: dict[str, list[float]] = defaultdict(list)
        self._last_cleanup = time.time()

    def _cleanup(self, now: float) -> None:
        """Prune stale entries to prevent unbounded memory growth."""
        if now - self._last_cleanup < self._window:
            return
        self._last_cleanup = now
        stale = [k for k, v in self._hits.items() if not v or v[-1] < now - self._window]
        for k in stale:
            del self._hits[k]
        if len(self._hits) > self._MAX_ENTRIES:
            self._hits.clear()

    async def dispatch(self, request: StarletteRequest, call_next):
        client_ip = request.client.host if request.client else "unknown"
        now = time.time()

        self._cleanup(now)

        is_scan = request.url.path.startswith("/v1/scan") and request.method == "POST"
        limit = self._scan_rpm if is_scan else self._read_rpm

        key = f"{client_ip}:{'scan' if is_scan else 'read'}"
        self._hits[key] = [t for t in self._hits[key] if now - t < self._window]

        if len(self._hits[key]) >= limit:
            retry_after = max(int(self._window - (now - self._hits[key][0])), 1)
            return JSONResponse(
                status_code=429,
                content={"detail": "Rate limit exceeded"},
                headers={"Retry-After": str(retry_after)},
            )

        self._hits[key].append(now)
        return await call_next(request)


class MaxBodySizeMiddleware(BaseHTTPMiddleware):
    """Reject requests with body larger than max_bytes."""

    def __init__(self, app: ASGIApp, max_bytes: int = 10 * 1024 * 1024):
        super().__init__(app)
        self._max_bytes = max_bytes

    async def dispatch(self, request: StarletteRequest, call_next):
        content_length = request.headers.get("content-length")
        if content_length and int(content_length) > self._max_bytes:
            return JSONResponse(
                status_code=413,
                content={"detail": f"Request body too large (max {self._max_bytes // (1024 * 1024)}MB)"},
            )
        return await call_next(request)


_MAX_CONCURRENT_JOBS = 10
_JOB_TTL_SECONDS = 3600  # 1 hour


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

    # Add optional middleware
    if api_key:
        app.add_middleware(APIKeyMiddleware, api_key=api_key)

    app.add_middleware(RateLimitMiddleware, scan_rpm=rate_limit_rpm, read_rpm=rate_limit_rpm * 5)
    app.add_middleware(MaxBodySizeMiddleware)


# Thread pool for running blocking scan functions without blocking the event loop
_executor = ThreadPoolExecutor(max_workers=4)

# ─── Job store (pluggable) ────────────────────────────────────────────────────
# Import lazily to avoid circular import at module level
_store: Any = None  # Initialized on first use


def _get_store():
    """Get the active job store, creating InMemoryJobStore if not yet set."""
    global _store
    if _store is None:
        from agent_bom.api.store import InMemoryJobStore

        _store = InMemoryJobStore()
    return _store


def set_job_store(store: Any) -> None:
    """Switch the job store backend. Call before server startup."""
    global _store
    _store = store


# Legacy alias for direct dict access (read-only compatibility)
_jobs: dict[str, "ScanJob"] = {}


# ─── Models ───────────────────────────────────────────────────────────────────


class JobStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    DONE = "done"
    FAILED = "failed"
    CANCELLED = "cancelled"


class ScanRequest(BaseModel):
    """Options accepted by POST /v1/scan — mirrors agent-bom scan CLI flags."""

    inventory: str | None = None
    """Path to agents.json inventory file."""

    images: list[str] = []
    """Docker image references to scan (e.g. ['myapp:latest', 'redis:7'])."""

    k8s: bool = False
    """Scan running Kubernetes pods via kubectl."""

    k8s_namespace: str | None = None
    """Kubernetes namespace (None = all)."""

    tf_dirs: list[str] = []
    """Terraform directories to scan."""

    gha_path: str | None = None
    """Path to a Git repo to scan GitHub Actions workflows."""

    agent_projects: list[str] = []
    """Python project directories using AI agent frameworks."""

    jupyter_dirs: list[str] = []
    """Directories to scan for Jupyter notebooks (.ipynb) with AI library usage."""

    sbom: str | None = None
    """Path to an existing CycloneDX / SPDX SBOM file."""

    enrich: bool = False
    """Enrich with NVD CVSS, EPSS, and CISA KEV data."""

    connectors: list[str] = []
    """SaaS connectors to discover from (e.g. ['jira', 'servicenow', 'slack'])."""

    filesystem_paths: list[str] = []
    """Filesystem directories or tar archives to scan via Syft."""

    format: str = "json"
    """Output format: json | cyclonedx | sarif | spdx | html | text."""


class ScanJob(BaseModel):
    """Represents a running or completed scan job."""

    job_id: str
    status: JobStatus = JobStatus.PENDING
    created_at: str
    started_at: str | None = None
    completed_at: str | None = None
    request: ScanRequest
    progress: list[str] = []
    result: dict[str, Any] | None = None
    error: str | None = None

    model_config = {"arbitrary_types_allowed": True}


class VersionInfo(BaseModel):
    version: str
    api_version: str = "v1"
    python_package: str = "agent-bom"


class HealthResponse(BaseModel):
    status: str = "ok"
    version: str


# ─── Helpers ──────────────────────────────────────────────────────────────────


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


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
            store.put(existing)
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
            store.put(fleet_agent)


def _run_scan_sync(job: ScanJob) -> None:
    """Run the full scan pipeline in a thread (blocking). Updates job in-place."""
    job.status = JobStatus.RUNNING
    job.started_at = _now()
    job.progress.append("Starting scan...")

    try:
        from agent_bom.discovery import discover_all
        from agent_bom.output import to_json
        from agent_bom.parsers import extract_packages
        from agent_bom.scanners import scan_agents_sync

        req = job.request
        agents = []
        warnings_all: list[str] = []

        # Step 1 — auto-discover local MCP configs
        job.progress.append("Discovering local MCP configurations...")
        local_agents = discover_all()
        agents.extend(local_agents)

        # Step 2 — inventory file
        if req.inventory:
            job.progress.append(f"Loading inventory: {req.inventory}")
            import json as _json

            from agent_bom.models import Agent, AgentType, MCPServer

            with open(req.inventory) as _f:
                inv_data = _json.load(_f)
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
            job.progress.append(f"Loaded {len(inv_data.get('agents', []))} agent(s) from inventory")

        # Step 3 — Docker images
        for image_ref in req.images:
            job.progress.append(f"Scanning image: {image_ref}")
            from agent_bom.image import scan_image

            img_agents, img_warnings = scan_image(image_ref)
            agents.extend(img_agents)
            warnings_all.extend(img_warnings)

        # Step 4 — Kubernetes
        if req.k8s:
            job.progress.append("Scanning Kubernetes pods...")
            from agent_bom.k8s import discover_images

            k8s_records = discover_images(namespace=req.k8s_namespace)
            # Convert discovered images to image scans
            for img, _pod, _ctr in k8s_records:
                from agent_bom.image import scan_image

                k8s_agents, k8s_warns = scan_image(img)
                agents.extend(k8s_agents)
                warnings_all.extend(k8s_warns)

        # Step 5 — Terraform
        for tf_dir in req.tf_dirs:
            job.progress.append(f"Scanning Terraform: {tf_dir}")
            from agent_bom.terraform import scan_terraform_dir

            tf_agents, tf_warnings = scan_terraform_dir(tf_dir)
            agents.extend(tf_agents)
            warnings_all.extend(tf_warnings)

        # Step 6 — GitHub Actions
        if req.gha_path:
            job.progress.append(f"Scanning GitHub Actions: {req.gha_path}")
            from agent_bom.github_actions import scan_github_actions

            gha_agents, gha_warnings = scan_github_actions(req.gha_path)
            agents.extend(gha_agents)
            warnings_all.extend(gha_warnings)

        # Step 7 — Python agent projects
        for ap in req.agent_projects:
            job.progress.append(f"Scanning Python agent project: {ap}")
            from agent_bom.python_agents import scan_python_agents

            py_agents, py_warnings = scan_python_agents(ap)
            agents.extend(py_agents)
            warnings_all.extend(py_warnings)

        # Step 7b — Jupyter notebooks
        for jdir in req.jupyter_dirs:
            job.progress.append(f"Scanning Jupyter notebooks: {jdir}")
            from agent_bom.jupyter import scan_jupyter_notebooks

            j_agents, j_warnings = scan_jupyter_notebooks(jdir)
            agents.extend(j_agents)
            warnings_all.extend(j_warnings)

        # Step 8 — existing SBOM
        if req.sbom:
            job.progress.append(f"Ingesting SBOM: {req.sbom}")
            from agent_bom.sbom import load_sbom

            sbom_packages, _fmt = load_sbom(req.sbom)
            # Attach SBOM packages to a synthetic agent
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

        # Step 9a — SaaS connectors
        for connector_name in req.connectors:
            job.progress.append(f"Discovering from connector: {connector_name}")
            try:
                from agent_bom.connectors import discover_from_connector

                con_agents, con_warnings = discover_from_connector(connector_name)
                agents.extend(con_agents)
                warnings_all.extend(con_warnings)
            except Exception as con_exc:  # noqa: BLE001
                warnings_all.append(f"{connector_name} connector error: {con_exc}")

        # Step 9b — Filesystem / disk snapshot scanning
        for fs_path in req.filesystem_paths:
            job.progress.append(f"Scanning filesystem: {fs_path}")
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
                    job.progress.append(f"Filesystem {fs_path}: {len(fs_pkgs)} packages via {fs_strat}")
            except Exception as fs_exc:  # noqa: BLE001
                warnings_all.append(f"Filesystem scan error for {fs_path}: {fs_exc}")

        if not agents:
            job.progress.append("No agents found.")
            job.result = {"agents": [], "vulnerabilities": [], "blast_radius": [], "warnings": warnings_all}
            job.status = JobStatus.DONE
            job.completed_at = _now()
            return

        # Extract packages for all discovered agents
        job.progress.append(f"Found {len(agents)} agent(s). Extracting packages...")
        for agent in agents:
            for server in agent.mcp_servers:
                if not server.packages:
                    server.packages = extract_packages(server)

        job.progress.append("Querying OSV.dev for CVEs...")

        # Step 9 — CVE scan + blast radius
        blast_radii = scan_agents_sync(agents, enable_enrichment=req.enrich)

        if req.enrich:
            job.progress.append("Enriching with NVD CVSS, EPSS, CISA KEV...")

        job.progress.append("Computing blast radius...")

        # Build report and serialise
        from agent_bom.models import AIBOMReport

        report = AIBOMReport(agents=agents, blast_radii=blast_radii)
        report_json = to_json(report)
        report_json["warnings"] = warnings_all
        job.result = report_json
        job.status = JobStatus.DONE
        job.progress.append("Scan complete.")

        # Auto-sync discovered agents to fleet registry
        try:
            _sync_scan_agents_to_fleet(agents)
        except Exception as fleet_exc:  # noqa: BLE001
            job.progress.append(f"Fleet sync skipped: {fleet_exc}")

    except Exception as exc:  # noqa: BLE001
        job.status = JobStatus.FAILED
        job.error = str(exc)
        job.progress.append(f"Error: {exc}")
    finally:
        job.completed_at = _now()
        # Persist final state
        _get_store().put(job)


_cleanup_task: asyncio.Task | None = None


async def _cleanup_loop():
    """Background task that removes expired jobs every 5 minutes."""
    while True:
        await asyncio.sleep(300)
        _get_store().cleanup_expired(_JOB_TTL_SECONDS)


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
    _jobs[job.job_id] = job

    loop = asyncio.get_event_loop()
    loop.run_in_executor(_executor, _run_scan_sync, job)

    return job


@app.get("/v1/scan/{job_id}", response_model=ScanJob, tags=["scan"])
async def get_scan(job_id: str) -> ScanJob:
    """Poll scan status and results."""
    # Check in-memory first (for in-progress jobs with live progress)
    if job_id in _jobs:
        return _jobs[job_id]
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
    job = _jobs.get(job_id) or _get_store().get(job_id)
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


@app.get("/v1/scan/{job_id}/skill-audit", tags=["scan"])
async def get_skill_audit(job_id: str) -> dict:
    """Get the skill security audit results for a completed scan.

    Returns findings from the skill file security audit including
    typosquat detection, unverified servers, shell access, and more.
    Empty results if no skill files were scanned.
    """
    job = _jobs.get(job_id) or _get_store().get(job_id)
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
    in_memory = _jobs.pop(job_id, None)
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

    if job_id not in _jobs:
        raise HTTPException(status_code=404, detail=f"Job {job_id} not found")

    import json as _json

    async def event_generator():
        sent = 0
        while True:
            current = _jobs.get(job_id)
            if current is None:
                break
            # Send any new progress lines
            for line in current.progress[sent:]:
                yield {"data": _json.dumps({"type": "progress", "message": line})}
                sent += 1
            if current.status in (JobStatus.DONE, JobStatus.FAILED, JobStatus.CANCELLED):
                yield {"data": _json.dumps({"type": "done", "status": current.status, "job_id": job_id})}
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
async def list_jobs() -> dict:
    """List all scan jobs (for the UI job history panel)."""
    summary = _get_store().list_summary()
    return {
        "jobs": summary,
        "count": len(summary),
    }


# ─── Compliance Posture ───────────────────────────────────────────────────────


@app.get("/v1/compliance", tags=["compliance"])
async def get_compliance() -> dict:
    """Aggregate OWASP LLM Top 10, OWASP MCP Top 10, MITRE ATLAS, NIST AI RMF,
    OWASP Agentic Top 10, and EU AI Act compliance posture across all completed scans.

    Returns per-control pass/warning/fail status and an overall compliance score.
    """
    from agent_bom.atlas import ATLAS_TECHNIQUES
    from agent_bom.nist_ai_rmf import NIST_AI_RMF
    from agent_bom.owasp import OWASP_LLM_TOP10

    # Collect blast_radius entries from all completed scans
    all_blast: list[dict] = []
    latest_scan: str | None = None
    scan_count = 0

    for job in _get_store().list_all():
        if job.status != JobStatus.DONE or not job.result:
            continue
        scan_count += 1
        br_list = job.result.get("blast_radius", [])
        all_blast.extend(br_list)
        if latest_scan is None or (job.completed_at and job.completed_at > latest_scan):
            latest_scan = job.completed_at

    def _build_controls(
        catalog: dict[str, str],
        tag_field: str,
        id_key: str,
    ) -> list[dict]:
        """Build per-control compliance entries from blast_radius data."""
        controls = []
        for code, name in sorted(catalog.items()):
            sev_breakdown = {"critical": 0, "high": 0, "medium": 0, "low": 0}
            affected_pkgs: set[str] = set()
            affected_agents: set[str] = set()
            findings = 0

            for br in all_blast:
                tags = br.get(tag_field, [])
                if code in tags:
                    findings += 1
                    sev = (br.get("severity") or "").lower()
                    if sev in sev_breakdown:
                        sev_breakdown[sev] += 1
                    pkg = br.get("package")
                    if pkg:
                        affected_pkgs.add(pkg)
                    for agent in br.get("affected_agents", []):
                        affected_agents.add(agent)

            if findings == 0:
                status = "pass"
            elif sev_breakdown["critical"] > 0 or sev_breakdown["high"] > 0:
                status = "fail"
            else:
                status = "warning"

            controls.append(
                {
                    id_key: code,
                    "name": name,
                    "findings": findings,
                    "status": status,
                    "severity_breakdown": sev_breakdown,
                    "affected_packages": sorted(affected_pkgs),
                    "affected_agents": sorted(affected_agents),
                }
            )
        return controls

    from agent_bom.eu_ai_act import EU_AI_ACT
    from agent_bom.owasp_agentic import OWASP_AGENTIC_TOP10
    from agent_bom.owasp_mcp import OWASP_MCP_TOP10

    owasp = _build_controls(OWASP_LLM_TOP10, "owasp_tags", "code")
    owasp_mcp = _build_controls(OWASP_MCP_TOP10, "owasp_mcp_tags", "code")
    atlas = _build_controls(ATLAS_TECHNIQUES, "atlas_tags", "code")
    nist = _build_controls(NIST_AI_RMF, "nist_ai_rmf_tags", "code")
    owasp_agentic = _build_controls(OWASP_AGENTIC_TOP10, "owasp_agentic_tags", "code")
    eu_ai_act = _build_controls(EU_AI_ACT, "eu_ai_act_tags", "code")

    def _count_statuses(controls: list[dict]) -> tuple[int, int, int]:
        p = sum(1 for c in controls if c["status"] == "pass")
        w = sum(1 for c in controls if c["status"] == "warning")
        f = sum(1 for c in controls if c["status"] == "fail")
        return p, w, f

    op, ow, of_ = _count_statuses(owasp)
    mp, mw, mf = _count_statuses(owasp_mcp)
    ap, aw, af = _count_statuses(atlas)
    np_, nw, nf = _count_statuses(nist)
    oap, oaw, oaf = _count_statuses(owasp_agentic)
    eup, euw, euf = _count_statuses(eu_ai_act)

    total_controls = len(owasp) + len(owasp_mcp) + len(atlas) + len(nist) + len(owasp_agentic) + len(eu_ai_act)
    total_pass = op + mp + ap + np_ + oap + eup
    overall_score = round((total_pass / total_controls) * 100, 1) if total_controls > 0 else 100.0

    if of_ > 0 or mf > 0 or af > 0 or nf > 0 or oaf > 0 or euf > 0:
        overall_status = "fail"
    elif ow > 0 or mw > 0 or aw > 0 or nw > 0 or oaw > 0 or euw > 0:
        overall_status = "warning"
    else:
        overall_status = "pass"

    return {
        "overall_score": overall_score,
        "overall_status": overall_status,
        "scan_count": scan_count,
        "latest_scan": latest_scan,
        "owasp_llm_top10": owasp,
        "owasp_mcp_top10": owasp_mcp,
        "mitre_atlas": atlas,
        "nist_ai_rmf": nist,
        "owasp_agentic_top10": owasp_agentic,
        "eu_ai_act": eu_ai_act,
        "summary": {
            "owasp_pass": op,
            "owasp_warn": ow,
            "owasp_fail": of_,
            "owasp_mcp_pass": mp,
            "owasp_mcp_warn": mw,
            "owasp_mcp_fail": mf,
            "atlas_pass": ap,
            "atlas_warn": aw,
            "atlas_fail": af,
            "nist_pass": np_,
            "nist_warn": nw,
            "nist_fail": nf,
            "owasp_agentic_pass": oap,
            "owasp_agentic_warn": oaw,
            "owasp_agentic_fail": oaf,
            "eu_ai_act_pass": eup,
            "eu_ai_act_warn": euw,
            "eu_ai_act_fail": euf,
        },
    }


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
    raw = _json.loads(registry_path.read_text())
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
        raise HTTPException(status_code=404, detail=str(exc)) from exc


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


# ─── Compliance by Framework ────────────────────────────────────────────────


@app.get("/v1/compliance/{framework}", tags=["compliance"])
async def get_compliance_by_framework(framework: str) -> dict:
    """Get compliance posture for a single framework.

    Supported frameworks: owasp-llm, owasp-mcp, atlas, nist, owasp-agentic, eu-ai-act
    """
    full = await get_compliance()

    framework_map = {
        "owasp-llm": "owasp_llm_top10",
        "owasp-mcp": "owasp_mcp_top10",
        "atlas": "mitre_atlas",
        "nist": "nist_ai_rmf",
        "owasp-agentic": "owasp_agentic_top10",
        "eu-ai-act": "eu_ai_act",
    }

    key = framework_map.get(framework.lower())
    if not key:
        raise HTTPException(
            status_code=400,
            detail=f"Unknown framework '{framework}'. Supported: {', '.join(framework_map.keys())}",
        )

    controls = full.get(key, [])
    pass_count = sum(1 for c in controls if c["status"] == "pass")
    warn_count = sum(1 for c in controls if c["status"] == "warning")
    fail_count = sum(1 for c in controls if c["status"] == "fail")

    return {
        "framework": framework,
        "controls": controls,
        "summary": {"pass": pass_count, "warning": warn_count, "fail": fail_count},
        "score": round((pass_count / len(controls)) * 100, 1) if controls else 100.0,
    }


# ─── Proxy Status & Alerts ──────────────────────────────────────────────────

# In-process ring buffer for proxy alerts/metrics.  The proxy (when running
# in the same process, e.g. via the API) pushes records here.  External proxy
# processes write to the JSONL audit log, and these endpoints read it.

_proxy_alerts: list[dict] = []
_proxy_metrics: dict | None = None


def push_proxy_alert(alert: dict) -> None:
    """Called by the proxy to record a runtime alert (in-process path)."""
    _proxy_alerts.append(alert)
    if len(_proxy_alerts) > 1000:
        _proxy_alerts.pop(0)


def push_proxy_metrics(metrics: dict) -> None:
    """Called by the proxy to record latest metrics summary."""
    global _proxy_metrics
    _proxy_metrics = metrics


def _get_configured_log_path() -> _Path | None:
    """Return the server-configured audit log path, if set.

    The path is set via the AGENT_BOM_LOG environment variable (server-side
    config only — never from user input).  Returns None when the env var is
    unset or the file doesn't exist.
    """
    import os

    log_env = os.environ.get("AGENT_BOM_LOG")
    if not log_env:
        return None
    path = _Path(log_env).resolve()
    if not path.is_file() or path.suffix != ".jsonl":
        return None
    return path


def _read_alerts_from_log(path: _Path) -> list[dict]:
    """Read runtime_alert records from a JSONL audit log."""
    import json as _json

    alerts = []
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            record = _json.loads(line)
            if record.get("type") == "runtime_alert":
                alerts.append(record)
        except (ValueError, KeyError):
            continue
    return alerts


def _read_metrics_from_log(path: _Path) -> dict | None:
    """Read the last proxy_summary record from a JSONL audit log."""
    import json as _json

    last_summary = None
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            record = _json.loads(line)
            if record.get("type") == "proxy_summary":
                last_summary = record
        except (ValueError, KeyError):
            continue
    return last_summary


@app.get("/v1/proxy/status", tags=["proxy"])
async def proxy_status() -> dict:
    """Get runtime proxy metrics.

    Returns the latest proxy metrics summary.  Reads from the in-process
    buffer (populated by ``push_proxy_metrics``) or from the audit log
    configured via the ``AGENT_BOM_LOG`` environment variable.
    """
    if _proxy_metrics is not None:
        return _proxy_metrics

    log_path = _get_configured_log_path()
    if log_path:
        metrics = _read_metrics_from_log(log_path)
        if metrics is not None:
            return metrics

    return {
        "status": "no_proxy_session",
        "message": "No proxy metrics available. Start a proxy session or set AGENT_BOM_LOG.",
    }


@app.get("/v1/proxy/alerts", tags=["proxy"])
async def proxy_alerts(
    severity: str | None = None,
    detector: str | None = None,
    limit: int = 100,
) -> dict:
    """Get recent runtime proxy alerts.

    Returns alerts from the in-process buffer or the audit log configured
    via the ``AGENT_BOM_LOG`` environment variable.

    Query params:
        severity: Filter by severity (critical, high, medium, low, info).
        detector: Filter by detector name.
        limit: Maximum number of alerts to return (default 100).
    """
    log_path = _get_configured_log_path()
    if log_path and not _proxy_alerts:
        alerts = _read_alerts_from_log(log_path)
    else:
        alerts = list(_proxy_alerts)

    # Apply filters
    if severity:
        alerts = [a for a in alerts if a.get("severity", "").lower() == severity.lower()]
    if detector:
        alerts = [a for a in alerts if a.get("detector", "").lower() == detector.lower()]

    # Newest first, apply limit
    alerts = alerts[-limit:][::-1]

    return {
        "alerts": alerts,
        "count": len(alerts),
        "filters": {
            "severity": severity,
            "detector": detector,
            "limit": limit,
        },
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


# ─── Fleet Management ────────────────────────────────────────────────────────

_fleet_store: Any = None


def _get_fleet_store():
    """Get the active fleet store, creating InMemoryFleetStore if not set."""
    global _fleet_store
    if _fleet_store is None:
        from agent_bom.api.fleet_store import InMemoryFleetStore

        _fleet_store = InMemoryFleetStore()
    return _fleet_store


def set_fleet_store(store: Any) -> None:
    """Switch the fleet store backend. Call before server startup."""
    global _fleet_store
    _fleet_store = store


_policy_store: Any = None


def _get_policy_store():
    """Get the active policy store, creating InMemoryPolicyStore if not set."""
    global _policy_store
    if _policy_store is None:
        from agent_bom.api.policy_store import InMemoryPolicyStore

        _policy_store = InMemoryPolicyStore()
    return _policy_store


def set_policy_store(store: Any) -> None:
    """Switch the policy store backend. Call before server startup."""
    global _policy_store
    _policy_store = store


class StateUpdate(BaseModel):
    state: str
    reason: str = ""


class FleetAgentUpdate(BaseModel):
    owner: str | None = None
    environment: str | None = None
    tags: list[str] | None = None
    notes: str | None = None


@app.get("/v1/fleet", tags=["fleet"])
async def list_fleet(
    state: str | None = None,
    environment: str | None = None,
    min_trust: float | None = None,
):
    """List all agents in the fleet registry."""
    agents = _get_fleet_store().list_all()
    if state:
        agents = [a for a in agents if a.lifecycle_state.value == state]
    if environment:
        agents = [a for a in agents if a.environment == environment]
    if min_trust is not None:
        agents = [a for a in agents if a.trust_score >= min_trust]
    return {
        "agents": [a.model_dump() for a in agents],
        "count": len(agents),
    }


@app.get("/v1/fleet/stats", tags=["fleet"])
async def fleet_stats():
    """Fleet-wide statistics."""
    agents = _get_fleet_store().list_all()
    by_state: dict[str, int] = {}
    by_env: dict[str, int] = {}
    trust_scores: list[float] = []
    for a in agents:
        by_state[a.lifecycle_state.value] = by_state.get(a.lifecycle_state.value, 0) + 1
        env = a.environment or "unset"
        by_env[env] = by_env.get(env, 0) + 1
        trust_scores.append(a.trust_score)
    return {
        "total": len(agents),
        "by_state": by_state,
        "by_environment": by_env,
        "avg_trust_score": round(sum(trust_scores) / len(trust_scores), 1) if trust_scores else 0.0,
        "low_trust_count": sum(1 for s in trust_scores if s < 50),
    }


@app.get("/v1/fleet/{agent_id}", tags=["fleet"])
async def get_fleet_agent(agent_id: str):
    """Get a single fleet agent with trust score breakdown."""
    agent = _get_fleet_store().get(agent_id)
    if agent is None:
        raise HTTPException(status_code=404, detail="Fleet agent not found")
    return agent.model_dump()


@app.post("/v1/fleet/sync", tags=["fleet"])
async def sync_fleet():
    """Run discovery and sync results into the fleet registry.

    New agents → state=DISCOVERED. Existing agents → counts updated.
    Trust scores are recomputed for all synced agents.
    """
    from agent_bom.api.fleet_store import FleetAgent, FleetLifecycleState
    from agent_bom.discovery import discover_all
    from agent_bom.fleet.trust_scoring import compute_trust_score

    discovered = discover_all()
    store = _get_fleet_store()
    now = datetime.now(timezone.utc).isoformat()
    new_count = 0
    updated_count = 0

    for agent in discovered:
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
            existing.last_discovery = now
            existing.updated_at = now
            existing.config_path = agent.config_path or ""
            store.put(existing)
            updated_count += 1
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
            store.put(fleet_agent)
            new_count += 1

    return {
        "synced": new_count + updated_count,
        "new": new_count,
        "updated": updated_count,
    }


@app.put("/v1/fleet/{agent_id}/state", tags=["fleet"])
async def update_fleet_state(agent_id: str, body: StateUpdate):
    """Update agent lifecycle state."""
    from agent_bom.api.fleet_store import FleetLifecycleState

    try:
        new_state = FleetLifecycleState(body.state)
    except ValueError:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid state: {body.state}. Valid: {[s.value for s in FleetLifecycleState]}",
        )
    store = _get_fleet_store()
    if not store.update_state(agent_id, new_state):
        raise HTTPException(status_code=404, detail="Fleet agent not found")
    return {"agent_id": agent_id, "lifecycle_state": new_state.value}


@app.put("/v1/fleet/{agent_id}", tags=["fleet"])
async def update_fleet_agent(agent_id: str, body: FleetAgentUpdate):
    """Update agent metadata (owner, environment, tags, notes)."""
    store = _get_fleet_store()
    agent = store.get(agent_id)
    if agent is None:
        raise HTTPException(status_code=404, detail="Fleet agent not found")
    if body.owner is not None:
        agent.owner = body.owner
    if body.environment is not None:
        agent.environment = body.environment
    if body.tags is not None:
        agent.tags = body.tags
    if body.notes is not None:
        agent.notes = body.notes
    agent.updated_at = datetime.now(timezone.utc).isoformat()
    store.put(agent)
    return agent.model_dump()


# ─── Gateway Policies ────────────────────────────────────────────────────────


class PolicyCreate(BaseModel):
    name: str
    description: str = ""
    mode: str = "audit"
    rules: list[dict] = []
    bound_agents: list[str] = []
    bound_agent_types: list[str] = []
    bound_environments: list[str] = []
    enabled: bool = True


class PolicyUpdate(BaseModel):
    name: str | None = None
    description: str | None = None
    mode: str | None = None
    rules: list[dict] | None = None
    bound_agents: list[str] | None = None
    bound_agent_types: list[str] | None = None
    bound_environments: list[str] | None = None
    enabled: bool | None = None


class EvaluateRequest(BaseModel):
    agent_name: str = ""
    tool_name: str
    arguments: dict = {}


@app.get("/v1/gateway/policies", tags=["gateway"])
async def list_gateway_policies(enabled: bool | None = None, mode: str | None = None):
    """List all gateway policies."""
    policies = _get_policy_store().list_policies()
    if enabled is not None:
        policies = [p for p in policies if p.enabled == enabled]
    if mode:
        policies = [p for p in policies if p.mode.value == mode]
    return {"policies": [p.model_dump() for p in policies], "count": len(policies)}


@app.post("/v1/gateway/policies", tags=["gateway"], status_code=201)
async def create_gateway_policy(body: PolicyCreate):
    """Create a new gateway policy."""
    import uuid

    from agent_bom.api.policy_store import GatewayPolicy, GatewayRule, PolicyMode

    try:
        policy_mode = PolicyMode(body.mode)
    except ValueError:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid mode: {body.mode}. Valid: {[m.value for m in PolicyMode]}",
        )
    now = datetime.now(timezone.utc).isoformat()
    rules = [GatewayRule(**r) for r in body.rules]
    policy = GatewayPolicy(
        policy_id=str(uuid.uuid4()),
        name=body.name,
        description=body.description,
        mode=policy_mode,
        rules=rules,
        bound_agents=body.bound_agents,
        bound_agent_types=body.bound_agent_types,
        bound_environments=body.bound_environments,
        enabled=body.enabled,
        created_at=now,
        updated_at=now,
    )
    _get_policy_store().put_policy(policy)
    return policy.model_dump()


@app.get("/v1/gateway/policies/{policy_id}", tags=["gateway"])
async def get_gateway_policy(policy_id: str):
    """Get a gateway policy by ID."""
    policy = _get_policy_store().get_policy(policy_id)
    if policy is None:
        raise HTTPException(status_code=404, detail="Policy not found")
    return policy.model_dump()


@app.put("/v1/gateway/policies/{policy_id}", tags=["gateway"])
async def update_gateway_policy(policy_id: str, body: PolicyUpdate):
    """Update an existing gateway policy."""
    from agent_bom.api.policy_store import GatewayRule, PolicyMode

    store = _get_policy_store()
    policy = store.get_policy(policy_id)
    if policy is None:
        raise HTTPException(status_code=404, detail="Policy not found")
    if body.name is not None:
        policy.name = body.name
    if body.description is not None:
        policy.description = body.description
    if body.mode is not None:
        try:
            policy.mode = PolicyMode(body.mode)
        except ValueError:
            raise HTTPException(status_code=400, detail=f"Invalid mode: {body.mode}")
    if body.rules is not None:
        policy.rules = [GatewayRule(**r) for r in body.rules]
    if body.bound_agents is not None:
        policy.bound_agents = body.bound_agents
    if body.bound_agent_types is not None:
        policy.bound_agent_types = body.bound_agent_types
    if body.bound_environments is not None:
        policy.bound_environments = body.bound_environments
    if body.enabled is not None:
        policy.enabled = body.enabled
    policy.updated_at = datetime.now(timezone.utc).isoformat()
    store.put_policy(policy)
    return policy.model_dump()


@app.delete("/v1/gateway/policies/{policy_id}", tags=["gateway"])
async def delete_gateway_policy(policy_id: str):
    """Delete a gateway policy."""
    if not _get_policy_store().delete_policy(policy_id):
        raise HTTPException(status_code=404, detail="Policy not found")
    return {"deleted": True, "policy_id": policy_id}


@app.post("/v1/gateway/evaluate", tags=["gateway"])
async def evaluate_gateway(body: EvaluateRequest):
    """Dry-run evaluation of gateway policies against a tool call."""
    from agent_bom.gateway import evaluate_gateway_policies

    policies = _get_policy_store().list_policies()
    active = [p for p in policies if p.enabled]
    allowed, reason, policy_id = evaluate_gateway_policies(
        active,
        body.tool_name,
        body.arguments,
    )
    return {
        "allowed": allowed,
        "reason": reason,
        "policy_id": policy_id,
        "policies_evaluated": len(active),
    }


@app.get("/v1/gateway/audit", tags=["gateway"])
async def list_gateway_audit(
    policy_id: str | None = None,
    agent_name: str | None = None,
    limit: int = 100,
):
    """Query the gateway policy audit log."""
    entries = _get_policy_store().list_audit_entries(
        policy_id=policy_id,
        agent_name=agent_name,
        limit=limit,
    )
    return {"entries": [e.model_dump() for e in entries], "count": len(entries)}


@app.get("/v1/gateway/stats", tags=["gateway"])
async def gateway_stats():
    """Gateway-wide statistics."""
    policies = _get_policy_store().list_policies()
    audit = _get_policy_store().list_audit_entries(limit=10000)
    enforce_count = sum(1 for p in policies if p.mode.value == "enforce" and p.enabled)
    audit_count = sum(1 for p in policies if p.mode.value == "audit" and p.enabled)
    blocked = sum(1 for e in audit if e.action_taken == "blocked")
    alerted = sum(1 for e in audit if e.action_taken == "alerted")
    return {
        "total_policies": len(policies),
        "enforce_count": enforce_count,
        "audit_count": audit_count,
        "enabled_count": sum(1 for p in policies if p.enabled),
        "total_rules": sum(len(p.rules) for p in policies),
        "audit_entries": len(audit),
        "blocked_count": blocked,
        "alerted_count": alerted,
    }


# ─── Governance ──────────────────────────────────────────────────────────────


@app.get("/v1/governance", tags=["governance"])
async def governance_report(days: int = 30):
    """Run Snowflake governance discovery and return findings.

    Mines ACCESS_HISTORY, GRANTS_TO_ROLES, TAG_REFERENCES, and
    CORTEX_AGENT_USAGE_HISTORY. Requires SNOWFLAKE_ACCOUNT env var.
    """
    import os as _os

    if not _os.environ.get("SNOWFLAKE_ACCOUNT"):
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
    import os as _os

    if not _os.environ.get("SNOWFLAKE_ACCOUNT"):
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
    import os as _os

    if not _os.environ.get("SNOWFLAKE_ACCOUNT"):
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

        flagged = flag_vulnerable_tool_calls(traces, vuln_packages, vuln_servers)

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


# ── Dashboard static file serving ────────────────────────────────────────────
# Must be registered LAST so API routes take precedence.


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
