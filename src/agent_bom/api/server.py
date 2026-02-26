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
    GET  /v1/compliance                full 4-framework compliance posture
    GET  /v1/compliance/{framework}    single framework (owasp-llm, owasp-mcp, atlas, nist)
    GET  /v1/malicious/check           malicious package / typosquat check
    GET  /v1/proxy/status              runtime proxy metrics
    GET  /v1/proxy/alerts              recent runtime proxy alerts
    GET  /v1/scorecard/{eco}/{pkg}     OpenSSF Scorecard lookup
"""

from __future__ import annotations

import asyncio
import secrets
import time
import uuid
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from agent_bom import __version__

# ─── Dependency check ─────────────────────────────────────────────────────────

try:
    from fastapi import FastAPI, HTTPException
    from fastapi.middleware.cors import CORSMiddleware
    from fastapi.responses import RedirectResponse
    from pydantic import BaseModel
except ImportError as exc:  # pragma: no cover
    raise ImportError(
        "agent-bom API requires extra dependencies.\n"
        "Install with:  pip install 'agent-bom[api]'"
    ) from exc

# ─── App ──────────────────────────────────────────────────────────────────────

from contextlib import asynccontextmanager  # noqa: E402


@asynccontextmanager
async def _lifespan(app_instance: FastAPI):
    """Start background cleanup task on startup, cancel on shutdown."""
    global _cleanup_task
    _cleanup_task = asyncio.create_task(_cleanup_loop())
    yield
    if _cleanup_task:
        _cleanup_task.cancel()


app = FastAPI(
    title="agent-bom API",
    description=(
        "AI Bill of Materials — map the full trust chain from AI agents and "
        "MCP servers to CVEs, credentials, and blast radius."
    ),
    version=__version__,
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=_lifespan,
)

# ── API hardening config ─────────────────────────────────────────────────
_cors_origins: list[str] = ["http://localhost:3000", "http://127.0.0.1:3000"]
_api_key: str | None = None
_rate_limit_rpm: int = 60

# CORS: defaults to localhost; configure via configure_api() before startup
app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
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

        return JSONResponse(status_code=401, content={"detail": "Unauthorized — provide API key via Authorization: Bearer <key> or X-API-Key header"})


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Per-IP sliding window rate limiter."""

    def __init__(self, app: ASGIApp, scan_rpm: int = 60, read_rpm: int = 300):
        super().__init__(app)
        self._scan_rpm = scan_rpm
        self._read_rpm = read_rpm
        self._hits: dict[str, list[float]] = defaultdict(list)

    async def dispatch(self, request: StarletteRequest, call_next):
        client_ip = request.client.host if request.client else "unknown"
        now = time.time()

        is_scan = request.url.path.startswith("/v1/scan") and request.method == "POST"
        limit = self._scan_rpm if is_scan else self._read_rpm

        key = f"{client_ip}:{'scan' if is_scan else 'read'}"
        self._hits[key] = [t for t in self._hits[key] if now - t < 60]

        if len(self._hits[key]) >= limit:
            retry_after = max(int(60 - (now - self._hits[key][0])), 1)
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
                content={"detail": f"Request body too large (max {self._max_bytes // (1024*1024)}MB)"},
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
                    servers.append(MCPServer(
                        name=s.get("name", "unknown"),
                        command=s.get("command", ""),
                        args=s.get("args", []),
                        env=s.get("env", {}),
                    ))
                agents.append(Agent(
                    name=agent_data.get("name", "unknown"),
                    agent_type=AgentType.CUSTOM,
                    config_path=req.inventory,
                    mcp_servers=servers,
                ))
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

    return job.result.get("skill_audit", {
        "findings": [],
        "packages_checked": 0,
        "servers_checked": 0,
        "credentials_checked": 0,
        "passed": True,
    })


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
        raise HTTPException(status_code=500, detail=str(exc)) from exc


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
    """Aggregate OWASP LLM Top 10, MITRE ATLAS, and NIST AI RMF compliance
    posture across all completed scans.

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

            controls.append({
                id_key: code,
                "name": name,
                "findings": findings,
                "status": status,
                "severity_breakdown": sev_breakdown,
                "affected_packages": sorted(affected_pkgs),
                "affected_agents": sorted(affected_agents),
            })
        return controls

    from agent_bom.owasp_mcp import OWASP_MCP_TOP10

    owasp = _build_controls(OWASP_LLM_TOP10, "owasp_tags", "code")
    owasp_mcp = _build_controls(OWASP_MCP_TOP10, "owasp_mcp_tags", "code")
    atlas = _build_controls(ATLAS_TECHNIQUES, "atlas_tags", "code")
    nist = _build_controls(NIST_AI_RMF, "nist_ai_rmf_tags", "code")

    def _count_statuses(controls: list[dict]) -> tuple[int, int, int]:
        p = sum(1 for c in controls if c["status"] == "pass")
        w = sum(1 for c in controls if c["status"] == "warning")
        f = sum(1 for c in controls if c["status"] == "fail")
        return p, w, f

    op, ow, of_ = _count_statuses(owasp)
    mp, mw, mf = _count_statuses(owasp_mcp)
    ap, aw, af = _count_statuses(atlas)
    np_, nw, nf = _count_statuses(nist)

    total_controls = len(owasp) + len(owasp_mcp) + len(atlas) + len(nist)
    total_pass = op + mp + ap + np_
    overall_score = round((total_pass / total_controls) * 100, 1) if total_controls > 0 else 100.0

    if of_ > 0 or mf > 0 or af > 0 or nf > 0:
        overall_status = "fail"
    elif ow > 0 or mw > 0 or aw > 0 or nw > 0:
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
        "summary": {
            "owasp_pass": op, "owasp_warn": ow, "owasp_fail": of_,
            "owasp_mcp_pass": mp, "owasp_mcp_warn": mw, "owasp_mcp_fail": mf,
            "atlas_pass": ap, "atlas_warn": aw, "atlas_fail": af,
            "nist_pass": np_, "nist_warn": nw, "nist_fail": nf,
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
            name = name[len(prefix):]
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
        result.append({
            "id": key,
            "name": entry.get("name", _derive_name(key)),
            "publisher": _infer_publisher(key),
            "verified": entry.get("verified", False),
            "transport": "stdio",
            "risk_level": entry.get("risk_level", "low"),
            "packages": [{"name": entry["package"], "ecosystem": entry["ecosystem"]}]
            if entry.get("package")
            else [],
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
        })
    return result


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

    Supported frameworks: owasp-llm, owasp-mcp, atlas, nist
    """
    full = await get_compliance()

    framework_map = {
        "owasp-llm": "owasp_llm_top10",
        "owasp-mcp": "owasp_mcp_top10",
        "atlas": "mitre_atlas",
        "nist": "nist_ai_rmf",
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


def _validate_log_path(log_path: str) -> str:
    """Validate and sanitize a log file path.

    Ensures the path:
    - Has a .jsonl extension (audit log format)
    - Is resolved to an absolute path (no traversal)
    - Does not traverse outside the resolved parent directory

    Returns the resolved absolute path string.
    Raises HTTPException on invalid paths.
    """
    from pathlib import Path as _Pth

    resolved = _Pth(log_path).resolve()

    # Must be a .jsonl file
    if resolved.suffix != ".jsonl":
        raise HTTPException(status_code=400, detail="Log path must be a .jsonl file")

    # Must not contain path traversal components
    if ".." in _Pth(log_path).parts:
        raise HTTPException(status_code=400, detail="Path traversal not allowed")

    return str(resolved)


def _read_alerts_from_log(log_path: str) -> list[dict]:
    """Read runtime_alert records from a JSONL audit log."""
    import json as _json
    from pathlib import Path as _Pth

    safe_path = _validate_log_path(log_path)
    path = _Pth(safe_path)
    if not path.exists():
        return []
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


def _read_metrics_from_log(log_path: str) -> dict | None:
    """Read the last proxy_summary record from a JSONL audit log."""
    import json as _json
    from pathlib import Path as _Pth

    safe_path = _validate_log_path(log_path)
    path = _Pth(safe_path)
    if not path.exists():
        return None
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
async def proxy_status(log: str | None = None) -> dict:
    """Get runtime proxy metrics.

    Returns the latest proxy metrics summary. If running in-process, reads
    from the shared buffer. If a ``log`` query param is provided, reads the
    last proxy_summary from that JSONL audit log file.

    Query params:
        log: Path to the proxy audit log (JSONL) to read metrics from.
    """
    if log:
        metrics = _read_metrics_from_log(log)
        if metrics is None:
            raise HTTPException(status_code=404, detail="No proxy metrics found in log")
        return metrics

    if _proxy_metrics is not None:
        return _proxy_metrics

    return {
        "status": "no_proxy_session",
        "message": "No proxy metrics available. Start a proxy session or provide ?log=path/to/audit.jsonl",
    }


@app.get("/v1/proxy/alerts", tags=["proxy"])
async def proxy_alerts(
    log: str | None = None,
    severity: str | None = None,
    detector: str | None = None,
    limit: int = 100,
) -> dict:
    """Get recent runtime proxy alerts.

    Returns alerts from the current or most recent proxy session.

    Query params:
        log: Path to the proxy audit log (JSONL) to read alerts from.
        severity: Filter by severity (critical, high, medium, low, info).
        detector: Filter by detector name.
        limit: Maximum number of alerts to return (default 100).
    """
    if log:
        alerts = _read_alerts_from_log(log)
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
    from agent_bom.scorecard import extract_github_repo, fetch_scorecard

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
