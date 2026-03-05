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
"""

from __future__ import annotations

import asyncio
import logging
import secrets
import threading
import time
import uuid
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from agent_bom import __version__
from agent_bom.config import API_JOB_TTL_SECONDS as _JOB_TTL_SECONDS
from agent_bom.config import API_MAX_CONCURRENT_JOBS as _MAX_CONCURRENT_JOBS
from agent_bom.config import API_MAX_IN_MEMORY_JOBS as _MAX_IN_MEMORY_JOBS
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
    if os.environ.get("SNOWFLAKE_ACCOUNT"):
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
    elif os.environ.get("AGENT_BOM_POSTGRES_URL"):
        from agent_bom.api.postgres_store import (
            PostgresFleetStore,
            PostgresJobStore,
            PostgresPolicyStore,
        )

        if _store is None:
            set_job_store(PostgresJobStore())
        if _fleet_store is None:
            set_fleet_store(PostgresFleetStore())
        if _policy_store is None:
            set_policy_store(PostgresPolicyStore())
    elif os.environ.get("AGENT_BOM_DB"):
        db_path = os.environ["AGENT_BOM_DB"]
        if _store is None:
            from agent_bom.api.store import SQLiteJobStore

            set_job_store(SQLiteJobStore(db_path))
        if _fleet_store is None:
            from agent_bom.api.fleet_store import SQLiteFleetStore

            set_fleet_store(SQLiteFleetStore(db_path))
        if _policy_store is None:
            from agent_bom.api.policy_store import SQLitePolicyStore

            set_policy_store(SQLitePolicyStore(db_path))

    # ── Schedule store ──
    global _schedule_store
    if _schedule_store is None:
        if os.environ.get("AGENT_BOM_POSTGRES_URL"):
            from agent_bom.api.postgres_store import PostgresScheduleStore

            _schedule_store = PostgresScheduleStore()
        elif os.environ.get("AGENT_BOM_DB"):
            from agent_bom.api.schedule_store import SQLiteScheduleStore

            _schedule_store = SQLiteScheduleStore(os.environ["AGENT_BOM_DB"])
        else:
            from agent_bom.api.schedule_store import InMemoryScheduleStore

            _schedule_store = InMemoryScheduleStore()

    # ── Analytics store (ClickHouse OLAP — optional) ──
    if os.environ.get("AGENT_BOM_CLICKHOUSE_URL") and _analytics_store is None:
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

    _scheduler_task = asyncio.create_task(scheduler_loop(_schedule_store, _schedule_scan))

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

from starlette.middleware.base import BaseHTTPMiddleware  # noqa: E402
from starlette.requests import Request as StarletteRequest  # noqa: E402
from starlette.responses import JSONResponse  # noqa: E402
from starlette.types import ASGIApp  # noqa: E402


class TrustHeadersMiddleware(BaseHTTPMiddleware):
    """Add trust + standard security headers to every response."""

    async def dispatch(self, request: StarletteRequest, call_next):
        response = await call_next(request)
        response.headers["X-Agent-Bom-Read-Only"] = "true"
        response.headers["X-Agent-Bom-No-Credential-Storage"] = "true"
        response.headers["X-Agent-Bom-Version"] = __version__
        # Standard security headers
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Cache-Control"] = "no-store"
        response.headers["Content-Security-Policy"] = "default-src 'self'"
        return response


app.add_middleware(TrustHeadersMiddleware)


class APIKeyMiddleware(BaseHTTPMiddleware):
    """Optional API key authentication via Bearer token or X-API-Key header.

    Supports two modes:
    - Simple mode: single static API key (backward compatible)
    - RBAC mode: role-based access control via KeyStore with per-endpoint role checks
    """

    _EXEMPT_PATHS = {"/", "/health", "/version", "/docs", "/redoc", "/openapi.json"}

    # Endpoints requiring ADMIN role (mutating / destructive operations)
    _ADMIN_PATHS: set[tuple[str, str]] = {
        ("DELETE", "/v1/scan/"),
        ("POST", "/v1/gateway/policies"),
        ("PUT", "/v1/gateway/policies/"),
        ("DELETE", "/v1/gateway/policies/"),
        ("POST", "/v1/fleet/sync"),
        ("PUT", "/v1/fleet/"),
        ("POST", "/v1/auth/keys"),
        ("DELETE", "/v1/auth/keys/"),
        ("POST", "/v1/exceptions"),
        ("PUT", "/v1/exceptions/"),
        ("DELETE", "/v1/exceptions/"),
    }

    # Endpoints requiring ANALYST role (scan + write operations)
    _ANALYST_PATHS: set[tuple[str, str]] = {
        ("POST", "/v1/scan"),
        ("POST", "/v1/gateway/evaluate"),
        ("POST", "/v1/traces"),
        ("POST", "/v1/results/push"),
        ("POST", "/v1/schedules"),
        ("DELETE", "/v1/schedules/"),
        ("PUT", "/v1/schedules/"),
    }

    def __init__(self, app: ASGIApp, api_key: str):
        super().__init__(app)
        self._api_key = api_key

    def _required_role(self, method: str, path: str) -> str:
        """Determine the minimum role required for a request."""
        for m, p in self._ADMIN_PATHS:
            if method == m and path.startswith(p):
                return "admin"
        for m, p in self._ANALYST_PATHS:
            if method == m and path.startswith(p):
                return "analyst"
        return "viewer"

    async def dispatch(self, request: StarletteRequest, call_next):
        if request.url.path in self._EXEMPT_PATHS:
            return await call_next(request)

        # Extract raw key from headers
        raw_key = ""
        auth = request.headers.get("authorization", "")
        if auth.startswith("Bearer "):
            raw_key = auth[7:]
        if not raw_key:
            raw_key = request.headers.get("x-api-key", "")

        if not raw_key:
            return JSONResponse(
                status_code=401,
                content={"detail": "Unauthorized — provide API key via Authorization: Bearer <key> or X-API-Key header"},
            )

        # Simple mode: single static key (backward compatible, all access)
        if secrets.compare_digest(raw_key, self._api_key):
            request.state.api_key_name = "static-key"
            request.state.api_key_role = "admin"
            return await call_next(request)

        # RBAC mode: check against KeyStore
        from agent_bom.api.auth import Role, get_key_store

        store = get_key_store()
        if store.has_keys():
            api_key = store.verify(raw_key)
            if api_key:
                required = self._required_role(request.method, request.url.path)
                required_role = Role(required)
                if not api_key.has_role(required_role):
                    return JSONResponse(
                        status_code=403,
                        content={"detail": f"Forbidden — requires {required} role, you have {api_key.role.value}"},
                    )
                request.state.api_key_name = api_key.name
                request.state.api_key_role = api_key.role.value
                return await call_next(request)

        return JSONResponse(
            status_code=401,
            content={"detail": "Unauthorized — invalid API key"},
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
        if content_length:
            try:
                cl = int(content_length)
            except (ValueError, OverflowError):
                return JSONResponse(status_code=400, content={"detail": "Invalid Content-Length header"})
            if cl > self._max_bytes:
                return JSONResponse(
                    status_code=413,
                    content={"detail": f"Request body too large (max {self._max_bytes // (1024 * 1024)}MB)"},
                )
        return await call_next(request)


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
_executor = ThreadPoolExecutor(max_workers=min(8, (os.cpu_count() or 4) + 2))

# ─── Lazy-init lock (protects _store, _fleet_store, _policy_store) ───────────
_store_lock = threading.Lock()

# ─── Job store (pluggable) ────────────────────────────────────────────────────
# Import lazily to avoid circular import at module level
_store: Any = None  # Initialized on first use


def _get_store():
    """Get the active job store, creating InMemoryJobStore if not yet set."""
    global _store
    if _store is None:
        with _store_lock:
            if _store is None:
                from agent_bom.api.store import InMemoryJobStore

                _store = InMemoryJobStore()
    return _store


def set_job_store(store: Any) -> None:
    """Switch the job store backend. Call before server startup."""
    global _store
    _store = store


# In-memory job refs for SSE streaming (bounded, thread-safe)
_jobs: dict[str, "ScanJob"] = {}
_jobs_lock = threading.Lock()
_job_locks: dict[str, threading.Lock] = {}  # per-job locks for thread-safe field access


def _job_lock(job_id: str) -> threading.Lock:
    """Get or create a per-job lock for thread-safe field access."""
    with _jobs_lock:
        if job_id not in _job_locks:
            _job_locks[job_id] = threading.Lock()
        return _job_locks[job_id]


def _jobs_put(job_id: str, job: "ScanJob") -> None:
    """Add a job to _jobs with bounded eviction."""
    with _jobs_lock:
        _jobs[job_id] = job
        if len(_jobs) > _MAX_IN_MEMORY_JOBS:
            # Evict oldest completed jobs first
            completed = [(jid, j) for jid, j in _jobs.items() if j.status in (JobStatus.DONE, JobStatus.FAILED, JobStatus.CANCELLED)]
            completed.sort(key=lambda x: x[1].completed_at or "")
            for jid, _ in completed[: len(_jobs) - _MAX_IN_MEMORY_JOBS]:
                _jobs.pop(jid, None)


def _jobs_get(job_id: str) -> "ScanJob | None":
    """Thread-safe get from _jobs."""
    with _jobs_lock:
        return _jobs.get(job_id)


def _jobs_pop(job_id: str) -> "ScanJob | None":
    """Thread-safe pop from _jobs."""
    with _jobs_lock:
        return _jobs.pop(job_id, None)


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

    dynamic_discovery: bool = False
    """Enable dynamic content-based MCP config discovery."""

    dynamic_max_depth: int = 4
    """Max directory depth for dynamic discovery."""


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


# ─── Scan Pipeline (structured SSE events) ────────────────────────────────────


class StepStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    DONE = "done"
    FAILED = "failed"
    SKIPPED = "skipped"


PIPELINE_STEPS = ["discovery", "extraction", "scanning", "enrichment", "analysis", "output"]


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
            pipeline.update_step("discovery", f"Scanning image: {image_ref}", sub_step=image_ref)
            from agent_bom.image import scan_image

            img_agents, img_warnings = scan_image(image_ref)
            agents.extend(img_agents)
            warnings_all.extend(img_warnings)

        if req.k8s:
            pipeline.update_step("discovery", "Scanning Kubernetes pods...")
            from agent_bom.k8s import discover_images

            k8s_records = discover_images(namespace=req.k8s_namespace)
            for img, _pod, _ctr in k8s_records:
                from agent_bom.image import scan_image

                k8s_agents, k8s_warns = scan_image(img)
                agents.extend(k8s_agents)
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

            sbom_packages, _fmt = load_sbom(req.sbom)
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
                if not server.packages:
                    server.packages = extract_packages(server)
                total_pkgs += len(server.packages)
        pipeline.complete_step("extraction", f"Extracted {total_pkgs} packages", {"packages": total_pkgs})

        # ── Scanning phase ──
        pipeline.start_step("scanning", "Querying OSV.dev for CVEs...")
        blast_radii = scan_agents_sync(agents, enable_enrichment=req.enrich)
        total_vulns = sum(len(p.vulnerabilities) for a in agents for s in a.mcp_servers for p in s.packages)
        pipeline.complete_step("scanning", f"Found {total_vulns} vulnerabilities", {"vulnerabilities": total_vulns})

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


_cleanup_task: asyncio.Task | None = None
_scheduler_task: asyncio.Task | None = None
_schedule_store = None


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
        model_agents.append(_AgentModel(name=ad.get("name", ""), agent_type=ad.get("type", ""), mcp_servers=servers))

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

    from agent_bom.cis_controls import CIS_CONTROLS
    from agent_bom.eu_ai_act import EU_AI_ACT
    from agent_bom.iso_27001 import ISO_27001
    from agent_bom.nist_csf import NIST_CSF
    from agent_bom.owasp_agentic import OWASP_AGENTIC_TOP10
    from agent_bom.owasp_mcp import OWASP_MCP_TOP10
    from agent_bom.soc2 import SOC2_TSC

    owasp = _build_controls(OWASP_LLM_TOP10, "owasp_tags", "code")
    owasp_mcp = _build_controls(OWASP_MCP_TOP10, "owasp_mcp_tags", "code")
    atlas = _build_controls(ATLAS_TECHNIQUES, "atlas_tags", "code")
    nist = _build_controls(NIST_AI_RMF, "nist_ai_rmf_tags", "code")
    owasp_agentic = _build_controls(OWASP_AGENTIC_TOP10, "owasp_agentic_tags", "code")
    eu_ai_act = _build_controls(EU_AI_ACT, "eu_ai_act_tags", "code")
    nist_csf = _build_controls(NIST_CSF, "nist_csf_tags", "code")
    iso27001 = _build_controls(ISO_27001, "iso_27001_tags", "code")
    soc2 = _build_controls(SOC2_TSC, "soc2_tags", "code")
    cis = _build_controls(CIS_CONTROLS, "cis_tags", "code")

    def _count_statuses(controls: list[dict]) -> tuple[int, int, int]:
        p = sum(1 for c in controls if c["status"] == "pass")
        w = sum(1 for c in controls if c["status"] == "warning")
        f = sum(1 for c in controls if c["status"] == "fail")
        return p, w, f

    all_frameworks = [owasp, owasp_mcp, atlas, nist, owasp_agentic, eu_ai_act, nist_csf, iso27001, soc2, cis]
    total_controls = sum(len(fw) for fw in all_frameworks)
    total_pass = sum(_count_statuses(fw)[0] for fw in all_frameworks)
    any_fail = any(_count_statuses(fw)[2] > 0 for fw in all_frameworks)
    any_warn = any(_count_statuses(fw)[1] > 0 for fw in all_frameworks)
    overall_score = round((total_pass / total_controls) * 100, 1) if total_controls > 0 else 100.0

    if any_fail:
        overall_status = "fail"
    elif any_warn:
        overall_status = "warning"
    else:
        overall_status = "pass"

    op, ow, of_ = _count_statuses(owasp)
    mp, mw, mf = _count_statuses(owasp_mcp)
    ap, aw, af = _count_statuses(atlas)
    np_, nw, nf = _count_statuses(nist)
    oap, oaw, oaf = _count_statuses(owasp_agentic)
    eup, euw, euf = _count_statuses(eu_ai_act)
    ncp, ncw, ncf = _count_statuses(nist_csf)
    ip, iw, if2 = _count_statuses(iso27001)
    sp, sw, sf = _count_statuses(soc2)
    cp, cw, cf = _count_statuses(cis)

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
        "nist_csf": nist_csf,
        "iso_27001": iso27001,
        "soc2": soc2,
        "cis_controls": cis,
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
            "nist_csf_pass": ncp,
            "nist_csf_warn": ncw,
            "nist_csf_fail": ncf,
            "iso_27001_pass": ip,
            "iso_27001_warn": iw,
            "iso_27001_fail": if2,
            "soc2_pass": sp,
            "soc2_warn": sw,
            "soc2_fail": sf,
            "cis_pass": cp,
            "cis_warn": cw,
            "cis_fail": cf,
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


# ─── Compliance by Framework ────────────────────────────────────────────────


@app.get("/v1/compliance/{framework}", tags=["compliance"])
async def get_compliance_by_framework(framework: str) -> dict:
    """Get compliance posture for a single framework.

    Supported frameworks: owasp-llm, owasp-mcp, atlas, nist, owasp-agentic, eu-ai-act,
    nist-csf, iso-27001, soc2, cis
    """
    full = await get_compliance()

    framework_map = {
        "owasp-llm": "owasp_llm_top10",
        "owasp-mcp": "owasp_mcp_top10",
        "atlas": "mitre_atlas",
        "nist": "nist_ai_rmf",
        "owasp-agentic": "owasp_agentic_top10",
        "eu-ai-act": "eu_ai_act",
        "nist-csf": "nist_csf",
        "iso-27001": "iso_27001",
        "soc2": "soc2",
        "cis": "cis_controls",
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


# ─── Posture Scorecard ─────────────────────────────────────────────────────


@app.get("/v1/posture", tags=["compliance"])
async def get_posture_scorecard() -> dict:
    """Compute enterprise posture scorecard from the latest completed scan.

    Returns a letter grade (A-F), numeric score (0-100), and per-dimension
    breakdown covering vulnerability posture, credential hygiene, supply
    chain quality, compliance coverage, active exploitation, and configuration.
    """
    latest_result = None
    for job in _get_store().list_all():
        if job.status != JobStatus.DONE or not job.result:
            continue
        latest_result = job.result
        break  # list_all returns newest first

    if latest_result is None:
        return {
            "grade": "N/A",
            "score": 0,
            "summary": "No completed scans available",
            "dimensions": {},
        }

    scorecard = latest_result.get("posture_scorecard")
    if scorecard:
        return scorecard

    return {
        "grade": "N/A",
        "score": 0,
        "summary": "Scorecard not computed for this scan",
        "dimensions": {},
    }


@app.get("/v1/posture/credentials", tags=["compliance"])
async def get_credential_risk_ranking() -> dict:
    """Rank credentials by blast radius exposure from the latest scan.

    Returns credentials sorted by risk tier (critical to low) with
    associated vulnerability counts and affected agents.
    """
    latest_result = None
    for job in _get_store().list_all():
        if job.status != JobStatus.DONE or not job.result:
            continue
        latest_result = job.result
        break

    if latest_result is None:
        return {"credentials": [], "count": 0}

    ranking = latest_result.get("credential_risk_ranking", [])
    return {"credentials": ranking, "count": len(ranking)}


@app.get("/v1/posture/incidents", tags=["compliance"])
async def get_incident_correlation() -> dict:
    """Group vulnerabilities by agent for SOC incident correlation.

    Returns agent-centric incident summaries with priority (P1-P4),
    severity counts, credential exposure, and recommended actions.
    """
    latest_result = None
    for job in _get_store().list_all():
        if job.status != JobStatus.DONE or not job.result:
            continue
        latest_result = job.result
        break

    if latest_result is None:
        return {"incidents": [], "count": 0}

    incidents = latest_result.get("incident_correlation", [])
    return {"incidents": incidents, "count": len(incidents)}


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


_MAX_LOG_LINES = 50_000  # Cap log parsing to prevent memory issues


def _read_alerts_from_log(path: _Path) -> list[dict]:
    """Read runtime_alert records from a JSONL audit log."""
    import json as _json

    alerts: list[dict] = []
    try:
        with open(path) as f:
            for i, raw_line in enumerate(f):
                if i >= _MAX_LOG_LINES:
                    break
                line = raw_line.strip()
                if not line:
                    continue
                try:
                    record = _json.loads(line)
                    if record.get("type") == "runtime_alert":
                        alerts.append(record)
                except (ValueError, KeyError):
                    continue
    except OSError:
        pass
    return alerts


def _read_metrics_from_log(path: _Path) -> dict | None:
    """Read the last proxy_summary record from a JSONL audit log."""
    import json as _json

    last_summary = None
    try:
        with open(path) as f:
            for i, raw_line in enumerate(f):
                if i >= _MAX_LOG_LINES:
                    break
                line = raw_line.strip()
                if not line:
                    continue
                try:
                    record = _json.loads(line)
                    if record.get("type") == "proxy_summary":
                        last_summary = record
                except (ValueError, KeyError):
                    continue
    except OSError:
        pass
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
        with _store_lock:
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
        with _store_lock:
            if _policy_store is None:
                from agent_bom.api.policy_store import InMemoryPolicyStore

                _policy_store = InMemoryPolicyStore()
    return _policy_store


def set_policy_store(store: Any) -> None:
    """Switch the policy store backend. Call before server startup."""
    global _policy_store
    _policy_store = store


# ─── Analytics store (ClickHouse OLAP — optional) ────────────────────────────
_analytics_store: Any = None


def _get_analytics_store():
    """Get the active analytics store, defaulting to NullAnalyticsStore."""
    global _analytics_store
    if _analytics_store is None:
        with _store_lock:
            if _analytics_store is None:
                from agent_bom.api.clickhouse_store import NullAnalyticsStore

                _analytics_store = NullAnalyticsStore()
    return _analytics_store


def set_analytics_store(store: Any) -> None:
    """Switch the analytics store backend. Call before server startup."""
    global _analytics_store
    _analytics_store = store


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
    limit: int = 50,
    offset: int = 0,
):
    """List all agents in the fleet registry.

    Supports pagination via ``limit`` (default 50, max 200) and ``offset``.
    """
    limit = max(1, min(limit, 200))
    offset = max(0, offset)
    agents = _get_fleet_store().list_all()
    if state:
        agents = [a for a in agents if a.lifecycle_state.value == state]
    if environment:
        agents = [a for a in agents if a.environment == environment]
    if min_trust is not None:
        agents = [a for a in agents if a.trust_score >= min_trust]
    total = len(agents)
    page = agents[offset : offset + limit]
    return {
        "agents": [a.model_dump() for a in page],
        "count": len(page),
        "total": total,
        "limit": limit,
        "offset": offset,
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
        from agent_bom.cloud.snowflake import _get_connection
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
        from agent_bom.cloud.snowflake import _get_connection
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


# ── Hybrid Push — receive results from CLI ────────────────────────────────────


class PushPayload(BaseModel):
    source_id: str = ""
    agents: list = []
    blast_radii: list = []
    warnings: list = []


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


class ScheduleCreate(BaseModel):
    name: str
    cron_expression: str
    scan_config: dict = {}
    enabled: bool = True
    tenant_id: str = "default"


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
    _schedule_store.put(schedule)
    return schedule.model_dump()


@app.get("/v1/schedules", tags=["schedules"])
async def list_schedules() -> list[dict]:
    """List all scan schedules."""
    return [s.model_dump() for s in _schedule_store.list_all()]


@app.get("/v1/schedules/{schedule_id}", tags=["schedules"])
async def get_schedule(schedule_id: str) -> dict:
    """Get a specific schedule."""
    s = _schedule_store.get(schedule_id)
    if s is None:
        raise HTTPException(status_code=404, detail=f"Schedule {schedule_id} not found")
    return s.model_dump()


@app.delete("/v1/schedules/{schedule_id}", tags=["schedules"], status_code=204)
async def delete_schedule(schedule_id: str):
    """Delete a schedule."""
    if not _schedule_store.delete(schedule_id):
        raise HTTPException(status_code=404, detail=f"Schedule {schedule_id} not found")


@app.put("/v1/schedules/{schedule_id}/toggle", tags=["schedules"])
async def toggle_schedule(schedule_id: str) -> dict:
    """Enable or disable a schedule."""
    s = _schedule_store.get(schedule_id)
    if s is None:
        raise HTTPException(status_code=404, detail=f"Schedule {schedule_id} not found")
    s.enabled = not s.enabled
    s.updated_at = datetime.now(timezone.utc).isoformat()
    _schedule_store.put(s)
    return s.model_dump()


# ── Enterprise: API Key Management (RBAC) ──────────────────────────────────


class CreateKeyRequest(BaseModel):
    name: str
    role: str = "viewer"
    expires_at: str | None = None
    scopes: list[str] = []


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

_exception_store: Any = None


def _get_exception_store():
    global _exception_store
    if _exception_store is None:
        from agent_bom.api.exception_store import InMemoryExceptionStore

        _exception_store = InMemoryExceptionStore()
    return _exception_store


class ExceptionRequest(BaseModel):
    vuln_id: str
    package_name: str
    server_name: str = ""
    reason: str = ""
    requested_by: str = ""
    expires_at: str = ""
    tenant_id: str = "default"


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

_trend_store: Any = None
_last_scan_report: dict | None = None


def _get_trend_store():
    global _trend_store
    if _trend_store is None:
        from agent_bom.baseline import InMemoryTrendStore

        _trend_store = InMemoryTrendStore()
    return _trend_store


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
