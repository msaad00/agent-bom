"""agent-bom FastAPI server.

Start with:
    agent-bom api                      # default: http://localhost:8422
    agent-bom api --host 0.0.0.0 --port 8422

Core infrastructure: lifespan, middleware, CORS, meta routes (/, /health, /version),
dashboard mounting. All domain routes live in api/routes/ sub-modules.
"""

from __future__ import annotations

import asyncio
import logging
import os
import uuid

from agent_bom import __version__
from agent_bom.api import stores as _stores
from agent_bom.api.middleware import (
    APIKeyMiddleware,
    MaxBodySizeMiddleware,
    RateLimitMiddleware,
    TrustHeadersMiddleware,
)

# ─── Extracted modules ────────────────────────────────────────────────────────
from agent_bom.api.models import (
    AnalyticsHealth,
    HealthResponse,
    JobStatus,
    ScanJob,
    ScanRequest,
    StepStatus,  # noqa: F401 — re-exported for tests
    TracingHealth,
    VersionInfo,
)
from agent_bom.api.stores import (
    _get_schedule_store,
    _get_store,
    _jobs,
    _jobs_get,  # noqa: F401 — re-exported for tests
    _jobs_lock,
    _jobs_pop,  # noqa: F401 — re-exported for tests
    _jobs_put,  # noqa: F401 — re-exported for tests
    set_analytics_store,
    set_exception_store,
    set_fleet_store,
    set_job_store,
    set_policy_store,
    set_schedule_store,
    set_trend_store,
)
from agent_bom.api.tracing import configure_otel_tracing, get_tracing_health
from agent_bom.config import API_JOB_TTL_SECONDS as _JOB_TTL_SECONDS
from agent_bom.config import API_MAX_CONCURRENT_JOBS as _MAX_CONCURRENT_JOBS  # noqa: F401 — re-exported for tests

_logger = logging.getLogger(__name__)

# ─── Dependency check ─────────────────────────────────────────────────────────

try:
    from fastapi import FastAPI
    from fastapi.middleware.cors import CORSMiddleware
    from fastapi.responses import RedirectResponse
    from pydantic import BaseModel  # noqa: F401 — presence check for [api] extra
except ImportError as exc:  # pragma: no cover
    raise ImportError("agent-bom API requires extra dependencies.\nInstall with:  pip install 'agent-bom[api]'") from exc

# ─── App ──────────────────────────────────────────────────────────────────────

from contextlib import asynccontextmanager  # noqa: E402


def _analytics_backend_config() -> tuple[str, str | None]:
    """Resolve the requested analytics backend and configured ClickHouse URL."""
    backend = os.environ.get("AGENT_BOM_ANALYTICS_BACKEND", "").strip().lower()
    clickhouse_url = os.environ.get("AGENT_BOM_CLICKHOUSE_URL", "").strip() or None
    if backend in {"", "auto"}:
        backend = "clickhouse" if clickhouse_url else "disabled"
    return backend, clickhouse_url


def _analytics_health() -> AnalyticsHealth:
    """Return the active analytics backend contract for operators."""
    backend, clickhouse_url = _analytics_backend_config()
    active_store = _stores._analytics_store
    if active_store is None:
        return AnalyticsHealth(
            backend=backend if backend != "disabled" else "disabled",
            enabled=False,
            buffered=False,
            clickhouse_url_configured=bool(clickhouse_url),
        )

    store_name = type(active_store).__name__
    buffered = hasattr(active_store, "flush_interval") and hasattr(active_store, "max_batch")
    return AnalyticsHealth(
        backend="clickhouse" if "ClickHouse" in store_name or buffered else backend,
        enabled=store_name != "NullAnalyticsStore",
        buffered=buffered,
        clickhouse_url_configured=bool(clickhouse_url),
        flush_interval_seconds=float(getattr(active_store, "flush_interval", 0.0)) if buffered else None,
        max_batch=int(getattr(active_store, "max_batch", 0)) if buffered else None,
    )


@asynccontextmanager
async def _lifespan(app_instance: FastAPI):
    """Start background cleanup task on startup, cancel on shutdown."""
    configure_otel_tracing()
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
        from agent_bom.api import audit_log as _audit_log_mod
        from agent_bom.api import auth as _auth
        from agent_bom.api.audit_log import set_audit_log
        from agent_bom.api.auth import set_key_store
        from agent_bom.api.postgres_store import (
            PostgresAuditLog,
            PostgresExceptionStore,
            PostgresFleetStore,
            PostgresJobStore,
            PostgresKeyStore,
            PostgresPolicyStore,
            PostgresTrendStore,
        )

        if _stores._store is None:
            set_job_store(PostgresJobStore())
        if _stores._fleet_store is None:
            set_fleet_store(PostgresFleetStore())
        if _stores._policy_store is None:
            set_policy_store(PostgresPolicyStore())
        if _stores._exception_store is None:
            set_exception_store(PostgresExceptionStore())
        if _stores._trend_store is None:
            set_trend_store(PostgresTrendStore())
        if _auth._key_store is None:
            set_key_store(PostgresKeyStore())
        if _audit_log_mod._audit_log is None:
            set_audit_log(PostgresAuditLog())
    elif os.environ.get("AGENT_BOM_DB"):
        from agent_bom.api import audit_log as _audit_log_mod
        from agent_bom.api.audit_log import SQLiteAuditLog, set_audit_log

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
        if _stores._trend_store is None:
            from agent_bom.baseline import SQLiteTrendStore

            set_trend_store(SQLiteTrendStore(db_path))
        if _audit_log_mod._audit_log is None:
            set_audit_log(SQLiteAuditLog(db_path))

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
    analytics_backend, clickhouse_url = _analytics_backend_config()
    if analytics_backend == "clickhouse" and _stores._analytics_store is None:
        try:
            from agent_bom.api.clickhouse_store import BufferedAnalyticsStore, ClickHouseAnalyticsStore

            if not clickhouse_url:
                raise ValueError("ClickHouse analytics backend requires AGENT_BOM_CLICKHOUSE_URL")
            base_store = ClickHouseAnalyticsStore(url=clickhouse_url)
            if os.environ.get("AGENT_BOM_CLICKHOUSE_BUFFERED", "1").strip().lower() not in {"0", "false", "no"}:
                flush_interval = float(os.environ.get("AGENT_BOM_CLICKHOUSE_FLUSH_INTERVAL", "1.0"))
                max_batch = int(os.environ.get("AGENT_BOM_CLICKHOUSE_MAX_BATCH", "200"))
                set_analytics_store(BufferedAnalyticsStore(base_store, flush_interval=flush_interval, max_batch=max_batch))
                _logger.info(
                    "ClickHouse analytics store enabled with buffered writes (batch=%s, flush_interval=%.2fs)",
                    max_batch,
                    flush_interval,
                )
            else:
                set_analytics_store(base_store)
                _logger.info("ClickHouse analytics store enabled without buffering")
        except Exception:
            _logger.warning("ClickHouse analytics unavailable, using NullAnalyticsStore", exc_info=True)

    global _cleanup_task
    _cleanup_task = asyncio.create_task(_cleanup_loop())

    # Start scheduler background loop
    global _scheduler_task
    from agent_bom.api.pipeline import _now
    from agent_bom.api.pipeline import _run_scan_sync as _run_scan  # local alias avoids F811 with re-export
    from agent_bom.api.scheduler import scheduler_loop

    def _schedule_scan(scan_config: dict) -> str:
        """Trigger a scan from a schedule."""
        tenant_id = (
            getattr(scan_config, "tenant_id", None) if hasattr(scan_config, "tenant_id") else scan_config.get("tenant_id", "default")
        )
        job = ScanJob(
            job_id=str(uuid.uuid4()),
            tenant_id=str(tenant_id or "default"),
            created_at=_now(),
            request=ScanRequest(**scan_config) if isinstance(scan_config, dict) else scan_config,
        )
        _get_store().put(job)
        _jobs_put(job.job_id, job)
        loop = asyncio.get_running_loop()
        loop.run_in_executor(_executor, _run_scan, job)
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
    try:
        if _stores._analytics_store is not None and hasattr(_stores._analytics_store, "close"):
            _stores._analytics_store.close()
    except Exception:
        _logger.debug("Analytics store close skipped", exc_info=True)


app = FastAPI(
    title="agent-bom API",
    description=("Security scanner for AI infrastructure — map the full trust chain from agents to CVEs, credentials, and blast radius."),
    version=__version__,
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=_lifespan,
)

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


# ─── Scan Pipeline (extracted to api/pipeline.py) ────────────────────────────
from agent_bom.api.pipeline import (  # noqa: E402
    PIPELINE_STEPS,  # noqa: F401 — re-exported for tests
    ScanPipeline,  # noqa: F401 — re-exported for tests
    _executor,  # noqa: F401 — re-exported for tests
    _run_scan_sync,  # noqa: F401 — re-exported for backward compat
    _sync_scan_agents_to_fleet,  # noqa: F401 — re-exported for tests
)

# ─── Route modules ────────────────────────────────────────────────────────
from agent_bom.api.routes.assets import router as _assets_router  # noqa: E402
from agent_bom.api.routes.compliance import router as _compliance_router  # noqa: E402
from agent_bom.api.routes.connectors import router as _connectors_router  # noqa: E402
from agent_bom.api.routes.discovery import router as _discovery_router  # noqa: E402
from agent_bom.api.routes.enterprise import router as _enterprise_router  # noqa: E402
from agent_bom.api.routes.fleet import router as _fleet_router  # noqa: E402
from agent_bom.api.routes.gateway import router as _gateway_router  # noqa: E402
from agent_bom.api.routes.governance import router as _governance_router  # noqa: E402
from agent_bom.api.routes.graph import router as _graph_router  # noqa: E402
from agent_bom.api.routes.observability import router as _observability_router  # noqa: E402
from agent_bom.api.routes.proxy import router as _proxy_router  # noqa: E402
from agent_bom.api.routes.scan import router as _scan_router  # noqa: E402
from agent_bom.api.routes.schedules import router as _schedules_router  # noqa: E402

app.include_router(_assets_router)
app.include_router(_compliance_router)
app.include_router(_connectors_router)
app.include_router(_discovery_router)
app.include_router(_enterprise_router)
app.include_router(_fleet_router)
app.include_router(_gateway_router)
app.include_router(_governance_router)
app.include_router(_graph_router)
app.include_router(_observability_router)
app.include_router(_proxy_router)
app.include_router(_scan_router)
app.include_router(_schedules_router)

# Re-export proxy push functions for backward compatibility
# Re-export connectors helpers for backward compatibility
from agent_bom.api.routes.connectors import _load_registry  # noqa: E402, F401
from agent_bom.api.routes.proxy import push_proxy_alert, push_proxy_metrics  # noqa: E402, F401

# Re-export scan helpers for backward compatibility
from agent_bom.api.routes.scan import _dataclass_to_dict, _sanitize_api_path  # noqa: E402, F401

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


# ─── Meta Routes ─────────────────────────────────────────────────────────────


@app.get("/", include_in_schema=False)
async def root() -> RedirectResponse:
    return RedirectResponse(url="/docs")


@app.get("/health", response_model=HealthResponse, tags=["meta"])
async def health() -> HealthResponse:
    """Liveness probe."""
    return HealthResponse(
        status="ok",
        version=__version__,
        tracing=TracingHealth(**get_tracing_health()),
        analytics=_analytics_health(),
    )


@app.get("/version", response_model=VersionInfo, tags=["meta"])
async def version() -> VersionInfo:
    """Version information."""
    return VersionInfo(version=__version__)


# ── Dashboard static file serving ────────────────────────────────────────────
# Must be registered LAST so API routes take precedence.


def _mount_dashboard(application: FastAPI) -> None:
    """Mount pre-built Next.js dashboard if ui_dist/ exists in the package."""
    from pathlib import Path as _DashPath  # noqa: N814

    from fastapi import HTTPException as _HTTPException

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
            raise _HTTPException(status_code=404)
        # Look up the pre-resolved path — user input is only a dict key,
        # never used in any filesystem operation (no path-injection risk).
        resolved = _static_file_map.get(path)
        if resolved:
            return FileResponse(resolved)
        # SPA fallback — serve index.html for client-side routing
        return FileResponse(_index_html)


_mount_dashboard(app)
