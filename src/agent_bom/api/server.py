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
from typing import Any, cast

from agent_bom import __version__
from agent_bom.api import stores as _stores
from agent_bom.api.audit_log import get_audit_log
from agent_bom.api.auth import get_key_store
from agent_bom.api.middleware import (
    APIKeyMiddleware,
    MaxBodySizeMiddleware,
    RateLimitMiddleware,
    TrustHeadersMiddleware,
    configure_auth_runtime,
)

# ─── Extracted modules ────────────────────────────────────────────────────────
from agent_bom.api.models import (
    AnalyticsHealth,
    HealthResponse,
    JobStatus,
    ScanJob,
    ScanRequest,
    StepStatus,  # noqa: F401 — re-exported for tests
    StorageHealth,
    TracingHealth,
    VersionInfo,
)
from agent_bom.api.stores import (
    _get_schedule_store,
    _get_source_store,
    _get_store,
    _jobs,
    _jobs_get,  # noqa: F401 — re-exported for tests
    _jobs_lock,
    _jobs_pop,  # noqa: F401 — re-exported for tests
    _jobs_put,  # noqa: F401 — re-exported for tests
    set_analytics_store,
    set_exception_store,
    set_fleet_store,
    set_graph_store,
    set_job_store,
    set_policy_store,
    set_schedule_store,
    set_source_store,
    set_trend_store,
)
from agent_bom.api.tracing import configure_otel_tracing, get_tracing_health
from agent_bom.config import API_JOB_TTL_SECONDS as _JOB_TTL_SECONDS

_logger = logging.getLogger(__name__)

# ─── Dependency check ─────────────────────────────────────────────────────────

try:
    from fastapi import FastAPI
    from fastapi.middleware.cors import CORSMiddleware
    from fastapi.responses import JSONResponse, RedirectResponse
    from pydantic import BaseModel  # noqa: F401 — presence check for [api] extra
    from starlette.middleware import Middleware
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


def _backend_name(store: object | None) -> str:
    if store is None:
        return "disabled"
    name = type(store).__name__.lower()
    if "snowflake" in name:
        return "snowflake"
    if "postgres" in name:
        return "postgres"
    if "sqlite" in name:
        return "sqlite"
    if "clickhouse" in name:
        return "clickhouse"
    if "memory" in name:
        return "inmemory"
    if "null" in name:
        return "disabled"
    return type(store).__name__


def _control_plane_backend(storage: StorageHealth) -> str:
    primary = [storage.job_store, storage.fleet_store, storage.policy_store, storage.source_store]
    if any(name == "snowflake" for name in primary):
        return "snowflake"
    if any(name == "postgres" for name in primary):
        return "postgres"
    if any(name == "sqlite" for name in primary):
        return "sqlite"
    return "inmemory"


def _storage_health() -> StorageHealth:
    try:
        source_store = _get_source_store()
    except RuntimeError:
        source_store = None
    try:
        schedule_store = _get_schedule_store()
    except RuntimeError:
        schedule_store = None

    storage = StorageHealth(
        job_store=_backend_name(_stores._store or _stores._get_store()),
        fleet_store=_backend_name(_stores._fleet_store or _stores._get_fleet_store()),
        policy_store=_backend_name(_stores._policy_store or _stores._get_policy_store()),
        source_store=_backend_name(_stores._source_store or source_store),
        schedule_store=_backend_name(_stores._schedule_store or schedule_store),
        exception_store=_backend_name(_stores._exception_store or _stores._get_exception_store()),
        trend_store=_backend_name(_stores._trend_store or _stores._get_trend_store()),
        graph_store=_backend_name(_stores._graph_store or _stores._get_graph_store()),
        key_store=_backend_name(get_key_store()),
        audit_log=_backend_name(get_audit_log()),
    )
    storage.control_plane_backend = _control_plane_backend(storage)
    return storage


@asynccontextmanager
async def _lifespan(app_instance: FastAPI):
    """Start background cleanup task on startup, cancel on shutdown."""
    configure_otel_tracing()
    # Priority: Snowflake > Postgres > SQLite > InMemory (lazy default)
    if os.environ.get("SNOWFLAKE_ACCOUNT"):
        from agent_bom.api.snowflake_store import (
            SnowflakeExceptionStore,
            SnowflakeFleetStore,
            SnowflakeJobStore,
            SnowflakePolicyStore,
            SnowflakeScheduleStore,
            build_connection_params,
        )

        sf = build_connection_params()
        if _stores._store is None:
            set_job_store(SnowflakeJobStore(sf))
        if _stores._fleet_store is None:
            set_fleet_store(SnowflakeFleetStore(sf))
        if _stores._policy_store is None:
            set_policy_store(SnowflakePolicyStore(sf))
        if _stores._schedule_store is None:
            set_schedule_store(SnowflakeScheduleStore(sf))
        if _stores._exception_store is None:
            set_exception_store(SnowflakeExceptionStore(sf))
    elif os.environ.get("AGENT_BOM_POSTGRES_URL"):
        from agent_bom.api import audit_log as _audit_log_mod
        from agent_bom.api import auth as _auth
        from agent_bom.api.audit_log import set_audit_log
        from agent_bom.api.auth import set_key_store
        from agent_bom.api.postgres_store import (
            PostgresAuditLog,
            PostgresExceptionStore,
            PostgresFleetStore,
            PostgresGraphStore,
            PostgresJobStore,
            PostgresKeyStore,
            PostgresPolicyStore,
            PostgresSourceStore,
            PostgresTrendStore,
        )

        if _stores._store is None:
            set_job_store(PostgresJobStore())
        if _stores._fleet_store is None:
            set_fleet_store(PostgresFleetStore())
        if _stores._policy_store is None:
            set_policy_store(PostgresPolicyStore())
        if _stores._source_store is None:
            set_source_store(PostgresSourceStore())
        if _stores._exception_store is None:
            set_exception_store(PostgresExceptionStore())
        if _stores._trend_store is None:
            set_trend_store(PostgresTrendStore())
        if _stores._graph_store is None:
            set_graph_store(PostgresGraphStore())
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
        if _stores._source_store is None:
            from agent_bom.api.source_store import SQLiteSourceStore

            set_source_store(SQLiteSourceStore(db_path))
        if _stores._trend_store is None:
            from agent_bom.baseline import SQLiteTrendStore

            set_trend_store(SQLiteTrendStore(db_path))
        if _stores._graph_store is None:
            from agent_bom.api.graph_store import SQLiteGraphStore

            set_graph_store(SQLiteGraphStore())
        if _audit_log_mod._audit_log is None:
            set_audit_log(SQLiteAuditLog(db_path))

    if _stores._source_store is None:
        if os.environ.get("AGENT_BOM_POSTGRES_URL"):
            from agent_bom.api.postgres_store import PostgresSourceStore

            set_source_store(PostgresSourceStore())
        elif os.environ.get("AGENT_BOM_DB"):
            from agent_bom.api.source_store import SQLiteSourceStore

            set_source_store(SQLiteSourceStore(os.environ["AGENT_BOM_DB"]))
        else:
            from agent_bom.api.source_store import InMemorySourceStore

            set_source_store(InMemorySourceStore())

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

    # ── Rate-limit key rotation status ──
    try:
        from agent_bom.api.middleware import get_rate_limit_key_status

        _rl_status = get_rate_limit_key_status()
        if _rl_status["status"] == "max_age_exceeded":
            _logger.error(
                "rate_limit_key_rotation status=%s age_days=%s message=%s",
                _rl_status["status"],
                _rl_status["age_days"],
                _rl_status["message"],
            )
        elif _rl_status["status"] in {"rotation_due", "ephemeral", "unknown_age"}:
            _logger.warning(
                "rate_limit_key_rotation status=%s age_days=%s message=%s",
                _rl_status["status"],
                _rl_status["age_days"],
                _rl_status["message"],
            )
        else:
            _logger.info(
                "rate_limit_key_rotation status=%s age_days=%s",
                _rl_status["status"],
                _rl_status["age_days"],
            )
    except Exception:
        _logger.debug("rate_limit_key_rotation status check skipped", exc_info=True)

    global _cleanup_task
    _cleanup_task = asyncio.create_task(_cleanup_loop())

    # Start scheduler background loop
    global _scheduler_task
    from agent_bom.api.pipeline import _now
    from agent_bom.api.pipeline import _run_scan_sync as _run_scan  # local alias avoids F811 with re-export
    from agent_bom.api.scheduler import scheduler_loop
    from agent_bom.api.tenant_quota import enforce_active_scan_quota, enforce_retained_jobs_quota

    def _schedule_scan(scan_config: dict) -> str:
        """Trigger a scan from a schedule."""
        tenant_id = (
            getattr(scan_config, "tenant_id", None) if hasattr(scan_config, "tenant_id") else scan_config.get("tenant_id", "default")
        )
        tenant_id = str(tenant_id or "default")
        enforce_active_scan_quota(tenant_id)
        enforce_retained_jobs_quota(tenant_id)
        job = ScanJob(
            job_id=str(uuid.uuid4()),
            tenant_id=tenant_id,
            triggered_by="scheduler",
            created_at=_now(),
            request=ScanRequest(**scan_config) if isinstance(scan_config, dict) else scan_config,
        )
        _get_store().put(job)
        _jobs_put(job.job_id, job)
        loop = asyncio.get_running_loop()
        loop.run_in_executor(get_executor(), _run_scan, job)
        return job.job_id

    _scheduler_task = asyncio.create_task(scheduler_loop(_get_schedule_store(), _schedule_scan))

    yield

    # ── Graceful shutdown ──
    # Flip readiness to not-ready so upstream load balancers stop routing new
    # traffic while in-flight requests drain. The readiness probe reads
    # _shutting_down under the same module; see meta_routes.
    global _shutting_down
    _shutting_down = True
    if _scheduler_task:
        _scheduler_task.cancel()
    if _cleanup_task:
        _cleanup_task.cancel()
    # Drain in-flight scans. Honor the operator-configured drain budget so the
    # pod exits before Kubernetes force-kills at terminationGracePeriodSeconds.
    # Default 25s leaves a 5s margin under the recommended 30s Helm value.
    _drain_seconds = float(os.environ.get("AGENT_BOM_SHUTDOWN_DRAIN_SECONDS", "25"))
    try:
        await asyncio.wait_for(
            asyncio.to_thread(lambda: get_executor().shutdown(wait=True, cancel_futures=False)),
            timeout=_drain_seconds,
        )
    except asyncio.TimeoutError:
        _logger.warning(
            "shutdown drain timeout after %.1fs; force-cancelling in-flight scans",
            _drain_seconds,
        )
        get_executor().shutdown(wait=False, cancel_futures=True)
    # Close Postgres connection pool if active
    try:
        if os.environ.get("AGENT_BOM_POSTGRES_URL"):
            from agent_bom.api import postgres_common as _postgres_common

            if _postgres_common._pool is not None:
                _postgres_common._pool.close()
    except Exception:
        _logger.debug("Postgres pool close skipped")
    try:
        if _stores._analytics_store is not None and hasattr(_stores._analytics_store, "close"):
            _stores._analytics_store.close()
    except Exception:
        _logger.debug("Analytics store close skipped", exc_info=True)


app = FastAPI(
    title="agent-bom API",
    description=(
        "Security scanner for AI supply chain and infrastructure — "
        "map the full trust chain from agents to CVEs, credentials, and blast radius."
    ),
    version=__version__,
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=_lifespan,
)

_default_origins = [
    "http://localhost:3000",
    "http://127.0.0.1:3000",
    "http://localhost:3001",
    "http://127.0.0.1:3001",
]
_cors_env = os.environ.get("CORS_ORIGINS")
_cors_origins: list[str] = [o.strip() for o in _cors_env.split(",") if o.strip()] if _cors_env else _default_origins
_api_key: str | None = None
_rate_limit_rpm: int = 60


def _apply_cors_middleware(origins: list[str]) -> None:
    """Install or refresh the CORS middleware with the current origin policy."""
    _replace_middleware(
        CORSMiddleware,
        allow_origins=origins,
        allow_credentials="*" not in origins,
        allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
        allow_headers=["Content-Type", "Authorization", "X-API-Key", "X-Agent-Bom-CSRF"],
    )
    if app.middleware_stack is not None:
        app.middleware_stack = app.build_middleware_stack()


def _replace_middleware(middleware_cls: object, /, **kwargs: object) -> None:
    """Replace a middleware class in-place so runtime config updates actually apply."""
    app.user_middleware = [m for m in app.user_middleware if m.cls is not middleware_cls]
    app.user_middleware.insert(0, Middleware(cast(Any, middleware_cls), **kwargs))


# CORS: defaults to localhost; configure via configure_api() before startup
_apply_cors_middleware(_cors_origins)


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

    _apply_cors_middleware(_cors_origins)

    _api_key = api_key
    _rate_limit_rpm = rate_limit_rpm

    from agent_bom.api.oidc import oidc_enabled_from_env

    oidc_enabled = oidc_enabled_from_env()
    trusted_proxy_enabled = os.environ.get("AGENT_BOM_TRUST_PROXY_AUTH", "").strip().lower() in {"1", "true", "yes", "on"}
    auth_required = bool(api_key or oidc_enabled or trusted_proxy_enabled)
    configure_auth_runtime(
        api_key_configured=bool(api_key),
        oidc_enabled=oidc_enabled,
        trusted_proxy_enabled=trusted_proxy_enabled,
    )

    # Warn if API is exposed without authentication
    if not auth_required:
        _logger.warning(
            "SECURITY: No AGENT_BOM_API_KEY set — API endpoints are unauthenticated. "
            "Set AGENT_BOM_API_KEY environment variable for production deployments."
        )

    # Refresh runtime-configurable middleware
    if auth_required:
        _replace_middleware(APIKeyMiddleware, api_key=api_key)
    else:
        app.user_middleware = [m for m in app.user_middleware if m.cls is not APIKeyMiddleware]

    _replace_middleware(RateLimitMiddleware, scan_rpm=rate_limit_rpm, read_rpm=rate_limit_rpm * 5)
    _replace_middleware(MaxBodySizeMiddleware)
    if app.middleware_stack is not None:
        app.middleware_stack = app.build_middleware_stack()


# ─── Scan Pipeline (extracted to api/pipeline.py) ────────────────────────────
from agent_bom.api.pipeline import (  # noqa: E402
    PIPELINE_STEPS,  # noqa: F401 — re-exported for tests
    ScanPipeline,  # noqa: F401 — re-exported for tests
    _executor,  # noqa: F401 — re-exported for tests (may be replaced on shutdown; use get_executor() for new submissions)
    _run_scan_sync,  # noqa: F401 — re-exported for backward compat
    _sync_scan_agents_to_fleet,  # noqa: F401 — re-exported for tests
    get_executor,  # noqa: F401 — re-exported for tests
)

# ─── Route modules ────────────────────────────────────────────────────────
from agent_bom.api.routes.assets import router as _assets_router  # noqa: E402
from agent_bom.api.routes.compliance import router as _compliance_router  # noqa: E402
from agent_bom.api.routes.connectors import router as _connectors_router  # noqa: E402
from agent_bom.api.routes.discovery import router as _discovery_router  # noqa: E402
from agent_bom.api.routes.enterprise import router as _enterprise_router  # noqa: E402
from agent_bom.api.routes.fleet import router as _fleet_router  # noqa: E402
from agent_bom.api.routes.frameworks import router as _frameworks_router  # noqa: E402
from agent_bom.api.routes.gateway import router as _gateway_router  # noqa: E402
from agent_bom.api.routes.governance import router as _governance_router  # noqa: E402
from agent_bom.api.routes.graph import router as _graph_router  # noqa: E402
from agent_bom.api.routes.observability import router as _observability_router  # noqa: E402
from agent_bom.api.routes.proxy import router as _proxy_router  # noqa: E402
from agent_bom.api.routes.scan import router as _scan_router  # noqa: E402
from agent_bom.api.routes.schedules import router as _schedules_router  # noqa: E402
from agent_bom.api.routes.sources import router as _sources_router  # noqa: E402

app.include_router(_assets_router)
app.include_router(_compliance_router)
app.include_router(_connectors_router)
app.include_router(_discovery_router)
app.include_router(_enterprise_router)
app.include_router(_fleet_router)
app.include_router(_frameworks_router)
app.include_router(_gateway_router)
app.include_router(_governance_router)
app.include_router(_graph_router)
app.include_router(_observability_router)
app.include_router(_proxy_router)
app.include_router(_scan_router)
app.include_router(_schedules_router)
app.include_router(_sources_router)

# Re-export proxy push functions for backward compatibility
# Re-export connectors helpers for backward compatibility
from agent_bom.api.routes.connectors import _load_registry  # noqa: E402, F401
from agent_bom.api.routes.proxy import push_proxy_alert, push_proxy_metrics  # noqa: E402, F401

# Re-export scan helpers for backward compatibility
from agent_bom.api.routes.scan import _dataclass_to_dict, _sanitize_api_path  # noqa: E402, F401

_cleanup_task: asyncio.Task | None = None
_scheduler_task: asyncio.Task | None = None
# Flipped to True during graceful shutdown so the /readyz probe goes red
# and upstream load balancers stop sending new traffic while in-flight
# requests complete under the drain budget.
_shutting_down: bool = False


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


def _dashboard_index_file() -> str | None:
    """Return the packaged dashboard index path when bundled UI assets exist."""
    from pathlib import Path as _DashPath  # noqa: N814

    index_file = _DashPath(__file__).resolve().parents[1] / "ui_dist" / "index.html"
    if index_file.is_file():
        return str(index_file)
    return None


@app.api_route("/", methods=["GET", "HEAD"], include_in_schema=False)
async def root():
    dashboard_index = _dashboard_index_file()
    if dashboard_index:
        from fastapi.responses import FileResponse

        return FileResponse(dashboard_index)
    return RedirectResponse(url="/docs")


@app.get("/health", response_model=HealthResponse, tags=["meta"])
async def health() -> HealthResponse:
    """Liveness probe."""
    return HealthResponse(
        status="ok",
        version=__version__,
        tracing=TracingHealth(**get_tracing_health()),
        analytics=_analytics_health(),
        storage=_storage_health(),
    )


@app.get("/version", response_model=VersionInfo, tags=["meta"])
async def version() -> VersionInfo:
    """Version information."""
    return VersionInfo(version=__version__)


@app.get("/readyz", tags=["meta"])
async def readiness() -> JSONResponse:
    """Readiness probe — returns 503 once graceful shutdown has started.

    Kubernetes removes the pod from the service endpoint list on first 503,
    so new requests stop arriving while in-flight work drains under the
    operator-configured drain budget (AGENT_BOM_SHUTDOWN_DRAIN_SECONDS).
    """
    if _shutting_down:
        return JSONResponse(status_code=503, content={"status": "draining"})
    return JSONResponse(status_code=200, content={"status": "ready"})


# ── Dashboard static file serving ────────────────────────────────────────────
# Must be registered LAST so API routes take precedence.


def _mount_dashboard(application: FastAPI) -> None:
    """Mount pre-built Next.js dashboard if ui_dist/ exists in the package."""
    from pathlib import Path as _DashPath  # noqa: N814

    from fastapi import HTTPException as _HTTPException

    ui_dist = _DashPath(__file__).resolve().parents[1] / "ui_dist"
    if not ui_dist.is_dir() or not (ui_dist / "index.html").exists():
        return

    from starlette.responses import FileResponse
    from starlette.staticfiles import StaticFiles

    # Hashed JS/CSS assets
    next_static = ui_dist / "_next"
    if next_static.is_dir():
        application.mount("/_next", StaticFiles(directory=str(next_static)), name="next-static")

    # Pre-build a whitelist of static files at startup so the catch-all
    # handler never constructs filesystem paths from user input.
    _static_file_map: dict[str, str] = {}
    for _f in ui_dist.rglob("*"):
        if _f.is_file() and not str(_f.relative_to(ui_dist)).startswith("_next"):
            _static_file_map[str(_f.relative_to(ui_dist))] = str(_f.resolve())
    _index_html = str((ui_dist / "index.html").resolve())

    # SPA catch-all for client-side routing
    @application.api_route("/{path:path}", methods=["GET", "HEAD"], include_in_schema=False)
    async def _spa_catch_all(path: str):
        # Skip API and docs paths
        if path.startswith(("v1/", "docs", "redoc", "openapi.json", "health", "version", "readyz", "metrics")):
            raise _HTTPException(status_code=404)
        # Look up the pre-resolved path — user input is only a dict key,
        # never used in any filesystem operation (no path-injection risk).
        resolved = _static_file_map.get(path)
        if resolved:
            return FileResponse(resolved)
        # SPA fallback — serve index.html for client-side routing
        return FileResponse(_index_html)


_mount_dashboard(app)
