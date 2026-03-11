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
import os
import uuid
from concurrent.futures import ThreadPoolExecutor
from contextlib import asynccontextmanager

import agent_bom.api.stores as _stores  # module ref for mutable globals
from agent_bom import __version__
from agent_bom.api.middleware import (
    APIKeyMiddleware,
    MaxBodySizeMiddleware,
    RateLimitMiddleware,
    TrustHeadersMiddleware,
)
from agent_bom.api.models import (
    HealthResponse,
    JobStatus,  # noqa: F401 — re-export for tests
    ScanJob,
    ScanRequest,
    VersionInfo,
)
from agent_bom.api.pipeline import (  # noqa: F401
    _STUCK_JOB_TIMEOUT,
    PIPELINE_STEPS,
    ScanPipeline,
    _cleanup_loop,
    _now,
    _run_scan_sync,
    _sync_scan_agents_to_fleet,
)
from agent_bom.api.stores import (  # noqa: F401
    _get_analytics_store,
    _get_configured_log_path,
    _get_exception_store,
    _get_fleet_store,
    _get_policy_store,
    _get_schedule_store,
    _get_store,
    _get_trend_store,
    _job_lock,
    _jobs,
    _jobs_get,
    _jobs_lock,
    _jobs_pop,
    _jobs_put,
    _proxy_alerts,
    _read_alerts_from_log,
    _read_metrics_from_log,
    _store_lock,
    get_executor,
    push_proxy_alert,
    push_proxy_metrics,
    set_analytics_store,
    set_executor,
    set_fleet_store,
    set_job_store,
    set_policy_store,
)
from agent_bom.config import API_MAX_CONCURRENT_JOBS as _MAX_CONCURRENT_JOBS  # noqa: F401

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

            _stores._schedule_store = PostgresScheduleStore()
        elif os.environ.get("AGENT_BOM_DB"):
            from agent_bom.api.schedule_store import SQLiteScheduleStore

            _stores._schedule_store = SQLiteScheduleStore(os.environ["AGENT_BOM_DB"])
        else:
            from agent_bom.api.schedule_store import InMemoryScheduleStore

            _stores._schedule_store = InMemoryScheduleStore()

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
        loop.run_in_executor(get_executor(), _run_scan_sync, job)
        return job.job_id

    _scheduler_task = asyncio.create_task(scheduler_loop(_stores._schedule_store, _schedule_scan))

    yield

    # ── Graceful shutdown ──
    if _scheduler_task:
        _scheduler_task.cancel()
    if _cleanup_task:
        _cleanup_task.cancel()
    # Shut down thread pool (wait for in-flight scans, 30s timeout)
    if _stores._executor is not None:
        _stores._executor.shutdown(wait=True, cancel_futures=True)
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


# ─── Thread pool executor ─────────────────────────────────────────────────────

_executor = ThreadPoolExecutor(max_workers=min(8, (os.cpu_count() or 4) + 2))
set_executor(_executor)

_cleanup_task: asyncio.Task | None = None
_scheduler_task: asyncio.Task | None = None


# ─── Meta routes ──────────────────────────────────────────────────────────────


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


# ─── Include route modules ────────────────────────────────────────────────────

from agent_bom.api.routes_compliance import router as _compliance_router  # noqa: E402
from agent_bom.api.routes_discovery import router as _discovery_router  # noqa: E402
from agent_bom.api.routes_enterprise import router as _enterprise_router  # noqa: E402
from agent_bom.api.routes_fleet import router as _fleet_router  # noqa: E402
from agent_bom.api.routes_gateway import router as _gateway_router  # noqa: E402
from agent_bom.api.routes_governance import router as _governance_router  # noqa: E402
from agent_bom.api.routes_misc import router as _misc_router  # noqa: E402
from agent_bom.api.routes_proxy import router as _proxy_router  # noqa: E402
from agent_bom.api.routes_registry import router as _registry_router  # noqa: E402
from agent_bom.api.routes_scan import router as _scan_router  # noqa: E402
from agent_bom.api.routes_schedules import router as _schedules_router  # noqa: E402

app.include_router(_scan_router)
app.include_router(_discovery_router)
app.include_router(_compliance_router)
app.include_router(_registry_router)
app.include_router(_proxy_router)
app.include_router(_fleet_router)
app.include_router(_gateway_router)
app.include_router(_governance_router)
app.include_router(_enterprise_router)
app.include_router(_schedules_router)
app.include_router(_misc_router)


# ─── Backward-compat re-exports from route modules ───────────────────────────
# Many test files import endpoint functions from server.py.

from agent_bom.api.routes_compliance import (  # noqa: E402, F401
    check_malicious,
    get_compliance,
    get_compliance_by_framework,
    get_credential_risk_ranking,
    get_incident_correlation,
    get_posture_counts,
    get_posture_scorecard,
    scorecard_lookup,
)
from agent_bom.api.routes_discovery import (  # noqa: E402, F401
    get_agent_detail,
    get_agent_lifecycle,
    get_agent_mesh,
    list_agents,
)
from agent_bom.api.routes_enterprise import (  # noqa: E402, F401
    approve_exception,
    audit_integrity,
    compare_baseline,
    create_exception,
    create_key,
    delete_exception,
    delete_key,
    get_exception,
    get_trends,
    list_audit_entries,
    list_exceptions,
    list_keys,
    list_siem_connectors,
    revoke_exception,
    test_siem_connection,
)
from agent_bom.api.routes_fleet import (  # noqa: E402, F401
    fleet_stats,
    get_fleet_agent,
    list_fleet,
    sync_fleet,
    update_fleet_agent,
    update_fleet_state,
)
from agent_bom.api.routes_gateway import (  # noqa: E402, F401
    create_gateway_policy,
    delete_gateway_policy,
    evaluate_gateway,
    gateway_stats,
    get_gateway_policy,
    list_gateway_audit,
    list_gateway_policies,
    update_gateway_policy,
)
from agent_bom.api.routes_governance import (  # noqa: E402, F401
    activity_timeline,
    cortex_agent_telemetry,
    cortex_health,
    cortex_telemetry,
    governance_findings,
    governance_report,
)
from agent_bom.api.routes_misc import (  # noqa: E402, F401
    get_asset_stats,
    ingest_traces,
    list_assets,
    receive_push,
)
from agent_bom.api.routes_proxy import (  # noqa: E402, F401
    proxy_alerts,
    proxy_status,
    ws_proxy_alerts,
    ws_proxy_metrics,
)
from agent_bom.api.routes_registry import (  # noqa: E402, F401
    _load_registry,
    connector_health,
    get_registry_server,
    list_available_connectors,
    list_registry,
    siem_formats,
)
from agent_bom.api.routes_scan import (  # noqa: E402, F401
    _dataclass_to_dict,
    _sanitize_api_path,
    create_scan,
    delete_scan,
    get_attack_flow,
    get_context_graph,
    get_licenses,
    get_scan,
    get_skill_audit,
    get_vex,
    list_jobs,
    scan_browser_extensions_endpoint,
    scan_dataset_cards,
    scan_model_files_endpoint,
    scan_model_provenance,
    scan_prompts,
    scan_training_pipelines,
    stream_scan,
)
from agent_bom.api.routes_schedules import (  # noqa: E402, F401
    create_schedule,
    delete_schedule,
    get_schedule,
    list_schedules,
    toggle_schedule,
)

# ─── Dashboard static file serving ───────────────────────────────────────────
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
