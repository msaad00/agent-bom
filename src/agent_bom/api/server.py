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
import re
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast

from agent_bom import __version__
from agent_bom.api import stores as _stores
from agent_bom.api.audit_log import get_audit_log
from agent_bom.api.auth import Role, create_api_key_record, get_key_store
from agent_bom.api.middleware import (
    DEFAULT_SCAN_RATE_LIMIT_RPM,
    MAX_RATE_LIMIT_RPM,
    APIKeyMiddleware,
    GlobalRateLimitMiddleware,
    MaxBodySizeMiddleware,
    RateLimitMiddleware,
    TrustHeadersMiddleware,
    configure_auth_runtime,
    global_ip_rate_limit_rpm,
    install_error_envelope,
)

# ─── Extracted modules ────────────────────────────────────────────────────────
from agent_bom.api.models import (
    AnalyticsHealth,
    EntitlementHealth,
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
    _get_credential_ref_store,
    _get_schedule_store,
    _get_source_store,
    _get_store,
    _jobs,
    _jobs_get,  # noqa: F401 — re-exported for tests
    _jobs_lock,
    _jobs_pop,  # noqa: F401 — re-exported for tests
    _jobs_put,  # noqa: F401 — re-exported for tests
    set_analytics_store,
    set_credential_ref_store,
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
from agent_bom.config import resolved_cors_origins_raw

_logger = logging.getLogger(__name__)
_DASHBOARD_CSP_META_RE = re.compile(
    r"<meta\s+[^>]*(?:http-equiv|httpEquiv)=[\"']Content-Security-Policy[\"'][^>]*>",
    re.IGNORECASE,
)

# ─── Dependency check ─────────────────────────────────────────────────────────


def _api_extra_import_error_message(exc: ImportError) -> str:
    missing = getattr(exc, "name", None)
    missing_line = f"\nMissing import: {missing!r}" if missing else ""
    return (
        "agent-bom API could not import its runtime dependencies."
        f"{missing_line}\n"
        "Install with:  pip install 'agent-bom[api]'\n"
        "If those packages are already installed, verify that `agent-bom api` is running in the same Python "
        "environment that contains fastapi, uvicorn, sse-starlette, pydantic, and starlette."
    )


try:
    from fastapi import FastAPI, Request
    from fastapi.middleware.cors import CORSMiddleware
    from fastapi.responses import JSONResponse, RedirectResponse
    from pydantic import BaseModel  # noqa: F401 — presence check for [api] extra
    from starlette.middleware import Middleware
    from starlette.middleware.gzip import GZipMiddleware
except ImportError as exc:  # pragma: no cover
    raise ImportError(_api_extra_import_error_message(exc)) from exc

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
        credential_ref_store = _get_credential_ref_store()
    except RuntimeError:
        credential_ref_store = None
    try:
        schedule_store = _get_schedule_store()
    except RuntimeError:
        schedule_store = None

    storage = StorageHealth(
        job_store=_backend_name(_stores._store or _stores._get_store()),
        fleet_store=_backend_name(_stores._fleet_store or _stores._get_fleet_store()),
        policy_store=_backend_name(_stores._policy_store or _stores._get_policy_store()),
        source_store=_backend_name(_stores._source_store or source_store),
        credential_ref_store=_backend_name(_stores._credential_ref_store or credential_ref_store),
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
    snowflake_configured = bool(os.environ.get("SNOWFLAKE_ACCOUNT"))
    if snowflake_configured:
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
    elif os.environ.get("AGENT_BOM_GRAPH_BACKEND", "").strip().lower() == "neptune":
        from agent_bom.api.neptune_graph import NeptuneGraphStore

        if _stores._graph_store is None:
            set_graph_store(NeptuneGraphStore())
    elif os.environ.get("AGENT_BOM_POSTGRES_URL"):
        from agent_bom.api import audit_log as _audit_log_mod
        from agent_bom.api import auth as _auth
        from agent_bom.api import cost_store as _cost_store_mod
        from agent_bom.api.audit_log import set_audit_log
        from agent_bom.api.auth import set_key_store
        from agent_bom.api.cost_store import set_cost_store
        from agent_bom.api.postgres_store import (
            PostgresAuditLog,
            PostgresCostStore,
            PostgresCredentialRefStore,
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
        if _cost_store_mod._COST_STORE is None:
            set_cost_store(PostgresCostStore())
        if _stores._fleet_store is None:
            set_fleet_store(PostgresFleetStore())
        if _stores._policy_store is None:
            set_policy_store(PostgresPolicyStore())
        if _stores._source_store is None:
            set_source_store(PostgresSourceStore())
        if _stores._credential_ref_store is None:
            set_credential_ref_store(PostgresCredentialRefStore())
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
        if _stores._credential_ref_store is None:
            from agent_bom.api.credential_store import SQLiteCredentialRefStore

            set_credential_ref_store(SQLiteCredentialRefStore(db_path))
        if _stores._trend_store is None:
            from agent_bom.baseline import SQLiteTrendStore

            set_trend_store(SQLiteTrendStore(db_path))
        if _stores._graph_store is None:
            from agent_bom.api.graph_store import SQLiteGraphStore

            set_graph_store(SQLiteGraphStore())
        if _audit_log_mod._audit_log is None:
            set_audit_log(SQLiteAuditLog(db_path))

    if _stores._source_store is None:
        if os.environ.get("AGENT_BOM_POSTGRES_URL") and not snowflake_configured:
            from agent_bom.api.postgres_store import PostgresSourceStore

            set_source_store(PostgresSourceStore())
        elif os.environ.get("AGENT_BOM_DB"):
            from agent_bom.api.source_store import SQLiteSourceStore

            set_source_store(SQLiteSourceStore(os.environ["AGENT_BOM_DB"]))
        else:
            from agent_bom.api.source_store import InMemorySourceStore

            set_source_store(InMemorySourceStore())

    if _stores._credential_ref_store is None:
        if os.environ.get("AGENT_BOM_POSTGRES_URL") and not snowflake_configured:
            from agent_bom.api.postgres_store import PostgresCredentialRefStore

            set_credential_ref_store(PostgresCredentialRefStore())
        elif os.environ.get("AGENT_BOM_DB"):
            from agent_bom.api.credential_store import SQLiteCredentialRefStore

            set_credential_ref_store(SQLiteCredentialRefStore(os.environ["AGENT_BOM_DB"]))
        else:
            from agent_bom.api.credential_store import InMemoryCredentialRefStore

            set_credential_ref_store(InMemoryCredentialRefStore())

    # ── Schedule store ──
    if _stores._schedule_store is None:
        if os.environ.get("AGENT_BOM_POSTGRES_URL") and not snowflake_configured:
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
    from agent_bom.api.scan_job_reconciliation import fail_orphaned_active_scan_jobs, reconcile_scan_jobs_active

    try:
        store = _get_store()
        fail_orphaned_active_scan_jobs(store)
        reconcile_scan_jobs_active(store)
    except Exception:  # noqa: BLE001
        _logger.debug("scan job metric startup reconciliation skipped", exc_info=True)

    _cleanup_task = asyncio.create_task(_cleanup_loop())

    # Start scheduler background loop
    global _scheduler_task
    from agent_bom.api.pipeline import _now
    from agent_bom.api.scheduler import scheduler_loop
    from agent_bom.api.tenant_quota import enforce_active_scan_quota, enforce_retained_jobs_quota, tenant_quota_guard

    def _schedule_scan(scan_config: dict, *, schedule_id: str | None = None, tenant_id: str | None = None) -> str:
        """Trigger a scan from a schedule."""
        resolved_tenant_id = tenant_id or (
            getattr(scan_config, "tenant_id", None) if hasattr(scan_config, "tenant_id") else scan_config.get("tenant_id", "default")
        )
        tenant_id = str(resolved_tenant_id or "default")
        request_payload = scan_config
        if isinstance(scan_config, dict):
            request_payload = {key: value for key, value in scan_config.items() if key in ScanRequest.model_fields}
            legacy_path = scan_config.get("path")
            if isinstance(legacy_path, str) and legacy_path and not request_payload.get("agent_projects"):
                request_payload["agent_projects"] = [legacy_path]
        job = ScanJob(
            job_id=str(uuid.uuid4()),
            tenant_id=tenant_id,
            schedule_id=schedule_id,
            triggered_by="scheduler",
            created_at=_now(),
            request=ScanRequest(**request_payload) if isinstance(request_payload, dict) else request_payload,
        )
        # Per-tenant quota lock makes (check + insert) atomic. See
        # tenant_quota.tenant_quota_guard for rationale (audit-4 P1).
        with tenant_quota_guard(
            tenant_id,
            lambda: enforce_active_scan_quota(tenant_id),
            lambda: enforce_retained_jobs_quota(tenant_id),
        ):
            store = _get_store()
            store.put(job)
            _jobs_put(job.job_id, job)
            try:
                from agent_bom.api.scan_job_reconciliation import reconcile_scan_jobs_active

                reconcile_scan_jobs_active(store)
            except Exception:  # noqa: BLE001
                pass
        from agent_bom.api.scan_queue import distributed_scans_enabled, store_supports_dispatch

        if distributed_scans_enabled() and store_supports_dispatch(store):
            store.enqueue_for_dispatch(job)
        else:
            loop = asyncio.get_running_loop()
            submit_scheduled_scan_job(loop, job)
        return job.job_id

    _scheduler_task = asyncio.create_task(scheduler_loop(_get_schedule_store(), _schedule_scan))

    # ── Cloud-connection scan scheduler (Phase B.2) ──
    # Opt-in background loop that re-scans due cloud connections so a connection
    # with an interval keeps evaluating without a manual /scan call. Off unless
    # AGENT_BOM_CONNECTIONS_SCHEDULER is set, so it never runs in CLI/dev.
    global _connection_scheduler_task
    from agent_bom.api.connection_scheduler import connection_scheduler_loop, connections_scheduler_enabled

    if connections_scheduler_enabled():
        _connection_scheduler_task = asyncio.create_task(connection_scheduler_loop())
        _logger.info("Cloud-connection scan scheduler enabled")

    # ── Distributed scan dispatch ──
    # Start a per-replica claim-loop so queued scans are stolen across the
    # cluster. No-op on single-node / non-Postgres deployments.
    _scan_worker = None
    try:
        from agent_bom.api.scan_queue import (
            DistributedScanWorker,
            distributed_scans_enabled,
            store_supports_dispatch,
        )

        _scan_store = _get_store()
        if distributed_scans_enabled() and store_supports_dispatch(_scan_store):
            _scan_worker = DistributedScanWorker(_scan_store)
            await _scan_worker.start()
    except Exception:  # noqa: BLE001
        _logger.exception("Distributed scan worker failed to start; continuing single-node")
        _scan_worker = None

    if os.environ.get("AGENT_BOM_DEMO_ESTATE", "").strip().lower() in {"1", "true", "yes", "on"}:
        try:
            from agent_bom.demo_estate.bootstrap import maybe_bootstrap_demo_estate

            await asyncio.to_thread(maybe_bootstrap_demo_estate)
        except Exception:  # noqa: BLE001
            _logger.warning("demo estate bootstrap skipped", exc_info=True)

    yield

    # ── Graceful shutdown ──
    # Flip readiness to not-ready so upstream load balancers stop routing new
    # traffic while in-flight requests drain. The readiness probe reads
    # _shutting_down under the same module; see meta_routes.
    global _shutting_down
    _shutting_down = True
    # Stop claiming new distributed work before draining in-flight scans.
    if _scan_worker is not None:
        try:
            await _scan_worker.stop()
        except Exception:  # noqa: BLE001
            _logger.debug("scan worker stop skipped", exc_info=True)
    if _scheduler_task:
        _scheduler_task.cancel()
    if _connection_scheduler_task:
        _connection_scheduler_task.cancel()
    if _cleanup_task:
        _cleanup_task.cancel()
    # Drain in-flight scans. Honor the operator-configured drain budget so the
    # pod exits before Kubernetes force-kills at terminationGracePeriodSeconds.
    # Default 25s leaves a 5s margin under the recommended 30s Helm value.
    _drain_seconds = float(os.environ.get("AGENT_BOM_SHUTDOWN_DRAIN_SECONDS", "25"))
    try:
        await asyncio.wait_for(
            asyncio.to_thread(lambda: shutdown_scan_executor(wait=True, cancel_futures=False)),
            timeout=_drain_seconds,
        )
    except asyncio.TimeoutError:
        _logger.warning(
            "shutdown drain timeout after %.1fs; force-cancelling in-flight scans",
            _drain_seconds,
        )
        shutdown_scan_executor(wait=False, cancel_futures=True)
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
_cors_env = resolved_cors_origins_raw()
_cors_origins: list[str] = [o.strip() for o in _cors_env.split(",") if o.strip()] if _cors_env else _default_origins
_api_key: str | None = None
DEFAULT_RATE_LIMIT_RPM = DEFAULT_SCAN_RATE_LIMIT_RPM
_rate_limit_rpm: int = DEFAULT_RATE_LIMIT_RPM
_env_api_keys_seeded = False
_runtime_api_key_seeded = False
# Ephemeral, per-process loopback dev API key. Only ever set by the CLI
# (`agent-bom serve`) on a LOOPBACK bind when no other auth is configured, so
# the same-origin dashboard can mint a matching browser session and load with
# zero flags. Never persisted; non-loopback binds never set this (the CLI auth
# gate refuses them first). See cli/_server._should_auto_generate_dev_key.
_dev_api_key: str | None = None


def set_dev_api_key(raw_key: str | None) -> None:
    """Register (or clear) the ephemeral loopback dev API key for the UI.

    The key itself is seeded into the RBAC key store by ``configure_api``; this
    holder only lets the dashboard HTML routes issue a matching browser-session
    cookie so the first-party same-origin UI authenticates automatically on a
    loopback bind. Process-local and never written to disk.
    """
    global _dev_api_key
    _dev_api_key = (raw_key or "").strip() or None


def get_dev_api_key() -> str | None:
    """Return the active ephemeral loopback dev API key, if any."""
    return _dev_api_key


def _env_truthy(name: str) -> bool:
    return os.environ.get(name, "").strip().lower() in {"1", "true", "yes", "on"}


def _parse_cors_origins_from_env(default: list[str]) -> tuple[list[str], bool]:
    raw = resolved_cors_origins_raw()
    if not raw:
        return default, False
    origins = [origin.strip() for origin in raw.split(",") if origin.strip()]
    return origins or default, "*" in origins


def _seed_api_key_store_from_env() -> bool:
    """Seed RBAC keys from AGENT_BOM_API_KEYS (env or ``*_FILE``) for direct ASGI imports."""
    global _env_api_keys_seeded

    from agent_bom.api.secret_source import resolve_secret

    configured = resolve_secret("AGENT_BOM_API_KEYS")
    if not configured:
        return False
    if _env_api_keys_seeded:
        return get_key_store().has_keys()

    store = get_key_store()
    for idx, item in enumerate(configured.split(","), start=1):
        raw_item = item.strip()
        if not raw_item:
            continue
        raw_key, sep, role_value = raw_item.partition(":")
        if not sep or not raw_key.strip() or not role_value.strip():
            raise RuntimeError("AGENT_BOM_API_KEYS entries must use '<raw-key>:<admin|analyst|viewer>' format")
        try:
            role = Role(role_value.strip().lower())
        except ValueError as exc:
            raise RuntimeError(f"Invalid AGENT_BOM_API_KEYS role {role_value!r}; expected admin, analyst, or viewer") from exc
        store.add(create_api_key_record(raw_key.strip(), f"env:{role.value}:{idx}", role))

    _env_api_keys_seeded = True
    return store.has_keys()


def _seed_runtime_api_key(raw_key: str | None) -> bool:
    """Seed the process-local key store from ``configure_api(api_key=...)``."""
    global _runtime_api_key_seeded

    value = (raw_key or "").strip()
    if not value:
        return False
    if _runtime_api_key_seeded:
        return get_key_store().has_keys()

    get_key_store().add(create_api_key_record(value, "runtime:admin", Role.ADMIN))
    _runtime_api_key_seeded = True
    return True


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


def _validated_rate_limit_rpm(value: int) -> int:
    try:
        rpm = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError("rate_limit_rpm must be an integer") from exc
    if rpm < 1:
        raise ValueError("rate_limit_rpm must be at least 1")
    if rpm > MAX_RATE_LIMIT_RPM:
        raise ValueError(f"rate_limit_rpm must be <= {MAX_RATE_LIMIT_RPM}")
    return rpm


# CORS: defaults to localhost; configure via configure_api() before startup
_apply_cors_middleware(_cors_origins)


# ─── Trust headers middleware ──────────────────────────────────────────────────


app.add_middleware(TrustHeadersMiddleware)
app.add_middleware(GZipMiddleware, minimum_size=500)

# wrap FastAPI's bare ``{"detail": ...}`` errors in the
# structured ``{error: {code, message, correlation_id, details}}`` envelope.
install_error_envelope(app)


def configure_api(
    cors_origins: list[str] | None = None,
    cors_allow_all: bool = False,
    api_key: str | None = None,
    rate_limit_rpm: int = DEFAULT_RATE_LIMIT_RPM,
    allow_unauthenticated: bool | None = None,
) -> None:
    """Configure API hardening before server startup.

    Call this before uvicorn.run() to set CORS, auth, and rate limiting.
    """
    global _cors_origins, _api_key, _rate_limit_rpm

    validated_rate_limit_rpm = _validated_rate_limit_rpm(rate_limit_rpm)

    if cors_allow_all:
        _cors_origins = ["*"]
    elif cors_origins:
        _cors_origins = cors_origins

    _apply_cors_middleware(_cors_origins)

    _api_key = api_key
    _rate_limit_rpm = validated_rate_limit_rpm

    env_key_store_configured = _seed_api_key_store_from_env()
    runtime_key_store_configured = _seed_runtime_api_key(api_key)

    from agent_bom.api.oidc import oidc_enabled_from_env
    from agent_bom.api.scim import scim_enabled_from_env

    oidc_enabled = oidc_enabled_from_env()
    scim_enabled = scim_enabled_from_env()
    trusted_proxy_enabled = os.environ.get("AGENT_BOM_TRUST_PROXY_AUTH", "").strip().lower() in {"1", "true", "yes", "on"}
    auth_configured = bool(
        api_key or env_key_store_configured or runtime_key_store_configured or oidc_enabled or trusted_proxy_enabled or scim_enabled
    )
    # Honor AGENT_BOM_ALLOW_UNAUTHENTICATED_API on every (re)configure, not just
    # when the caller omits the argument. CLI wrappers (`serve` / `api`) pass the
    # ``--allow-insecure-no-auth`` flag as an explicit bool, so a ``None`` check
    # alone would silently drop the env-var opt-out and leave the loopback banner
    # claiming unauthenticated access while the API actually fails closed (401).
    # Non-loopback binds stay fail-closed because the CLI auth gate refuses them
    # before configure_api runs unless real auth or the explicit flag is present.
    allow_unauthenticated = bool(allow_unauthenticated) or _env_truthy("AGENT_BOM_ALLOW_UNAUTHENTICATED_API")
    auth_required = auth_configured or not allow_unauthenticated
    configure_auth_runtime(
        api_key_configured=bool(api_key or env_key_store_configured or runtime_key_store_configured),
        oidc_enabled=oidc_enabled,
        trusted_proxy_enabled=trusted_proxy_enabled,
        scim_enabled=scim_enabled,
        unauthenticated_allowed=allow_unauthenticated,
    )

    if not auth_configured and not allow_unauthenticated:
        _logger.critical(
            "SECURITY: No control-plane authentication configured; protected API endpoints will fail closed. "
            "Set AGENT_BOM_API_KEY, AGENT_BOM_API_KEYS, OIDC/SAML/proxy auth, or "
            "AGENT_BOM_ALLOW_UNAUTHENTICATED_API=1 for local development only."
        )
    elif not auth_configured:
        _logger.warning(
            "SECURITY: AGENT_BOM_ALLOW_UNAUTHENTICATED_API=1 enables unauthenticated API access. "
            "Use only for single-user local development."
        )

    # Refresh runtime-configurable middleware. _replace_middleware inserts at
    # the front; this call order keeps the coarse per-IP limiter outermost
    # (capping unauthenticated floods before auth), then body-size, then auth
    # before the tenant-scoped rate limiter, which needs tenant/auth state.
    _replace_middleware(RateLimitMiddleware, scan_rpm=_rate_limit_rpm, read_rpm=_rate_limit_rpm * 5)
    # ``auth_required`` is ``auth_configured or not allow_unauthenticated`` so the
    # middleware is still installed whenever any credential is configured — even
    # with the unauthenticated opt-in on. In that combined mode it authenticates
    # valid credentials to their role and lets credential-less callers fall
    # through to NO_AUTH_ROLE (via ``allow_unauthenticated``); a present-but-
    # invalid credential is still rejected. Only the pure no-auth mode (nothing
    # configured + opt-in) removes the middleware entirely.
    if auth_required:
        _replace_middleware(APIKeyMiddleware, api_key=api_key, allow_unauthenticated=allow_unauthenticated)
    else:
        app.user_middleware = [m for m in app.user_middleware if m.cls is not APIKeyMiddleware]
    _replace_middleware(MaxBodySizeMiddleware)
    _replace_middleware(GlobalRateLimitMiddleware, rpm=global_ip_rate_limit_rpm())
    if app.middleware_stack is not None:
        app.middleware_stack = app.build_middleware_stack()


def configure_api_from_env() -> None:
    """Configure API hardening for direct ASGI imports such as raw uvicorn."""
    from agent_bom.api.secret_source import resolve_secret

    api_key = resolve_secret("AGENT_BOM_API_KEY") or None
    origins, allow_all = _parse_cors_origins_from_env(_default_origins)
    configure_api(
        cors_origins=origins,
        cors_allow_all=allow_all,
        api_key=api_key,
        rate_limit_rpm=DEFAULT_RATE_LIMIT_RPM,
    )


configure_api_from_env()


# ─── Scan Pipeline (extracted to api/pipeline.py) ────────────────────────────
from agent_bom.api.pipeline import (  # noqa: E402
    PIPELINE_DAG_EDGES,  # noqa: F401 — re-exported for tests/artifact consumers
    PIPELINE_DAG_EVENT_SCHEMA,  # noqa: F401 — re-exported for tests/artifact consumers
    PIPELINE_STEPS,  # noqa: F401 — re-exported for tests
    ScanPipeline,  # noqa: F401 — re-exported for tests
    _executor,  # noqa: F401 — re-exported for tests (may be replaced on shutdown; use get_executor() for new submissions)
    _run_scan_sync,  # noqa: F401 — re-exported for backward compat
    _sync_scan_agents_to_fleet,  # noqa: F401 — re-exported for tests
    get_executor,  # noqa: F401 — re-exported for tests
    iter_pipeline_dag_event_records,  # noqa: F401 — re-exported for tests/artifact consumers
    pipeline_dag_events_jsonl,  # noqa: F401 — re-exported for tests/artifact consumers
    shutdown_scan_executor,
    submit_scheduled_scan_job,
)
from agent_bom.api.routes.agent_manifest import router as _agent_manifest_router  # noqa: E402

# ─── Route modules ────────────────────────────────────────────────────────
from agent_bom.api.routes.assets import router as _assets_router  # noqa: E402
from agent_bom.api.routes.cloud import router as _cloud_router  # noqa: E402
from agent_bom.api.routes.cloud_connections import router as _cloud_connections_router  # noqa: E402
from agent_bom.api.routes.compliance import router as _compliance_router  # noqa: E402
from agent_bom.api.routes.connectors import router as _connectors_router  # noqa: E402
from agent_bom.api.routes.credentials import router as _credentials_router  # noqa: E402
from agent_bom.api.routes.datasets import router as _datasets_router  # noqa: E402
from agent_bom.api.routes.discovery import router as _discovery_router  # noqa: E402
from agent_bom.api.routes.enterprise import router as _enterprise_router  # noqa: E402
from agent_bom.api.routes.entitlements import router as _entitlements_router  # noqa: E402
from agent_bom.api.routes.estate import router as _estate_router  # noqa: E402
from agent_bom.api.routes.evaluations import router as _evaluations_router  # noqa: E402
from agent_bom.api.routes.fleet import router as _fleet_router  # noqa: E402
from agent_bom.api.routes.frameworks import router as _frameworks_router  # noqa: E402
from agent_bom.api.routes.gateway import router as _gateway_router  # noqa: E402
from agent_bom.api.routes.gateway_feed import router as _gateway_feed_router  # noqa: E402
from agent_bom.api.routes.governance import router as _governance_router  # noqa: E402
from agent_bom.api.routes.graph import router as _graph_router  # noqa: E402
from agent_bom.api.routes.identities import router as _identities_router  # noqa: E402
from agent_bom.api.routes.intel import router as _intel_router  # noqa: E402
from agent_bom.api.routes.observability import infra_router as _observability_infra_router  # noqa: E402
from agent_bom.api.routes.observability import router as _observability_router  # noqa: E402
from agent_bom.api.routes.overview import router as _overview_router  # noqa: E402
from agent_bom.api.routes.plugins import router as _plugins_router  # noqa: E402
from agent_bom.api.routes.posture_streaming import router as _posture_streaming_router  # noqa: E402
from agent_bom.api.routes.privacy import router as _privacy_router  # noqa: E402
from agent_bom.api.routes.proxy import router as _proxy_router  # noqa: E402
from agent_bom.api.routes.proxy import ws_router as _proxy_ws_router  # noqa: E402
from agent_bom.api.routes.reports import router as _reports_router  # noqa: E402
from agent_bom.api.routes.runtime_blueprints import router as _runtime_blueprints_router  # noqa: E402
from agent_bom.api.routes.scan import router as _scan_router  # noqa: E402
from agent_bom.api.routes.schedules import router as _schedules_router  # noqa: E402
from agent_bom.api.routes.scim import router as _scim_router  # noqa: E402
from agent_bom.api.routes.sources import router as _sources_router  # noqa: E402
from agent_bom.api.routes.webhooks import router as _webhooks_router  # noqa: E402
from agent_bom.api.versioning import create_v1_api_router  # noqa: E402

_v1_api_router = create_v1_api_router()

for _router in (
    _assets_router,
    _agent_manifest_router,
    _cloud_router,
    _cloud_connections_router,
    _compliance_router,
    _connectors_router,
    _credentials_router,
    _datasets_router,
    _discovery_router,
    _entitlements_router,
    _estate_router,
    _enterprise_router,
    _fleet_router,
    _evaluations_router,
    _frameworks_router,
    _gateway_router,
    _gateway_feed_router,
    _governance_router,
    _graph_router,
    _identities_router,
    _intel_router,
    _observability_router,
    _overview_router,
    _plugins_router,
    _posture_streaming_router,
    _privacy_router,
    _proxy_router,
    _reports_router,
    _runtime_blueprints_router,
    _scan_router,
    _schedules_router,
    _sources_router,
    _webhooks_router,
):
    _v1_api_router.include_router(_router)

app.include_router(_v1_api_router)
# SCIM base path is RFC-driven (/scim/v2 by default), not under API_V1_PREFIX.
app.include_router(_scim_router)
# Prometheus scrape surface stays unversioned (infra contract).
app.include_router(_observability_infra_router)
# Proxy live streams are root-level WebSocket paths (/ws/proxy/*), not /v1.
app.include_router(_proxy_ws_router)

# Resolve agent-bom-issued (abi_) identity tokens through the lifecycle store so
# the proxy/gateway honor issuance, rotation overlap, and revocation.
from agent_bom.api.agent_identity_store import register_local_identity_verifier  # noqa: E402

register_local_identity_verifier()

# Re-export proxy push functions for backward compatibility
# Re-export connectors helpers for backward compatibility
from agent_bom.api.routes.connectors import _load_registry  # noqa: E402, F401
from agent_bom.api.routes.proxy import push_proxy_alert, push_proxy_metrics  # noqa: E402, F401

# Re-export scan helpers for backward compatibility
from agent_bom.api.routes.scan import _dataclass_to_dict, _sanitize_api_path  # noqa: E402, F401

_cleanup_task: asyncio.Task | None = None
_scheduler_task: asyncio.Task | None = None
_connection_scheduler_task: asyncio.Task | None = None
# Flipped to True during graceful shutdown so the /readyz probe goes red
# and upstream load balancers stop sending new traffic while in-flight
# requests complete under the drain budget.
_shutting_down: bool = False


_STUCK_JOB_TIMEOUT = 1800  # 30 minutes — mark RUNNING jobs as FAILED


async def _cleanup_loop():
    """Background task that removes expired jobs and unsticks RUNNING jobs.

    Also drives the tier-B (replay-only) evidence TTL purge from issue
    #2261: rows in ``proxy_replay_log`` with ``not_after < now`` are deleted
    on every tick.
    """
    while True:
        await asyncio.sleep(60)
        store = _get_store()
        store.cleanup_expired(_JOB_TTL_SECONDS)
        # Tier-B replay-log TTL purge (#2261). Wrapped so a backend hiccup
        # never takes down the whole cleanup loop.
        try:
            from agent_bom.api.proxy_replay_store import get_proxy_replay_store

            removed = get_proxy_replay_store().cleanup_expired()
            if removed:
                _logger.info("proxy_replay_log cleanup removed %d expired rows", removed)
        except Exception:  # noqa: BLE001
            _logger.debug("proxy_replay_log cleanup skipped", exc_info=True)
        # Hub observations partition retention (#3463). Postgres-only; no-op on
        # SQLite and legacy unpartitioned tables. Fail-open like other cleanup
        # hooks so a backend hiccup never stops the loop.
        try:
            from agent_bom.api.hub_observations_partition import run_hub_observations_retention

            dropped_partitions = run_hub_observations_retention()
            if dropped_partitions:
                _logger.info(
                    "hub_findings_current_observations retention dropped %d partition(s)",
                    dropped_partitions,
                )
        except Exception:  # noqa: BLE001
            _logger.debug("hub observations retention skipped", exc_info=True)
        # Generic partition maintenance for the other append-only tables (#3463):
        # ensure next partitions exist and roll over expired ones. Postgres-only;
        # a strict no-op on SQLite and on any table an operator has not converted
        # to declarative partitioning. Fail-open like the hooks above.
        try:
            from agent_bom.api.partition_maintenance import run_partition_retention

            partition_results = run_partition_retention()
            for table, (partitions_created, partitions_dropped) in partition_results.items():
                _logger.info(
                    "%s partition maintenance: %d created, %d dropped",
                    table,
                    partitions_created,
                    partitions_dropped,
                )
        except Exception:  # noqa: BLE001
            _logger.debug("partition maintenance skipped", exc_info=True)
        # NHI lifecycle enforcement (#nhi): expire lingering JIT grants, opt-in
        # dormant-identity deprovision, advisory token rotation-due flagging.
        # Backend-agnostic and fail-open — a store error logs and is skipped so
        # the loop survives. Timestamp injected for deterministic, replica-safe
        # transitions.
        try:
            from datetime import datetime as _dt
            from datetime import timezone as _tz

            from agent_bom.api.agent_identity_store import get_agent_identity_store, run_nhi_lifecycle_cleanup
            from agent_bom.api.governance_audit_log import get_governance_audit_log

            nhi_now = _dt.now(_tz.utc)
            nhi_result = run_nhi_lifecycle_cleanup(
                get_agent_identity_store(),
                now=nhi_now,
                audit_log=get_governance_audit_log(),
            )
            grants = nhi_result.get("grants", {})
            dormant = nhi_result.get("dormant", {})
            rotation = nhi_result.get("rotation", {})
            acted = grants.get("expired", 0) + grants.get("pruned", 0) + dormant.get("revoked", 0) + rotation.get("flagged", 0)
            if acted:
                _logger.info(
                    "nhi lifecycle cleanup: %d grants expired, %d denied pruned, %d dormant revoked, %d rotation-due",
                    grants.get("expired", 0),
                    grants.get("pruned", 0),
                    dormant.get("revoked", 0),
                    rotation.get("flagged", 0),
                )
        except Exception:  # noqa: BLE001 — cleanup must never crash the loop
            _logger.warning(
                "nhi lifecycle cleanup skipped this tick; check the agent-identity store and governance audit-log backend connectivity",
                exc_info=True,
            )
        # Unstick jobs that have been RUNNING for too long
        try:
            from datetime import datetime, timezone

            from agent_bom.api.scan_job_reconciliation import fail_stale_active_scan_jobs, reconcile_scan_jobs_active

            now = datetime.now(timezone.utc)
            with _jobs_lock:
                for job in list(_jobs.values()):
                    if job.status == JobStatus.RUNNING and job.created_at:
                        try:
                            job_created = datetime.fromisoformat(job.created_at.replace("Z", "+00:00"))
                            if (now - job_created).total_seconds() > _STUCK_JOB_TIMEOUT:
                                job.status = JobStatus.FAILED
                                job.error = "Timed out (stuck in RUNNING state)"
                                job.completed_at = now.isoformat()
                                store.put(job)
                        except (ValueError, TypeError):
                            pass
            fail_stale_active_scan_jobs(store, timeout_seconds=_STUCK_JOB_TIMEOUT, now=now)
            reconcile_scan_jobs_active(store)
        except Exception:  # noqa: BLE001
            pass


# ─── Meta Routes ─────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class _DashboardFile:
    path: Path
    relative_path: str


def _dashboard_dist_dir() -> Path:
    return Path(__file__).resolve().parents[1] / "ui_dist"


def _validated_dashboard_file(ui_dist: Path, relative_path: str) -> _DashboardFile | None:
    ui_root = ui_dist.resolve()
    raw_path = relative_path.strip()
    if not raw_path:
        return None
    if Path(raw_path).is_absolute():
        return None
    rel = raw_path.strip("/")
    if not rel:
        return None
    rel_path = Path(rel)
    candidate = (ui_root / rel_path).resolve()
    try:
        normalized = candidate.relative_to(ui_root).as_posix()
    except ValueError:
        return None
    if not candidate.is_file():
        return None
    return _DashboardFile(path=candidate, relative_path=normalized)


def _dashboard_index_file() -> _DashboardFile | None:
    """Return the packaged dashboard index path when bundled UI assets exist."""

    return _validated_dashboard_file(_dashboard_dist_dir(), "index.html")


def _dashboard_html_response(dashboard_file: _DashboardFile):
    from fastapi.responses import HTMLResponse

    try:
        html = dashboard_file.path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        html = dashboard_file.path.read_text(encoding="utf-8", errors="replace")
    return HTMLResponse(_DASHBOARD_CSP_META_RE.sub("", html))


_DEV_SESSION_MAX_AGE_SECONDS = 8 * 60 * 60


def _maybe_attach_dev_session_cookie(response: Any, request: Request) -> None:
    """Seed a loopback browser session so the zero-config dev key authenticates
    the same-origin dashboard without any flag or manual key entry.

    No-op unless an ephemeral dev key is active. The dev key is only ever set on
    a loopback bind (the CLI auth gate refuses non-loopback binds before the key
    is generated), so a set key already means "loopback, no other auth". The
    minted session carries no ``key_id``, so it stays valid for the process
    lifetime without depending on key-store lookups, and is re-used across page
    loads instead of churning a fresh nonce each request.
    """
    if _dev_api_key is None:
        return
    from agent_bom.api.browser_session import (
        CSRF_COOKIE_NAME,
        SESSION_COOKIE_NAME,
        BrowserSessionError,
        create_browser_session_token,
        verify_browser_session_token,
    )

    existing = request.cookies.get(SESSION_COOKIE_NAME, "")
    if existing:
        try:
            verify_browser_session_token(existing)
            return
        except BrowserSessionError:
            pass
    try:
        token, csrf = create_browser_session_token(
            subject="loopback-dev-key",
            role="admin",
            tenant_id="default",
            auth_method="browser_session_dev_key",
            key_id=None,
            scopes=[],
            max_age_seconds=_DEV_SESSION_MAX_AGE_SECONDS,
        )
    except BrowserSessionError:
        return
    response.set_cookie(
        SESSION_COOKIE_NAME,
        token,
        max_age=_DEV_SESSION_MAX_AGE_SECONDS,
        httponly=True,
        secure=False,
        samesite="strict",
        path="/",
    )
    response.set_cookie(
        CSRF_COOKIE_NAME,
        csrf,
        max_age=_DEV_SESSION_MAX_AGE_SECONDS,
        httponly=False,
        secure=False,
        samesite="strict",
        path="/",
    )


@app.api_route("/", methods=["GET", "HEAD"], include_in_schema=False)
async def root(request: Request):
    dashboard_index = _dashboard_index_file()
    if dashboard_index:
        response = _dashboard_html_response(dashboard_index)
        _maybe_attach_dev_session_cookie(response, request)
        return response
    return RedirectResponse(url="/docs")


@app.get("/health", response_model=HealthResponse, tags=["meta"])
async def health() -> HealthResponse:
    """Liveness probe."""
    from agent_bom.api.middleware import get_auth_runtime_status
    from agent_bom.entitlements import load_entitlement_state

    auth_runtime = get_auth_runtime_status()
    return HealthResponse(
        status="ok",
        version=__version__,
        auth_required=bool(auth_runtime["auth_required"]),
        auth_configured=bool(auth_runtime.get("auth_configured", False)),
        configured_auth_modes=list(cast(list[str], auth_runtime["configured_modes"])),
        unauthenticated_allowed=bool(auth_runtime.get("unauthenticated_allowed", False)),
        tracing=TracingHealth(**get_tracing_health()),
        analytics=_analytics_health(),
        storage=_storage_health(),
        entitlements=EntitlementHealth(**load_entitlement_state().health_summary()),
    )


@app.get("/healthz", response_model=HealthResponse, tags=["meta"])
async def healthz() -> HealthResponse:
    """Kubernetes-style liveness probe alias for /health."""
    return await health()


@app.get("/version", response_model=VersionInfo, tags=["meta"])
async def version() -> VersionInfo:
    """Version information."""
    return VersionInfo(version=__version__)


@app.get("/readyz", tags=["meta"])
async def readiness() -> JSONResponse:
    """Readiness probe — returns 503 during drain or when dependencies are unhealthy.

    Kubernetes removes the pod from the service endpoint list on first 503,
    so new requests stop arriving while in-flight work drains under the
    operator-configured drain budget (AGENT_BOM_SHUTDOWN_DRAIN_SECONDS).
    """
    if _shutting_down:
        return JSONResponse(status_code=503, content={"status": "draining"})
    from agent_bom.api.readiness import evaluate_control_plane_readiness

    status = evaluate_control_plane_readiness()
    if not status.ready:
        return JSONResponse(status_code=503, content=status.as_dict())
    return JSONResponse(status_code=200, content=status.as_dict())


@app.get("/livez", response_model=HealthResponse, tags=["meta"])
async def liveness() -> HealthResponse:
    """Kubernetes-style liveness probe alias for /health."""
    return await health()


@app.get("/ping", tags=["meta"])
async def ping() -> dict[str, str]:
    """Minimal ping endpoint for load balancers and smoke checks."""
    return {"status": "ok"}


@app.get("/status", response_model=HealthResponse, tags=["meta"])
async def status() -> HealthResponse:
    """Operator status alias for the health payload."""
    return await health()


# ── Dashboard static file serving ────────────────────────────────────────────
# Must be registered LAST so API routes take precedence.


def _mount_dashboard(application: FastAPI) -> None:
    """Mount pre-built Next.js dashboard if ui_dist/ exists in the package."""
    import os as _os

    from fastapi import HTTPException as _HTTPException

    # REST-only mode (`serve --no-ui` / legacy `api`): never mount the dashboard.
    if _os.environ.get("AGENT_BOM_NO_UI"):
        return

    ui_dist = _dashboard_dist_dir()
    if not ui_dist.is_dir() or not (ui_dist / "index.html").exists():
        return

    from starlette.responses import FileResponse
    from starlette.staticfiles import StaticFiles

    # Hashed JS/CSS assets
    next_static = ui_dist / "_next"
    if next_static.is_dir():
        application.mount("/_next", StaticFiles(directory=str(next_static)), name="next-static")

    # Pre-build a bounded static file map at startup so request paths are
    # resolved only as lookup keys.
    _static_file_map: dict[str, _DashboardFile] = {}
    for _f in ui_dist.rglob("*"):
        if not _f.is_file():
            continue
        relative = _f.relative_to(ui_dist).as_posix()
        if relative.startswith("_next"):
            continue
        dashboard_file = _validated_dashboard_file(ui_dist, relative)
        if dashboard_file is not None:
            _static_file_map[dashboard_file.relative_path] = dashboard_file
    _index_html = _validated_dashboard_file(ui_dist, "index.html")
    if _index_html is None:
        return

    # SPA catch-all for client-side routing
    @application.api_route("/{path:path}", methods=["GET", "HEAD"], include_in_schema=False)
    async def _spa_catch_all(path: str, request: Request):
        # Skip API and docs paths
        if path.startswith(("v1/", "docs", "redoc", "openapi.json", "health", "version", "readyz", "metrics")):
            raise _HTTPException(status_code=404)
        # Look up the pre-resolved path — user input is only a dict key,
        # never used in any filesystem operation (no path-injection risk).
        normalized_path = path.strip("/")
        resolved = (
            _static_file_map.get(path)
            or (normalized_path and _static_file_map.get(f"{normalized_path}.html"))
            or (normalized_path and _static_file_map.get(f"{normalized_path}/index.html"))
        )
        if resolved:
            if path.lower().endswith(".html") or resolved.relative_path.lower().endswith(".html"):
                html_response = _dashboard_html_response(resolved)
                _maybe_attach_dev_session_cookie(html_response, request)
                return html_response
            return FileResponse(resolved.path)
        # SPA fallback — serve index.html for client-side routing
        fallback_response = _dashboard_html_response(_index_html)
        _maybe_attach_dev_session_cookie(fallback_response, request)
        return fallback_response


_mount_dashboard(app)
