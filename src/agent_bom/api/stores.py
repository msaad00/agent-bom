"""Centralized store globals and thread-safe accessors for the agent-bom API.

All pluggable store backends (job, fleet, policy, analytics, schedule,
exception, trend) are lazily initialized with double-checked locking.
Call the ``set_*`` functions before server startup to swap backends
(Snowflake, Postgres, SQLite); otherwise an in-memory default is used.
"""

from __future__ import annotations

import os
import threading
from typing import TYPE_CHECKING, Any

from agent_bom.config import API_MAX_IN_MEMORY_JOBS as _MAX_IN_MEMORY_JOBS

if TYPE_CHECKING:
    from agent_bom.api.graph_store import GraphStoreProtocol
    from agent_bom.api.mcp_observation_store import MCPObservationStore
    from agent_bom.api.models import ScanJob
    from agent_bom.api.schedule_store import ScheduleStore
    from agent_bom.api.scim_store import SCIMStore
    from agent_bom.api.source_store import SourceStore
    from agent_bom.api.tenant_quota_store import TenantQuotaStore

# ── Shared lock (protects lazy init of all stores) ───────────────────────────
_store_lock = threading.Lock()

# ─── Job store (pluggable) ───────────────────────────────────────────────────
_store: Any = None


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


# ─── In-memory job refs (bounded, thread-safe) ──────────────────────────────
_jobs: dict[str, ScanJob] = {}
_jobs_lock = threading.Lock()
_job_locks: dict[str, threading.Lock] = {}


def _job_lock(job_id: str) -> threading.Lock:
    """Get or create a per-job lock for thread-safe field access."""
    with _jobs_lock:
        if job_id not in _job_locks:
            _job_locks[job_id] = threading.Lock()
        return _job_locks[job_id]


def _jobs_put(job_id: str, job: ScanJob) -> None:
    """Add a job to _jobs with bounded eviction."""
    from agent_bom.api.models import JobStatus

    with _jobs_lock:
        _jobs[job_id] = job
        if len(_jobs) > _MAX_IN_MEMORY_JOBS:
            completed = [(jid, j) for jid, j in _jobs.items() if j.status in (JobStatus.DONE, JobStatus.FAILED, JobStatus.CANCELLED)]
            # Evict the oldest completed jobs first. Jobs missing a completion
            # timestamp are treated as newest/unknown so they are not discarded
            # ahead of jobs with a concrete older completed_at value.
            completed.sort(key=lambda x: (x[1].completed_at is None, x[1].completed_at or ""))
            for jid, _ in completed[: len(_jobs) - _MAX_IN_MEMORY_JOBS]:
                _jobs.pop(jid, None)


def _jobs_get(job_id: str) -> ScanJob | None:
    """Thread-safe get from _jobs."""
    with _jobs_lock:
        return _jobs.get(job_id)


def _jobs_pop(job_id: str) -> ScanJob | None:
    """Thread-safe pop from _jobs."""
    with _jobs_lock:
        return _jobs.pop(job_id, None)


# ─── Fleet store (pluggable) ────────────────────────────────────────────────
_fleet_store: Any = None
_idempotency_store: Any = None


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


def _get_idempotency_store():
    """Get the active idempotency store for retry-safe write endpoints."""
    global _idempotency_store
    if _idempotency_store is None:
        with _store_lock:
            if _idempotency_store is None:
                if os.environ.get("AGENT_BOM_DB"):
                    from agent_bom.api.idempotency_store import SQLiteIdempotencyStore

                    _idempotency_store = SQLiteIdempotencyStore(os.environ["AGENT_BOM_DB"])
                else:
                    from agent_bom.api.idempotency_store import InMemoryIdempotencyStore

                    _idempotency_store = InMemoryIdempotencyStore()
    return _idempotency_store


def set_idempotency_store(store: Any) -> None:
    """Switch the idempotency store backend. Call before server startup."""
    global _idempotency_store
    _idempotency_store = store


# ─── Policy store (pluggable) ───────────────────────────────────────────────
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


# ─── Analytics store (ClickHouse OLAP — optional) ───────────────────────────
_analytics_store: Any = None


def _get_analytics_store() -> Any:
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


# ─── Schedule store (pluggable) ─────────────────────────────────────────────
_schedule_store: ScheduleStore | None = None


def _get_schedule_store() -> ScheduleStore:
    """Get the active schedule store. Must be initialized during lifespan."""
    if _schedule_store is None:
        raise RuntimeError("Schedule store not initialized")
    return _schedule_store


def set_schedule_store(store: ScheduleStore) -> None:
    """Switch the schedule store backend."""
    global _schedule_store
    _schedule_store = store


# ─── Tenant quota override store (pluggable) ───────────────────────────────
_tenant_quota_store: TenantQuotaStore | None = None
_scim_store: SCIMStore | None = None


def _get_tenant_quota_store() -> TenantQuotaStore:
    """Get the active tenant quota override store."""
    global _tenant_quota_store
    if _tenant_quota_store is None:
        with _store_lock:
            if _tenant_quota_store is None:
                if os.environ.get("AGENT_BOM_POSTGRES_URL"):
                    from agent_bom.api.postgres_tenant_quota import PostgresTenantQuotaStore

                    _tenant_quota_store = PostgresTenantQuotaStore()
                elif os.environ.get("AGENT_BOM_DB"):
                    from agent_bom.api.tenant_quota_store import SQLiteTenantQuotaStore

                    _tenant_quota_store = SQLiteTenantQuotaStore(os.environ["AGENT_BOM_DB"])
                else:
                    from agent_bom.api.tenant_quota_store import InMemoryTenantQuotaStore

                    _tenant_quota_store = InMemoryTenantQuotaStore()
    return _tenant_quota_store


def set_tenant_quota_store(store: TenantQuotaStore) -> None:
    """Switch the tenant quota override store backend."""
    global _tenant_quota_store
    _tenant_quota_store = store


# ─── SCIM lifecycle store (enterprise identity) ────────────────────────────
def _get_scim_store() -> SCIMStore:
    """Get the active SCIM lifecycle store.

    Postgres is selected for clustered self-hosted deployments. SQLite remains
    a single-node pilot fallback and must not be used for multi-replica API
    deployments because SCIM users/groups are identity state.
    """
    global _scim_store
    if _scim_store is None:
        with _store_lock:
            if _scim_store is None:
                if os.environ.get("AGENT_BOM_POSTGRES_URL"):
                    from agent_bom.api.postgres_scim import PostgresSCIMStore

                    _scim_store = PostgresSCIMStore()
                elif os.environ.get("AGENT_BOM_DB"):
                    from agent_bom.api.scim import scim_enabled_from_env, scim_requires_shared_store
                    from agent_bom.api.scim_store import SQLiteSCIMStore

                    if scim_enabled_from_env() and scim_requires_shared_store():
                        raise RuntimeError("SCIM lifecycle storage requires AGENT_BOM_POSTGRES_URL for multi-replica deployments")
                    _scim_store = SQLiteSCIMStore(os.environ["AGENT_BOM_DB"])
                else:
                    from agent_bom.api.scim import scim_enabled_from_env, scim_requires_shared_store
                    from agent_bom.api.scim_store import InMemorySCIMStore

                    if scim_enabled_from_env() and scim_requires_shared_store():
                        raise RuntimeError("SCIM lifecycle storage requires AGENT_BOM_POSTGRES_URL for multi-replica deployments")
                    _scim_store = InMemorySCIMStore()
    return _scim_store


def set_scim_store(store: SCIMStore | None) -> None:
    """Switch the SCIM lifecycle store backend."""
    global _scim_store
    _scim_store = store


# ─── Source store (pluggable) ───────────────────────────────────────────────
_source_store: SourceStore | None = None
_mcp_observation_store: MCPObservationStore | None = None


def _get_source_store() -> SourceStore:
    """Get the active source registry store. Must be initialized during lifespan."""
    if _source_store is None:
        raise RuntimeError("Source store not initialized")
    return _source_store


def set_source_store(store: SourceStore) -> None:
    """Switch the source registry store backend."""
    global _source_store
    _source_store = store


def _get_mcp_observation_store():
    """Get the active persisted MCP observation store."""
    global _mcp_observation_store
    if _mcp_observation_store is None:
        with _store_lock:
            if _mcp_observation_store is None:
                if os.environ.get("AGENT_BOM_DB"):
                    from agent_bom.api.mcp_observation_store import SQLiteMCPObservationStore

                    _mcp_observation_store = SQLiteMCPObservationStore(os.environ["AGENT_BOM_DB"])
                else:
                    from agent_bom.api.mcp_observation_store import InMemoryMCPObservationStore

                    _mcp_observation_store = InMemoryMCPObservationStore()
    return _mcp_observation_store


def set_mcp_observation_store(store: Any) -> None:
    """Switch the MCP observation store backend."""
    global _mcp_observation_store
    _mcp_observation_store = store


# ─── Exception store (enterprise) ───────────────────────────────────────────
_exception_store: Any = None


def _get_exception_store():
    """Get the active exception store, creating InMemoryExceptionStore if not set."""
    global _exception_store
    if _exception_store is None:
        with _store_lock:
            if _exception_store is None:
                from agent_bom.api.exception_store import InMemoryExceptionStore

                _exception_store = InMemoryExceptionStore()
    return _exception_store


def set_exception_store(store: Any) -> None:
    """Switch the exception store backend. Call before server startup."""
    global _exception_store
    _exception_store = store


# ─── Trend store (enterprise baseline comparison) ───────────────────────────
_trend_store: Any = None
_last_scan_report: dict | None = None


def _get_trend_store():
    """Get the active trend store, creating InMemoryTrendStore if not set."""
    global _trend_store
    if _trend_store is None:
        with _store_lock:
            if _trend_store is None:
                if os.environ.get("AGENT_BOM_POSTGRES_URL"):
                    from agent_bom.api.postgres_store import PostgresTrendStore

                    _trend_store = PostgresTrendStore()
                elif os.environ.get("AGENT_BOM_DB"):
                    from agent_bom.baseline import SQLiteTrendStore

                    _trend_store = SQLiteTrendStore(os.environ["AGENT_BOM_DB"])
                else:
                    from agent_bom.baseline import InMemoryTrendStore

                    _trend_store = InMemoryTrendStore()
    return _trend_store


def set_trend_store(store: Any) -> None:
    """Switch the trend store backend. Call before server startup."""
    global _trend_store
    _trend_store = store


# ─── Graph store (pluggable) ───────────────────────────────────────────────
_graph_store: GraphStoreProtocol | None = None


def _get_graph_store() -> GraphStoreProtocol:
    """Get the active graph store, selecting the configured backend lazily."""
    global _graph_store
    if _graph_store is None:
        with _store_lock:
            if _graph_store is None:
                if os.environ.get("AGENT_BOM_POSTGRES_URL"):
                    from agent_bom.api.postgres_store import PostgresGraphStore

                    _graph_store = PostgresGraphStore()
                else:
                    from agent_bom.api.graph_store import SQLiteGraphStore

                    _graph_store = SQLiteGraphStore()
    return _graph_store


def set_graph_store(store: GraphStoreProtocol) -> None:
    """Switch the graph store backend. Call before server startup."""
    global _graph_store
    _graph_store = store


def get_last_scan_report() -> dict | None:
    """Get the last scan report for baseline comparison."""
    return _last_scan_report


def set_last_scan_report(report: dict | None) -> None:
    """Set the last scan report for baseline comparison."""
    global _last_scan_report
    _last_scan_report = report
