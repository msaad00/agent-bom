"""Shared backend registries for API lifecycle and request handlers."""

from __future__ import annotations

import os
import threading
from typing import TYPE_CHECKING, Any, cast

from agent_bom.api.neptune_graph import NeptuneGraphStore
from agent_bom.api.storage.analytics import get_analytics_store
from agent_bom.api.storage.analytics import set_analytics_store as set_analytics_store
from agent_bom.api.storage.job_backends import configured_job_store
from agent_bom.api.storage.job_cache import (
    _COMPACTED_RESULT_MARKER as _COMPACTED_RESULT_MARKER,
)
from agent_bom.api.storage.job_cache import (
    _compact_terminal_job as _compact_terminal_job,
)
from agent_bom.api.storage.job_cache import (
    _compact_terminal_job_in_place as _compact_terminal_job_in_place,
)
from agent_bom.api.storage.job_cache import (
    _jobs_is_compacted as _jobs_is_compacted,
)
from agent_bom.api.storage_schema import postgres_deployment_configured
from agent_bom.config import API_MAX_IN_MEMORY_JOBS as _MAX_IN_MEMORY_JOBS

if TYPE_CHECKING:
    from agent_bom.api.credential_store import CredentialRefStore
    from agent_bom.api.graph_scenario_store import GraphScenarioStore
    from agent_bom.api.issue_mapping_store import IssueMappingStore
    from agent_bom.api.mcp_observation_store import MCPObservationStore
    from agent_bom.api.models import ScanJob
    from agent_bom.api.schedule_store import ScheduleStore
    from agent_bom.api.scim_store import SCIMStore
    from agent_bom.api.source_store import SourceStore
    from agent_bom.api.tenant_graph_retention_store import TenantGraphRetentionStore
    from agent_bom.api.tenant_quota_store import TenantQuotaStore
    from agent_bom.api.tenant_score_config_store import TenantScoreConfigStore
    from agent_bom.graph.ports import GraphStoreProtocol

# ── Shared lock (protects lazy init of all stores) ───────────────────────────
_store_lock = threading.Lock()

# ─── Job store (pluggable) ───────────────────────────────────────────────────
_store: Any = None


def _get_store() -> Any:
    """Get configured job evidence for API and standalone MCP readers.

    Preserve explicit overrides. Configured backend failures propagate instead
    of silently serving an empty in-memory estate.
    """
    global _store
    if _store is None:
        with _store_lock:
            if _store is None:
                _store = configured_job_store()
    return _store


def set_job_store(store: Any) -> None:
    """Switch the job store backend. Call before server startup."""
    global _store
    _store = store


# ─── In-memory job refs (bounded, thread-safe) ──────────────────────────────
_jobs: dict[tuple[str, str], ScanJob] = {}
_jobs_lock = threading.Lock()
_job_locks: dict[str, threading.Lock] = {}


def _job_lock(job_id: str) -> threading.Lock:
    """Get or create a per-job lock for thread-safe field access."""
    with _jobs_lock:
        if job_id not in _job_locks:
            _job_locks[job_id] = threading.Lock()
        return _job_locks[job_id]


def _jobs_put(job_id: str, job: ScanJob, *, compact_terminal: bool = False) -> None:
    """Add a job to _jobs with bounded eviction."""
    from agent_bom.api.models import JobStatus

    cached_job = _compact_terminal_job(job) if compact_terminal else job
    with _jobs_lock:
        _jobs[(job.tenant_id, job_id)] = cached_job
        if len(_jobs) > _MAX_IN_MEMORY_JOBS:
            completed = [(jid, j) for jid, j in _jobs.items() if j.status in (JobStatus.DONE, JobStatus.FAILED, JobStatus.CANCELLED)]
            # Evict the oldest completed jobs first. Jobs missing a completion
            # timestamp are treated as newest/unknown so they are not discarded
            # ahead of jobs with a concrete older completed_at value.
            completed.sort(key=lambda x: (x[1].completed_at is None, x[1].completed_at or ""))
            for jid, _ in completed[: len(_jobs) - _MAX_IN_MEMORY_JOBS]:
                _jobs.pop(jid, None)
                _job_locks.pop(jid[1], None)


def _jobs_get(job_id: str, *, tenant_id: str | None = None) -> ScanJob | None:
    """Read one tenant's hot row; an ambiguous legacy lookup is a cache miss."""
    with _jobs_lock:
        if tenant_id is not None:
            return _jobs.get((tenant_id, job_id))
        matches = [job for job in _jobs.values() if job.job_id == job_id]
        return matches[0] if len(matches) == 1 else None


def _jobs_pop(job_id: str, *, tenant_id: str | None = None) -> ScanJob | None:
    """Remove only the scoped hot row, preserving equal IDs in other tenants."""
    with _jobs_lock:
        if tenant_id is None:
            matches = [job for job in _jobs.values() if job.job_id == job_id]
            if len(matches) != 1:
                return None
            tenant_id = matches[0].tenant_id
        _job_locks.pop(job_id, None)
        return _jobs.pop((tenant_id, job_id), None)


# ─── Fleet store (pluggable) ────────────────────────────────────────────────
_fleet_store: Any = None
_idempotency_store: Any = None


def _get_fleet_store() -> Any:
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


def _get_idempotency_store() -> Any:
    """Get the active idempotency store for retry-safe write endpoints."""
    global _idempotency_store
    if _idempotency_store is None:
        with _store_lock:
            if _idempotency_store is None:
                if postgres_deployment_configured():
                    # Multi-replica deployments must share idempotency state so a
                    # retried write is recognized on any replica; a per-process
                    # in-memory map would silently drop the same-key-different-body
                    # 409 guarantee across replicas / restarts.
                    from agent_bom.api.idempotency_store import PostgresIdempotencyStore

                    _idempotency_store = PostgresIdempotencyStore()
                elif os.environ.get("AGENT_BOM_DB"):
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


def _get_policy_store() -> Any:
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


def _get_analytics_store() -> Any:
    """Compatibility entry point for the dedicated analytics registry."""
    return get_analytics_store()


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


# ─── Inter-agent firewall decision tally (#982 PR 4) ───────────────────────
_firewall_decision_store: Any = None


def _get_firewall_decision_store() -> Any:
    """Get the active firewall decision tally (in-memory, per-process)."""
    global _firewall_decision_store
    if _firewall_decision_store is None:
        with _store_lock:
            if _firewall_decision_store is None:
                from agent_bom.api.firewall_decision_store import FirewallDecisionStore

                _firewall_decision_store = FirewallDecisionStore()
    return _firewall_decision_store


def set_firewall_decision_store(store: Any) -> None:
    """Swap the firewall decision tally for tests."""
    global _firewall_decision_store
    _firewall_decision_store = store


# ─── Tenant quota override store (pluggable) ───────────────────────────────
_tenant_quota_store: TenantQuotaStore | None = None
_scim_store: SCIMStore | None = None


def _get_tenant_quota_store() -> TenantQuotaStore:
    """Get the active tenant quota override store."""
    global _tenant_quota_store
    if _tenant_quota_store is None:
        with _store_lock:
            if _tenant_quota_store is None:
                from agent_bom.api.tenant_quota_store import InMemoryTenantQuotaStore, SqlTenantQuotaStore

                if postgres_deployment_configured():
                    _tenant_quota_store = SqlTenantQuotaStore.postgres()
                elif os.environ.get("AGENT_BOM_DB"):
                    _tenant_quota_store = SqlTenantQuotaStore.sqlite(os.environ["AGENT_BOM_DB"])
                else:
                    _tenant_quota_store = InMemoryTenantQuotaStore()
    return _tenant_quota_store


def set_tenant_quota_store(store: TenantQuotaStore) -> None:
    """Switch the tenant quota override store backend."""
    global _tenant_quota_store
    _tenant_quota_store = store


# ─── Tenant graph retention override store (pluggable) ─────────────────────
_tenant_graph_retention_store: TenantGraphRetentionStore | None = None


def _get_tenant_graph_retention_store() -> TenantGraphRetentionStore:
    """Get the active tenant graph retention override store."""
    global _tenant_graph_retention_store
    if _tenant_graph_retention_store is None:
        with _store_lock:
            if _tenant_graph_retention_store is None:
                if postgres_deployment_configured():
                    from agent_bom.api.tenant_graph_retention_store import PostgresTenantGraphRetentionStore

                    _tenant_graph_retention_store = PostgresTenantGraphRetentionStore()
                elif os.environ.get("AGENT_BOM_DB"):
                    from agent_bom.api.tenant_graph_retention_store import SQLiteTenantGraphRetentionStore

                    _tenant_graph_retention_store = SQLiteTenantGraphRetentionStore(os.environ["AGENT_BOM_DB"])
                else:
                    from agent_bom.api.tenant_graph_retention_store import InMemoryTenantGraphRetentionStore

                    _tenant_graph_retention_store = InMemoryTenantGraphRetentionStore()
    return _tenant_graph_retention_store


def set_tenant_graph_retention_store(store: TenantGraphRetentionStore) -> None:
    """Switch the tenant graph retention override store backend."""
    global _tenant_graph_retention_store
    _tenant_graph_retention_store = store


# ─── Tenant exec-score config override store (pluggable) ───────────────────
_tenant_score_config_store: TenantScoreConfigStore | None = None


def _get_tenant_score_config_store() -> TenantScoreConfigStore:
    """Get the active per-tenant exec-score config override store (#3940)."""
    global _tenant_score_config_store
    if _tenant_score_config_store is None:
        with _store_lock:
            if _tenant_score_config_store is None:
                if postgres_deployment_configured():
                    from agent_bom.api.postgres_tenant_score_config import PostgresTenantScoreConfigStore

                    _tenant_score_config_store = PostgresTenantScoreConfigStore()
                elif os.environ.get("AGENT_BOM_DB"):
                    from agent_bom.api.tenant_score_config_store import SQLiteTenantScoreConfigStore

                    _tenant_score_config_store = SQLiteTenantScoreConfigStore(os.environ["AGENT_BOM_DB"])
                else:
                    from agent_bom.api.tenant_score_config_store import InMemoryTenantScoreConfigStore

                    _tenant_score_config_store = InMemoryTenantScoreConfigStore()
    return _tenant_score_config_store


def set_tenant_score_config_store(store: TenantScoreConfigStore) -> None:
    """Switch the tenant exec-score config override store backend."""
    global _tenant_score_config_store
    _tenant_score_config_store = store


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
                if postgres_deployment_configured():
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
_credential_ref_store: CredentialRefStore | None = None
_mcp_observation_store: MCPObservationStore | None = None
_issue_mapping_store: IssueMappingStore | None = None


def _get_source_store() -> SourceStore:
    """Get the active source registry store. Must be initialized during lifespan."""
    if _source_store is None:
        raise RuntimeError("Source store not initialized")
    return _source_store


def set_source_store(store: SourceStore) -> None:
    """Switch the source registry store backend."""
    global _source_store
    _source_store = store


def _get_credential_ref_store() -> CredentialRefStore:
    """Get the active credential reference store. Must be initialized during lifespan."""
    if _credential_ref_store is None:
        raise RuntimeError("Credential reference store not initialized")
    return _credential_ref_store


def set_credential_ref_store(store: CredentialRefStore) -> None:
    """Switch the credential reference registry backend."""
    global _credential_ref_store
    _credential_ref_store = store


def _get_mcp_observation_store() -> MCPObservationStore:
    """Get the active persisted MCP observation store."""
    global _mcp_observation_store
    if _mcp_observation_store is None:
        with _store_lock:
            if _mcp_observation_store is None:
                if postgres_deployment_configured():
                    from agent_bom.api.storage.observation_registries import PostgresMCPObservationStore

                    _mcp_observation_store = PostgresMCPObservationStore()
                elif os.environ.get("AGENT_BOM_DB"):
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


def _get_issue_mapping_store() -> IssueMappingStore:
    """Get the tenant-scoped external issue mapping store."""
    global _issue_mapping_store
    if _issue_mapping_store is None:
        with _store_lock:
            if _issue_mapping_store is None:
                if postgres_deployment_configured():
                    from agent_bom.api.storage.observation_registries import PostgresIssueMappingStore

                    _issue_mapping_store = PostgresIssueMappingStore()
                elif os.environ.get("AGENT_BOM_DB"):
                    from agent_bom.api.issue_mapping_store import SQLiteIssueMappingStore

                    _issue_mapping_store = SQLiteIssueMappingStore(os.environ["AGENT_BOM_DB"])
                else:
                    from agent_bom.api.issue_mapping_store import InMemoryIssueMappingStore

                    _issue_mapping_store = InMemoryIssueMappingStore()
    return _issue_mapping_store


def set_issue_mapping_store(store: IssueMappingStore | None) -> None:
    """Switch the issue mapping store backend."""
    global _issue_mapping_store
    _issue_mapping_store = store


# ─── Exception store (enterprise) ───────────────────────────────────────────
_exception_store: Any = None


def _get_exception_store() -> Any:
    """Keep explicit backend overrides; otherwise honor configured persistence."""
    global _exception_store
    if _exception_store is None:
        with _store_lock:
            if _exception_store is None:
                from agent_bom.api.exception_store import configured_exception_store

                _exception_store = configured_exception_store()
    return _exception_store


def set_exception_store(store: Any) -> None:
    """Switch the exception store backend. Call before server startup."""
    global _exception_store
    _exception_store = store


# ─── Trend store (enterprise baseline comparison) ───────────────────────────
_trend_store: Any = None
_last_scan_report: dict | None = None


def _get_trend_store() -> Any:
    """Get the active trend store, creating InMemoryTrendStore if not set."""
    global _trend_store
    if _trend_store is None:
        with _store_lock:
            if _trend_store is None:
                if postgres_deployment_configured():
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
                backend = os.environ.get("AGENT_BOM_GRAPH_BACKEND", "").strip().lower()
                if backend == "neptune":
                    _graph_store = NeptuneGraphStore()
                elif postgres_deployment_configured():
                    from agent_bom.api.postgres_store import PostgresGraphStore

                    _graph_store = PostgresGraphStore()
                else:
                    from agent_bom.api.graph_store import SQLiteGraphStore

                    _graph_store = SQLiteGraphStore()
    from agent_bom.api.current_graph import current_graph_store

    return cast("GraphStoreProtocol", current_graph_store(cast(Any, _graph_store), _get_store()))


def set_graph_store(store: GraphStoreProtocol) -> None:
    """Switch the graph store backend. Call before server startup."""
    global _graph_store
    _graph_store = store


# ─── Proposed graph scenarios (pluggable, never observed graph tables) ──────
_graph_scenario_store: GraphScenarioStore | None = None


def _get_graph_scenario_store() -> GraphScenarioStore:
    """Get durable scenario persistence for the configured deployment tier."""
    global _graph_scenario_store
    if _graph_scenario_store is None:
        with _store_lock:
            if _graph_scenario_store is None:
                if postgres_deployment_configured():
                    from agent_bom.api.postgres_graph_scenario import PostgresGraphScenarioStore

                    _graph_scenario_store = PostgresGraphScenarioStore()
                elif os.environ.get("AGENT_BOM_DB"):
                    from agent_bom.api.graph_scenario_store import SQLiteGraphScenarioStore

                    _graph_scenario_store = SQLiteGraphScenarioStore(os.environ["AGENT_BOM_DB"])
                else:
                    from agent_bom.api.durable_store import default_state_db_path
                    from agent_bom.api.graph_scenario_store import SQLiteGraphScenarioStore

                    _graph_scenario_store = SQLiteGraphScenarioStore(default_state_db_path())
    return _graph_scenario_store


def set_graph_scenario_store(store: GraphScenarioStore) -> None:
    """Switch scenario persistence explicitly, primarily for isolated tests."""
    global _graph_scenario_store
    _graph_scenario_store = store


def get_last_scan_report() -> dict | None:
    """Get the last scan report for baseline comparison."""
    return _last_scan_report


def set_last_scan_report(report: dict | None) -> None:
    """Set the last scan report for baseline comparison."""
    global _last_scan_report
    _last_scan_report = report
