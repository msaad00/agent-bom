"""Durable provider-neutral contracts for opt-in workload disk side-scans.

This module contains state and evidence contracts only.  It does not create,
attach, mount, or delete cloud resources and it does not load provider
credentials.  AWS execution lives in :mod:`agent_bom.cloud.side_scan`; the
Azure Managed Disk and GCP Persistent Disk executors live in
:mod:`agent_bom.cloud.side_scan_provider_adapters` and are driven by
:func:`agent_bom.cloud.side_scan_targets.run_provider_side_scan`.  All three
providers ship a CLI executor; no live credentialed smoke is claimed for any of
them (``credentialed_smoke=False``).
"""

from __future__ import annotations

import hashlib
import os
import threading
import uuid
from pathlib import Path

from agent_bom.storage import state_home

from .side_scan_lifecycle_models import (
    SideScanCleanupOwnership,
    SideScanExecutionRecord,
    SideScanStateConflictError,
    SideScanTemporaryResource,
    _coerce_int,
    _now,
    _record_from_json,
    _record_json,
)
from .side_scan_lifecycle_postgres import PostgresSideScanStateStore
from .side_scan_lifecycle_status import (
    _CLEANUP_TRANSITIONS,
    _EXECUTION_NAMESPACE,
    _EXECUTION_TRANSITIONS,
    _PHASES,
    _RESOURCE_TRANSITIONS,
    EVIDENCE_SCHEMA_VERSION,
    LIFECYCLE_SCHEMA_VERSION,
    CleanupStatus,
    ExecutionStatus,
    SideScanProvider,
    SideScanProviderCapability,
    TemporaryResourceStatus,
    side_scan_provider_capabilities,
)
from .side_scan_lifecycle_stores import (
    InMemorySideScanStateStore,
    SideScanStateStore,
    SQLiteSideScanStateStore,
)

__all__ = [
    "EVIDENCE_SCHEMA_VERSION",
    "LIFECYCLE_SCHEMA_VERSION",
    "CleanupStatus",
    "ExecutionStatus",
    "InMemorySideScanStateStore",
    "PostgresSideScanStateStore",
    "SQLiteSideScanStateStore",
    "SideScanCleanupOwnership",
    "SideScanExecutionRecord",
    "SideScanProvider",
    "SideScanProviderCapability",
    "SideScanStateConflictError",
    "SideScanStateStore",
    "SideScanTemporaryResource",
    "TemporaryResourceStatus",
    "_CLEANUP_TRANSITIONS",
    "_EXECUTION_NAMESPACE",
    "_EXECUTION_TRANSITIONS",
    "_PHASES",
    "_RESOURCE_TRANSITIONS",
    "_coerce_int",
    "_now",
    "_record_from_json",
    "_record_json",
    "get_side_scan_state_store",
    "new_side_scan_execution",
    "reset_side_scan_state_store",
    "side_scan_provider_capabilities",
]


_default_side_scan_store: SideScanStateStore | None = None
_default_side_scan_store_lock = threading.Lock()


def get_side_scan_state_store(*, state_db_path: str | Path | None = None) -> SideScanStateStore:
    """Resolve the shared lifecycle backend used by CLI, API, MCP, and scheduler."""
    if state_db_path is not None:
        return SQLiteSideScanStateStore(state_db_path)
    explicit_path = os.environ.get("AGENT_BOM_SIDE_SCAN_STATE_DB", "").strip()
    if explicit_path:
        return SQLiteSideScanStateStore(Path(explicit_path).expanduser())

    global _default_side_scan_store
    with _default_side_scan_store_lock:
        if _default_side_scan_store is not None:
            return _default_side_scan_store
        from agent_bom.api.durable_store import select_backend

        backend = select_backend()
        if backend == "postgres":
            _default_side_scan_store = PostgresSideScanStateStore()
        elif backend == "memory":
            _default_side_scan_store = InMemorySideScanStateStore()
        else:
            state_dir = state_home.state_dir()
            state_dir.mkdir(parents=True, exist_ok=True)
            _default_side_scan_store = SQLiteSideScanStateStore(state_dir / "side_scan_state.db")
        return _default_side_scan_store


def reset_side_scan_state_store() -> None:
    global _default_side_scan_store
    with _default_side_scan_store_lock:
        _default_side_scan_store = None


def new_side_scan_execution(
    *,
    tenant_id: str,
    provider: SideScanProvider,
    account_id: str,
    target_id: str,
    collector_id: str,
    idempotency_key: str,
    request_fingerprint: str = "",
    now: str | None = None,
) -> SideScanExecutionRecord:
    """Build a deterministic execution identity for retry-safe scheduling."""
    scope = "\x1f".join((tenant_id, provider, account_id, target_id, idempotency_key))
    execution_id = str(uuid.uuid5(_EXECUTION_NAMESPACE, scope))
    owner_id = hashlib.sha256(f"owner\x1f{execution_id}".encode()).hexdigest()[:24]
    scope_hash = hashlib.sha256(f"scope\x1f{tenant_id}\x1f{provider}\x1f{account_id}".encode()).hexdigest()[:24]
    timestamp = now or _now()
    ownership = SideScanCleanupOwnership(execution_id=execution_id, owner_id=owner_id, scope_hash=scope_hash)
    return SideScanExecutionRecord(
        execution_id=execution_id,
        idempotency_key=idempotency_key,
        tenant_id=tenant_id,
        provider=provider,
        account_id=account_id,
        target_id=target_id,
        collector_id=collector_id,
        cleanup_ownership=ownership,
        request_fingerprint=request_fingerprint,
        created_at=timestamp,
        updated_at=timestamp,
    )
