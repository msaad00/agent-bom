"""Durable managed-trial tenant lifecycle and cleanup coordination."""

from __future__ import annotations

import os
import threading
from collections.abc import Callable
from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Protocol

MANAGED_TRIAL_DURATION = timedelta(days=14)
MANAGED_TRIAL_CLEANUP_GRACE = timedelta(days=7)

# Trial offboarding deletes every tenant-keyed product table discovered in the
# deployed PostgreSQL schema. Tamper-evident audit evidence and the lifecycle
# tombstone follow their documented retention contract and are the only
# intentional exclusions.
MANAGED_TRIAL_RETAINED_POSTGRES_TABLES = frozenset(
    {
        "audit_log",
        "policy_audit_log",
        "governance_audit_log",
        "audit_chain_checkpoint",
        "managed_trial_tenants",
    }
)
_MANAGED_TRIAL_DELETE_FIRST = (
    "access_review_items",
    "agent_identity_jit_grants",
    "ai_system_blueprint_versions",
    "model_virtual_keys",
    "hub_findings_current_observations",
    "scan_dispatch_queue",
    "managed_trial_invitations",
)


class TenantLifecycleError(ValueError):
    """Raised for invalid or conflicting lifecycle transitions."""


class TenantLifecycleState(str, Enum):
    ACTIVE = "active"
    SUSPENDED = "suspended"
    EXPIRED = "expired"
    DELETED = "deleted"


@dataclass(frozen=True)
class TenantLifecycleRecord:
    tenant_id: str
    state: TenantLifecycleState
    created_at: datetime
    trial_ends_at: datetime
    cleanup_after: datetime
    updated_at: datetime
    cleanup_attempts: int = 0
    cleanup_error: str | None = None
    cleanup_completed_at: datetime | None = None


class TenantLifecycleStore(Protocol):
    def create(
        self,
        *,
        tenant_id: str,
        trial_ends_at: datetime,
        cleanup_after: datetime,
        now: datetime | None = None,
    ) -> TenantLifecycleRecord: ...

    def get(self, tenant_id: str) -> TenantLifecycleRecord: ...
    def list_due_expiry(self, *, now: datetime) -> list[TenantLifecycleRecord]: ...
    def list_due_cleanup(self, *, now: datetime) -> list[TenantLifecycleRecord]: ...
    def transition(
        self,
        tenant_id: str,
        *,
        state: TenantLifecycleState,
        now: datetime | None = None,
    ) -> TenantLifecycleRecord: ...

    def record_cleanup_failure(
        self,
        tenant_id: str,
        *,
        error: str,
        now: datetime | None = None,
    ) -> TenantLifecycleRecord: ...


_ALLOWED_TRANSITIONS: dict[TenantLifecycleState, frozenset[TenantLifecycleState]] = {
    TenantLifecycleState.ACTIVE: frozenset({TenantLifecycleState.SUSPENDED, TenantLifecycleState.EXPIRED}),
    TenantLifecycleState.SUSPENDED: frozenset({TenantLifecycleState.ACTIVE, TenantLifecycleState.EXPIRED}),
    TenantLifecycleState.EXPIRED: frozenset({TenantLifecycleState.DELETED}),
    TenantLifecycleState.DELETED: frozenset(),
}


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _aware(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


class InMemoryTenantLifecycleStore:
    """Thread-safe lifecycle backend for tests and local single-process use."""

    def __init__(self) -> None:
        self._records: dict[str, TenantLifecycleRecord] = {}
        self._lock = threading.RLock()

    def create(
        self,
        *,
        tenant_id: str,
        trial_ends_at: datetime,
        cleanup_after: datetime,
        now: datetime | None = None,
    ) -> TenantLifecycleRecord:
        current = _aware(now or _utcnow())
        trial_end = _aware(trial_ends_at)
        cleanup = _aware(cleanup_after)
        if not tenant_id or trial_end < current or cleanup < trial_end:
            raise TenantLifecycleError("Invalid managed-trial lifecycle")
        record = TenantLifecycleRecord(
            tenant_id=tenant_id,
            state=TenantLifecycleState.ACTIVE,
            created_at=current,
            trial_ends_at=trial_end,
            cleanup_after=cleanup,
            updated_at=current,
        )
        with self._lock:
            if tenant_id in self._records:
                raise TenantLifecycleError("Managed-trial tenant already exists")
            self._records[tenant_id] = record
        return record

    def get(self, tenant_id: str) -> TenantLifecycleRecord:
        with self._lock:
            record = self._records.get(tenant_id)
        if record is None:
            raise TenantLifecycleError("Managed-trial tenant not found")
        return record

    def list_due_expiry(self, *, now: datetime) -> list[TenantLifecycleRecord]:
        current = _aware(now)
        with self._lock:
            return [
                record
                for record in self._records.values()
                if record.state in {TenantLifecycleState.ACTIVE, TenantLifecycleState.SUSPENDED}
                and record.trial_ends_at <= current
            ]

    def list_due_cleanup(self, *, now: datetime) -> list[TenantLifecycleRecord]:
        current = _aware(now)
        with self._lock:
            return [
                record
                for record in self._records.values()
                if record.state is TenantLifecycleState.EXPIRED and record.cleanup_after <= current
            ]

    def transition(
        self,
        tenant_id: str,
        *,
        state: TenantLifecycleState,
        now: datetime | None = None,
    ) -> TenantLifecycleRecord:
        current = _aware(now or _utcnow())
        with self._lock:
            record = self.get(tenant_id)
            if record.state is state:
                return record
            if state not in _ALLOWED_TRANSITIONS[record.state]:
                raise TenantLifecycleError(f"Invalid tenant lifecycle transition: {record.state.value} -> {state.value}")
            updated = replace(
                record,
                state=state,
                updated_at=current,
                cleanup_error=None,
                cleanup_completed_at=current if state is TenantLifecycleState.DELETED else record.cleanup_completed_at,
            )
            self._records[tenant_id] = updated
            return updated

    def record_cleanup_failure(
        self,
        tenant_id: str,
        *,
        error: str,
        now: datetime | None = None,
    ) -> TenantLifecycleRecord:
        current = _aware(now or _utcnow())
        with self._lock:
            record = self.get(tenant_id)
            if record.state is not TenantLifecycleState.EXPIRED:
                raise TenantLifecycleError("Cleanup failures may only be recorded for expired tenants")
            updated = replace(
                record,
                updated_at=current,
                cleanup_attempts=record.cleanup_attempts + 1,
                cleanup_error=error[:256],
            )
            self._records[tenant_id] = updated
            return updated


def expire_due_tenants(
    store: TenantLifecycleStore,
    *,
    now: datetime | None = None,
    revoke: Callable[[str], object],
) -> int:
    """Revoke and expire every due tenant; successful retries are idempotent."""

    current = _aware(now or _utcnow())
    expired = 0
    for record in store.list_due_expiry(now=current):
        revoke(record.tenant_id)
        store.transition(record.tenant_id, state=TenantLifecycleState.EXPIRED, now=current)
        expired += 1
    return expired


def run_due_tenant_cleanup(
    store: TenantLifecycleStore,
    *,
    now: datetime | None = None,
    delete: Callable[[str], object],
) -> int:
    """Delete due tenant datasets and mark completion only after success."""

    current = _aware(now or _utcnow())
    completed = 0
    for record in store.list_due_cleanup(now=current):
        try:
            delete(record.tenant_id)
        except Exception as exc:  # noqa: BLE001 - cleanup remains retryable
            from agent_bom.security import sanitize_error

            store.record_cleanup_failure(
                record.tenant_id,
                error=sanitize_error(exc, generic=True),
                now=current,
            )
            continue
        store.transition(record.tenant_id, state=TenantLifecycleState.DELETED, now=current)
        completed += 1
    return completed


def tenant_access_active(tenant_id: str) -> bool:
    """Return whether a registered managed-trial tenant may authenticate.

    Tenants absent from the managed registry are ordinary self-hosted tenants
    and remain unaffected.
    """

    try:
        record = get_tenant_lifecycle_store().get(tenant_id)
    except TenantLifecycleError:
        return True
    return record.state is TenantLifecycleState.ACTIVE


def revoke_tenant_access(tenant_id: str) -> dict[str, int]:
    """Immediately revoke keys and disable connections for one trial tenant."""

    from agent_bom.api.auth import get_key_store
    from agent_bom.api.connection_store import STATUS_ERROR, get_connection_store

    key_store = get_key_store()
    revoked_keys = 0
    for key in key_store.list_keys(tenant_id=tenant_id):
        if key_store.remove(key.key_id):
            revoked_keys += 1

    connection_store = get_connection_store()
    disabled_connections = 0
    for record in connection_store.list_for_tenant(tenant_id):
        record.status = STATUS_ERROR
        record.status_detail = "Managed trial access is inactive."
        record.updated_at = _utcnow().isoformat()
        connection_store.put(record)
        disabled_connections += 1
    return {
        "api_keys": revoked_keys,
        "cloud_connections": disabled_connections,
    }


def delete_tenant_records(tenant_id: str) -> dict[str, int]:
    """Delete one managed tenant's data while retaining its lifecycle tombstone.

    The ordinary privacy deletion spine owns the backend-specific tenant data
    inventory.  Managed-trial cleanup adds the invitation and team roots that
    are intentionally outside the tenant's own deletion authority.
    """

    from agent_bom.api.postgres_common import (
        _maintenance_connection,
        bypass_tenant_rls,
        reset_current_tenant,
        set_current_tenant,
    )
    from agent_bom.api.routes.privacy import _delete_records
    from agent_bom.api.storage_schema import postgres_deployment_configured

    token = set_current_tenant(tenant_id)
    try:
        deleted = _delete_records(tenant_id)
    finally:
        reset_current_tenant(token)
    deleted["postgres_tenant_rows"] = 0
    deleted["tenant_root"] = 0
    if postgres_deployment_configured():
        from psycopg import sql

        with bypass_tenant_rls():
            with _maintenance_connection() as conn:
                table_rows = conn.execute(
                    """SELECT table_name
                       FROM information_schema.columns
                       WHERE table_schema = current_schema() AND column_name = 'tenant_id'"""
                ).fetchall()
                tables = {
                    str(row[0])
                    for row in table_rows
                    if str(row[0]) not in MANAGED_TRIAL_RETAINED_POSTGRES_TABLES
                }
                ordered = [
                    *[table for table in _MANAGED_TRIAL_DELETE_FIRST if table in tables],
                    *sorted(tables.difference(_MANAGED_TRIAL_DELETE_FIRST)),
                ]
                postgres_deleted = 0
                for table in ordered:
                    cursor = conn.execute(
                        sql.SQL("DELETE FROM {} WHERE tenant_id = %s").format(sql.Identifier(table)),
                        (tenant_id,),
                    )
                    postgres_deleted += max(0, int(cursor.rowcount))
                team_cursor = conn.execute("DELETE FROM teams WHERE team_id = %s", (tenant_id,))
                conn.commit()
                deleted["postgres_tenant_rows"] = postgres_deleted
                deleted["tenant_root"] = int(team_cursor.rowcount)
    return deleted


def run_managed_trial_lifecycle_tick(*, now: datetime | None = None) -> dict[str, int]:
    """Expire due trials and clean tenants whose grace period elapsed."""

    store = get_tenant_lifecycle_store()
    current = _aware(now or _utcnow())
    expired = expire_due_tenants(store, now=current, revoke=revoke_tenant_access)
    deleted = run_due_tenant_cleanup(store, now=current, delete=delete_tenant_records)
    return {"expired": expired, "deleted": deleted}


_store: TenantLifecycleStore | None = None
_store_lock = threading.Lock()


def get_tenant_lifecycle_store() -> TenantLifecycleStore:
    global _store
    if _store is None:
        with _store_lock:
            if _store is None:
                if os.environ.get("AGENT_BOM_POSTGRES_URL"):
                    from agent_bom.api.postgres_tenant_lifecycle import PostgresTenantLifecycleStore

                    _store = PostgresTenantLifecycleStore()
                else:
                    _store = InMemoryTenantLifecycleStore()
    return _store


def set_tenant_lifecycle_store_for_tests(store: TenantLifecycleStore | None) -> None:
    global _store
    _store = store
