"""PostgreSQL authority for managed-trial tenant lifecycle state."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from agent_bom.api.postgres_common import ConnectionPool, _get_pool, _tenant_connection, bypass_tenant_rls
from agent_bom.api.storage_schema import ensure_postgres_schema_version
from agent_bom.api.tenant_lifecycle import (
    TenantLifecycleError,
    TenantLifecycleRecord,
    TenantLifecycleState,
)


class PostgresTenantLifecycleStore:
    def __init__(self, pool: ConnectionPool | None = None) -> None:
        self._pool = pool or _get_pool()
        with self._pool.connection() as conn:
            ensure_postgres_schema_version(conn, "managed_trial_tenants")

    @staticmethod
    def _row(row: tuple[Any, ...]) -> TenantLifecycleRecord:
        return TenantLifecycleRecord(
            tenant_id=str(row[0]),
            state=TenantLifecycleState(str(row[1])),
            created_at=row[2],
            trial_ends_at=row[3],
            cleanup_after=row[4],
            updated_at=row[5],
            cleanup_attempts=int(row[6] or 0),
            cleanup_error=str(row[7]) if row[7] is not None else None,
            cleanup_completed_at=row[8],
        )

    def create(
        self,
        *,
        tenant_id: str,
        trial_ends_at: datetime,
        cleanup_after: datetime,
        now: datetime | None = None,
    ) -> TenantLifecycleRecord:
        current = now or datetime.now(timezone.utc)
        with bypass_tenant_rls():
            with _tenant_connection(self._pool) as conn:
                try:
                    row = conn.execute(
                        """INSERT INTO managed_trial_tenants
                           (tenant_id, state, created_at, trial_ends_at, cleanup_after, updated_at)
                           VALUES (%s, 'active', %s, %s, %s, %s)
                           RETURNING tenant_id, state, created_at, trial_ends_at, cleanup_after,
                                     updated_at, cleanup_attempts, cleanup_error, cleanup_completed_at""",
                        (tenant_id, current, trial_ends_at, cleanup_after, current),
                    ).fetchone()
                    conn.commit()
                except Exception as exc:
                    raise TenantLifecycleError("Managed-trial tenant could not be created") from exc
        if row is None:
            raise TenantLifecycleError("Managed-trial tenant could not be created")
        return self._row(row)

    def get(self, tenant_id: str) -> TenantLifecycleRecord:
        with bypass_tenant_rls():
            with _tenant_connection(self._pool) as conn:
                row = conn.execute(
                    """SELECT tenant_id, state, created_at, trial_ends_at, cleanup_after,
                              updated_at, cleanup_attempts, cleanup_error, cleanup_completed_at
                       FROM managed_trial_tenants WHERE tenant_id = %s""",
                    (tenant_id,),
                ).fetchone()
        if row is None:
            raise TenantLifecycleError("Managed-trial tenant not found")
        return self._row(row)

    def _list_due(self, *, now: datetime, cleanup: bool) -> list[TenantLifecycleRecord]:
        if cleanup:
            query = """SELECT tenant_id, state, created_at, trial_ends_at, cleanup_after,
                              updated_at, cleanup_attempts, cleanup_error, cleanup_completed_at
                       FROM managed_trial_tenants
                       WHERE state = 'expired' AND cleanup_after <= %s
                       ORDER BY tenant_id"""
        else:
            query = """SELECT tenant_id, state, created_at, trial_ends_at, cleanup_after,
                              updated_at, cleanup_attempts, cleanup_error, cleanup_completed_at
                       FROM managed_trial_tenants
                       WHERE state IN ('active', 'suspended') AND trial_ends_at <= %s
                       ORDER BY tenant_id"""
        with bypass_tenant_rls():
            with _tenant_connection(self._pool) as conn:
                rows = conn.execute(query, (now,)).fetchall()
        return [self._row(row) for row in rows]

    def list_due_expiry(self, *, now: datetime) -> list[TenantLifecycleRecord]:
        return self._list_due(now=now, cleanup=False)

    def list_due_cleanup(self, *, now: datetime) -> list[TenantLifecycleRecord]:
        return self._list_due(now=now, cleanup=True)

    def transition(
        self,
        tenant_id: str,
        *,
        state: TenantLifecycleState,
        now: datetime | None = None,
    ) -> TenantLifecycleRecord:
        current = now or datetime.now(timezone.utc)
        allowed_from = {
            TenantLifecycleState.ACTIVE: ("suspended",),
            TenantLifecycleState.SUSPENDED: ("active",),
            TenantLifecycleState.EXPIRED: ("active", "suspended"),
            TenantLifecycleState.DELETED: ("expired",),
        }[state]
        with bypass_tenant_rls():
            with _tenant_connection(self._pool) as conn:
                row = conn.execute(
                    """UPDATE managed_trial_tenants
                       SET state = %s,
                           updated_at = %s,
                           cleanup_error = NULL,
                           cleanup_completed_at = CASE WHEN %s = 'deleted' THEN %s ELSE cleanup_completed_at END
                       WHERE tenant_id = %s AND (state = %s OR state = ANY(%s))
                       RETURNING tenant_id, state, created_at, trial_ends_at, cleanup_after,
                                 updated_at, cleanup_attempts, cleanup_error, cleanup_completed_at""",
                    (state.value, current, state.value, current, tenant_id, state.value, list(allowed_from)),
                ).fetchone()
                if row is not None:
                    conn.commit()
        if row is None:
            raise TenantLifecycleError("Invalid managed-trial tenant lifecycle transition")
        return self._row(row)

    def record_cleanup_failure(
        self,
        tenant_id: str,
        *,
        error: str,
        now: datetime | None = None,
    ) -> TenantLifecycleRecord:
        current = now or datetime.now(timezone.utc)
        with bypass_tenant_rls():
            with _tenant_connection(self._pool) as conn:
                row = conn.execute(
                    """UPDATE managed_trial_tenants
                       SET cleanup_attempts = cleanup_attempts + 1,
                           cleanup_error = %s,
                           updated_at = %s
                       WHERE tenant_id = %s AND state = 'expired'
                       RETURNING tenant_id, state, created_at, trial_ends_at, cleanup_after,
                                 updated_at, cleanup_attempts, cleanup_error, cleanup_completed_at""",
                    (error[:256], current, tenant_id),
                ).fetchone()
                if row is not None:
                    conn.commit()
        if row is None:
            raise TenantLifecycleError("Cleanup failure could not be recorded")
        return self._row(row)
