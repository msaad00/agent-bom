"""Correlation run persistence for the Postgres graph store."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any, Mapping

if TYPE_CHECKING:
    from agent_bom.graph import UnifiedGraph

from agent_bom.db.graph_store import (
    normalize_graph_tenant_id,
)
from agent_bom.graph.correlation import CorrelationRunStatus, GraphCorrelationRun, validate_correlation_update

from .postgres_common import (
    _tenant_connection,
)
from .postgres_graph_support import (
    _CORRELATION_RUN_COLUMNS,
    _DB_LEASE_ISO,
    _DB_NOW_ISO,
    PostgresGraphStoreBase,
    _correlation_run_from_row,
)


class PostgresGraphCorrelationMixin(PostgresGraphStoreBase):
    """Create, claim, heartbeat and complete cross-snapshot correlation runs."""

    def get_correlation_run(self, *, tenant_id: str, correlation_id: str) -> GraphCorrelationRun | None:
        tenant = normalize_graph_tenant_id(tenant_id)
        with _tenant_connection(self._pool) as conn:
            row = conn.execute(
                f"SELECT {_CORRELATION_RUN_COLUMNS} FROM graph_correlation_runs WHERE tenant_id = %s AND correlation_id = %s",  # nosec B608 - static internal column list
                (tenant, correlation_id),
            ).fetchone()
        return _correlation_run_from_row(row) if row is not None else None

    def get_correlation_run_by_idempotency_key(
        self,
        *,
        tenant_id: str,
        idempotency_key: str,
    ) -> GraphCorrelationRun | None:
        tenant = normalize_graph_tenant_id(tenant_id)
        with _tenant_connection(self._pool) as conn:
            row = conn.execute(
                f"SELECT {_CORRELATION_RUN_COLUMNS} FROM graph_correlation_runs WHERE tenant_id = %s AND idempotency_key = %s",  # nosec B608 - static internal column list
                (tenant, idempotency_key),
            ).fetchone()
        return _correlation_run_from_row(row) if row is not None else None

    def complete_correlation_run(
        self,
        graph: UnifiedGraph,
        *,
        result_manifest: Mapping[str, Any],
        manifest_sha256: str,
        completed_at: str = "",
        execution_owner: str = "",
    ) -> GraphCorrelationRun:
        from agent_bom.graph.correlation import validate_correlation_output_manifest

        validate_correlation_output_manifest(
            graph,
            result_manifest=result_manifest,
            manifest_sha256=manifest_sha256,
        )
        self.save_graph_streaming(
            scan_id=graph.scan_id,
            tenant_id=graph.tenant_id,
            created_at=graph.created_at,
            nodes=graph.nodes.values(),
            edges=graph.edges,
            attack_paths=graph.attack_paths,
            interaction_risks=graph.interaction_risks,
            analysis_status=graph.analysis_status,
            snapshot_kind="correlation",
            correlation_id=graph.scan_id,
            evidence_manifest_sha256=manifest_sha256,
            correlation_result_manifest=result_manifest,
            correlation_completed_at=completed_at,
            correlation_execution_owner=execution_owner,
        )
        completed = self.get_correlation_run(tenant_id=graph.tenant_id, correlation_id=graph.scan_id)
        if completed is None:  # pragma: no cover - defensive invariant
            raise RuntimeError("completed correlation run disappeared")
        return completed

    def create_correlation_run(self, run: GraphCorrelationRun) -> tuple[GraphCorrelationRun, bool]:
        tenant = normalize_graph_tenant_id(run.tenant_id)
        with _tenant_connection(self._pool) as conn:
            existing = conn.execute(
                f"SELECT {_CORRELATION_RUN_COLUMNS} FROM graph_correlation_runs WHERE tenant_id = %s AND idempotency_key = %s",  # nosec B608 - static internal column list
                (tenant, run.idempotency_key),
            ).fetchone()
            if existing is not None:
                replay = _correlation_run_from_row(existing)
                if replay.request_fingerprint() != run.request_fingerprint():
                    raise ValueError("idempotency key was already used for a different correlation request")
                return replay, False
            row = conn.execute(
                f"""
                INSERT INTO graph_correlation_runs ({_CORRELATION_RUN_COLUMNS})
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT DO NOTHING
                RETURNING {_CORRELATION_RUN_COLUMNS}
                """,  # nosec B608 - static internal column list
                (
                    run.correlation_id,
                    tenant,
                    run.idempotency_key,
                    run.name,
                    run.status.value,
                    run.max_age_hours,
                    int(run.allow_stale),
                    json.dumps(run.input_manifest, sort_keys=True, separators=(",", ":")),
                    run.manifest_sha256,
                    json.dumps(run.result_manifest, sort_keys=True, separators=(",", ":")),
                    run.output_scan_id,
                    run.failure_code,
                    run.created_at,
                    run.started_at,
                    run.completed_at,
                    run.execution_owner,
                    run.execution_lease_expires_at,
                ),
            ).fetchone()
            if row is not None:
                conn.commit()
                return _correlation_run_from_row(row), True
            replay_row = conn.execute(
                f"SELECT {_CORRELATION_RUN_COLUMNS} FROM graph_correlation_runs WHERE tenant_id = %s AND idempotency_key = %s",  # nosec B608 - static internal column list
                (tenant, run.idempotency_key),
            ).fetchone()
            if replay_row is None:
                raise ValueError("correlation_id already exists with a different idempotency key")
            concurrent_replay = _correlation_run_from_row(replay_row)
            if concurrent_replay.request_fingerprint() != run.request_fingerprint():
                raise ValueError("idempotency key was already used for a different correlation request")
            return concurrent_replay, False

    def list_correlation_runs(self, *, tenant_id: str, limit: int = 100) -> list[GraphCorrelationRun]:
        tenant = normalize_graph_tenant_id(tenant_id)
        with _tenant_connection(self._pool) as conn:
            rows = conn.execute(
                f"SELECT {_CORRELATION_RUN_COLUMNS} FROM graph_correlation_runs "
                "WHERE tenant_id = %s ORDER BY created_at DESC, correlation_id DESC LIMIT %s",  # nosec B608
                (tenant, max(1, min(int(limit), 1000))),
            ).fetchall()
        return [_correlation_run_from_row(row) for row in rows]

    def count_active_correlation_runs(self, *, tenant_id: str) -> int:
        tenant = normalize_graph_tenant_id(tenant_id)
        with _tenant_connection(self._pool) as conn:
            row = conn.execute(
                "SELECT COUNT(*) FROM graph_correlation_runs WHERE tenant_id = %s AND status IN (%s, %s)",
                (
                    tenant,
                    CorrelationRunStatus.PENDING.value,
                    CorrelationRunStatus.RUNNING.value,
                ),
            ).fetchone()
        return int(row[0]) if row is not None else 0

    def claim_correlation_run_execution(
        self,
        *,
        tenant_id: str,
        correlation_id: str,
        owner_token: str,
        lease_seconds: int,
        now: str,
    ) -> GraphCorrelationRun | None:
        tenant = normalize_graph_tenant_id(tenant_id)
        with _tenant_connection(self._pool) as conn:
            row = conn.execute(
                f"""
                UPDATE graph_correlation_runs
                SET status = %s, started_at = CASE WHEN started_at = '' THEN {_DB_NOW_ISO} ELSE started_at END,
                    execution_owner = %s, execution_lease_expires_at = {_DB_LEASE_ISO}
                WHERE tenant_id = %s AND correlation_id = %s
                  AND (status = %s OR (status = %s AND execution_lease_expires_at <= {_DB_NOW_ISO}))
                RETURNING {_CORRELATION_RUN_COLUMNS}
                """,  # nosec B608 - static internal column list and fixed clock expressions
                (
                    CorrelationRunStatus.RUNNING.value,
                    owner_token,
                    max(1, int(lease_seconds)),
                    tenant,
                    correlation_id,
                    CorrelationRunStatus.PENDING.value,
                    CorrelationRunStatus.RUNNING.value,
                ),
            ).fetchone()
            if row is None:
                return None
            conn.commit()
            return _correlation_run_from_row(row)

    def heartbeat_correlation_run_execution(
        self,
        *,
        tenant_id: str,
        correlation_id: str,
        owner_token: str,
        lease_seconds: int,
        now: str,
    ) -> bool:
        tenant = normalize_graph_tenant_id(tenant_id)
        with _tenant_connection(self._pool) as conn:
            row = conn.execute(
                f"""
                UPDATE graph_correlation_runs SET execution_lease_expires_at = {_DB_LEASE_ISO}
                WHERE tenant_id = %s AND correlation_id = %s AND status = %s AND execution_owner = %s
                RETURNING correlation_id
                """,  # nosec B608 - fixed internal clock expression
                (max(1, int(lease_seconds)), tenant, correlation_id, CorrelationRunStatus.RUNNING.value, owner_token),
            ).fetchone()
            if row is None:
                return False
            conn.commit()
            return True

    def update_correlation_run(
        self,
        *,
        tenant_id: str,
        correlation_id: str,
        status: CorrelationRunStatus,
        manifest_sha256: str = "",
        result_manifest: Mapping[str, Any] | None = None,
        output_scan_id: str = "",
        failure_code: str = "",
        started_at: str = "",
        completed_at: str = "",
        execution_owner: str = "",
    ) -> GraphCorrelationRun:
        tenant = normalize_graph_tenant_id(tenant_id)
        existing = self.get_correlation_run(tenant_id=tenant, correlation_id=correlation_id)
        if existing is None:
            raise KeyError("correlation run not found")
        resolved_manifest, resolved_result_manifest, resolved_output, resolved_failure = validate_correlation_update(
            existing,
            status=status,
            manifest_sha256=manifest_sha256,
            result_manifest=result_manifest,
            output_scan_id=output_scan_id,
            failure_code=failure_code,
        )
        with _tenant_connection(self._pool) as conn:
            row = conn.execute(
                f"""
                UPDATE graph_correlation_runs
                SET status = %s, manifest_sha256 = %s, result_manifest = %s, output_scan_id = %s,
                    failure_code = %s, started_at = %s, completed_at = %s
                WHERE tenant_id = %s AND correlation_id = %s AND status = %s
                  AND (%s = '' OR execution_owner = %s)
                RETURNING {_CORRELATION_RUN_COLUMNS}
                """,  # nosec B608 - static internal column list
                (
                    status.value,
                    resolved_manifest,
                    json.dumps(resolved_result_manifest, sort_keys=True, separators=(",", ":")),
                    resolved_output,
                    resolved_failure,
                    started_at or existing.started_at,
                    completed_at or existing.completed_at,
                    tenant,
                    correlation_id,
                    existing.status.value,
                    execution_owner,
                    execution_owner,
                ),
            ).fetchone()
            if row is None:
                raise ValueError("correlation run status changed concurrently")
            conn.commit()
            return _correlation_run_from_row(row)
