"""Tenant-bound durable Postgres adapters for evidence registries."""

from __future__ import annotations

import builtins
from dataclasses import asdict
from typing import Any

from agent_bom.api import postgres_common
from agent_bom.api.dataset_version_store import DatasetVersionRecord
from agent_bom.api.drift_incident_store import DriftIncident
from agent_bom.api.evaluation_store import EvaluationRunRecord
from agent_bom.api.storage.registry_schema import REGISTRY_TABLES, registry_table_ddl
from agent_bom.api.storage_schema import ensure_postgres_schema_version
from agent_bom.api.webhook_store import WebhookSubscription, storage_payload, unseal_subscription
from agent_bom.core.tenancy import require_explicit_tenant_id


class RegistryStore:
    """Only fixed adapter-owned table and column names enter SQL expressions."""

    table: str
    keys: tuple[str, ...]
    columns: tuple[str, ...]
    record_type: Any

    def __init__(self, pool: Any = None) -> None:
        self._pool = pool or postgres_common._get_pool()
        with self._pool.connection() as conn:
            if ensure_postgres_schema_version(conn, self.table):
                conn.execute(registry_table_ddl(self.table))
                postgres_common._ensure_tenant_rls(conn, self.table, "tenant_id")
                conn.commit()

    def _put_record(self, record: Any) -> None:
        self._put_payload(record, asdict(record))

    def _put_payload(self, record: Any, payload: dict[str, Any]) -> None:
        from psycopg.types.json import Jsonb

        require_explicit_tenant_id(record.tenant_id)
        columns = ("tenant_id", *self.columns, "data")
        values = (record.tenant_id, *(getattr(record, column) for column in self.columns), Jsonb(payload))
        assignments = ", ".join(f"{column}=excluded.{column}" for column in columns if column not in ("tenant_id", *self.keys))
        with postgres_common._tenant_connection(self._pool) as conn:
            conn.execute(
                f"INSERT INTO {self.table} ({', '.join(columns)}) VALUES ({', '.join(['%s'] * len(columns))}) "  # nosec B608 - identifiers and query fragments are fixed by internal adapters; values are bound
                f"ON CONFLICT (tenant_id, {', '.join(self.keys)}) DO UPDATE SET {assignments}",
                values,
            )
            conn.commit()

    def _get(self, tenant_id: str, *keys: str) -> Any:
        require_explicit_tenant_id(tenant_id)
        with postgres_common._tenant_connection(self._pool) as conn:
            row = conn.execute(
                f"SELECT data FROM {self.table} WHERE tenant_id=%s AND " + " AND ".join(f"{key}=%s" for key in self.keys),  # nosec B608 - identifiers and query fragments are fixed by internal adapters; values are bound
                (tenant_id, *keys),
            ).fetchone()
        return self.record_type(**row[0]) if row else None

    def _list(self, tenant_id: str, predicate: str, params: tuple[Any, ...], order: str, limit: int = 200, offset: int = 0) -> list[Any]:
        require_explicit_tenant_id(tenant_id)
        with postgres_common._tenant_connection(self._pool) as conn:
            rows = conn.execute(
                f"SELECT data FROM {self.table} WHERE tenant_id=%s {predicate} ORDER BY {order} LIMIT %s OFFSET %s",  # nosec B608 - identifiers and query fragments are fixed by internal adapters; values are bound
                (tenant_id, *params, max(0, limit), max(0, offset)),
            ).fetchall()
        return [self.record_type(**row[0]) for row in rows]


class PostgresDatasetVersionStore(RegistryStore):
    put = RegistryStore._put_record
    table = "dataset_versions"
    keys = ("dataset_id", "version_id")
    columns = ("dataset_id", "version_id", "created_at")
    record_type = DatasetVersionRecord

    def get(self, tenant_id: str, dataset_id: str, version_id: str) -> DatasetVersionRecord | None:
        return self._get(tenant_id, dataset_id, version_id)

    def list(self, tenant_id: str, dataset_id: str) -> list[DatasetVersionRecord]:
        # Existing dataset contract returns all versions of the selected dataset.
        return self._list(tenant_id, "AND dataset_id=%s", (dataset_id,), "created_at DESC, version_id", 2147483647)


class PostgresEvaluationRunStore(RegistryStore):
    put = RegistryStore._put_record
    table = "evaluation_runs"
    keys = ("evaluation_id",)
    columns = ("evaluation_id", "dataset_id", "created_at")
    record_type = EvaluationRunRecord

    def get(self, tenant_id: str, evaluation_id: str) -> EvaluationRunRecord | None:
        return self._get(tenant_id, evaluation_id)

    def list(self, tenant_id: str, *, dataset_id: str | None = None, limit: int = 100, offset: int = 0) -> list[EvaluationRunRecord]:
        return self._list(
            tenant_id,
            "AND dataset_id=%s" if dataset_id is not None else "",
            (dataset_id,) if dataset_id is not None else (),
            "created_at DESC, evaluation_id",
            limit,
            offset,
        )


class PostgresWebhookSubscriptionStore(RegistryStore):
    table = "webhook_subscriptions"
    keys = ("subscription_id",)
    columns = ("subscription_id", "status", "created_at")
    record_type = WebhookSubscription

    def put(self, subscription: WebhookSubscription) -> None:
        self._put_payload(subscription, storage_payload(subscription))

    def get(self, subscription_id: str) -> WebhookSubscription | None:
        # Legacy interface omits tenant; RLS binds the authenticated request scope.
        with postgres_common._tenant_connection(self._pool) as conn:
            row = conn.execute("SELECT data FROM webhook_subscriptions WHERE subscription_id=%s", (subscription_id,)).fetchone()
        return unseal_subscription(WebhookSubscription(**row[0])) if row else None

    def delete(self, subscription_id: str) -> bool:
        with postgres_common._tenant_connection(self._pool) as conn:
            count = conn.execute("DELETE FROM webhook_subscriptions WHERE subscription_id=%s", (subscription_id,)).rowcount
            conn.commit()
        return count > 0

    def list(self, tenant_id: str, *, include_disabled: bool = False, limit: int = 200) -> list[WebhookSubscription]:
        rows = self._list(tenant_id, "" if include_disabled else "AND status='active'", (), "created_at DESC, subscription_id", limit)
        return [unseal_subscription(record) for record in rows]

    def matching(self, tenant_id: str, event_type: str) -> builtins.list[WebhookSubscription]:
        return [record for record in self.list(tenant_id, limit=500) if record.wants(event_type)]


class PostgresDriftIncidentStore(RegistryStore):
    put = RegistryStore._put_record
    table = "drift_incidents"
    keys = ("incident_id",)
    columns = ("incident_id", "resolved", "last_detected_at")
    record_type = DriftIncident

    def get(self, tenant_id: str, incident_id: str) -> DriftIncident | None:
        return self._get(tenant_id, incident_id)

    def list(self, tenant_id: str, *, include_resolved: bool = False, limit: int = 200) -> list[DriftIncident]:
        return self._list(tenant_id, "" if include_resolved else "AND NOT resolved", (), "last_detected_at DESC, incident_id", limit)

    def upsert(self, incident: DriftIncident) -> DriftIncident:
        from psycopg.types.json import Jsonb

        require_explicit_tenant_id(incident.tenant_id)
        # A single statement handles both first insertion and concurrent increments.
        with postgres_common._tenant_connection(self._pool) as conn:
            row = conn.execute(
                "INSERT INTO drift_incidents (tenant_id,incident_id,resolved,last_detected_at,data) VALUES (%s,%s,%s,%s,%s) "
                "ON CONFLICT (tenant_id,incident_id) DO UPDATE SET "
                "resolved=CASE WHEN drift_incidents.resolved THEN excluded.resolved ELSE drift_incidents.resolved END, "
                "last_detected_at=excluded.last_detected_at, "
                "data=CASE WHEN drift_incidents.resolved THEN excluded.data ELSE drift_incidents.data || "
                "jsonb_build_object('last_detected_at',excluded.data->'last_detected_at',"
                "'drift_score',excluded.data->'drift_score','violation_count',excluded.data->'violation_count',"
                "'warning_count',excluded.data->'warning_count','top_violations',excluded.data->'top_violations',"
                "'occurrences',(drift_incidents.data->>'occurrences')::bigint + 1) END RETURNING data",
                (incident.tenant_id, incident.incident_id, incident.resolved, incident.last_detected_at, Jsonb(asdict(incident))),
            ).fetchone()
            conn.commit()
        assert row is not None
        return DriftIncident(**row[0])

    def resolve(self, tenant_id: str, incident_id: str, *, by: str, note: str, at: str) -> DriftIncident | None:
        from psycopg.types.json import Jsonb

        require_explicit_tenant_id(tenant_id)
        with postgres_common._tenant_connection(self._pool) as conn:
            row = conn.execute(
                "UPDATE drift_incidents SET resolved=TRUE,data=data || %s WHERE tenant_id=%s AND incident_id=%s RETURNING data",
                (Jsonb({"resolved": True, "resolved_at": at, "resolved_by": by, "resolution_note": note}), tenant_id, incident_id),
            ).fetchone()
            conn.commit()
        return DriftIncident(**row[0]) if row else None


def validate_postgres_registries() -> None:
    """Require all registry migrations before a configured API serves traffic."""
    pool = postgres_common._get_pool()
    with pool.connection() as conn:
        for table in (*REGISTRY_TABLES, "campaign_evidence_state"):
            ensure_postgres_schema_version(conn, table)
            conn.execute(f"SELECT 1 FROM {table} LIMIT 0")  # nosec B608 - identifiers and query fragments are fixed by internal adapters; values are bound
