"""Control-plane storage schema manifest and version helpers."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

CONTROL_PLANE_SCHEMA_VERSION = 1
CONTROL_PLANE_SCHEMA_TABLE = "control_plane_schema_versions"


@dataclass(frozen=True)
class StorageSchemaComponent:
    """Operator-visible storage contract for one control-plane component."""

    component: str
    backend: str
    tables: tuple[str, ...]
    tenant_scoped: bool = True
    version: int = CONTROL_PLANE_SCHEMA_VERSION

    def to_dict(self) -> dict[str, Any]:
        return {
            "component": self.component,
            "backend": self.backend,
            "tables": list(self.tables),
            "tenant_scoped": self.tenant_scoped,
            "version": self.version,
        }


CONTROL_PLANE_SCHEMA_COMPONENTS: tuple[StorageSchemaComponent, ...] = (
    StorageSchemaComponent("scan_jobs", "sqlite/postgres", ("jobs", "scan_jobs", "cis_benchmark_checks")),
    StorageSchemaComponent("api_keys", "postgres", ("api_keys",)),
    StorageSchemaComponent("audit_log", "sqlite/postgres", ("audit_log",)),
    StorageSchemaComponent("trend_history", "postgres", ("trend_history",)),
    StorageSchemaComponent("gateway_policies", "sqlite/postgres", ("gateway_policies", "policy_audit_log")),
    StorageSchemaComponent("fleet", "sqlite/postgres/clickhouse", ("fleet_agents",)),
    StorageSchemaComponent("graph", "sqlite/postgres", ("graph_nodes", "graph_edges", "graph_node_search")),
    StorageSchemaComponent("identity_scim", "sqlite/postgres", ("scim_users", "scim_groups")),
    StorageSchemaComponent("tenant_quotas", "sqlite/postgres", ("tenant_quota_overrides",)),
    StorageSchemaComponent("sources", "sqlite/postgres", ("sources", "control_plane_sources")),
    StorageSchemaComponent("schedules", "sqlite/postgres", ("schedules", "scan_schedules")),
    StorageSchemaComponent("exceptions", "sqlite/postgres", ("vuln_exceptions",)),
    StorageSchemaComponent("idempotency", "sqlite", ("idempotency_keys",)),
    StorageSchemaComponent("mcp_observations", "sqlite", ("mcp_observations",)),
    StorageSchemaComponent(
        "analytics",
        "clickhouse",
        ("vulnerability_scans", "runtime_events", "posture_scores", "scan_metadata", "cis_benchmark_checks"),
    ),
    StorageSchemaComponent("warehouse", "snowflake", ("snowflake_posture_snapshots", "snowflake_control_plane_events")),
)


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def ensure_sqlite_schema_version(conn: Any, component: str, version: int = CONTROL_PLANE_SCHEMA_VERSION) -> None:
    """Record the current schema version for a SQLite control-plane component."""

    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS control_plane_schema_versions (
            component TEXT PRIMARY KEY,
            version INTEGER NOT NULL,
            updated_at TEXT NOT NULL
        )
        """
    )
    conn.execute(
        """
        INSERT INTO control_plane_schema_versions (component, version, updated_at)
        VALUES (?, ?, ?)
        ON CONFLICT(component) DO UPDATE SET
            version = excluded.version,
            updated_at = excluded.updated_at
        """,
        (component, int(version), _now_iso()),
    )


def ensure_postgres_schema_version(conn: Any, component: str, version: int = CONTROL_PLANE_SCHEMA_VERSION) -> None:
    """Record the current schema version for a Postgres control-plane component."""

    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS control_plane_schema_versions (
            component TEXT PRIMARY KEY,
            version INTEGER NOT NULL,
            updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
        )
        """
    )
    conn.execute(
        """
        INSERT INTO control_plane_schema_versions (component, version, updated_at)
        VALUES (%s, %s, now())
        ON CONFLICT (component) DO UPDATE SET
            version = EXCLUDED.version,
            updated_at = EXCLUDED.updated_at
        """,
        (component, int(version)),
    )


def describe_control_plane_storage_schema() -> dict[str, Any]:
    """Return a non-secret schema contract for operator and release checks."""

    components = [component.to_dict() for component in CONTROL_PLANE_SCHEMA_COMPONENTS]
    return {
        "schema_version": CONTROL_PLANE_SCHEMA_VERSION,
        "schema_table": CONTROL_PLANE_SCHEMA_TABLE,
        "components": components,
        "component_count": len(components),
        "upgrade_policy": "idempotent_bootstrap_migrations_with_explicit_component_versions",
        "operator_message": (
            "Each persistent control-plane backend should expose this schema table or an equivalent native "
            "version marker before rolling upgrades. Graph keeps its legacy graph_schema_version table and is "
            "also listed here for release-readiness checks."
        ),
    }
