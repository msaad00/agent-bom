"""Control-plane storage schema manifest and version helpers."""

from __future__ import annotations

import os
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

CONTROL_PLANE_SCHEMA_VERSION = 1
CONTROL_PLANE_SCHEMA_TABLE = "control_plane_schema_versions"


def postgres_deployment_configured() -> bool:
    """Return whether either supported environment variable selects Postgres."""

    if os.environ.get("AGENT_BOM_POSTGRES_URL", "").strip():
        return True
    return os.environ.get("AGENT_BOM_DB", "").strip().lower().startswith(("postgres://", "postgresql://"))


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
    StorageSchemaComponent("llm_costs", "sqlite/postgres", ("llm_costs", "llm_cost_budgets")),
    StorageSchemaComponent("cloud_connections", "sqlite/postgres", ("cloud_connections",)),
    StorageSchemaComponent("compliance_hub", "sqlite/postgres", ("compliance_hub_findings", "hub_findings_current")),
    StorageSchemaComponent("access_review_campaigns", "sqlite/postgres", ("access_review_campaigns", "access_review_items")),
    StorageSchemaComponent("risk_campaign_workflows", "sqlite/postgres", ("risk_campaign_workflows",)),
    StorageSchemaComponent("fleet", "sqlite/postgres/clickhouse", ("fleet_agents",)),
    StorageSchemaComponent("graph", "sqlite/postgres", ("graph_nodes", "graph_edges", "graph_node_search")),
    StorageSchemaComponent("identity_scim", "sqlite/postgres", ("scim_users", "scim_groups")),
    # Agent-identity lifecycle is durable by default (SQLite single-node) and
    # upgrades to shared Postgres (tenant RLS) for multi-replica deployments;
    # in-memory is an explicit AGENT_BOM_EPHEMERAL_STORE opt-out.
    StorageSchemaComponent(
        "agent_identities",
        "sqlite/postgres",
        ("agent_identities", "agent_identity_jit_grants", "agent_conditional_access_policies"),
    ),
    # Runtime session/observation timeline is durable by default (same tiering).
    StorageSchemaComponent("runtime_events", "sqlite/postgres", ("runtime_observations", "runtime_sessions")),
    StorageSchemaComponent("tenant_quotas", "sqlite/postgres", ("tenant_quota_overrides",)),
    StorageSchemaComponent("tenant_graph_retention", "sqlite/postgres", ("tenant_graph_retention_overrides",)),
    StorageSchemaComponent("sources", "sqlite/postgres", ("sources", "control_plane_sources")),
    StorageSchemaComponent("schedules", "sqlite/postgres", ("scan_schedules",)),
    StorageSchemaComponent("exceptions", "sqlite/postgres", ("vuln_exceptions",)),
    StorageSchemaComponent("idempotency", "sqlite/postgres", ("idempotency_keys",)),
    StorageSchemaComponent("mcp_observations", "sqlite", ("mcp_observations",)),
    StorageSchemaComponent("proxy_replay_log", "sqlite/postgres", ("proxy_replay_log",)),
    StorageSchemaComponent("scan_cache", "sqlite/postgres", ("osv_cache",), tenant_scoped=False),
    StorageSchemaComponent("rate_limits", "postgres", ("api_rate_limit_hits",), tenant_scoped=False),
    StorageSchemaComponent("shared_auth_state", "postgres", ("auth_session_attempts", "revoked_session_nonces"), tenant_scoped=False),
    StorageSchemaComponent("governance_audit_log", "sqlite/postgres", ("governance_audit_log",)),
    StorageSchemaComponent("credential_refs", "sqlite/postgres", ("credential_refs",)),
    StorageSchemaComponent("ai_system_blueprints", "sqlite/postgres", ("ai_system_blueprints", "ai_system_blueprint_versions")),
    StorageSchemaComponent("mcp_client_configs", "sqlite/postgres", ("mcp_client_configs",)),
    StorageSchemaComponent("model_provider_keys", "sqlite/postgres", ("model_provider_keys", "model_virtual_keys")),
    StorageSchemaComponent("tenant_score_config", "sqlite/postgres", ("tenant_score_config_overrides",)),
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


def ensure_postgres_schema_version(conn: Any, component: str, version: int = CONTROL_PLANE_SCHEMA_VERSION) -> bool:
    """Bootstrap an isolated store or validate a migrated Postgres deployment.

    A configured deployment URL means Alembic owns every schema mutation and
    runtime stores are limited to a read-only version check.  Unit tests and
    explicitly constructed development pools without a deployment URL retain
    the historical idempotent bootstrap path.

    Returns ``True`` only when the caller should continue its bootstrap DDL.
    """

    if postgres_deployment_configured():
        row = conn.execute(
            "SELECT version FROM control_plane_schema_versions WHERE component = %s",
            (component,),
        ).fetchone()
        if row is None:
            raise RuntimeError(
                f"Postgres schema component {component!r} is not migrated; run Alembic before starting agent-bom."
            )
        current = int(row[0])
        if current < int(version):
            raise RuntimeError(
                f"Postgres schema component {component!r} is version {current}; version {int(version)} is required."
            )
        return False

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
    return True


def describe_control_plane_storage_schema() -> dict[str, Any]:
    """Return a non-secret schema contract for operator and release checks."""

    components = [component.to_dict() for component in CONTROL_PLANE_SCHEMA_COMPONENTS]
    return {
        "schema_version": CONTROL_PLANE_SCHEMA_VERSION,
        "schema_table": CONTROL_PLANE_SCHEMA_TABLE,
        "components": components,
        "component_count": len(components),
        "upgrade_policy": "alembic_authoritative_with_read_only_runtime_validation",
        "operator_message": (
            "Each persistent control-plane backend should expose this schema table or an equivalent native "
            "version marker before rolling upgrades. Graph keeps its legacy graph_schema_version table and is "
            "also listed here for release-readiness checks."
        ),
    }
