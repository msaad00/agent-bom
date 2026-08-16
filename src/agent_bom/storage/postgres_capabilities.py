"""Provider-neutral PostgreSQL portability posture and live diagnostics.

The control plane intentionally targets the PostgreSQL protocol and catalog
contract instead of inferring capabilities from a hostname.  Provider hints
are declarative and never upgrade compatibility into certification; the live
probe reports only bounded, non-identifying facts needed to operate safely.
"""

from __future__ import annotations

import os
import re
from dataclasses import asdict, dataclass, field
from typing import Any

_SCHEMA_VERSION = "postgres-portability.v1"
_DATABASE_UNAVAILABLE_ACTION = "verify the Postgres secret, network policy, and TLS settings; then rerun agent-bom doctor"

_PROVIDER_ALIASES = {
    "postgres": "postgres",
    "postgresql": "postgres",
    "community": "postgres",
    "community_postgres": "postgres",
    "aws": "aws_rds",
    "aws_rds": "aws_rds",
    "rds": "aws_rds",
    "aurora": "aurora",
    "aurora_postgres": "aurora",
    "gcp": "cloud_sql",
    "cloud_sql": "cloud_sql",
    "cloudsql": "cloud_sql",
    "azure": "azure_postgres",
    "azure_postgres": "azure_postgres",
    "supabase": "supabase",
    "crunchy": "crunchy",
    "crunchy_bridge": "crunchy",
    "edb": "edb",
    "enterprisedb": "edb",
    "snowflake_pg": "snowflake_postgres",
    "snowflake_postgres": "snowflake_postgres",
    "clickhouse": "clickhouse_postgres",
    "clickhouse_pg": "clickhouse_postgres",
    "clickhouse_postgres": "clickhouse_postgres",
}


def _safe_declared_hint(raw: str) -> str:
    return re.sub(r"[^a-z0-9._-]+", "_", raw.strip().lower()).strip("_")[:64]


def _normalized_hint(raw: str) -> str:
    normalized = re.sub(r"[^a-z0-9]+", "_", raw.strip().lower()).strip("_")
    return normalized[:64]


@dataclass(frozen=True)
class PostgresProviderPosture:
    provider: str
    declared_hint: str
    contract: str = "postgresql"
    evidence: str = "provider_unverified"
    next_action: str | None = "agent-bom doctor"

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True)
class PostgresPortabilityProbe:
    status: str
    provider: str
    contract: str
    evidence: str
    server_version: str | None = None
    server_version_num: int | None = None
    tls: bool | None = None
    runtime_role_rls_safe: bool | None = None
    alembic_schema_present: bool | None = None
    control_plane_schema_present: bool | None = None
    maintenance_role_configured: bool = False
    reasons: tuple[str, ...] = field(default_factory=tuple)
    next_action: str | None = None
    schema_version: str = _SCHEMA_VERSION

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "status": self.status,
            "provider": self.provider,
            "contract": self.contract,
            "evidence": self.evidence,
            "server_version": self.server_version,
            "server_version_num": self.server_version_num,
            "tls": self.tls,
            "runtime_role_rls_safe": self.runtime_role_rls_safe,
            "alembic_schema_present": self.alembic_schema_present,
            "control_plane_schema_present": self.control_plane_schema_present,
            "maintenance_role_configured": self.maintenance_role_configured,
            "reasons": list(self.reasons),
            "next_action": self.next_action,
        }


def declared_postgres_portability() -> PostgresProviderPosture:
    """Return the operator-declared provider posture without DSN inference."""
    raw_hint = os.environ.get("AGENT_BOM_POSTGRES_PROVIDER", "auto")
    hint = _normalized_hint(raw_hint) or "auto"
    declared_hint = _safe_declared_hint(raw_hint) or "auto"
    if hint in {"auto", "unspecified"}:
        return PostgresProviderPosture(provider="unspecified_postgres", declared_hint=declared_hint)

    provider = _PROVIDER_ALIASES.get(hint)
    if provider is None:
        return PostgresProviderPosture(provider="other", declared_hint=declared_hint)
    if provider == "postgres":
        return PostgresProviderPosture(
            provider=provider,
            declared_hint=hint,
            evidence="controlled_verified",
        )
    return PostgresProviderPosture(
        provider=provider,
        declared_hint=hint,
        evidence="compatible_unverified",
    )


def _next_action(reasons: list[str]) -> str | None:
    if not reasons:
        return None
    actions: list[str] = []
    if "runtime_role_bypasses_rls" in reasons:
        actions.append("use a NOSUPERUSER NOBYPASSRLS runtime role")
    if "alembic_schema_missing" in reasons or "control_plane_schema_missing" in reasons:
        actions.append("run the Postgres migration preflight and Alembic upgrade")
    if "maintenance_role_not_configured" in reasons:
        actions.append("configure AGENT_BOM_POSTGRES_MAINTENANCE_URL for multi-replica maintenance")
    if "tls_not_active" in reasons:
        actions.append("require TLS for the production Postgres connection")
    return "; ".join(actions) + "; then rerun agent-bom doctor"


def probe_postgres_portability(*, pool: Any | None = None) -> PostgresPortabilityProbe:
    """Probe the portable Postgres contract without returning connection identity."""
    posture = declared_postgres_portability()
    maintenance_configured = bool(os.environ.get("AGENT_BOM_POSTGRES_MAINTENANCE_URL", "").strip())
    try:
        if pool is None:
            from agent_bom.api.postgres_common import _get_pool

            pool = _get_pool()
        with pool.connection() as conn:
            row = conn.execute(
                """
                SELECT
                    current_setting('server_version'),
                    current_setting('server_version_num')::INTEGER,
                    COALESCE((SELECT ssl FROM pg_stat_ssl WHERE pid = pg_backend_pid()), FALSE),
                    role.rolsuper,
                    role.rolbypassrls,
                    to_regclass('public.alembic_version') IS NOT NULL,
                    to_regclass('public.control_plane_schema_versions') IS NOT NULL
                FROM pg_roles AS role
                WHERE role.rolname = current_user
                """
            ).fetchone()
        if row is None:
            raise RuntimeError("Postgres role probe returned no row")

        server_version, version_num, tls, role_super, role_bypass_rls, alembic_present, schema_present = row
        role_safe = not bool(role_super) and not bool(role_bypass_rls)
        reasons: list[str] = []
        if not role_safe:
            reasons.append("runtime_role_bypasses_rls")
        if not bool(alembic_present):
            reasons.append("alembic_schema_missing")
        if not bool(schema_present):
            reasons.append("control_plane_schema_missing")
        if not maintenance_configured:
            reasons.append("maintenance_role_not_configured")
        if not bool(tls):
            reasons.append("tls_not_active")

        return PostgresPortabilityProbe(
            status="ready" if not reasons else "degraded",
            provider=posture.provider,
            contract=posture.contract,
            evidence=posture.evidence,
            server_version=str(server_version),
            server_version_num=int(version_num),
            tls=bool(tls),
            runtime_role_rls_safe=role_safe,
            alembic_schema_present=bool(alembic_present),
            control_plane_schema_present=bool(schema_present),
            maintenance_role_configured=maintenance_configured,
            reasons=tuple(reasons),
            next_action=_next_action(reasons),
        )
    except Exception:
        return PostgresPortabilityProbe(
            status="unavailable",
            provider=posture.provider,
            contract=posture.contract,
            evidence=posture.evidence,
            maintenance_role_configured=maintenance_configured,
            reasons=("database_unavailable",),
            next_action=_DATABASE_UNAVAILABLE_ACTION,
        )


__all__ = [
    "PostgresPortabilityProbe",
    "PostgresProviderPosture",
    "declared_postgres_portability",
    "probe_postgres_portability",
]
