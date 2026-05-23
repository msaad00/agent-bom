"""Database and warehouse evidence connector lane definitions.

The default product lane prefers native, API-shaped connectors for posture
evidence. ODBC/JDBC remain optional enterprise fallback lanes for environments
where native drivers are unavailable or where customers already manage DSNs.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class DatabaseConnectorLane(str, Enum):
    """Supported database evidence connector lanes."""

    NATIVE = "native"
    ODBC = "odbc"
    JDBC = "jdbc"


class DatabaseEvidenceKind(str, Enum):
    """Evidence categories that database and warehouse connectors collect."""

    SCHEMA = "schema"
    TABLE = "table"
    VIEW = "view"
    GRANT = "grant"
    ROLE = "role"
    USER = "user"
    CLASSIFICATION_TAG = "classification_tag"
    GOVERNANCE_METADATA = "governance_metadata"
    EXTERNAL_SHARE = "external_share"
    EXTERNAL_STAGE = "external_stage"
    LINEAGE = "lineage"


@dataclass(frozen=True)
class DatabaseEvidenceConnector:
    """Contract metadata for a database evidence source."""

    name: str
    lane: DatabaseConnectorLane
    target_systems: tuple[str, ...]
    evidence_kinds: tuple[DatabaseEvidenceKind, ...]
    default_wheel: bool
    preferred: bool
    packaging_notes: str
    credential_boundary: str = "customer_managed"
    writes: bool = False


CORE_DATABASE_EVIDENCE: tuple[DatabaseEvidenceKind, ...] = (
    DatabaseEvidenceKind.SCHEMA,
    DatabaseEvidenceKind.TABLE,
    DatabaseEvidenceKind.VIEW,
    DatabaseEvidenceKind.GRANT,
    DatabaseEvidenceKind.ROLE,
    DatabaseEvidenceKind.USER,
    DatabaseEvidenceKind.CLASSIFICATION_TAG,
    DatabaseEvidenceKind.GOVERNANCE_METADATA,
    DatabaseEvidenceKind.EXTERNAL_SHARE,
    DatabaseEvidenceKind.EXTERNAL_STAGE,
    DatabaseEvidenceKind.LINEAGE,
)


DATABASE_EVIDENCE_CONNECTORS: tuple[DatabaseEvidenceConnector, ...] = (
    DatabaseEvidenceConnector(
        name="postgres-native",
        lane=DatabaseConnectorLane.NATIVE,
        target_systems=("postgres", "supabase"),
        evidence_kinds=CORE_DATABASE_EVIDENCE,
        default_wheel=True,
        preferred=True,
        packaging_notes="Native psycopg/Postgres paths are the preferred posture source for Postgres-compatible stores.",
    ),
    DatabaseEvidenceConnector(
        name="snowflake-native",
        lane=DatabaseConnectorLane.NATIVE,
        target_systems=("snowflake",),
        evidence_kinds=CORE_DATABASE_EVIDENCE,
        default_wheel=False,
        preferred=True,
        packaging_notes="Use the Snowflake connector or Native App path before any generic ODBC/JDBC lane.",
    ),
    DatabaseEvidenceConnector(
        name="databricks-native",
        lane=DatabaseConnectorLane.NATIVE,
        target_systems=("databricks",),
        evidence_kinds=CORE_DATABASE_EVIDENCE,
        default_wheel=False,
        preferred=True,
        packaging_notes="Use Databricks SQL/SDK inventory paths for workspace-governed posture evidence.",
    ),
    DatabaseEvidenceConnector(
        name="odbc-fallback",
        lane=DatabaseConnectorLane.ODBC,
        target_systems=("sqlserver", "oracle", "teradata", "customer-dsn"),
        evidence_kinds=CORE_DATABASE_EVIDENCE,
        default_wheel=False,
        preferred=False,
        packaging_notes="Optional extra only; DSN and native driver setup stay customer-owned.",
    ),
    DatabaseEvidenceConnector(
        name="jdbc-fallback",
        lane=DatabaseConnectorLane.JDBC,
        target_systems=("sqlserver", "oracle", "teradata", "customer-jdbc-url"),
        evidence_kinds=CORE_DATABASE_EVIDENCE,
        default_wheel=False,
        preferred=False,
        packaging_notes="Optional extra only; JVM and JDBC driver packaging stay outside the default wheel.",
    ),
)


def list_database_evidence_connectors() -> list[dict[str, object]]:
    """Return the public database evidence connector lane contract."""

    return [
        {
            "name": connector.name,
            "lane": connector.lane.value,
            "target_systems": list(connector.target_systems),
            "evidence_kinds": [kind.value for kind in connector.evidence_kinds],
            "default_wheel": connector.default_wheel,
            "preferred": connector.preferred,
            "packaging_notes": connector.packaging_notes,
            "credential_boundary": connector.credential_boundary,
            "writes": connector.writes,
        }
        for connector in DATABASE_EVIDENCE_CONNECTORS
    ]


def fallback_database_evidence_connectors() -> list[DatabaseEvidenceConnector]:
    """Return optional ODBC/JDBC fallback connectors, excluding native lanes."""

    return [
        connector
        for connector in DATABASE_EVIDENCE_CONNECTORS
        if connector.lane in {DatabaseConnectorLane.ODBC, DatabaseConnectorLane.JDBC}
    ]
