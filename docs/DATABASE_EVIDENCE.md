# Database Evidence Connectors

agent-bom treats database and warehouse integrations as evidence sources, not
event streams. Connectors query customer-owned systems for inventory,
governance, access, and lineage evidence, then map that evidence into the
same findings and graph model used by local scans and runtime telemetry.

The concrete shipped warehouse governance lane is Snowflake. Other database and
warehouse sources should be described as connector-contract, fallback, or
roadmap paths unless the specific connector and fixtures are present in code.

## Connector Lanes

| Lane | Status | Default wheel | Use when | Credential boundary |
|---|---|---:|---|---|
| Native | Preferred | Mixed | A first-party or vendor-supported Python SDK exists for the source system. | Customer-managed service account, role, or token |
| ODBC fallback | Optional | No | Customer already operates DSNs or the source has no usable native SDK. | Customer-managed DSN and driver config |
| JDBC fallback | Optional | No | Customer standardizes on JDBC drivers or JVM-based warehouse access. | Customer-managed JDBC URL, driver, JVM, and secret store |

Native connectors remain the preferred path for security-sensitive posture
because they avoid host-level DSN/JVM packaging and usually expose richer
identity, grants, policy, and lineage APIs. ODBC and JDBC are fallback lanes
for SQL Server, Oracle, Teradata, and customer-managed environments where a
generic SQL path is the only viable evidence source.

## Evidence Contract

Database evidence connectors should collect:

- schemas, tables, and views
- grants, roles, and users
- classification tags and governance metadata
- external shares, stages, and public/shared objects
- lineage metadata where available

Connectors must be read-only by default. They should report the source system,
connector lane, target object, evidence kind, collection timestamp, tenant or
account boundary, and confidence. If a connector cannot distinguish inventory
from inferred governance metadata, mark the confidence lower and explain the
query source.

## Non-Goals

- ODBC/JDBC are not event streaming connectors. Posture-event streaming uses
  webhooks or runtime emitter plugins.
- Generic database evidence is not full DSPM by itself. Only call data
  sensitive when explicit tags, classifications, imported classifier evidence,
  or target-scoped dataset scan results support that label.
- ODBC/JDBC do not replace native Snowflake, Postgres/Supabase, Databricks,
  BigQuery, Redshift, or Athena paths where native APIs are available.
- The default wheel does not bundle ODBC drivers, JDBC drivers, a JVM, or
  customer DSN configuration.

The code-level contract lives in `src/agent_bom/database_evidence.py`.
