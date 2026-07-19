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
  target-scoped dataset scan results, or opt-in object-store content-sampling
  evidence support that label.
- ODBC/JDBC do not replace native Snowflake, Postgres/Supabase, Databricks,
  BigQuery, Redshift, or Athena paths where native APIs are available.
- The default wheel does not bundle ODBC drivers, JDBC drivers, a JVM, or
  customer DSN configuration.

The code-level contract lives in `src/agent_bom/database_evidence.py`.

## DSPM database content classification (opt-in)

Beyond metadata evidence, agent-bom can sample a **bounded** number of rows from
a database and classify the data types they hold (PII, secrets, financial) into
redacted DSPM evidence — the database analog of the S3/GCS object-store content
sampling. Metadata-only discovery is never called content classification.

- **Opt-in.** Off by default. Enable with `AGENT_BOM_DSPM_DB_SAMPLING=1`. Caps:
  `AGENT_BOM_DSPM_DB_MAX_TABLES` (200), `AGENT_BOM_DSPM_DB_MAX_ROWS_PER_TABLE`
  (100), `AGENT_BOM_DSPM_DB_MAX_CELL_CHARS` (4096). See
  [ENV_VARS.md](operations/ENV_VARS.md).
- **Credential boundary — connect once, never per-action.** The scan resolves a
  stored, scoped, revocable `database` connection through the credential broker
  (`connection_broker.broker_session`), exactly like the cloud connections in
  [CLOUD_CONNECT.md](CLOUD_CONNECT.md). The single encrypted secret is the libpq
  connection string; the session is opened `default_transaction_read_only=on`,
  so only bounded `SELECT`s run and no row can be mutated. No credential is ever
  entered per-action, logged, or returned.
- **First command / flow.** Create a read-only `database` connection (provider
  `database`, `role_ref` a non-secret display DSN, `external_id` the connection
  string, `auth_params` carrying optional `schemas`/`include_tables` scope), then
  `POST /v1/cloud/connections/{id}/test` and
  `POST /v1/cloud/connections/{id}/scan`. With sampling enabled the scan runs
  `agent_bom.cloud.db_content_scan.scan_database_content` over the scoped tables.
- **Artifact — redacted evidence only.** Output is the
  `agent-bom.dspm.database_scan.v1` classification: data-type + count +
  location (`schema.table`). Raw rows, cell values, and matched values are
  **never** persisted, logged, or exported. The classification enriches the
  graph: a sampled database becomes a `DATA_STORE` crown jewel and an
  internet-exposed path to it becomes a toxic-combination finding.
- **Honest coverage states.** Every table is `executed`, `partial`, `skipped`,
  `unevaluable`, or `failed`. A denied / timed-out / unreadable table is
  `unevaluable` — never "clean". Absence of a finding from an unreadable source
  is not evidence of no sensitive data; the scan status downgrades to `partial`
  or `failed` accordingly.
- **Next step / deferred.** The Postgres/RDS wire path is live and covered by
  read-only PostgreSQL tests. The Azure Blob object-storage collector and the
  Snowflake/BigQuery warehouse sampling adapters remain credential-gated
  roadmap legs (tracked in #4157) — the row classifier and coverage envelope are
  DB-API-generic and ready for those adapters, but they are not wired until live
  warehouse/blob credentials are available.

The code-level contract lives in `src/agent_bom/cloud/db_content_scan.py`
(orchestration) and `src/agent_bom/cloud/db_data_classifier.py` (redacted
row classifier).
