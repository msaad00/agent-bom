# Backend and Security-Lake Strategy

> **You do not need to read this unless** you are reasoning about how
> Postgres, ClickHouse, Snowflake, object storage, Iceberg, and Databricks fit
> together as a tiered store strategy. For the per-API capability
> matrix use [Backend Parity](backend-parity.md).

`agent-bom` is one product, but not every backend does the same job.

The backend strategy should stay simple:

- `Postgres` is the transactional control-plane default
- `ClickHouse` is the analytics scale-out tier
- `Snowflake` is the warehouse-native governance and selected backend option
- object storage is the archive and evidence tier
- `Parquet` + Apache Iceberg provide the open evidence-table boundary
- `Databricks` is a scheduled findings-export destination, not a control-plane store

This page explains how those stores fit together in a self-hosted deployment.

### Hosting model per tier

The self-hosted story does not depend on a managed cloud warehouse. `Postgres`
and `ClickHouse` both ship open-source servers you can run inside your own VPC,
Kubernetes cluster, or bare metal — the `deploy/` compose and Helm paths target
exactly these OSS builds. `ClickHouse` also offers a managed **ClickHouse Cloud**
service; that hosted option is optional — many deployments run the OSS server
self-hosted. `Snowflake` is warehouse SaaS only — choose it when
warehouse-native governance is the goal, not as a prerequisite for analytics
scale-out. A typical fully self-hostable stack is `Postgres` + OSS `ClickHouse`
+ optional `S3`-compatible object storage.

## The product contract

`agent-bom` should not require operators to choose between:

- "good product semantics"
- "warehouse compatibility"

The right contract is:

- one canonical control-plane model
- multiple storage targets behind it
- explicit parity boundaries

That means:

- findings, fleet state, policies, MCP inventory, runtime evidence, and graph
  concepts should stay the same
- storage choice changes scale, retention, and integration posture
- storage choice should not silently rewrite the product model

## Recommended roles by backend

| Backend | Role | Use it for | Do not treat it as |
|---|---|---|---|
| `SQLite` | local persistence | laptop demos, local review, single-node testing | enterprise control plane |
| `Postgres` / `Supabase` | transactional control plane | auth, policy, fleet, schedules, graph, recent scan state | long-range event lake |
| `ClickHouse` | event and analytics tier | runtime history, trend queries, retained audit analytics | transactional API store |
| `Snowflake` | warehouse-native governance and selected backend paths | governance joins, selected enterprise store paths, warehouse-centric orgs | universal parity until documented |
| Object storage | archive and evidence tier | signed evidence bundles, backups, export archives | interactive operator query plane |
| Parquet / Apache Iceberg | open evidence-table tier | portable finding snapshots, schema evolution, multi-engine catalog access | transactional control-plane state |
| `Databricks` | lakehouse export destination | scheduled tenant-scoped findings feeds | control-plane backend parity |

## Recommended deployment shapes

### 1. Default self-hosted control plane

- `Postgres`
- optional `S3`

Use when you want:

- the simplest reliable control-plane deployment
- broadest route coverage
- fast pilot-to-production path

### 2. Enterprise control plane with analytics scale-out

- `Postgres`
- `ClickHouse`
- optional `S3`

Use when you want:

- longer runtime history
- analytics-heavy dashboards
- retained trend queries without overloading `Postgres`

### 3. Warehouse-native governance deployment

- `Postgres` or selected `Snowflake` backend paths
- `Snowflake`
- optional `S3`

Use when:

- the customer already governs security data in `Snowflake`
- they want warehouse-native joins and governance workflows
- the documented Snowflake parity boundary is acceptable

This should be read as a supported security-lake and governance mode, not as a
claim that every transactional control-plane surface has already reached
Snowflake parity.

### 4. Open security-lake export

- control plane on `Postgres`
- Parquet artifacts or Apache Iceberg REST-catalog snapshots
- optional scheduled delivery to object stores, `Databricks`, `Snowflake`,
  `ClickHouse`, or `BigQuery`

Install `agent-bom[lake]`, then create a Parquet artifact and optionally publish
the same additively versioned finding schema to an Iceberg REST catalog:

```bash
agent-bom scan . --format parquet --output findings.parquet \
  --iceberg-catalog-url https://catalog.example.com
```

The Parquet file is written first. Once a catalog URL is configured, Iceberg is
a required requested artifact: catalog publication failure returns non-zero and
leaves the Parquet file available for retry. Catalog credentials remain in
`AGENT_BOM_ICEBERG_CREDENTIAL` or `AGENT_BOM_ICEBERG_TOKEN`; they are never CLI
arguments or output fields.

### Apache Polaris authentication

For Polaris, set the warehouse to the catalog name and activate the principal's
assigned roles with an explicit OAuth scope. Supply the credential through the
existing secret environment variable:

```bash
export AGENT_BOM_ICEBERG_CATALOG_URL="https://polaris.example/api/catalog"
export AGENT_BOM_ICEBERG_WAREHOUSE="security_evidence"
export AGENT_BOM_ICEBERG_SCOPE="PRINCIPAL_ROLE:ALL"
export AGENT_BOM_ICEBERG_OAUTH2_SERVER_URI="https://polaris.example/api/catalog/v1/oauth/tokens"
agent-bom scan . --format parquet --output findings.parquet
```

The principal needs permission to create the namespace/table, write table data,
and commit snapshots. Authentication alone does not grant catalog or storage
access. Scope and token-endpoint settings are optional for other REST catalogs;
no Polaris-specific scope is imposed by default. A pre-issued bearer token can
still be supplied through `AGENT_BOM_ICEBERG_TOKEN`.

See the [Polaris PyIceberg connection guide](https://polaris.apache.org/releases/1.7.0/getting-started/using-polaris/)
for role assignment and catalog storage configuration. After export, load the
configured `agent_bom.findings` table with an Iceberg client and inspect its
current snapshot and rows. Hosted catalog and cloud-storage permissions must be
verified in the target environment.

### Lake schema evolution

Parquet schema version 5 appends nullable `sla_due_at_source` after the original
40 columns, retaining their names and types. Read the
`agent_bom.parquet_schema_version` metadata and select columns by name.
Version 0.104.0 emitted that extra field inside the version-4 column block;
its positional layout must not be assumed to match the earlier 40-column v4
layout. Iceberg evolution matches names and retains existing field IDs, so
existing catalog tables keep their original column identity and row values.
The new field is nullable for older snapshots; it does not infer SLA provenance.

## Snowflake and Databricks

Both are valid security-lake destinations in real customer environments.

The product posture should be:

- `Snowflake` is part of the current interoperable backend story where parity is
  already documented and implemented
- `Databricks` is a shipped scheduled-export destination; live provider
  acceptance remains separate from its mocked adapter contracts
- Apache Iceberg is the open table boundary when a customer wants the same
  finding snapshots queryable across compatible engines

The operator rule stays simple:

- default to `Postgres` for the control plane
- add `ClickHouse` for event-scale analytics
- choose `Snowflake` when warehouse-native governance or selected store parity
  is the actual goal
- choose Parquet/Iceberg when portable, engine-neutral evidence is the goal

That keeps the story accurate without understating how customers actually run
security lakes.

## What this means in EKS

For a self-hosted AWS/EKS deployment, the clean shape is:

- `agent-bom-api`
- `agent-bom-ui`
- scan and discovery workers
- `agent-bom-gateway`
- selected endpoint proxy rollout and sidecars
- `Postgres` as the control-plane store
- optional `ClickHouse`
- optional `S3`
- optional Apache Iceberg REST catalog
- optional `Snowflake` integration

That lets the product stay:

- self-hosted
- operator-controlled
- easy to reason about
- easy to extend with analytics or archive tiers

## Why not put everything in one backend

Because the system has different workload types:

- transactional control-plane state
- event-scale analytics
- signed evidence and export archive
- warehouse-native governance joins

Trying to force one backend to do all of them creates drift or overclaiming.

The healthier product stance is:

- one model
- several storage roles
- explicit parity boundaries

## CLI, UI, API, and MCP surface alignment

This backend strategy should not create different products.

The same semantics should hold across:

- CLI
- UI/API control plane
- MCP server mode
- Docker and Helm
- CI/CD scan workflows

What changes is where data is stored and how long it is retained, not what the
finding, inventory object, or runtime event means.

## Related docs

- [Data Retention by Class](data-retention.md)
- [Backend Parity](backend-parity.md)
- [Snowflake-Native Backend](snowflake-backend.md)
- [How agent-bom Works](../architecture/how-agent-bom-works.md)
