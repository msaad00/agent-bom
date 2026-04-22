# Backend and Security-Lake Strategy

`agent-bom` is one product, but not every backend does the same job.

The backend strategy should stay simple:

- `Postgres` is the transactional control-plane default
- `ClickHouse` is the analytics scale-out tier
- `Snowflake` is the warehouse-native governance and selected backend option
- `S3` is the archive and evidence tier
- `Databricks` is a future target only when code-backed

This page explains how those stores fit together in a self-hosted deployment.

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
| `S3` | archive and evidence tier | signed evidence bundles, backups, export archives | interactive operator query plane |
| `Databricks` | future security-lake target | lakehouse export target when implemented | current shipped parity |

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

### 4. Future lakehouse export target

- control plane on `Postgres`
- exports or mirrored datasets to `Databricks`

This should stay roadmap wording until code-backed. Do not market it as shipped
parity before the implementation exists.

## Snowflake and Databricks

Both are valid security-lake destinations in real customer environments.

The product posture should be:

- `Snowflake` is part of the current interoperable backend story where parity is
  already documented and implemented
- `Databricks` is a supported direction for lakehouse export and governance once
  the implementation exists

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
- [How Agent-BOM Works](../architecture/how-agent-bom-works.md)
