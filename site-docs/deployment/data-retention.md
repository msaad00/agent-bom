# Data Retention by Class

> **You do not need to read this unless** you are tuning retention for a
> compliance or cost target — or trying to decide whether to add ClickHouse
> / S3 alongside the Postgres control plane. Default deployments work
> without changing retention settings.

`agent-bom` should not feel like "whatever the backend keeps." Retention is a
product contract.

The design principle is:

- keep the transactional control plane lean
- persist the security evidence you actually need
- push event-scale history into optional analytics or archive tiers when you
  want longer retention

This page defines the recommended retention model for a self-hosted deployment.

## Retention classes

| Data class | What it includes | Primary store | Recommended retention | Why |
|---|---|---|---|---|
| Control-plane state | tenants, policies, schedules, API keys, source registry, fleet state, graph state | `Postgres` / `Supabase` | keep current state + short operational history | transactional truth, not a data lake |
| Scan jobs and results | submitted scans, summaries, attached result payloads | `Postgres` / `Supabase` | 14-90 days in the control plane | enough for operator review without turning the API DB into an archive |
| Runtime operational evidence | proxy audit ingest, traces, OCSF ingest, gateway activity | `Postgres` for recent operational views, optional `ClickHouse` for longer history | 7-30 days in control plane, 30-365+ days in analytics | recent ops stay fast; history moves to analytics |
| Compliance evidence | signed evidence bundles, exported reports, review packets | `S3` or customer archive store | match framework policy | this is evidence, not dashboard cache |
| Security-lake / warehouse mirrors | analytics projections, governance joins, long-range history | `ClickHouse`, `Snowflake`, future `Databricks` target | customer-defined | lake and warehouse retention should be explicit and owned by the operator |

## Product rule

The control plane should stay good at:

- answering "what is true right now?"
- supporting operator workflows
- serving recent scans, findings, fleet state, and runtime posture

It should not silently become:

- a multi-year event archive
- a warehouse substitute
- a compliance evidence bucket

That is why the recommended shape is:

- `Postgres` = transactional truth
- `ClickHouse` / `Snowflake` = analytics and governance tier
- `S3` = archive and evidence

## Recommended defaults

These are operator defaults, not enforced hard limits.

| Deployment shape | Scan job retention in control plane | Runtime evidence retention in control plane | Analytics/archive recommendation |
|---|---|---|---|
| Local / small team | 14-30 days | 7-14 days | no extra tier unless you need it |
| Enterprise pilot | 30-60 days | 14-30 days | add `ClickHouse` if runtime history matters |
| Broader rollout | 30-90 days | 7-30 days | move retained event history to `ClickHouse`, `Snowflake`, or archive |

## What stays in Postgres

Keep these in `Postgres` or `Supabase` even if you add a lake:

- tenant-scoped policy and auth state
- schedules and active job coordination
- fleet and source registry state
- graph and remediation workflow state
- recent operational views that need fast transactional reads

This keeps the control plane predictable and fast.

## What should move out of Postgres first

If retention pressure or query drag increases, move these first:

- long-range proxy and gateway audit history
- traces and event-heavy ingest
- trend and historical analytics reads
- exported evidence packets and old signed bundles

## Operator-visible retention

The product should be clear about retention in three places:

1. docs
2. deployment values and env settings
3. UI/runtime status surfaces

If a tenant asks "how long do we keep this?", the answer should not require
opening the database.

## Tenant data export and deletion

Self-hosted operators can inspect and remove tenant-scoped control-plane data
through the admin-only data subject endpoint:

```bash
curl -H "Authorization: Bearer $AGENT_BOM_API_KEY" \
  "https://agent-bom.example.com/v1/tenant/$TENANT_ID/data"

curl -X DELETE -H "Authorization: Bearer $AGENT_BOM_API_KEY" \
  "https://agent-bom.example.com/v1/tenant/$TENANT_ID/data?dry_run=true"

curl -X DELETE -H "Authorization: Bearer $AGENT_BOM_API_KEY" \
  "https://agent-bom.example.com/v1/tenant/$TENANT_ID/data?dry_run=false&confirm_tenant_id=$TENANT_ID"
```

The endpoint is intentionally conservative:

- only `admin` role callers can use it
- scoped keys must carry `privacy.data:read` or `privacy.data:delete`
- the path tenant must match the authenticated tenant context
- destructive deletes default to `dry_run=true`
- `dry_run=false` requires `confirm_tenant_id` to exactly match the path tenant
- source registry exports redact credential references and connector config

Delete removes tenant-scoped jobs, fleet records, gateway policies, scan
schedules, source records, exceptions, quota overrides, and graph rows. Audit
logs and policy audit entries are retained as immutable security evidence so
the HMAC chain and compliance history remain verifiable. API keys are managed
through the API-key lifecycle endpoints rather than silently removed by tenant
data deletion.

## EKS guidance

For the self-hosted EKS shape, the practical answer is:

- keep the packaged control plane on `Postgres`
- use `ClickHouse` only if retained runtime or trend analytics becomes heavy
- archive signed evidence bundles and longer-lived exports to `S3`
- mirror to `Snowflake` when governance or warehouse-native joins matter

That gives you:

- fast operator workflows
- explicit retention boundaries
- predictable storage cost
- less pressure on the API database

## Why this matters for trust

Operators care about three things here:

- how long sensitive telemetry lives in the control plane
- where evidence goes for audits
- whether long history forces them into an opaque hosted backend

The product answer should stay:

- self-hosted first
- explicit retention by data class
- customer-controlled analytics and archive tiers

## Related docs

- [Performance, Sizing, and Benchmarks](performance-and-sizing.md)
- [Backend Parity](backend-parity.md)
- [Snowflake-Native Backend](snowflake-backend.md)
- [AWS Company Rollout](aws-company-rollout.md)
