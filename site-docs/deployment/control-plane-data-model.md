# Control-Plane Data Model and Store Parity

This is the operator and auditor view of the `agent-bom` control-plane
data model.

It answers four questions directly:

1. Which logical entities are part of the control plane?
2. Which store or table backs each entity today?
3. Which backends are transactional control-plane stores versus
   analytics-only stores?
4. Which schema objects are created by bootstrap SQL versus lazily by
   the runtime?

Use this page together with [Backend Parity](backend-parity.md) and the
repo-root `docs/DATA_MODEL.md`.

## Canonical control-plane entities

The stable logical entities are:

- scan jobs
- fleet agents
- gateway policies
- gateway policy audit log
- source registry
- API keys and RBAC bindings
- exceptions
- schedules
- audit chain
- graph snapshots and attack paths
- trend/baseline history
- idempotency keys
- rate-limit state

Those names are the product contract. Table names vary by backend.

## Transactional vs analytics backends

Not every backend is meant to carry the same workload.

- `SQLite`: local and single-node transactional store
- `Postgres` / `Supabase`: default transactional control-plane store
- `ClickHouse`: analytics/event store, not a transactional control-plane
  replacement
- `Snowflake`: partial transactional control plane with explicit parity
  limits

The main operator rule is:

- if you need the broadest route and workflow coverage, use `Postgres`
- add `ClickHouse` only for analytics scale
- use `Snowflake` where the documented parity boundary is acceptable

## Entity-to-store matrix

| Logical entity | SQLite | Postgres / Supabase | ClickHouse | Snowflake |
|---|---|---|---|---|
| Scan jobs | `jobs` | `scan_jobs` | No | `scan_jobs` |
| Fleet agents | `fleet_agents` | `fleet_agents` | snapshot-only | `fleet_agents` |
| Gateway policies | `gateway_policies` | `gateway_policies` | No | `gateway_policies` |
| Gateway policy audit | `policy_audit_log` | `policy_audit_log` | No | `policy_audit_log` |
| Source registry | `sources` | `control_plane_sources` | No | No |
| API keys / RBAC | No default API wiring | `api_keys` | No | No |
| Exceptions | No default API wiring | `exceptions` | No | No |
| Schedules | `scan_schedules` | `scan_schedules` | No | `scan_schedules` |
| Audit chain | `audit_log` | `audit_log` | denormalized analytics copy only | No full transactional replacement |
| Graph / attack path | SQLite graph tables | Postgres graph tables | No | No |
| Trend / baseline | local control-plane tables | `trend_history` and related control-plane tables | analytics/event aggregation only | No |
| Idempotency | `idempotency_keys` | `idempotency_keys` | No | No |
| Rate-limit state | `api_rate_limits` | `api_rate_limits` | No | No shared runtime store |

## Important naming differences

These differences are intentional or historical, but operators should
not have to discover them by reading code.

### `jobs` vs `scan_jobs`

- SQLite uses `jobs`
- Postgres and Snowflake use `scan_jobs`

This is a backend table-name difference, not a product-model difference.
The logical entity remains "scan jobs."

### `sources` vs `control_plane_sources`

- SQLite uses `sources`
- Postgres uses `control_plane_sources`

This exists because the hosted/control-plane source registry was added
after the original local source store path. The logical entity remains
"source registry."

### Audit chain vs policy audit

These are separate mechanisms:

- `audit_log`: full control-plane HMAC-chained audit trail
- `policy_audit_log`: gateway policy mutation audit trail

`policy_audit_log` is not a replacement for the full audit chain.

## Bootstrap SQL vs runtime-created schema

Some schema objects exist in bootstrap SQL. Others are created lazily by
the runtime stores on first use.

### Bootstrap-first

These are primarily defined in the shipped Postgres bootstrap SQL under
`deploy/supabase/postgres/init.sql`:

- broad control-plane tables such as `scan_jobs`, `fleet_agents`,
  `api_keys`, `exceptions`, `audit_log`, graph tables, and
  `api_rate_limits`
- analytics and supporting indexes for the packaged self-hosted control
  plane

### Runtime-created or runtime-upgraded

These are created or upgraded by the runtime stores/middleware on first
use:

- SQLite `jobs`
- SQLite `sources`
- SQLite and Postgres `idempotency_keys`
- SQLite and Postgres `api_rate_limits` in the shared rate-limit path
- Postgres `gateway_policies`, `policy_audit_log`, `scan_schedules`,
  `control_plane_sources`
- Snowflake `scan_jobs`, `fleet_agents`, `scan_schedules`,
  `gateway_policies`, `policy_audit_log`

This is why "table exists in SQL" and "route is fully supported on this
backend" are different questions.

## Backend-specific operator notes

### SQLite

Use for:

- local development
- laptop or single-node control-plane deployments
- pilot paths where one file-backed store is acceptable

Caveats:

- broad enough for local control-plane work
- not the recommended answer for multi-operator transactional workloads
- table names differ from Postgres in a few places, especially `jobs`
  and `sources`

### Postgres / Supabase

Use for:

- the default control-plane deployment
- tenant-scoped transactional APIs
- API keys, schedules, exceptions, source registry, and graph

This is the current broadest parity backend.

### ClickHouse

Use for:

- high-volume runtime events
- trend and observability analytics
- OCSF / proxy / trace/event analytics paths

Do not treat it as a drop-in transactional control-plane backend. It is
analytics-only in the product contract.

### Snowflake

Use for:

- warehouse-native deployments
- fleet, scan jobs, gateway policies, and policy audit trails where
  Snowflake is the system of record

Current transactional parity boundary:

- supported: `scan_jobs`, `fleet_agents`, `scan_schedules`,
  `gateway_policies`, `policy_audit_log`
- not supported: source registry, API keys, exceptions,
  graph, trend/baseline, full audit-chain replacement

## Recommended selection

| Need | Recommended backend shape |
|---|---|
| Local or demo deployment | `SQLite` |
| Default self-hosted control plane | `Postgres` / `Supabase` |
| High analytics/event volume | `Postgres` + `ClickHouse` |
| Warehouse-native governance deployment | `Snowflake` with explicit parity limits |

## Related docs

- [Backend Parity](backend-parity.md)
- [Snowflake-Native Backend](snowflake-backend.md)
- [Postgres Provisioning Workflow](postgres-provisioning.md)
- [Packaged API + UI Control Plane](control-plane-helm.md)
- repo-root `docs/DATA_MODEL.md`
