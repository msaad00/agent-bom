# Backend Parity Matrix

`agent-bom` does not treat every backend as interchangeable.

The product contract is:

- `SQLite`: local and single-node persistence
- `Postgres` / `Supabase`: transactional control-plane default
- `ClickHouse`: analytics and time-series backend
- `Snowflake`: warehouse-native and governance-oriented backend where parity is explicitly implemented

This page documents what is wired today, not what might exist as a class on disk.

## Current API Backend Matrix

| Capability | SQLite | Postgres / Supabase | ClickHouse | Snowflake |
|---|---|---|---|---|
| Scan job persistence | Yes | Yes | No | Yes |
| Fleet agent persistence | Yes | Yes | No | Yes |
| Gateway policy persistence | Yes | Yes | No | Yes |
| Audit log persistence | Yes | Yes | No | Yes, via `SnowflakePolicyStore` |
| Exception workflow persistence | No default API wiring | Yes | No | No |
| API key persistence / RBAC store | No default API wiring | Yes | No | No |
| Schedule persistence | Yes | Yes | No | No |
| Trend / baseline persistence | Yes | Yes | No | No |
| Graph persistence | Yes | Yes | No | No |
| Analytics / OLAP writes | No | No | Yes | No |
| Snowflake governance discovery routes | No | No | No | Yes |

## What This Means

If you need the broadest control-plane coverage today, use `Postgres` or `Supabase`.

If you need local persistence, use `SQLite`.

If you need high-volume analytics or time-series aggregation, add `ClickHouse`.

If you need warehouse-native deployment or governance workflows in Snowflake, use `Snowflake` where the parity boundary is acceptable and explicit.

## Supported Deployment Modes

### 1. Postgres control plane with optional ClickHouse analytics

This is the default enterprise deployment mode.

Use when you want:

- full transactional API coverage
- tenant-scoped keys and exceptions
- schedule persistence
- graph persistence
- trend and baseline history

Typical layout:

- `Postgres` / `Supabase` for control plane
- optional `ClickHouse` for analytics
- optional `Snowflake` governance discovery for account-level visibility

### 2. Snowflake partial control plane

This is supported, but intentionally partial.

Use when you want:

- Snowflake-hosted `scan_jobs`
- Snowflake-hosted fleet inventory
- Snowflake-hosted gateway policies and policy audit trail

Current limitations:

- schedules do not persist to Snowflake
- graph persistence does not persist to Snowflake
- exceptions do not persist to Snowflake
- API keys do not persist to Snowflake
- baseline/trend storage does not persist to Snowflake

That makes Snowflake viable for selected control-plane paths, but not yet a full transactional replacement for Postgres.

### 3. Warehouse-native governance mode

Use when the primary goal is:

- Snowflake governance discovery
- activity and observability routes backed by Snowflake account data
- Snowflake Native App or Snowpark-adjacent operator workflows

This mode is compatible with:

- local CLI scans
- API/UI deployments
- hybrid control planes where the warehouse is the authoritative governance data source

## Recommended Selection

| Need | Recommended backend |
|---|---|
| Laptop, demo, single-node | `SQLite` |
| Team / enterprise API deployment | `Postgres` / `Supabase` |
| Large analytics or trend workloads | `ClickHouse` alongside Postgres |
| Snowflake-native governance and warehouse workflows | `Snowflake`, with explicit parity limits |

## Related Docs

- [Deployment Overview](overview.md)
- [SIEM Integration](siem-integration.md)
- [Canonical Model vs OCSF](../architecture/canonical-vs-ocsf.md)
- `docs/ENTERPRISE.md`
- `docs/ENTERPRISE_DEPLOYMENT.md`
