# Backend Parity Matrix

> **You do not need to read this unless** you are choosing between
> SQLite, Postgres / Supabase, ClickHouse, and Snowflake — or verifying
> exactly which API surfaces are wired against each backend today.
> Most deployments should use Postgres (the documented default).

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
| Source registry persistence | Yes | Yes | No | No |
| Exception workflow persistence | No default API wiring | Yes | No | Yes |
| API key persistence / RBAC store | No default API wiring | Yes | No | No |
| Schedule persistence | Yes | Yes | No | Yes |
| Trend / baseline persistence | Yes | Yes | No | No |
| Graph persistence | Yes | Yes | No | No |
| Analytics / OLAP writes | No | No | Yes | No |
| Snowflake governance discovery routes | No | No | No | Yes |

## Route-level parity summary

This is the operator-facing answer to: "which API surfaces are real on which
backend?"

| Route group | SQLite | Postgres / Supabase | ClickHouse | Snowflake |
|---|---|---|---|---|
| `/v1/scan*` job lifecycle | Yes | Yes | No | Yes |
| `/v1/fleet*` | Yes | Yes | No | Yes |
| `/v1/gateway/policies*` | Yes | Yes | No | Yes |
| `/v1/sources*` source registry | Yes | Yes | No | No |
| `/v1/audit*` primary trail | Yes | Yes | No | Partial; Snowflake policy audit exists, but it is not the full transactional audit replacement |
| `/v1/auth/keys*` | No default API wiring | Yes | No | No |
| `/v1/auth/me` capability contract | session-local only | Yes | No | No |
| `/v1/exceptions*` | No default API wiring | Yes | No | Yes |
| `/v1/schedules*` | Yes | Yes | No | Yes |
| `/v1/traces`, `/v1/proxy/audit`, `/v1/ocsf/ingest` analytics writes | No | No | Yes | No |
| Snowflake governance/account discovery routes | No | No | No | Yes |

The key distinction is:

- transactional control-plane parity
- analytics/event parity
- warehouse-native discovery parity

These are related, but not interchangeable.

## Snowflake parity target

The Snowflake story should be read in three layers:

1. **Current shipped parity**
   - `scan_jobs`
   - `fleet_agents`
   - `gateway_policies`
   - `policy_audit_log`
   - `exceptions`
   - `scan_schedules`
   - governance and activity discovery routes
2. **Current explicit non-parity**
   - source registry
   - API keys and RBAC persistence
   - graph persistence
   - trend and baseline state
   - full HMAC-chained `audit_log`
3. **Next parity targets, if warehouse-native control-plane coverage expands**
   - source registry
   - selected baseline/trend state

That means Snowflake is already a real backend mode, but it is still not the
same claim as “full transactional replacement for Postgres.”

## Snowflake control-plane parity plan

Snowflake parity should expand only where the warehouse is a natural
system of record. The current target is selected control-plane state plus
governance evidence, not a one-for-one clone of every Postgres table.

| Control-plane store | Current Snowflake state | Parity direction |
|---|---|---|
| Scan jobs | Implemented | Keep parity with Postgres job lifecycle behavior |
| Fleet inventory | Implemented | Keep parity for endpoint and MCP inventory history |
| Schedules | Implemented | Keep parity for recurring scan configuration |
| Vulnerability exceptions | Implemented | Keep parity for exception workflow persistence |
| Gateway policies | Implemented | Keep parity for runtime policy distribution |
| Policy audit trail | Implemented | Keep as the Snowflake-native audit path for gateway policy changes |
| Source registry | Not implemented | Candidate next parity target for warehouse-native source inventory |
| Trend and baseline state | Not implemented | Candidate next parity target where history joins matter |
| Graph persistence | Not implemented | Keep Postgres/SQLite as the graph-first path until Snowflake graph query shape is validated |
| API keys / RBAC | Not implemented | Keep Postgres as the operational auth store; do not move secrets into Snowflake by default |
| Full HMAC-chained audit log | Not implemented | Keep the transactional audit chain on the default control-plane backend |

This keeps the product interoperable: customers can run Postgres for the
broadest API coverage, add ClickHouse for high-volume analytics, and use
Snowflake for warehouse-native governance without making every deployment
depend on a Snowflake account.

## CI-Backed Snowflake Contract Coverage

The documented Snowflake parity slice is enforced in CI with mocked
connector-based tests:

- `tests/test_snowflake_stores.py` covers the store-layer contracts for jobs,
  fleet, gateway policies, schedules, and exceptions.
- `tests/test_snowflake_backend_contract.py` covers the API-advertised backend
  contract for health reporting and the supported schedule / exception routes
  in warehouse-native mode.

For the exact logical entity → table/store mapping, see
[Control-Plane Data Model and Store Parity](control-plane-data-model.md).

## What This Means

If you need the broadest control-plane coverage today, use `Postgres` or `Supabase`.

If you need local persistence, use `SQLite`.

If you need high-volume analytics or time-series aggregation, add `ClickHouse`.

If you need warehouse-native deployment or governance workflows in Snowflake, use `Snowflake` where the parity boundary is acceptable and explicit.

If you need the widest route coverage with the fewest caveats, use
`Postgres` / `Supabase` for the control plane and add `ClickHouse` only when
analytics volume justifies it.

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

- graph persistence does not persist to Snowflake
- source registry entries do not persist to Snowflake
- API keys do not persist to Snowflake
- baseline/trend storage does not persist to Snowflake
- full HMAC-chained audit log storage does not persist to Snowflake

That makes Snowflake viable for selected control-plane paths, but not yet a full transactional replacement for Postgres.

Recommended fit:

- teams already governed around Snowflake
- warehouse-native inventory, policy, and fleet history
- governance-heavy deployments where Snowflake is already the source of record

Not the best fit:

- broad control-plane admin workflows
- API-key-heavy operational setups
- graph-first operator workflows that expect backend-complete parity today

### 3. Warehouse-native governance mode

Use when the primary goal is:

- Snowflake governance discovery
- activity and observability routes backed by Snowflake account data
- Snowflake Native App or Snowpark-adjacent operator workflows

This mode is compatible with:

- local CLI scans
- API/UI deployments
- hybrid control planes where the warehouse is the authoritative governance data source

The practical shape is:

- `Postgres` remains the easiest full control-plane default
- `Snowflake` can be the warehouse-native governance and selected-store backend
- customers can still export or mirror data without locking the product model to one backend

### 4. Snowflake Native App / security-lake mode

Use when the customer wants the operator experience and evidence tables to
live inside the Snowflake account boundary. This mode is for posture
assessment, governance evidence, and optional runtime surfaces that can run
next to Snowflake data. It does not replace the Postgres default for every
admin, auth, graph, and trend workflow.

The supported shape is:

- Snowflake Native App assets package the Snowflake-side schema, Streamlit
  surface, scanner service, optional MCP runtime service, and Marketplace
  listing materials.
- Customers grant read-only account metadata access through Snowflake roles
  and external access integrations for approved advisory feeds.
- Postgres / Supabase remains the recommended backend when teams need the
  widest transactional control-plane API coverage on day one.

## Recommended Selection

| Need | Recommended backend |
|---|---|
| Laptop, demo, single-node | `SQLite` |
| Team / enterprise API deployment | `Postgres` / `Supabase` |
| Large analytics or trend workloads | `ClickHouse` alongside Postgres |
| Snowflake-native governance and warehouse workflows | `Snowflake`, with explicit parity limits |

## Recommended reading of this matrix

Use it in this order:

1. choose the backend that covers the routes you actually need
2. treat `Postgres` as the default control-plane answer unless you have a
   strong reason not to
3. add `ClickHouse` when analytics scale justifies it
4. use `Snowflake` where the documented parity boundary is acceptable

## Related Docs

- [Control-Plane Data Model and Store Parity](control-plane-data-model.md)
- [Deployment Overview](overview.md)
- [SIEM Integration](siem-integration.md)
- [Canonical Model vs OCSF](../architecture/canonical-vs-ocsf.md)
- `docs/ENTERPRISE.md`
- `docs/ENTERPRISE_DEPLOYMENT.md`
