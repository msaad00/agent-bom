# Snowflake-native backend

`agent-bom` runs against Snowflake as the primary store for scan jobs,
fleet agents, schedules, gateway policies, and the policy audit trail. Use this
mode when your organisation already governs data in Snowflake and you
want selected control-plane persistence to land in the same warehouse.

The parity boundary is explicit — some API surfaces (source registry,
exceptions, API keys, trend, graph, and the full audit
chain) have not been ported to `SnowflakeStore` yet. See
[backend-parity.md](backend-parity.md) for the current capability
matrix.

The safest way to think about this mode is:

- **real and supported**
- **warehouse-native**
- **not universal parity**

It is the right answer for teams that want Snowflake-native inventory, fleet,
policy, and governance workflows. It is not the default answer for every
self-hosted control-plane deployment.

---

## When Snowflake is the right fit

Pick Snowflake when:

- Your security and platform teams already have Snowflake as the system
  of record; adding another Postgres instance creates a data-governance
  headache.
- You want the policy audit trail, scan inventory, and compliance
  evidence in the same warehouse that drives your other security
  analytics.
- You want to join `agent-bom` findings against other Snowflake
  governance data (user activity, cloud asset tables) without moving
  data across systems.
- You want **one backend that covers the Snowflake-supported
  transactional, streaming, and analytical workloads**. Snowflake now
  ships:
  - **Hybrid Tables** (row-oriented) for fast transactional writes to
    the scan / fleet / policy / audit stores.
  - **Standard columnar tables** for the analytics queries the
    dashboard and compliance narratives run.
  - **Snowpipe Streaming** for real-time audit / telemetry ingest
    without a separate Kafka or ClickHouse hop.
  - **Postgres-compatible protocol** (via the Postgres API / drivers
    where applicable) so tooling that speaks `psycopg` can point at
    Snowflake the same way it points at Postgres — reducing client-side
    changes when you migrate.
  - **Native cross-cloud replication + listings** so the control plane
    in your EKS cluster can read/write the same Snowflake tables your
    cloud + Cortex MCPs read, regardless of region.

Pick Postgres when you want broad API surface coverage and the fastest
possible install, and you're comfortable adding ClickHouse only if
audit/event volume justifies it. Pick Snowflake when you'd rather
collapse both into one unified stack.

## Supported Snowflake deployment modes

### 1. Snowflake governance mode

Use when you mainly want:

- governance discovery
- activity and observability joins
- warehouse-native reporting and investigations

In this mode, Snowflake is primarily the governance and security-lake system of
record, while the rest of the control plane can remain on the default backend.

### 2. Snowflake selected control-plane mode

Use when you want these persisted in Snowflake:

- scan jobs
- fleet inventory
- schedules
- gateway policies
- gateway policy audit

This is the current partial-control-plane mode backed by
`SnowflakeJobStore`, `SnowflakeFleetStore`, `SnowflakeScheduleStore`,
and `SnowflakePolicyStore`.

### 3. Hybrid self-hosted control plane

Use when you want:

- `Postgres` for the broadest transactional control-plane coverage
- `Snowflake` for governance, warehouse joins, and selected mirrored or
  warehouse-native paths
- optional `ClickHouse` only if event analytics scale justifies it

This is often the cleanest enterprise answer because it keeps the default
control-plane semantics broad while still respecting warehouse-centric data
governance.

## Auth — zero-credential model

**Key-pair auth is required** for the Snowflake backend in production
([`build_connection_params`](https://github.com/msaad00/agent-bom/blob/main/src/agent_bom/api/snowflake_store.py)).
Passwords are deprecated and emit a runtime warning; password auth is
intentionally not recommended because it breaks rotation and short-lived
credential hygiene.

SSO (externalbrowser) is used for interactive operator CLI; the
control-plane API uses key-pair. Both reject the deprecated
`SNOWFLAKE_PASSWORD` path when
`AGENT_BOM_SNOWFLAKE_REQUIRE_KEYPAIR=1`.

### Generate a key pair once

```bash
openssl genrsa 2048 | openssl pkcs8 -topk8 -inform PEM -out rsa_key.p8 -nocrypt
openssl rsa -in rsa_key.p8 -pubout > rsa_key.pub
PUBLIC_KEY=$(grep -v "BEGIN\|END" rsa_key.pub | tr -d '\n')

# Install the public key on the Snowflake user
snowsql -a <account> -u <user> -q \
  "ALTER USER <user> SET RSA_PUBLIC_KEY='${PUBLIC_KEY}'"
```

### Store the private key + connection params in Secrets Manager

```bash
aws secretsmanager create-secret \
  --name agent-bom/snowflake \
  --secret-string "$(jq -n \
    --arg account "$SF_ACCOUNT" \
    --arg user "$SF_USER" \
    --arg warehouse "$SF_WAREHOUSE" \
    --arg database "$SF_DATABASE" \
    --arg schema "$SF_SCHEMA" \
    --arg role "$SF_ROLE" \
    --rawfile private_key rsa_key.p8 \
    '{account: $account, user: $user, warehouse: $warehouse, database: $database, schema: $schema, role: $role, private_key: $private_key}')"
```

Wire it to the cluster via ExternalSecrets pointing at
`agent-bom/snowflake`.

## Install

Use the shipped example values file:

```bash
helm install agent-bom deploy/helm/agent-bom \
  -n agent-bom --create-namespace \
  -f deploy/helm/agent-bom/examples/eks-snowflake-values.yaml
```

The example file configures:

- `AGENT_BOM_STORE_BACKEND=snowflake` (and equivalent for fleet / policy / audit)
- Key-pair auth via mounted `rsa_key.p8`
- `AGENT_BOM_SNOWFLAKE_REQUIRE_KEYPAIR=1` — hard-fail on password fallback
- Postgres backup CronJob disabled (Snowflake handles durability)
- Scanner CronJob still runs, pushes scan results to `/v1/fleet/sync`
- Egress NetworkPolicy allowing only `*.snowflakecomputing.com` on 443

## Schema bootstrap

`SnowflakeJobStore` / `SnowflakeFleetStore` / `SnowflakeScheduleStore` / `SnowflakePolicyStore`
create their tables on first connect with `CREATE TABLE IF NOT EXISTS`.
The schema lives in the database + schema you set via
`SNOWFLAKE_DATABASE` / `SNOWFLAKE_SCHEMA`.

Per-tenant isolation is row-level: every row carries a `TENANT_ID`
column and every query filters on it. See
[ClickHouse row-level tenant isolation (#1501)](https://github.com/msaad00/agent-bom/pull/1501)
for the equivalent enforcement on ClickHouse.

## What to monitor

The metrics catalog ([docs/OBSERVABILITY_METRICS.md](https://github.com/msaad00/agent-bom/blob/main/docs/OBSERVABILITY_METRICS.md))
applies here. Snowflake-specific signals worth alerting on:

- Query latency spikes on `SnowflakeJobStore.put` / `.list_all` —
  symptom of warehouse under-provisioning.
- Increased `agent_bom_auth_failures_total` after a key rotation —
  confirm the new public key landed on the Snowflake user.

## Break-glass

- **Warehouse exhausted** — scale the warehouse or point a backup Helm
  release at a different warehouse via `SNOWFLAKE_WAREHOUSE`.
- **Key rotation** — update the private key in Secrets Manager, run
  `ALTER USER ... SET RSA_PUBLIC_KEY` on Snowflake, `kubectl rollout
  restart deploy/agent-bom-api`. Old compliance bundles remain
  verifiable against the old **Ed25519** public key (that's a separate
  key from the Snowflake auth key — see
  [docs/COMPLIANCE_SIGNING.md](https://github.com/msaad00/agent-bom/blob/main/docs/COMPLIANCE_SIGNING.md)).
- **Access revoked** — bring up a Postgres backend from the nightly
  Postgres backup if you kept one; otherwise restore from Snowflake
  Time Travel.

## Caveats

- Source registry, exceptions, API-key persistence, trend,
  graph, and the full HMAC-chained `audit_log` are not yet on
  `SnowflakeStore`. Run Postgres alongside for these, or wait for
  parity.
- The scanner CronJob still runs in-cluster; it does not run inside
  Snowpark. Cortex / Snowpark-native discovery is a separate capability
  ([`src/agent_bom/cloud/snowflake.py`](https://github.com/msaad00/agent-bom/blob/main/src/agent_bom/cloud/snowflake.py)).
- Time Travel + Fail-safe provide durability, but configure a retention
  window that matches your compliance retention policy.

## Honest operator summary

`Snowflake` is already a valid warehouse-native backend mode for governance,
scan inventory, fleet state, schedules, and gateway policy paths. `Postgres` remains the
default full control-plane answer. Use Snowflake when that warehouse-native
shape is the goal, not because the product is pretending all backend roles are
already identical.
