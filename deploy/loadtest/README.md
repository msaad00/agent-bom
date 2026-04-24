# Load-test harness

These scripts are a compact validation harness for self-hosted `agent-bom`
deployments. They are not a full benchmark lab. They exercise the real
control-plane and proxy-ingest paths that matter for enterprise rollout.

## What is covered

- control-plane API health and authenticated fleet reads
- graph overview and graph search operator reads
- proxy audit ingest writes

## Prerequisites

- `k6` installed locally or in your CI runner
- a reachable `agent-bom` control plane
- an API token with access to the paths you are testing

Set:

```bash
export AGENT_BOM_BASE_URL=https://agent-bom.internal.example.com
export AGENT_BOM_API_TOKEN=replace-me
```

## Control-plane API baseline

```bash
k6 run deploy/loadtest/k6-control-plane-api.js
```

Optional overrides:

- `AGENT_BOM_BASE_URL`
- `AGENT_BOM_API_TOKEN`
- `K6_VUS`
- `K6_DURATION`

What it hits:

- `GET /health`
- `GET /v1/fleet`
- `GET /v1/fleet/stats`

## Proxy audit ingest baseline

```bash
k6 run deploy/loadtest/k6-proxy-audit.js
```

Optional overrides:

- `AGENT_BOM_BASE_URL`
- `AGENT_BOM_API_TOKEN`
- `K6_VUS`
- `K6_DURATION`
- `AGENT_BOM_PROXY_ALERT_BATCH`

What it hits:

- `POST /v1/proxy/audit`

## Graph operator baseline

```bash
k6 run deploy/loadtest/k6-graph-api.js
```

Optional overrides:

- `AGENT_BOM_BASE_URL`
- `AGENT_BOM_API_TOKEN`
- `AGENT_BOM_GRAPH_SCAN_ID`
- `AGENT_BOM_GRAPH_QUERY`
- `AGENT_BOM_GRAPH_ENTITY_TYPES`
- `K6_VUS`
- `K6_DURATION`

What it hits:

- `GET /v1/graph`
- `GET /v1/graph/search`

## How to use the results

Use these runs to answer four operator questions:

1. Are API replicas sized correctly for steady-state reads?
2. Does graph overview/search stay within the target operator latency budget?
3. Does proxy audit ingest stay healthy under expected concurrency?
4. At what point should `HPA` thresholds be widened?
5. At what point should analytics move from `Postgres`-only to
   `Postgres + ClickHouse`?

Do not treat one green run as a certification. Re-run after:

- changing replica counts
- enabling `HPA`
- changing storage backends
- widening endpoint or proxy rollout
