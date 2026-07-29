# Design: multi-MCP gateway — `agent-bom gateway serve`

**Status:** implemented and operator-documented. The core relay, policy, audit,
tenant auth, runtime rate limiting, visual leak detection, and control-plane
auto-discovery paths now ship; this design doc remains the architectural
overview behind those runtime surfaces.

**Problem statement:** a pilot team wants to front-door every MCP connection in their environment through a single host so they can apply policy + audit centrally without touching every laptop's editor config. Today, `agent-bom proxy` is **per-MCP** — one instance per upstream server, either as a K8s sidecar next to a workload or as a stdio wrapper on a developer laptop. Central policy + audit already exist (`/v1/gateway/policies`, `/v1/proxy/audit`); central *traffic* does not.

**Concrete pilot mix the gateway must cover:**
- SaaS MCPs (Jira, GitHub, etc.) — bearer-token auth, remote HTTPS.
- Snowflake-hosted MCPs (Cortex functions / container services) — OAuth2 client-credentials against the Snowflake IdP.
- In-cluster MCPs running alongside the gateway — no external auth; NetworkPolicy is the perimeter.
- stdio-only local MCPs — out of scope for this gateway; keep using `agent-bom proxy` per-MCP wrappers.

## Goal

Add a new CLI mode: `agent-bom gateway serve`.

One FastAPI service that:

1. Accepts MCP client connections over HTTP JSON-RPC / streamable HTTP request-response.
2. Routes each client connection to one of N configured upstream MCP servers (local or remote), keyed by server name.
3. Applies gateway policy (from the existing `/v1/gateway/policies` store) inline, on every `tools/call`, `tools/list`, `resources/read`, `prompts/get`.
4. Pushes every call into the existing HMAC-chained audit log via the existing `/v1/proxy/audit` contract.
5. Exposes per-upstream, per-tenant, and source-agent rate-limit metrics on the existing `/metrics` endpoint.

Non-goals (explicitly):

- Proxying **stdio** MCPs — clients that only speak stdio still use per-MCP `agent-bom proxy` wrappers. This gateway is HTTP/streamable-http only.
- A new transport or policy language. Re-uses `GatewayPolicy` + `check_policy` from [`src/agent_bom/gateway.py`](../../src/agent_bom/gateway.py).
- Replacing the sidecar mode. Both modes coexist; teams pick per workload.

## User-visible surface

### CLI

```bash
agent-bom gateway serve \
  --bind 0.0.0.0:8090 \
  --upstreams upstreams.yaml \
  --from-control-plane https://agent-bom.example.com \
  --control-plane-token "$CP_TOKEN" \
  --policy-reload-seconds 30 \
  --bearer-token "$GATEWAY_TOKEN"
```

The gateway pushes runtime audit events to the control plane when
`--from-control-plane` is configured. `--response-sign-key` is a **proxy-only**
option; it is not accepted by `gateway serve`.

### Canonical client-profile enforcement

Profile enforcement is off by default while existing OAuth/JWKS clients are
migrated to managed identities. Enable it only after creating one active
`McpClientConfigAssignment` for each managed `AgentIdentity`. The gateway must
read the same authoritative database that owns those records; replicated/Helm
deployments require the shared `AGENT_BOM_POSTGRES_URL` Secret. The chart
requires a gateway-scoped `gateway.envFrom` Secret and refuses to render
enforced mode when it is absent. Do not reuse the broader control-plane Secret:
it can contain unrelated session, audit, login, or encryption credentials:

```bash
agent-bom gateway serve \
  --bind 0.0.0.0:8090 \
  --upstreams upstreams.yaml \
  --bearer-token "$GATEWAY_TOKEN" \
  --profile-enforcement enforce \
  --profile-environment prod
```

The operator-controlled profile environment is matched to the assignment;
caller-supplied `X-Agent-Environment` metadata cannot select it. Enforce mode
denies unknown, inactive, revoked, expired, cross-tenant, issuer/environment/
blueprint-mismatched, under-scoped, or out-of-contract upstream/tool calls
before contacting the upstream. Warn mode records the same stable reason code
but allows the call. The gateway removes `_meta.agent_identity` before relay.

Managed `abi_` tokens do not carry OAuth scope claims. An assignment with
`required_scopes` therefore fails closed for those opaque tokens until the
managed identity is bound to a verified claims-bearing authentication path;
the assignment's required scopes are never treated as granted scopes.

For a local-only troubleshooting session, `--allow-profile-dev-bypass` works
only with a loopback `--bind` and emits
`gateway.runtime_profile_dev_bypass`. Merely binding to loopback does not
bypass enforcement. Kubernetes intentionally exposes no equivalent bypass.

Typed tool decisions carry a canonical client-profile ID and revision,
separate role-blueprint ID and revision, managed identity/agent IDs, bound
policy IDs, trace ID, and one stable event/decision ID. The control-plane audit
ingest stores these Tier-A fields in the bounded, tenant-scoped gateway
activity ledger (shared Postgres for replicas, SQLite for a single node). Feed
reads use server-owned ordinals and tenant-bound cursors; initial reads return
the newest bounded backfill, while cursor reads resume forward without using
caller timestamps for ordering. The response reports source, retention floor,
and complete/partial state. The local ring/JSONL path is explicitly degraded;
it cannot satisfy a durable cursor resume. KPI windows run from UTC midnight to
the request time and report whether retained evidence makes the count exact;
raw arguments, results, tokens, credential references, and unredacted previews
are excluded.

### `upstreams.yaml`

```yaml
upstreams:
  - name: jira
    url: https://snowflake.example.internal/mcp/jira
    transport: streamable-http
    auth: oauth2_client_credentials
    scopes: ["jira.read"]
  - name: github
    url: https://mcp.github.example.com/mcp
    transport: streamable-http
    auth: bearer
    token_env: GITHUB_MCP_TOKEN
  - name: filesystem-review-env
    url: http://review-fs.agent-bom-workloads.svc.cluster.local:8100
    transport: streamable-http
    auth: none
```

The upstream transport field defaults to `streamable-http`. `http` and `https`
are accepted as legacy aliases. `sse` and URLs whose path ends in `/sse` are
rejected at gateway config load because the relay POSTs JSON-RPC and does not
maintain a persistent SSE upstream client.

### Client config

Laptop editors point at **one** URL for every MCP, using the gateway's server-routing discriminator:

```jsonc
// Cursor / VS Code / Claude MCP config — one entry, not N
{
  "mcpServers": {
    "gateway": {
      "transport": "http",
      "url": "https://agent-bom-gateway.example.com/mcp/{server-name}",
      "headers": { "Authorization": "Bearer ${AGENT_BOM_USER_TOKEN}" }
    }
  }
}
```

`{server-name}` is replaced by the desired upstream (e.g. `/mcp/jira`, `/mcp/github`). Servers the user is not authorised for 403.

## Data flow

```mermaid
flowchart LR
  subgraph Laptops
    cursor[Cursor]
    claude[Claude Desktop]
    vscode[VS Code + Copilot]
  end
  gw["agent-bom gateway serve<br/>(FastAPI + policy engine)"]
  policy[("/v1/gateway/policies")]
  audit[("/v1/proxy/audit")]
  metrics[("/metrics")]
  subgraph Upstreams
    jira["Jira MCP (SaaS)"]
    gh["GitHub MCP (SaaS)"]
    snow["Snowflake MCP (Cortex / container service)"]
    fs["Filesystem MCP in EKS"]
  end

  Laptops -- Streamable HTTP --> gw
  gw -. pull every 30s .- policy
  gw -. push every 10s .- audit
  gw -. scrape .- metrics
  gw -->|tool call| jira
  gw -->|tool call| gh
  gw -->|tool call| snow
  gw -->|tool call| fs
```

## Reuse map — don't rewrite what exists

| Requirement | Existing code | Change |
|---|---|---|
| Policy evaluation | [`check_policy`](../../src/agent_bom/proxy.py) | Reuse unchanged — pure function |
| Policy fetch from control plane | `control_plane_url` / `control_plane_token` path in [`run_proxy`](../../src/agent_bom/proxy.py:527) | Extract into a module both `run_proxy` and `gateway serve` call |
| Runtime detectors | [`agent_bom.runtime.detectors`](../../src/agent_bom/runtime/detectors.py) | Reuse unchanged |
| Audit-push client | Proxy's current HTTPX POST to `/v1/proxy/audit` | Extract |
| Response signing | `response_signing_key` path in `run_proxy` | Proxy-only; gateway audit events use the control-plane audit chain when configured |
| `GatewayPolicy` format | [`agent_bom.api.policy_store`](../../src/agent_bom/api/policy_store.py) | Unchanged |
| Metrics | [`agent_bom.api.metrics`](../../src/agent_bom/api/metrics.py) | Add per-upstream labelled counters |
| Auth (API key / OIDC / SAML) | [`agent_bom.api.middleware`](../../src/agent_bom/api/middleware.py) | Gateway must accept the same auth methods the control plane does |

Net new code:

- `src/agent_bom/gateway_server.py` — the FastAPI app, upstream registry, HTTP JSON-RPC relay
- `src/agent_bom/cli/gateway.py` — `agent-bom gateway serve` entry point
- `src/agent_bom/gateway_upstreams.py` — upstream config loader + auth injector
- `tests/test_gateway_server.py` — real upstream + real policy + TestClient integration

## Security guarantees

- **Tenant isolation** — every upstream request carries the authenticated tenant's context; runtime rate limits are tenant-scoped and split by source-agent identity, with tenant-local `anonymous` buckets for calls that do not present `_meta.agent_identity`.
- **mTLS-ready** — gateway accepts a client cert at ingress for zero-trust environments; upstream TLS verification is mandatory (not optional like current proxy dev-mode).
- **No credential forwarding** — per-upstream credentials are injected by the gateway and the caller's `_meta.agent_identity` credential is removed before relay. This is the whole point of putting a gateway in front: the laptop doesn't hold the Jira token and the upstream never receives the gateway identity token.
- **Audit non-repudiation** — gateway calls are signed with the same Ed25519 key path the compliance bundle uses ([`docs/COMPLIANCE_SIGNING.md`](../COMPLIANCE_SIGNING.md)).
- **Replay protection** — same nonce + expiry envelope as the compliance bundle for every `tools/call` audit record.
- **Pod Security Admission restricted** — gateway runs as non-root, read-only root FS, no privilege escalation. Helm template ships this.

## Performance targets

| Metric | Target | Source |
|---|---|---|
| p50 added latency per `tools/call` | < 15 ms | existing proxy benchmarks |
| p99 added latency | < 60 ms | |
| Concurrent clients per pod | 500 request-response clients | FastAPI + uvloop |
| Policy refresh staleness | < 45 s (30 s pull + 15 s slack) | `policy_refresh_seconds` |
| Audit push queue backlog | alerts at > 10k events | `AuditDeliveryController` DLQ |

Horizontal scale via HPA; no upstream SSE stickiness is required because the
gateway relay is streamable-http request/response only.

## Rollout plan

1. **Day 1 (merge of this doc):** design published; pilot team can read the target architecture.
2. **Day 2–3:** extract policy-fetch + audit-push helpers from `run_proxy` into shared modules. Land with existing proxy still working (regression guard).
3. **Day 4–5:** `agent-bom gateway serve` MVP — streamable HTTP, 1 upstream, policy + audit + metrics wired.
4. **Day 6:** N upstreams, per-upstream auth injection, upstream config hot-reload.
5. **Day 7:** Helm chart `gateway` Deployment + HPA + NetworkPolicy + PrometheusRule + Grafana panel.
6. **Day 8:** pilot team installs, points editors at the gateway URL, validates policy enforcement on a SaaS MCP (Jira or GitHub) and a Snowflake-hosted MCP (Cortex function).

Every stage is behind a flag until the gateway-serve tests and the pilot team sign off — sidecars remain the documented default.

## Open questions

- **Upstream auth refresh**: OAuth2 client-credentials token rotation schedule. Day-1 answer: per-upstream auth policy in the config; background refresher with 80% jitter.
- **Client authentication**: do we require a per-user token (OIDC), a per-tenant API key, or both? Day-1 answer: per-user OIDC for laptop traffic, per-service API key for machine-to-machine.
- **Snowflake-hosted MCP specifics**: Snowflake MCPs should expose streamable HTTP endpoints via Cortex functions or container services, authenticated against the Snowflake IdP. We assume stock MCP over HTTPS and support OAuth2 client-credentials at the gateway — the `snowflake` example in `gateway-upstreams.example.yaml` is the shape. Legacy SSE upstream endpoints are not supported by this gateway relay.
