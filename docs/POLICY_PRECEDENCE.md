# Policy precedence

agent-bom enforces policy at four distinct layers. Each layer answers a
different question, runs at a different point in the lifecycle, and owns
different state. New users routinely conflate them — this page is the
authoritative map.

This document is reference, not introduction. For per-layer schemas
and operator runbooks see the linked source-of-truth docs at the end.

## The four layers at a glance

| Layer | Module | Decision it owns | When it runs | Loaded from |
|---|---|---|---|---|
| **Pre-flight (CLI)** | `agent-bom policy templates` (CLI) + `src/agent_bom/policy.py` | Is this *package* allowed to land in this build? | Before install / at scan time | YAML/JSON template selected per project |
| **Inter-agent firewall** | `src/agent_bom/firewall.py` | Is *agent A* allowed to delegate to *agent B*? | On every MCP delegation through the gateway/proxy | JSON policy file (hot-reloaded), schema in `docs/AGENT_FIREWALL.md` |
| **Runtime tool-call (proxy)** | `src/agent_bom/proxy.py` | Is *this tool call* on *this MCP server* allowed to proceed? Should the response be redacted? | Per JSON-RPC method on the local sidecar / proxy chain | Local cache pushed by control plane (`policyConfigMapName` in Helm) |
| **HTTP gateway** | `src/agent_bom/api/policy_store.py` | Is *this HTTP request* (tenant, method, route) allowed? Does it satisfy auth + RBAC + rate-limit? | At the edge of the FastAPI control plane, before the proxy/firewall layers see a request | Postgres-backed policy store + tenant config |

Layer ordering matters: **pre-flight runs once** during scan/install, the
other three run at every runtime hop. The next section walks through the
runtime ordering.

## Ordering for a runtime tool-call

Take a single end-to-end MCP tool call: a Cursor agent in tenant `acme`
asks the gateway to relay `tools/call` for `query_db` on the upstream
`snowflake-mcp` server. Each layer has a chance to short-circuit the
request before it reaches the upstream. If any layer denies, the request
fails with the layer's error and the lower layers never see it.

1. **HTTP gateway (`policy_store.py`)** authenticates the bearer token,
   resolves the tenant, applies RBAC, and checks rate limits. Failure
   here returns `401`/`403`/`429` directly to the agent. The gateway
   has no opinion on which agent is calling which tool — it only cares
   that the *HTTP caller* is allowed to use the relay at all.
2. **Inter-agent firewall (`firewall.py`)** then resolves the
   `(source_agent, target_agent)` pair from the MCP request payload
   and checks the firewall policy file. A `deny` decision here returns
   a structured firewall error and emits an audit record on the
   HMAC-chained `/v1/proxy/audit` relay; the upstream MCP is never
   contacted. This layer runs in both the central gateway and the
   per-MCP sidecar (`proxy.py` defers to it for the fast-path cache).
3. **Runtime tool-call policy (`proxy.py`)** receives the request only
   if the gateway and firewall have allowed it. It decides per-method:
   is `tools/call` enabled on `snowflake-mcp` for this tenant? Does the
   tool name match an allow-list entry? Should the response body be
   scanned for credentials and redacted? Does the call require an
   approval ticket? Pre-call decisions short-circuit; post-call
   decisions transform the response stream.
4. **Pre-flight (CLI)** does *not* run on the live request path. It ran
   before this whole graph existed, when the operator scanned the MCP
   server's package set with `agent-bom check` and refused to ship a
   build whose dependencies violated the policy template. By the time
   a runtime request arrives, the pre-flight layer's job is finished.

The precedence rule is therefore: **gateway > firewall > proxy** at
runtime, with **pre-flight** acting as a static admission control that
runs before the runtime triplet ever exists.

## Conflict resolution between layers

| Scenario | Outcome |
|---|---|
| Gateway allows, firewall denies, proxy would allow | Request denied with firewall error (firewall ran second). |
| Gateway allows, firewall allows, proxy denies | Request denied with proxy error (proxy ran last). |
| Gateway denies, firewall would allow, proxy would allow | Request denied with `403`/`429` — firewall and proxy never evaluated. |
| Pre-flight would have denied a transitive package, gateway allows the runtime call | Runtime call proceeds. Pre-flight is build-time admission, not runtime gating. The fix is to fail the build, not the call. |
| Two layers both deny | The earliest-running layer's denial wins; later layers don't run. |

Conflicts between layers are not "merged" — there is no precedence
*aggregation*. Each layer either short-circuits or hands off. This
keeps the audit log readable: every denial has exactly one owning
layer.

## Worked example: Cursor delegating to a Snowflake MCP

Setup:

- Tenant: `acme`.
- HTTP gateway: bearer-token auth on, tenant `acme` rate-limited to
  60 req/min, RBAC role `analyst` allowed to use `/v1/proxy/relay`.
- Firewall policy: `cursor → snowflake-mcp` is `allow`, but
  `cursor → admin-mcp` is `deny`.
- Proxy policy: `snowflake-mcp.tools/call` is enabled for the `query_db`
  tool only; `query_db` responses are scanned for credentials.
- Pre-flight: the snowflake-mcp build was scanned at deploy time;
  `better-sqlite3@9.0.0` was flagged as CRITICAL but waived because
  the SBOM marked it as not reachable.

Request: Cursor sends `tools/call query_db {"q": "..."}` to the
gateway, with the bearer token of an `analyst` role member.

| Step | Layer | Decision |
|---|---|---|
| 1 | Gateway | Bearer valid → tenant `acme` resolved → role `analyst` matches → rate limit (3/60) → ALLOW. |
| 2 | Firewall | source=`cursor`, target=`snowflake-mcp` → matches an `allow` rule → ALLOW. |
| 3 | Proxy (pre-call) | method=`tools/call`, tool=`query_db` → matches allow-list → ALLOW; mark response for credential scan. |
| 4 | Upstream | Snowflake MCP returns rows. |
| 5 | Proxy (post-call) | Response body scanned. No credentials matched. Response forwarded unchanged. |
| 6 | Gateway | Response streamed back to Cursor; audit record emitted on `/v1/proxy/audit`. |

If the same agent had asked for `tools/call admin_purge_users`, step 3
would deny (tool not on allow-list). If a different agent
(`untrusted-agent → snowflake-mcp`) had made the same request, step 2
would deny. If the bearer token was missing, step 1 would 401 and the
firewall + proxy would never run. The operator can read the failure
back from the audit log and know exactly which layer owned the
decision.

## Source-of-truth docs

- Pre-flight policy templates → `agent-bom policy --help`,
  `src/agent_bom/policy.py`.
- Inter-agent firewall → `docs/AGENT_FIREWALL.md`,
  `src/agent_bom/firewall.py`.
- Runtime tool-call policy → `docs/MCP_SECURITY_MODEL.md`,
  `src/agent_bom/proxy.py`.
- HTTP gateway → `docs/design/MULTI_MCP_GATEWAY.md`,
  `src/agent_bom/api/policy_store.py`.

Cross-cutting topology and audit relay: `docs/RUNTIME_REFERENCE.md`.
