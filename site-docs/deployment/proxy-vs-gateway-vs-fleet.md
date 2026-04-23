# When To Use Proxy vs Gateway vs Fleet

Use this page when the question is not "does `agent-bom` support runtime?" but
"which runtime or inventory surface should I deploy first, and why?"

The short answer:

- `fleet` gives you inventory, provenance, and review without requiring runtime relay
- `proxy` gives you local or sidecar MCP enforcement close to stdio and workload-local traffic
- `gateway` gives you a shared remote MCP traffic plane for HTTP/SSE MCP servers

These are all core product surfaces. They are not three different products.

## Quick choice table

| Surface | Best fit | Deploy where | Gives you | Does not replace |
|---|---|---|---|---|
| **Fleet** | "What is installed, configured, and reachable?" | endpoints, collectors, or scheduled scan jobs | endpoint inventory, MCP configs, transports, declared tools, auth mode, credential-backed env vars, last seen / last synced | inline runtime enforcement |
| **Proxy** | local stdio MCPs and sidecar enforcement | laptop, workstation, or selected workload | inline policy evaluation, detector chain, audit push, signed cached policy bundles, workload-local runtime visibility | shared remote MCP relay |
| **Gateway** | shared remote MCP traffic over `http` / `sse` | cluster or shared service tier | remote MCP relay, shared policy surface, tenant auth, shared rate limits, audit, upstream discovery overlay | local stdio or every endpoint runtime path |

## What each surface is for

### Fleet

Use `fleet` first when the adoption wedge is inventory:

- which endpoints have MCP-capable clients
- which MCP servers are configured
- which transports they use: `stdio`, `http`, `https`, `sse`
- which tools they declare
- which commands or URLs they point at
- which credential-backed environment variables they reference
- when the endpoint or collector last synced

This is the right first step for teams that want visibility before they commit
to a runtime rollout.

The normal endpoint path is:

```bash
agent-bom agents \
  --preset enterprise \
  --introspect \
  --push-url https://agent-bom.internal.example.com/v1/fleet/sync \
  --push-api-key "$AGENT_BOM_PUSH_API_KEY"
```

What `fleet` is not:

- not an always-on endpoint daemon product
- not inline MCP enforcement
- not a replacement for `proxy` or `gateway`

### Proxy

Use `proxy` when the MCP traffic is local, stdio-based, or best enforced close
to one workload:

- Claude Desktop / Claude Code launching stdio MCPs
- Cursor, Windsurf, Continue, or similar tools using local MCP configs
- workload-local sidecars where the MCP server should not hairpin through a shared gateway

Typical local path:

```bash
agent-bom proxy \
  --control-plane-url https://agent-bom.internal.example.com \
  --control-plane-token "$AGENT_BOM_API_TOKEN" \
  --detect-credentials \
  --block-undeclared \
  -- npx @modelcontextprotocol/server-filesystem ~/workspace
```

What `proxy` gives you today:

- inline tool-call inspection and response scanning
- policy evaluation using the same policy model the gateway uses
- control-plane policy pull with signed cached bundles
- fail-closed startup on tampered cached policy bundles
- replay detection
- trace-context preservation across the stdio JSON-RPC boundary
- audit push back to the control plane

What `proxy` is not:

- not a central HTTP relay for every remote MCP
- not the inventory/discovery wedge by itself

### Gateway

Use `gateway` when the MCP traffic is already remote and shared:

- multiple clients need one governed endpoint for remote MCP servers
- the MCP servers expose `http`, `https`, or `sse`
- you want one policy and audit plane for shared remote MCP traffic

Typical shared path:

```bash
agent-bom gateway serve \
  --bind 0.0.0.0:8090 \
  --from-control-plane https://agent-bom.internal.example.com \
  --control-plane-token "$AGENT_BOM_CONTROL_PLANE_TOKEN" \
  --bearer-token "$AGENT_BOM_GATEWAY_BEARER_TOKEN"
```

What `gateway` gives you today:

- tenant-aware authentication at the gateway edge
- tenant-scoped upstream routing keyed by the authenticated tenant, not just a global upstream name
- inline policy evaluation for JSON-RPC requests
- shared tenant rate limiting, including Postgres-backed multi-replica mode
- audit logging back into the control plane
- trace propagation and response trace metadata
- remote upstream discovery from fleet and scan history
- local credential overlay via `--upstreams` or environment-backed tokens
- in-process reload for file-backed policies

What `gateway` is not:

- not the right answer for every stdio MCP session
- not a replacement for local proxy enforcement where the workload is already local

## How they fit together

The clean operating model is:

1. deploy the control plane
2. start with scans and fleet sync
3. add `proxy` where local MCP runtime enforcement matters
4. add `gateway` where shared remote MCP traffic needs one governed plane

That gives you one operator story without pretending all MCP traffic should go
through the same choke point.

## Example rollouts

### Inventory-first rollout

Deploy:

- API + UI + Postgres
- scan jobs
- fleet sync from endpoints or collectors

You get:

- endpoint and MCP inventory
- tools, auth mode, credential-backed config exposure
- findings, graph, blast radius, remediation

You do **not** need `proxy` or `gateway` yet.

### Endpoint runtime rollout

Deploy:

- inventory-first stack
- `proxy` on selected endpoints or workloads

You get:

- local stdio / sidecar enforcement
- audit of actual MCP calls for those workloads
- runtime policy close to the workload

### Shared remote MCP rollout

Deploy:

- inventory-first stack
- `gateway` for the remote MCPs you want to front centrally

You get:

- one shared endpoint for remote MCP traffic
- tenant-scoped auth, audit, and rate limits
- discovered upstream bootstrap from the control plane

### Full self-hosted platform

Deploy:

- control plane
- scan jobs
- fleet sync
- `proxy` where local enforcement matters
- `gateway` where remote shared traffic matters

That gives one platform across:

- inventory
- findings
- remediation
- graph and blast radius
- runtime audit and policy

## Why `agent-bom` uses peer runtime surfaces

`agent-bom` deliberately keeps `proxy` and `gateway` as peer runtime surfaces:

- `proxy` is the right fit for local stdio MCPs and sidecars
- `gateway` is the right fit for shared remote MCP traffic

This is different from a centralized-only MCP gateway model where more traffic
is forced through one broker. For `agent-bom`, that would be the wrong fit for:

- endpoint-local stdio MCP sessions
- low-latency sidecar enforcement
- teams that need inventory and review before runtime rollout

The inventory and control-plane value should stand on its own. Runtime is a
deepening layer, not the only way to use the product.

## What `agent-bom` offers today vs what still comes from your platform

What `agent-bom` already provides:

- OIDC, SAML, API keys, RBAC, and tenant propagation in the control plane
- persisted MCP inventory and provenance across scans, fleet, gateway, and stored observations
- policy storage and evaluation
- proxy and gateway audit trails
- shared gateway rate limits and trace stitching
- credential-aware discovery and runtime scanning without storing credential values

What still usually comes from your surrounding platform:

- IdP configuration and identity lifecycle in Okta / Entra / Auth0 / similar
- vault and secret ownership in Secrets Manager / Vault / ExternalSecrets
- human approval workflows for especially sensitive actions
- turnkey managed-connection UX for every enterprise integration

That is an intentional self-hosted shape:

- `agent-bom` is the control plane and security layer
- your surrounding platform still owns identity, secrets, and environment policy

## Centralized admin boundary

If you compare this to a more centralized managed MCP gateway model, the honest
difference today is:

- `agent-bom` is stronger on self-hosted inventory + scan + fleet + proxy/gateway correlation
- `agent-bom` is less turnkey on managed connections, profiles, and centralized
  per-user connection administration

What ships now:

- tenant-aware control plane
- gateway policy storage and evaluation
- inventory and provenance across scans, fleet, gateway, and persisted observations
- environment-backed credential overlays for remote MCP upstreams

What is still behind the more centralized SaaS-style admin model:

- one-click managed connection setup for many enterprise integrations
- centralized personal-vs-managed connection UX
- broader identity-centric runtime administration beyond the current control-plane auth and RBAC surface

That is a product-shape tradeoff, not hidden drift:

- self-hosted first
- customer-owned platform integrations
- runtime governance close to the customer's infra

## EKS shape

In a customer EKS deployment, the common split is:

- `agent-bom-api`
- `agent-bom-ui`
- scan and discovery workers
- `agent-bom-gateway` for shared remote MCPs
- proxy sidecars only on selected workloads
- fleet sync for developer endpoints

That keeps the deployment easy to reason about:

- scans and fleet build inventory
- the control plane stores graph, findings, audit, and policy
- the gateway fronts shared remote MCPs
- proxies stay close to the workloads that need local runtime control

## Related guides

- [Deployment Overview](overview.md)
- [Endpoint Fleet](endpoint-fleet.md)
- [Gateway Auto-Discovery From the Control Plane](gateway-auto-discovery.md)
- [Runtime Operations](runtime-operations.md)
- [Your Own AWS / EKS](own-infra-eks.md)
