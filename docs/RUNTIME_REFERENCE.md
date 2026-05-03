# Runtime reference

agent-bom ships five runtime surfaces. They share an audit relay and a
control-plane API but otherwise sit at different points in the request
graph and own different decisions. New operators and external auditors
routinely re-derive this map from per-surface docs; this page is the
single canonical version.

For policy-layer ordering inside a single tool-call see
`docs/POLICY_PRECEDENCE.md`. This page is the higher-level surface map.

## Which surface owns which decision

| Surface | Module | Owns |
|---|---|---|
| **HTTP gateway** | `src/agent_bom/api/` (FastAPI app), `src/agent_bom/api/policy_store.py` | Edge auth, tenant resolution, RBAC, rate limits, multi-MCP fan-out from one URL. |
| **Inter-agent firewall** | `src/agent_bom/firewall.py` | Whether agent A may delegate to agent B. Returns `allow`/`deny` for an `(source, target)` pair. |
| **Proxy / sidecar** | `src/agent_bom/proxy.py`, `src/agent_bom/sidecar.py` | Per-method runtime policy on a single MCP server: which JSON-RPC methods are enabled, which tools are allow-listed, response-body credential redaction, approval-required gating. |
| **MCP server** | `src/agent_bom/mcp_server.py` | Exposes agent-bom's own tools (scan, blast-radius, evidence) over MCP for Claude/Cursor to consume. *Not* a policy layer; it's a tool surface. |
| **Sidecar injection webhook** | `src/agent_bom/sidecar_admission.py`, Helm `sidecarInjection` block | Mutates Pod specs at admission time so workloads get the proxy automatically. *Not* a runtime decision; it's a deploy-time injection path. |

The first three are policy layers and run on every request. The MCP
server is a tool publisher — it's a *target* of policy, not an
enforcer. The admission webhook is one-shot at Pod creation and never
sees runtime traffic.

## Topology

```
                     ┌──────────────────────────┐
   Agent ───────────▶│      HTTP gateway        │  edge auth / tenancy / RBAC / rate limit
   (Cursor/Claude)   └─────────────┬────────────┘
                                   │
                                   ▼
                     ┌──────────────────────────┐
                     │   Inter-agent firewall   │  agent-A → agent-B allow/deny
                     └─────────────┬────────────┘
                                   │
                                   ▼
                     ┌──────────────────────────┐
                     │   Proxy / sidecar        │  per-method runtime policy + redaction
                     └─────────────┬────────────┘
                                   │
                                   ▼
                     ┌──────────────────────────┐
                     │   Upstream MCP server    │  the actual tool surface
                     └──────────────────────────┘

   Out of band:                                       Out of band:
   ┌─────────────────────┐                            ┌──────────────────┐
   │  agent-bom MCP      │  exposes scan/evidence     │  Sidecar admission│  injects proxy
   │  server             │  tools to client agents    │  webhook          │  at Pod creation
   └─────────────────────┘                            └──────────────────┘
```

## Deployment modes

| Mode | What runs | Use when |
|---|---|---|
| **Local CLI only** | Pre-flight scanner + `agent-bom serve` (single-node API + UI). | Pilot, single workstation, no runtime enforcement. |
| **Per-MCP sidecar** | Proxy injected next to each MCP workload via the sidecar admission webhook. No central gateway. | Teams that prefer local-to-workload enforcement and a flatter blast radius. |
| **Central gateway** | One FastAPI gateway service fronting N upstream MCPs. Optional firewall and proxy logic colocated. | Multi-tenant control plane, single bearer-token surface for laptops, central audit relay. |
| **Hybrid** | Central gateway *plus* per-MCP sidecars. Gateway handles edge auth + tenancy; sidecars handle local fast-path policy with shared audit. | Regulated environments that want defence-in-depth and don't mind the operational surface. |

The Helm chart's `controlPlane.enabled=true` flag is what turns on the
gateway + API + dashboard + Postgres bundle. The `sidecarInjection`
block is independent and can run with or without the central gateway.
See `deploy/helm/agent-bom/values.yaml` for the full toggle set and
the README's Helm quick-start for the operator path.

## The audit relay

All three policy layers (gateway, firewall, proxy) emit decisions to
the same `/v1/proxy/audit` HMAC-chained relay. Each event carries:

- the layer that made the decision,
- the request fingerprint (tenant, agent, target, method, tool),
- the decision (`allow` / `deny` / `redact` / `approve`),
- the policy version that produced it,
- a hash chain link so tampering is detectable.

The chain is described in `docs/PROXY_AUDIT_LOG.md`. Operators reading
audit output can attribute every denial to exactly one layer; the
precedence rules in `docs/POLICY_PRECEDENCE.md` guarantee no event has
ambiguous ownership.

## Where to go for surface-specific detail

| Surface | Primary doc | Secondary references |
|---|---|---|
| HTTP gateway | `docs/design/MULTI_MCP_GATEWAY.md` | `src/agent_bom/api/policy_store.py`, Helm `gateway:` block |
| Inter-agent firewall | `docs/AGENT_FIREWALL.md` | `src/agent_bom/firewall.py`, Helm `gateway.firewallPolicyPath` |
| Proxy / sidecar | `docs/MCP_SECURITY_MODEL.md`, `docs/RUNTIME_MONITORING.md` | `src/agent_bom/proxy.py`, Helm `sidecarInjection:` block |
| MCP server (agent-bom's tool surface) | `docs/MCP_SERVER.md` | `src/agent_bom/mcp_server.py` |
| Audit relay | `docs/PROXY_AUDIT_LOG.md` | `/v1/proxy/audit` route |

This page is meant to be the first thing an operator reads when they
ask "what runs where?" The per-surface docs above remain the source of
truth for each surface's schema, configuration, and operational
runbook. None of those docs are deprecated by this reference; future
work may consolidate further once the runtime surface stabilises.
