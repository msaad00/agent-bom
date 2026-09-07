# Runtime reference

agent-bom ships five runtime surfaces. They share an audit relay and a
control-plane API but otherwise sit at different points in the request
graph and own different decisions. New operators and external auditors
routinely re-derive this map from per-surface docs; this page is the
single canonical version.

For policy-layer ordering inside a single tool-call see
`docs/POLICY_PRECEDENCE.md`. This page is the higher-level surface map.

The standalone gateway exposes separate liveness and admission signals.
`/healthz` reports delivery degradation and bounded backlog details. `/readyz`
returns 200 only while the configured audit path can admit tool execution. A
control-plane gateway therefore becomes unready when the remote durable
acknowledgement is unavailable, even though its bounded local spool retains the
event for retry. The Helm chart requires that spool on a restart-stable PVC for
both remote-connected and local-only gateways, runs one writer replica, and
rejects autoscaling until shared delivery leases exist. A local-only gateway
remains ready while its SQLite audit store is writable. Persistence failure, a
full bounded backlog, or shutdown returns 503.

### Runtime doc set

This page is the canonical runtime surface map. The detail docs:

- [`RUNTIME_MONITORING.md`](RUNTIME_MONITORING.md) — proxy sidecar deployment,
  detector configuration, enforcement modes, and alert routing
- [`RUNTIME_PROXY_AUDIT_JSONL.md`](RUNTIME_PROXY_AUDIT_JSONL.md) — the proxy
  audit JSONL record format for SIEM forwarding and release evidence
- `docs/POLICY_PRECEDENCE.md` — policy-layer ordering inside a single tool-call
- [`RUNTIME_FAIL_MODES.md`](RUNTIME_FAIL_MODES.md) — fail-open vs fail-closed
  posture per gateway enforcement subsystem, published on gateway `/healthz`
- [`design/OBSERVE_ENFORCE.md`](design/OBSERVE_ENFORCE.md) — security-eval
  scorecard + the observe→enforce bridge that turns runtime↔scan correlation
  into audit-mode gateway block-rule proposals (enforce only on explicit opt-in)

## Which surface owns which decision

| Surface | Module | Owns |
|---|---|---|
| **HTTP gateway** | `src/agent_bom/api/` (FastAPI app), `src/agent_bom/api/policy_store.py` | Edge auth, tenant resolution, RBAC, rate limits, multi-MCP fan-out from one URL. |
| **Inter-agent firewall** | `src/agent_bom/firewall.py` | Whether agent A may delegate to agent B. Returns `allow`/`deny` for an `(source, target)` pair. |
| **Proxy / sidecar** | `src/agent_bom/proxy.py`, `src/agent_bom/sidecar.py` | Per-method runtime policy on a single MCP server: which JSON-RPC methods are enabled, which tools are allow-listed, response-body credential redaction, approval-required gating. |
| **MCP server** | `src/agent_bom/mcp_server.py` | Exposes agent-bom's own tools (scan, blast-radius, evidence) over MCP for Claude/Cursor to consume. *Not* a policy layer; it's a tool surface. |
| **Sidecar injection webhook** | `src/agent_bom/sidecar_injector.py`, Helm `sidecarInjection` block | Mutates Pod specs at admission time so workloads get the proxy automatically. *Not* a runtime decision; it's a deploy-time injection path. |

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

Gateway, firewall and proxy processes submit reported decisions to
`POST /v1/proxy/audit`. Analyst ingestion remains supported. The server binds
tenant and receipt time to the admitted request; the caller's source name does
not authenticate the originating runtime.

New canonical gateway records carry `gateway.activity.record.v2` submission
provenance. `source_id` and `session_id` identify the submitting collector and
batch consistently in alerts, the ledger and analytics. A relay's differing
nested origins remain `reported_source_id` and `reported_session_id` inside
`submission_provenance`. Multiple reported origins in one batch are supported.
The server sets producer assurance to `caller_asserted`, discarding submitted
assurance or actor claims. Keys without a stable principal remain unidentified;
no person or producer identity is inferred from a key label.

Durability, event digests and the API audit log establish receipt and retained
record integrity. They do not prove the reported decision happened at an
authenticated producer. Consumer posture/health assessments must be read with
that evidence boundary; receipt freshness is not producer attestation.

Existing v1 records retain their bytes, digest and unknown producer assurance.
An exact canonical retry can be deduplicated without upgrading that history.
A new differing reported origin cannot be compared with v1, which did not
retain it, and remains an explicit conflict. Changed v2 actors or event claims
also conflict. Check `durable_conflict_count` and `durable_conflict_event_ids`
even on a successful batch response; conflicted records are not accepted.
Idempotency now includes authenticated submission context: an old cached
request fingerprint may return409 after upgrade. A new idempotency key allows
the unchanged canonical event to undergo ledger replay validation; it does not
bypass an event-ID conflict.

For a control-plane-connected multi-tenant gateway, an API key is first
validated by the gateway and then reused only for that tenant's audit ingest.
Each tenant has a distinct restart-stable backlog and retry state; an event is
rejected before upstream execution if its tenant does not match the validated
credential. Static gateway bearer and broker tokens remain bound to the
operator-configured `AGENT_BOM_TENANT_ID` and do not impersonate other tenants.
The restart registry stores only a bounded tenant identifier marker—never an
API key or bearer token. After restart, any discovered tenant backlog remains
degraded and blocks readiness until a newly authenticated request rebinds that
tenant's credential; malformed or unsafe registry state fails closed.

The [gateway activity store](../src/agent_bom/api/gateway_activity_store.py)
implements canonical digest, conflict and retention rules. The
[API audit log](../src/agent_bom/api/audit_log.py) records ingestion actions
separately from the producer's reported policy decision.

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
