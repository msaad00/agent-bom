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

Producer-supplied `trace_id` remains part of canonical event identity. When it
is absent, the API uses the stable `event_id` as the correlation fallback. The
first request's trace is retained separately as `receipt_trace_id`; like receipt
time, it is excluded from event-digest comparison and is not rewritten by a
retry. Request/audit correlation remains available without turning a new HTTP
request trace into a changed producer event. Historical records without this
receipt field retain their original serialization. A pre-upgrade event whose
trace was filled from an HTTP request can still conflict when retried without
that original trace; stored history is not silently rewritten.

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

## Resumable gateway activity

After configuring authenticated gateway audit ingest, read its canonical
activity from the control plane:

```bash
curl --no-buffer --fail-with-body \
  -H "X-API-Key: ${AGENT_BOM_API_KEY}" \
  "${AGENT_BOM_API_URL}/v1/gateway/feed/stream?limit=100"
```

The artifact is an SSE stream of metadata-only `activity` frames. Each frame
contains up to 500 canonical records in **ingest ordinal order**, including
tool decisions, DLP actions, profile denials, warnings, and enforcement outcomes.
Profile, blueprint, policy, evidence, and trace references remain distinct.
Submission provenance retains its `unknown` or `caller_asserted` assurance;
neither a received frame nor a heartbeat attests producer enforcement.

Save the frame's `id` after processing its **entire** JSON batch. Resume with
`Last-Event-ID: <saved-id>` or `?cursor=<saved-id>`. The header wins when both
are present, so a browser reconnect does not reuse a stale initial query
cursor. A `next_cursor` from `/v1/gateway/feed` can also start the stream. With
no cursor, the stream begins at the oldest retained event, drains history,
then polls for new commits. An empty ledger emits a `checkpoint` frame with a
cursor that still catches events appended immediately after that read.

This stream covers **canonical gateway activity only**. Legacy process-local
alerts and LLM cost observations remain on the REST compatibility projection;
they have no shared ledger ordinal. Historical records removed by retention
are unavailable, as indicated by `retention_floor_ordinal`. Replaying an
unacknowledged frame after a client crash is possible: consumers should commit
their batch and cursor together or deduplicate by event ID. Store deduplication
is bounded by the reported `dedupe_window_events`.

| Condition | Behavior and next step |
|---|---|
| Anonymous caller, including loopback | HTTP 401; authenticate with a read-capable API key, browser session, or attested proxy identity. |
| Malformed, future, or cross-tenant cursor | HTTP 400; do not switch tenants or silently discard the cursor. |
| Cursor older than retention | HTTP 410 before streaming, or terminal `gap` after streaming starts; stop automatic reconnect, record the missing history, and explicitly reset to retained history. |
| Ledger unavailable | HTTP 503, or terminal `unavailable`; back off and reconnect from the last processed cursor. No ring-buffer fallback. |
| Ephemeral memory backend | HTTP 503; configure SQLite for one node or shared Postgres for replicas. |
| Stream capacity exhausted | HTTP 503 with `Retry-After: 5`; retry with backoff. Capacity is 64 active streams per API worker. |
| Normal connection renewal | Terminal `reconnect`; reconnect from the saved cursor through authentication again. |

Connections renew after 30 seconds of iteration; a blocked send times out
after 5 seconds. Revocation/expiry is rechecked on the next authenticated
connection, rather than continuously during an existing connection. SSE
comments every 10 seconds maintain the transport without advancing the cursor.
Backfill and tailing use the same ledger reads, with no process-local subscribe
handoff; database work runs off the event loop and holds no DB connection while
waiting to send. Configure ingress to permit streaming, disable response
buffering, and allow idle periods longer than the heartbeat interval. The stream
sends `Cache-Control: no-store, no-transform` so intermediary compression does
not buffer activity until connection renewal.

Rollback is additive: stop stream consumers and use `/v1/gateway/feed` REST
readback. This endpoint requires no schema migration and changes no gateway
enforcement settings. The dashboard consumes this stream and retains its last
complete batch and cursor across transport reconnects.

Local SQLite restart/readback and API contracts remain distinct from the
Helm/Postgres deployment probe described below.

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

### Producer assurance in runtime views

Gateway feed events expose `producer_assurance` as `unknown` or
`caller_asserted`. An authenticated collector may report a producer; storage
integrity and a fresh receipt do not authenticate that reported producer.
Historical records without submission provenance remain `unknown`.

Feed and KPI responses expose `producer_assurance_counts` with
`producer_assurance_count_basis: classified_events`. Feed counts describe the
returned page; KPI counts describe classified events in the stated retained
window. These include data-filter and LLM records, so they are not a replacement
for tool-call totals. Unknown assurance does not mean an event is absent.
Window completeness and receipt freshness retain their separate fields.

Proxy status includes receipt health with `assurance_basis: transport_receipt`.
A recent server receipt can report live transport while producer assurance
remains unknown. Configuration alone indicates a connected/configured runtime
surface and does not establish a live producer.

The runtime production index counts alert and metrics submissions under
`producer_assurance_count_basis: submissions`; a metrics summary may describe
many calls. Blueprint comparison reports `comparison_scope:
reported_activity_only`: an aligned result covers submitted activity only,
not producer identity, unreported activity, or an approval of the deployment.

## Managed profile CLI and SDK

Use the authenticated control-plane API with a tenant and an operator credential.
`agent-bom runtime profiles` manages server-side MCP config assignments bound to
managed agent identities. `agent-bom profiles` remains the local CLI configuration
selector. The assignment `config_id` is the runtime profile ID; its creation
`profile_id` selects the identity's role blueprint.

```bash
export AGENT_BOM_API_URL=https://control-plane.example.com
export AGENT_BOM_TENANT_ID=tenant-a
# Inject AGENT_BOM_API_TOKEN through the operator's secret mechanism.
agent-bom runtime profiles create --file managed-profile.json
agent-bom runtime profiles list
agent-bom runtime profiles validate CONFIG_ID --environment prod --scope tools:read
agent-bom runtime profiles test CONFIG_ID --environment prod --scope tools:read \
  --upstream filesystem --tool read_file
```

The JSON creation file uses the existing `/v1/mcp-config/assignments` contract:
`name`, role-blueprint `profile_id`, `connector_ids`, managed `identity_id`, and
`environment`, plus optional tool, scope, policy and connection constraints.
Create requires an identity already provisioned in this tenant and a matching
blueprint. Creation needs config permission; listing and authenticated contract
previews need read permission. Responses contain assignment IDs and revisions,
which can be used in the next command without copying credentials.

Validate and test call `POST /v1/runtime/profiles/evaluate` with hypothetical
issuer, environment and granted scopes. The canonical relay profile resolver
checks tenant/identity bindings, lifecycle, expiry and constraints. Test also
checks the proposed upstream/tool. A denied preview exits nonzero. Every result
is marked `scope: profile_contract_only` and `executed: false`: a successful
preview neither verifies a caller token nor runs an upstream, firewall, policy,
quota or DLP check. Storage failures deny evaluation; anonymous requests are
rejected even in development no-auth mode. Evaluation is audited without tool
arguments or credentials.

Python `AgentBomClient` provides `runtime_profiles`, `create_runtime_profile`,
`get_runtime_profile`, `update_runtime_profile`, `revoke_runtime_profile`,
`validate_runtime_profile`, and `test_runtime_profile`. The TypeScript client
provides the equivalent camelCase methods. Updates send `expected_revision` and
retain the existing optimistic-concurrency contract. Revoke is the rollback for
an unwanted assignment; a stale or revoked profile fails closed at relay.

## Checkpointed activity command

```bash
agent-bom runtime feed --cursor-file ./prod-activity.cursor.json --follow \
  > activity-batches.jsonl
```

Each JSON line contains an SSE event, cursor ID and a complete canonical activity
batch. The cursor file is atomically replaced with owner-only permissions after
the batch is printed and stdout is flushed. It is bound to the API URL and tenant;
use a separate file for each consumer. A crash after output but before checkpoint
can replay a batch: downstream consumers must deduplicate `event_id`. The cursor
is an acknowledgement of local output, not proof that an external sink committed
it. Do not share a cursor file between concurrently running consumers.

The command reconnects from its last completed batch and reauthenticates on each
connection. Five consecutive transport failures stop follow mode. A retention
gap, invalid cursor, authentication failure or unavailable ledger stops with a
nonzero exit and preserves the checkpoint. Inspect the outage/retention boundary
before explicitly starting with a new cursor file; the CLI never silently resets
it. Without `--follow`, it reads one bounded server connection and exits.

Python `client.gateway_activity(cursor=...)` and TypeScript
`client.gatewayActivity({ cursor, signal })` yield complete frames for one
connection. Save an activity/checkpoint ID only after consuming its entire batch,
then reconnect with that ID. Both clients expose terminal `gap`, `unavailable`
and `reconnect` events, reject malformed batches, and discard partial frames on
disconnect. Close/break the iterator to release the HTTP response. These commands
require the durable SQLite/Postgres activity store and its configured retention;
the process-local metrics socket cannot supply this history.

## Dashboard profile lifecycle and resumable activity

Open `/runtime?tab=gateway`. **Live Feed** reads canonical gateway activity over
an authenticated SSE connection. Complete batches advance the in-memory resume
cursor; connection loss reconnects from that cursor. The metrics socket no longer
drives this panel. The view shows the newest 1,000 received records. **Browse
retained history** pages the same canonical contract from the oldest retained
record, including profile/enforcement outcomes and their policy/evidence IDs.
Historical paging uses its own cursor and does not interrupt the live cursor.
Reloading the page starts at the retained floor; no cursor or activity is persisted
in browser storage.

An expired or invalid cursor stops with an explicit gap. **Start a new retained
window** is the operator's explicit reset; ordinary **Reconnect** retains the
cursor. Authentication, unavailable-store and malformed-response errors never
fall back to a latest-200 metrics refresh. Subject or tenant changes clear the local
view and cursors. Receipt time, reported time and producer assurance remain
separate evidence; a connected transport does not authenticate the producer.

Use **Runtime profiles** to inspect assignment status, environment, identity,
blueprint, revision and constraints. Administrators can create a profile from an
active managed identity, update it with the displayed expected revision, or revoke
it after explicit confirmation. A revision conflict keeps the editor open and asks
for a reload. The list includes revoked assignments and explicitly reports its
1,000-assignment display limit when reached.

**Validate profile** previews its stored issuer, environment and required scopes.
**Test saved profile** adds a proposed upstream/tool and excludes unsaved edits.
Results state that they are simulations: these actions do not execute tools,
verify caller credentials, or exercise live firewall, DLP, policy or quota checks.
Read-only users can inspect and preview; the API enforces permissions on every
request. Browser writes use the existing session cookie and CSRF header boundary.

## Reproduce gateway deployment acceptance

The disposable-kind probe installs the actual Helm chart with two API replicas,
one PVC-backed gateway, and TLS-enabled Postgres. It sends 205 real JSON-RPC
calls to a synthetic upstream through enforced managed identity/profile checks,
reads their authenticated durable activity, restarts an API pod and the gateway,
and verifies seven further calls through the replacement API using the saved
cursor. It checks contiguous ordinals, event uniqueness, profile attribution,
foreign-tenant cursor rejection, and preservation of the gateway PVC.

```bash
docker build --build-arg AGENT_BOM_EXTRAS=api,postgres -t agent-bom:runtime-acceptance .
kind create cluster --name runtime-acceptance --kubeconfig /tmp/runtime-kubeconfig
kind load docker-image agent-bom:runtime-acceptance --name runtime-acceptance
python3 scripts/demo/check_runtime_reconnect.py \
  --kubeconfig /tmp/runtime-kubeconfig --output /tmp/runtime-helm-proof.json
kind delete cluster --name runtime-acceptance
```

The probe removes its namespace and Helm release on success or failure; the
caller removes the cluster. It requires Docker, kind, kubectl, Helm, OpenSSL,
and Python. Its JSON artifact is written only after every assertion and cleanup
succeeds. Record a clean source commit and the image identity before treating a
run as release evidence. CI pins kind, Helm and the Kubernetes node image.

For browser acceptance, build the production dashboard with Node 22, copy
`.next/static` to `.next/standalone/.next/static` and `public` to
`.next/standalone/public`, install Playwright Chromium, and add `--ui-root ui`.
The browser uses a short-lived signed session verified by the real Helm API
through the production Next proxy. It checks light/dark desktop/mobile layouts,
persisted activity and profile presentation, retained rows during a real
port-forward interruption, and reconnect with `Last-Event-ID`. Screenshots are
written beside the JSON artifact. No API response fixtures replace this path.

The `Runtime Helm Acceptance` workflow repeats this deployment and browser
proof for affected changes. `tests/api/test_gateway_runtime_acceptance.py`
separately exercises allow, profile/policy block, PII redaction, secret blocking
and visual redaction through gateway emission, authenticated ingest, SQLite
reopen and signed-session SSE resume. Its upstream and OCR detector are fixtures.

Proof boundaries: the deployment probe uses a synthetic upstream and locally
signed browser session, not an external identity-provider login. Its self-signed
Postgres TLS checks do not certify a managed provider, ingress TLS, network-policy
enforcement or multi-node failure. A single persistent gateway restart does not
prove concurrent gateway replicas or audit delivery during a total control-plane
outage. Missing/foreign auth and invalid tenant cursors fail closed; a transport
failure preserves the last complete browser batch until authenticated reconnect.

Managed identity lookup now requires schema component version 2. Run Alembic
migrations before starting API/gateway replicas: the additive migration creates
and backfills `agent_id`, then records readiness. A version-1 database fails
closed at store initialization. Legacy databases without identity tables receive
no readiness marker; provision the runtime schema before enabling profiles.
Application rollback preserves the added column,
index and identity/revocation data; the downgrade does not delete them.
