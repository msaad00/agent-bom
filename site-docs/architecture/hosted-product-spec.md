# Hosted Product Control-Plane Spec

This spec tracks the hosted control-plane shape for `agent-bom`: one coherent
product surface across sources, jobs, schedules, evidence, graph, runtime
policy, and reports.

The product rule stays simple:

- `UI` drives workflows
- `API / control plane` owns auth, RBAC, tenant scope, orchestration, graph, persistence, audit, and policy
- `workers / connectors` do the privileged read and collection work
- `proxy / gateway` handles runtime MCP enforcement and audit
- the Node.js UI is **never** the collector

## Goals

1. Map every meaningful UI action to a real API route and persisted control-plane state.
2. Make source, job, schedule, evidence, and policy lifecycles visible in the product.
3. Enforce tenant scope, RBAC, and auditability across UI, API, workers, and storage.
4. Make ingest and discovery paths explicit, secure, and operable at enterprise scale.

## Canonical control-plane entities

These are the core entities the hosted product should expose directly.

| Entity | Purpose | Required fields |
|---|---|---|
| `Source` | Operator-managed data source or runtime intake path | `source_id`, `tenant_id`, `kind`, `display_name`, `status`, `owner`, `credential_mode`, `scope`, `last_run_at`, `last_success_at` |
| `Job` | One execution of a scan, sync, import, or connector run | `job_id`, `tenant_id`, `source_id`, `job_type`, `status`, `requested_by`, `started_at`, `finished_at`, `result_summary`, `evidence_count` |
| `Schedule` | Recurring execution policy for a source or scan profile | `schedule_id`, `tenant_id`, `source_id`, `cron`, `enabled`, `last_run_at`, `next_run_at` |
| `Evidence` | Immutable pointer to raw or normalized output | `evidence_id`, `tenant_id`, `job_id`, `source_id`, `kind`, `storage_uri`, `content_type`, `hash`, `created_at` |
| `CredentialRef` | Reference to customer-managed credentials or roles | `credential_ref_id`, `tenant_id`, `provider`, `mode`, `external_ref`, `last_validated_at`, `health` |
| `PolicyBinding` | Policy attached to a source, gateway, or tenant scope | `binding_id`, `tenant_id`, `policy_kind`, `target_type`, `target_id`, `mode`, `updated_at` |
| `AuditEvent` | Immutable record of control-plane actions | `event_id`, `tenant_id`, `actor`, `target_type`, `target_id`, `action`, `request_id`, `trace_id`, `timestamp` |

## Source types

Every supported intake path should map to one of these `Source.kind` values:

- `scan.repo`
- `scan.image`
- `scan.iac`
- `scan.cloud`
- `scan.mcp_config`
- `connector.cloud_read_only`
- `connector.registry`
- `connector.warehouse`
- `ingest.fleet_sync`
- `ingest.trace_push`
- `ingest.result_push`
- `ingest.artifact_import`
- `runtime.proxy`
- `runtime.gateway`

That keeps the UI model, job model, and audit model aligned even when the
collection paths differ.

The default named-connector catalog is Jira, ServiceNow, and Slack. The
Connections UI registers those under the generic `connector.cloud_read_only`
kind because the current connector registry does not expose a trustworthy
registry/warehouse family discriminator. The `connector.registry` and
`connector.warehouse` API values remain compatibility points for explicitly
installed connectors; their names alone do not prove that such a connector is
available.

## Backend model and storage expectations

The control plane should persist these entities in the transactional backend
today (`Postgres` / `Supabase`) and project them into graph or analytics stores
only where needed.

### Transactional state

- `sources`
- `source_runs` or `jobs`
- `schedules`
- `credential_refs`
- `source_policy_bindings`
- `evidence_index`
- `audit_events`
- `tenant_settings`

### Derived or projected state

- findings and graph nodes
- fleet inventory
- compliance snapshots
- gateway and proxy alerts
- long-retention event history in optional analytics backends

## Existing API routes the hosted product already uses

These routes are already code-backed and should remain the foundation of the
product surface.

| Product surface | Existing routes |
|---|---|
| Scan jobs | `POST /v1/scan`, `GET /v1/scan/{job_id}`, `GET /v1/scan/{job_id}/stream`, `GET /v1/jobs`, `DELETE /v1/scan/{job_id}` |
| Scan exports | `GET /v1/scan/{job_id}/graph-export`, `/licenses`, `/vex`, `/skill-audit` |
| Schedules | `POST /v1/schedules`, `GET /v1/schedules`, `GET /v1/schedules/{schedule_id}`, `PUT /v1/schedules/{schedule_id}/toggle`, `DELETE /v1/schedules/{schedule_id}` |
| Fleet | `GET /v1/fleet`, `GET /v1/fleet/stats`, `GET /v1/fleet/{agent_id}`, `POST /v1/fleet/sync` |
| Runtime proxy | `POST /v1/proxy/audit`, `GET /v1/proxy/status`, `GET /v1/proxy/alerts` |
| Gateway | `GET/POST/PUT/DELETE /v1/gateway/policies`, `POST /v1/gateway/evaluate`, `GET /v1/gateway/audit`, `GET /v1/gateway/stats`, `GET /v1/gateway/upstreams/discovered` |
| Connectors | `GET /v1/connectors`, `GET /v1/connectors/{name}/health` |
| Pushed ingest | `POST /v1/traces`, `POST /v1/results/push` |
| Auth / audit | `/v1/auth/*`, `/v1/audit*`, `/v1/exceptions*` |
| Findings / posture / graph | `/v1/assets*`, `/v1/graph*`, `/v1/compliance*`, `/v1/posture*`, `/v1/governance*` |

## Source and credential API surface

The control plane now has first-class source and credential-reference routes.
They are tenant-scoped and RBAC-gated, and should remain the canonical backend
for the Connections and Sources product surfaces. The remaining work is
productization: customer-0 bootstrap, hosted smoke tests, connection validation
clarity, and source-to-evidence provenance.

### `Source` registry routes

| Route | Purpose |
|---|---|
| `POST /v1/sources` | create a source definition |
| `GET /v1/sources` | list sources in tenant scope |
| `GET /v1/sources/{source_id}` | load one source |
| `PUT /v1/sources/{source_id}` | update metadata, scope, labels, ownership |
| `DELETE /v1/sources/{source_id}` | disable or remove a source |
| `POST /v1/sources/{source_id}/test` | validate stored scan configuration and connector health |
| `POST /v1/sources/{source_id}/run` | trigger a job for direct-scan, artifact-import, or named-connector kinds; push/runtime kinds return `409` |
| `POST /v1/sources/run-cohort` | launch 2-32 exact runnable source IDs as one tenant-bound immutable cohort; requires `Idempotency-Key` and records a strict freshness bound for automatic correlation |
| `GET /v1/sources/{source_id}/jobs` | show source-linked job history |

Source-linked evidence is currently reached through the job records returned by
`GET /v1/sources/{source_id}/jobs` and the existing job export routes. There is
no separate source-evidence endpoint.

Recurring cohorts use the same contract in a scan schedule: set
`scan_config.source_ids` to 2-32 exact registered source IDs and optionally set
`scan_config.max_age_hours` (default `168`). Each scheduled occurrence receives
its own deterministic cohort ID; retries of that exact occurrence reuse it.
Membership is never inferred from source names, labels, image tags, or whichever
snapshot happens to be newest. Push-driven runtime sources remain ingest-owned
and cannot be launched through this route.

### Credential reference routes

| Route | Purpose |
|---|---|
| `POST /v1/credentials` | create a credential reference |
| `GET /v1/credentials` | list references without exposing secrets |
| `GET /v1/credentials/{credential_ref_id}` | show status, provider, scope, last validation |
| `PUT /v1/credentials/{credential_ref_id}` | update reference metadata and lifecycle status |
| `POST /v1/credentials/{credential_ref_id}/test` | validate reference shape and, for supported providers, the control plane's default identity reachability |
| `DELETE /v1/credentials/{credential_ref_id}` | retire an unreferenced record; returns `409` until attached sources are detached |

Credential references are metadata records, not executable secret bindings.
The test route does not assume a referenced role or resolve secret material.
Runnable sources therefore use brokered cloud connections or connector
credentials configured on the self-hosted control plane.
`credential_mode` is canonicalized to `none` or `reference` (`credential_ref`
is accepted as a legacy alias for `reference`). An explicit `null` on
`SourceUpdate.credential_ref` detaches a reference; omitted fields remain
unchanged.

## Worker and connector contract

Workers should never invent their own tenancy or persistence rules. They should
execute from one persisted control-plane contract.

Each queued job should include:

- `job_id`
- `tenant_id`
- `source_id`
- `job_type`
- `requested_by`
- an executable brokered connection or server-side connector configuration when credentials are needed
- `scope`
- `policy_bindings`
- `trace_id`
- `idempotency_key`

Each worker result should emit:

- normalized summary
- raw evidence reference
- findings and graph updates
- connector or scan health
- audit event on success, partial success, timeout, or failure

## UI surfaces to productize

The next UI work should make the control plane legible rather than adding more
static explanation pages.

| Screen | Purpose | Must show |
|---|---|---|
| `Sources` | source registry and connector health | source status, credential mode, scope, last run, last result |
| `Source detail` | one source end to end | jobs, schedules, evidence, audit trail, linked findings |
| `Schedules` | recurring collection control | cron, enabled state, next run, last run outcome |
| `Jobs` | execution lifecycle | running, queued, failed, retried, evidence count |
| `Evidence / provenance` | why a result exists | source, job, collector, raw artifact references |
| `Auth / tenant` | operator trust model | auth mode, tenant scope, role, active policy mode |
| `Gateway / runtime` | runtime control plane | policies, alerts, upstream discovery, audit |

## Security and isolation rules

These rules should be enforced in both the API and background execution paths.

- every `Source`, `Job`, `Schedule`, `Evidence`, and `AuditEvent` is tenant-bound
- RBAC is checked at the API boundary and rechecked in worker claim logic where needed
- credential material is referenced, not echoed back into the UI
- imports and pushed ingest use idempotency keys and request-size limits
- audit events are emitted for create, update, run, toggle, delete, export, allow, and block actions
- gateway and proxy events carry tenant context, source identity, and trace correlation

## Remaining hosted-product rollout

The core source and credential route layer has landed. The next work should be
alignment and hosted-readiness work, not unrelated surface-area sprawl.

1. **Customer-0 bootstrap**
   Provide an operator script or runbook path that creates one tenant-bound
   admin/API key without requiring an already-authenticated browser session.
2. **Hosted POC smoke**
   Test login, connect, scan, scan detail, findings, graph, compliance export,
   and audit export against the hosted compose profile.
3. **Connection test clarity**
   Keep "test and scan" clear in the UI, or add a standalone connection
   validation route for roles and warehouse credentials.
4. **Source / job / evidence linkage**  
   Continue tightening provenance views so every finding can be traced to a
   source and job.

## Short implementation rule

If the UI cannot answer these for a given data path, the hosted product is not
finished yet:

- what source was configured
- who owns it
- how it authenticates
- what tenant it belongs to
- when it last ran
- what it collected
- where the evidence came from
- what policy and audit trail apply to it
