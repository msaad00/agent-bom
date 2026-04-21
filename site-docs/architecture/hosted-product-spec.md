# Hosted Product Control-Plane Spec

This is the next implementation spec for making `agent-bom` feel like one
coherent hosted product instead of a collection of good but partially separate
surfaces.

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

## New API surface to add next

The control plane is still missing a first-class source registry. That should
be the next backend slice.

### `Source` registry routes

| Route | Purpose |
|---|---|
| `POST /v1/sources` | create a source definition |
| `GET /v1/sources` | list sources in tenant scope |
| `GET /v1/sources/{source_id}` | load one source |
| `PUT /v1/sources/{source_id}` | update metadata, scope, labels, ownership |
| `DELETE /v1/sources/{source_id}` | disable or remove a source |
| `POST /v1/sources/{source_id}/test` | validate credentials and connectivity |
| `POST /v1/sources/{source_id}/run` | trigger a job now |
| `GET /v1/sources/{source_id}/jobs` | show source-linked job history |
| `GET /v1/sources/{source_id}/evidence` | show evidence and provenance linked to the source |

### Credential reference routes

| Route | Purpose |
|---|---|
| `POST /v1/credentials` | create a credential reference |
| `GET /v1/credentials` | list references without exposing secrets |
| `GET /v1/credentials/{credential_ref_id}` | show status, provider, scope, last validation |
| `POST /v1/credentials/{credential_ref_id}/test` | validate connectivity or role assumption |
| `DELETE /v1/credentials/{credential_ref_id}` | retire the reference |

## Worker and connector contract

Workers should never invent their own tenancy or persistence rules. They should
execute from one persisted control-plane contract.

Each queued job should include:

- `job_id`
- `tenant_id`
- `source_id`
- `job_type`
- `requested_by`
- `credential_ref_id` when needed
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

## Rollout order for the next PRs

This should land as alignment work, not surface-area sprawl.

1. **Source registry backend**  
   Add `sources`, `credential_refs`, and source-linked job metadata.
2. **Real Sources control-plane UI**  
   Replace brochure content with source list, health, status, and run actions.
3. **Schedule CRUD in UI**  
   Make recurring runs editable from the product, not only via API.
4. **Source / job / evidence linkage**  
   Add provenance views so every finding can be traced to a source and job.
5. **Auth / RBAC / tenant enforcement pass**  
   Confirm every source, job, schedule, and evidence route is tenant-scoped and role-gated.
6. **Credential reference model**  
   Support customer-managed secrets and role references without leaking secret material into the UI.
7. **Audit trail views**  
   Add source and job-level audit visibility in the product.
8. **Multi-tenant isolation hardening**  
   Make tenant ownership explicit in DB access paths, worker claims, exports, and UI filters.

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
