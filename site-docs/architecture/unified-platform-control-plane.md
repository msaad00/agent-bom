# Unified Platform Control Plane

This is the product contract for `agent-bom` as a self-hosted platform.

It exists to keep the code, UI, CLI, API, docs, storage, and deployment model
aligned around one system instead of a set of loosely related tools.

## Product identity

`agent-bom` is the self-hosted control plane for:

- AI supply chain security
- AI and cloud infrastructure security
- MCP security
- agent and endpoint security
- runtime policy and audit

It should feel like one coherent operator platform across:

- scan and discovery
- fleet and endpoint inventory
- MCP inventory and granted surface area
- proxy runtime inspection and enforcement
- gateway policy and shared MCP traffic
- graph, findings, remediation, audit, and evidence

## Packaged product surfaces

The platform is shipped through multiple operator-facing surfaces that must stay
semantically aligned:

| Surface | Role in the product |
|---|---|
| **CLI** | local scans, CI-friendly execution, endpoint discovery, fleet push, remediation, exports |
| **Docker image** | isolated execution, self-hosted runtime image, API/jobs/gateway/proxy entrypoints |
| **Node.js UI** | browser control-plane workflow surface, same-origin operator experience |
| **API** | tenant-scoped control-plane contract for findings, fleet, graph, audit, policy, and auth |
| **CI/CD offering** | GitHub Action and pipeline-friendly gating for repos, images, IaC, and MCP config scans |
| **MCP server mode** | exposes `agent-bom` itself as tools to MCP-capable clients |
| **Skills** | curated MCP/agent context and productized capability surfaces that should still map back to the same model |
| **Proxy** | workload-local or endpoint-local runtime enforcement and audit |
| **Gateway** | shared MCP traffic, shared policy evaluation, upstream discovery, runtime audit |

The rule is simple:

- every surface can specialize
- no surface gets its own conflicting product model

The CLI, Docker path, CI/CD path, UI, MCP server mode, and runtime surfaces
should all describe the same entities, provenance, findings, and retention
semantics.

## Platform principles

The platform should always be:

- **self-hosted first**: runs in customer-controlled infrastructure today
- **operator-clear**: every score, finding, policy, and graph edge is inspectable
- **secure**: tenant-scoped, fail-closed where needed, auditable, policy-driven
- **scalable**: transactional control plane stays lean; event-scale history can offload
- **performant**: runtime enforcement stays close to workloads; heavy history belongs in analytics tiers
- **consistent**: CLI, API, UI, docs, and diagrams describe the same system
- **interoperable**: storage and export paths remain flexible without changing the product model

## Core surfaces

These are core product surfaces, not side features:

| Surface | What it does |
|---|---|
| **API + UI control plane** | auth, RBAC, tenant scope, graph, findings, remediation, audit, evidence, operator workflows |
| **Scan / discovery** | repos, images, IaC, skills, MCP configs, packages, and cloud surfaces |
| **Fleet** | endpoint and collector inventory, sync, last-seen state, trust/lifecycle metadata |
| **Proxy** | endpoint or workload-local runtime inspection, policy enforcement, runtime audit |
| **Gateway** | shared remote MCP traffic plane, policy pull/evaluation, runtime audit, upstream discovery |

That means the product is not just:

- a Node app
- a scanner
- an MCP server
- a proxy

It is the coordinated control plane behind all of them.

The deployment can be selective by workload, but these surfaces are all part of
the product.

## Inventory and runtime are both first-class

There are two valid starting points:

- **inventory and discovery first**
- **runtime policy and enforcement where needed**

That means:

- scans and fleet sync should already provide useful MCP inventory without proxy rollout
- proxy and gateway should deepen the same model into live runtime visibility and enforcement

Runtime is not secondary. It is a later operational layer on top of the same
canonical control plane.

## Canonical MCP provenance model

Every MCP object should be explainable through provenance, not just existence.

For each MCP server, the system should be able to say:

- discovered in repo config
- present on 14 endpoints via fleet
- registered as a gateway upstream
- runtime-observed on 3 workloads in the last 24 hours

The canonical provenance fields should cover:

| Field | Meaning |
|---|---|
| `tenant_id` | tenant ownership |
| `source_id` | source or sync origin |
| `observed_via` | `repo_scan`, `fleet_sync`, `gateway_discovery`, `proxy_runtime`, `import` |
| `observed_scope` | `repo`, `endpoint`, `cluster`, `gateway`, `runtime` |
| `deployment_mode` | `local`, `fleet`, `cluster`, `hybrid` |
| `first_seen` | first observation |
| `last_seen` | last observation |
| `last_synced` | last successful sync into control plane |
| `runtime_observed` | whether runtime evidence exists |
| `gateway_registered` | whether gateway upstream registration exists |
| `fleet_present` | whether endpoint inventory includes it |
| `repo_present` | whether repo/config discovery includes it |
| `transport` | `stdio`, `sse`, `http`, `streamable-http`, or unknown |
| `auth_mode` | best-effort posture such as `env-credentials`, `local-stdio`, `network-no-auth-observed` |
| `command` | configured local command when applicable |
| `url` | configured remote URL when applicable |
| `config_path` | where the config was discovered |

## Correlation rule

The product should correlate:

- repo scan
- fleet inventory
- gateway upstream discovery
- proxy runtime evidence

into **one MCP object** whenever they refer to the same server surface.

That correlation should power:

- Agents
- Fleet
- Registry
- Graph
- Findings and blast radius

The operator should not have to mentally join four disconnected records.

## EKS reference shape

For a customer deploying in AWS / EKS, the normal shape is:

### In EKS

- `agent-bom-api`
- `agent-bom-ui`
- scan and discovery workers / CronJobs
- `agent-bom-gateway`
- selected proxy sidecars on chosen workloads

### Outside or adjacent

- Postgres / RDS
- optional ClickHouse
- optional S3 archive / evidence / backup
- ingress, IdP, secrets, IRSA

### Data flow

1. scan jobs discover repos, images, IaC, skills, MCP configs, and cloud surfaces
2. fleet sync pushes endpoint inventory into the control plane
3. gateway contributes shared remote MCP discovery and upstream registration
4. proxy contributes runtime-observed MCP evidence where deployed
5. the UI presents one correlated inventory and policy view with provenance labels

## Storage tiers

The storage model should stay explicit:

| Tier | Role |
|---|---|
| **Postgres** | control-plane truth for transactional state |
| **ClickHouse** | event-scale analytics and runtime history |
| **S3** | evidence archive, backups, export bundles |
| **Snowflake** | warehouse-native governance and security-lake workflows where shipped parity exists |
| **Databricks** | future lakehouse target when code-backed support is shipped |

The rule is:

- the control-plane truth should not depend on every analytics backend
- analytics and lake backends should be interoperable sinks or optional deeper stores
- the product semantics should stay the same even when customers choose different storage tiers

## Retention model by data class

Retention should be explicit by data class, not "whatever the backend keeps."

| Data class | Typical intent |
|---|---|
| **Control-plane state** | findings, graph, fleet, policy, auth, exceptions, schedules; persisted until pruned by operator policy |
| **Runtime evidence** | proxy/gateway audit, traces, OCSF events; medium retention in control plane, longer retention in analytics or SIEM if enabled |
| **Compliance evidence** | signed exports, audit bundles, backup artifacts; durable retention and archive path |
| **Ephemeral runtime state** | caches, replay windows, job buffers, local spillover; bounded and short-lived |

This should be visible in:

- docs
- config
- operator UI
- archive/offload guidance

## Implementation checklist

Use this checklist to keep the platform aligned:

- [ ] canonical provenance fields exist in MCP inventory models
- [ ] API returns provenance and correlation metadata, not just summary counts
- [ ] CLI surfaces the same deployment and provenance model
- [ ] UI shows provenance pills and source rollups in Agents, Fleet, Registry, and Graph
- [ ] repo + fleet + gateway + runtime are correlated into one MCP object
- [ ] docs define retention by data class
- [ ] storage guidance is explicit for Postgres, ClickHouse, S3, Snowflake, and future lake targets
- [ ] README and deployment docs describe inventory and runtime as one coherent platform
- [ ] EKS reference architecture reflects the actual control-plane, scan, fleet, gateway, and proxy deployment shape

## Managed future

If `agent-bom` becomes hosted or managed later, the hosted product should keep
the same core guarantees:

- same canonical data model
- same policy and audit semantics
- same exportability and retention clarity
- same operator understanding of what is discovered, observed, enforced, and stored

Managed convenience should be an operational layer on top of the same platform,
not a different product.
