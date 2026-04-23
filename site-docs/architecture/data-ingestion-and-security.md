# Data Ingestion and Security

This page explains how data gets into `agent-bom`, how it is normalized and used, and which security boundaries apply to each path.

The product should support four honest intake modes:

1. `Direct scan`
2. `Read-only integration`
3. `Pushed ingest`
4. `Imported artifact`

Those are not the same thing, and the security model is different for each.

## Platform record invariants

Regardless of intake mode, the persisted platform record should keep a few
stable invariants:

- `tenant_id` is normalized server-side and never trusted from ad hoc UI state
- timestamps are stored in UTC ISO-8601 form for correlation, graph windows, and audit
- collectors may differ, but the canonical model stays the same across fleet, gateway, runtime, and findings

That contract matters because graph slices, fleet rollups, runtime evidence, and
audit trails all depend on consistent tenant and time semantics.

## The four intake modes

| Mode | What agent-bom does | Typical examples | Security posture |
|------|----------------------|------------------|------------------|
| `Direct scan` | Reads local or directly reachable targets itself | MCP config discovery, project scans, image scans, IaC scans, some cloud discovery | Read-only scanner behavior |
| `Read-only integration` | Connects to an existing system that already contains the data | Snowflake governance, connector-backed discovery, cloud account inventory | Read-only connected source |
| `Pushed ingest` | Accepts evidence pushed by the customer or collector | OTLP traces, runtime events, fleet sync, security-lake feeds | Inbound ingest with API/auth boundaries |
| `Imported artifact` | Parses customer-exported files without owning collection | SBOMs, inventories, JSON findings, offline exports | File import only |

## Hosted control plane rule

In a hosted deployment, the UI is not a collector. The web app should only act
as the operator surface for the control plane.

The secure and scalable split is:

- `UI` = trigger jobs, configure sources, show health, review findings
- `API / control plane` = auth, RBAC, tenant scope, orchestration, graph, persistence, audit, and policy
- `workers / connectors` = collect from cloud APIs, connected systems, repos, images, and IaC targets
- `proxy / gateway` = capture runtime MCP evidence and apply policy at the execution boundary

That is why every supported intake path should be reachable through one of these
backend paths:

- API-triggered scan jobs
- read-only connectors
- authenticated pushed ingest
- imported artifacts
- proxy or gateway audit flows

This keeps credentials, execution, rate limits, retries, and tenant isolation
in the backend instead of moving collection logic into the Node.js UI.

## End-to-end flow

```mermaid
flowchart LR
    subgraph Inputs["Input modes"]
        A["Direct scan"]
        B["Read-only integration"]
        C["Pushed ingest"]
        D["Imported artifact"]
    end

    subgraph Normalize["Canonical normalization"]
        N1["Raw source evidence"]
        N2["Canonical entities / findings / events"]
        N3["Graph nodes / edges / paths"]
    end

    subgraph Product["Product surfaces"]
        P1["Findings"]
        P2["Remediation"]
        P3["Security Graph"]
        P4["Agent Mesh"]
        P5["Compliance / Governance"]
        P6["Runtime / Gateway / Fleet"]
    end

    A --> N1
    B --> N1
    C --> N1
    D --> N1

    N1 --> N2
    N2 --> N3

    N2 --> P1
    N2 --> P2
    N3 --> P3
    N3 --> P4
    N2 --> P5
    N2 --> P6
```

## Direct scan

Direct scan is the most local-first mode. `agent-bom` reads the target itself and derives inventory, findings, and graph context.

Typical sources:

- MCP client config discovery
- project and lockfile scans
- container image scans
- Kubernetes manifests
- Terraform, Helm, CloudFormation, Dockerfile IaC
- selected agentless cloud inventory reads

```mermaid
flowchart LR
    A["Local files / project / image / cloud API"] --> B["Scanner / discovery modules"]
    B --> C["Packages / servers / agents / cloud resources"]
    C --> D["Vulnerability + misconfiguration matching"]
    D --> E["Canonical findings + graph"]
```

Security boundaries:

- scanner mode is read-only
- no source code or credential values are sent to third parties
- outbound lookups are limited to explicit enrichment sources unless offline mode is used
- cloud discovery remains read-only and should never mutate the provider

Relevant docs:

- [Scanning & Discovery](../features/scanning.md)
- [Cloud Normalization](../features/cloud-normalization.md)
- [Permissions](https://github.com/msaad00/agent-bom/blob/main/docs/PERMISSIONS.md)

## Read-only integration

Read-only integration is for systems that already hold the relevant evidence. `agent-bom` connects to them instead of rebuilding their collection path.

Typical sources:

- Snowflake governance data
- warehouse-backed security or activity data
- connector-backed enterprise sources
- cloud account inventory where the customer grants read-only access

```mermaid
flowchart LR
    A["Customer source of truth"] --> B["Read-only connector / query path"]
    B --> C["Canonical envelopes"]
    C --> D["Findings / governance / graph context"]
```

Security boundaries:

- customer-owned source systems remain authoritative
- `agent-bom` should prefer read-only access
- no write-back to the upstream platform unless the feature explicitly says otherwise
- warehouse or lake integrations should be treated as connected sources, not hidden scan jobs

Relevant docs:

- [Backend Parity](../deployment/backend-parity.md)
- [Enterprise Deployment](https://github.com/msaad00/agent-bom/blob/main/docs/ENTERPRISE_DEPLOYMENT.md)

## Pushed ingest

Pushed ingest is for evidence that is already collected elsewhere and sent into `agent-bom`.

Typical sources:

- OTLP traces to `POST /v1/traces`
- runtime events
- fleet sync submissions
- analytics or security-lake event batches

```mermaid
flowchart LR
    A["Collector / agent / platform"] --> B["API ingest route"]
    B --> C["Validation / auth / tenant scope"]
    C --> D["Canonical event / trace records"]
    D --> E["Correlation against known assets and findings"]
```

Security boundaries:

- this is not local scanner mode; it is an API ingestion surface
- API auth, RBAC, rate limits, request size limits, and audit logging matter here
- the ingest path should preserve source evidence and timestamps
- analytics backends may store summaries or events, but the canonical model still governs the product view

Relevant docs:

- [Runtime Monitoring](../deployment/runtime-monitoring.md)
- [Security Architecture](https://github.com/msaad00/agent-bom/blob/main/docs/SECURITY_ARCHITECTURE.md)

## Imported artifact

Imported artifact is the simplest enterprise-friendly path when the customer already exports data.

Typical sources:

- CycloneDX or SPDX SBOMs
- inventory JSON
- external scanner results
- offline evidence exports

```mermaid
flowchart LR
    A["Exported file"] --> B["Artifact parser"]
    B --> C["Canonical packages / findings / metadata"]
    C --> D["Findings, remediation, compliance, graph context"]
```

Security boundaries:

- `agent-bom` parses the artifact only; it does not manage the upstream source system
- good fit for air-gapped or approval-heavy environments
- file parsing still needs validation and bounded trust assumptions

Relevant docs:

- [SBOM Generation](../features/sbom.md)
- [Canonical Model vs OCSF](canonical-vs-ocsf.md)

## Runtime, fleet, gateway, and policy surfaces

Discovery and ingest are only the front door. Once data is in the canonical model, the product exposes different operating surfaces:

| Surface | Primary purpose |
|---------|------------------|
| `Findings` | Evidence-first exploration |
| `Remediation` | Fix-first prioritization |
| `Security Graph` | Path and blast-radius analysis |
| `Agent Mesh` | Agent-centered shared-infrastructure topology |
| `Fleet` | Multi-agent operational inventory |
| `Gateway` / `Proxy` | Runtime tool-call enforcement and audit |
| `Compliance` / `Governance` | Framework and policy views |

This separation is intentional. The intake path should not be confused with the product view layered on top of it.

## How data is secured

The main security rules are:

- preserve raw source evidence only as needed for audit and debugging
- normalize into canonical `agent-bom` entities, findings, and events
- do not store credential values
- keep direct discovery read-only
- treat pushed ingest as an authenticated API boundary
- treat connected sources as explicit read-only integrations
- only project to OCSF when interoperability requires it

```mermaid
flowchart TD
    A["Raw source evidence"] --> B["Validation and redaction"]
    B --> C["Canonical normalization"]
    C --> D["Persistence / graph / analytics"]
    D --> E["Views and exports"]

    E --> F["Raw product views"]
    E --> G["Optional OCSF projection"]
```

## What leaves the machine and what does not

The short version:

- local scanning and config discovery stay local-first
- offline mode can avoid external enrichment calls entirely
- direct cloud discovery uses explicit read-only provider access
- pushed ingest sends data into `agent-bom`, not from `agent-bom` to arbitrary third parties
- optional exports and SIEM integrations are explicit, not hidden defaults

For the detailed trust model:

- [Security Architecture](https://github.com/msaad00/agent-bom/blob/main/docs/SECURITY_ARCHITECTURE.md)
- [Permissions](https://github.com/msaad00/agent-bom/blob/main/docs/PERMISSIONS.md)
- [SIEM Integration](../deployment/siem-integration.md)

## Current product stance

The product should be described honestly:

- `New Scan` is for direct scan jobs
- `Data Sources` is the map of direct scans, connected sources, pushed ingest, and imported artifacts
- `Findings`, `Remediation`, `Security Graph`, `Mesh`, `Fleet`, `Gateway`, and `Compliance` are operating surfaces after the data is in the system

That keeps the architecture:

- accurate
- interoperable
- scalable
- not marketing ahead of the actual data model
