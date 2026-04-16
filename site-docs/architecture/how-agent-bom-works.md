# How Agent-BOM Works

`agent-bom` discovers security-relevant AI infrastructure data, normalizes it
into one canonical model, then exposes it through the right operator surfaces.

This is the shortest accurate explanation of the product.

## End-to-end flow

```mermaid
flowchart LR
    subgraph Inputs
        A["Direct scans
        agent configs
        lockfiles
        images
        IaC
        cloud reads"]
        B["Imported artifacts
        SBOMs
        inventories
        Trivy / Grype / Syft JSON"]
        C["Pushed ingest
        traces
        runtime events
        API payloads"]
        D["Read-only integrations
        cloud accounts
        governance feeds
        analytics backends"]
    end

    subgraph Engine
        E["Discovery + parsing"]
        F["Canonical normalization
        nodes
        edges
        findings
        events"]
        G["Analysis
        CVEs
        misconfigurations
        trust
        runtime correlation
        policy"]
        H["Storage + graph
        SQLite
        Postgres
        ClickHouse
        Snowflake"]
    end

    subgraph Surfaces
        I["CLI / CI"]
        J["API / UI"]
        K["MCP server"]
        L["Proxy / gateway"]
        M["Exports
        JSON
        SARIF
        CycloneDX
        SPDX
        HTML"]
    end

    A --> E
    B --> E
    C --> F
    D --> E
    E --> F --> G --> H
    H --> I
    H --> J
    H --> K
    G --> L
    H --> M
```

## What comes in

`agent-bom` supports four intake modes.

| Intake mode | What it means | Typical inputs | Best when |
|---|---|---|---|
| Direct scan | `agent-bom` reads the target itself | agent configs, projects, lockfiles, images, IaC, read-only cloud APIs | you want local or CI-native discovery |
| Imported artifact | you hand `agent-bom` an exported file | CycloneDX, SPDX, Trivy, Grype, Syft, inventories | collection already happens elsewhere |
| Pushed ingest | another system sends evidence in | traces, runtime events, audit payloads | runtime telemetry already exists |
| Read-only integration | `agent-bom` connects to an existing source | cloud accounts, governance systems, analytics backends | you want central review without modifying the source |

## What the engine does

The core flow stays the same regardless of how the data arrived.

1. Discovery and parsing
- local config discovery
- manifest and lockfile parsing
- SBOM and external scanner ingest
- cloud and infrastructure inventory reads

2. Canonical normalization
- assets become nodes
- relationships become edges
- package, IaC, runtime, and governance findings stay in one model
- OCSF remains an optional projection, not the source of truth

3. Analysis
- CVE and advisory enrichment
- misconfiguration and benchmark checks
- blast radius and attack-path building
- runtime correlation
- trust, drift, and policy evaluation

4. Storage and graph
- local and control-plane state in SQLite or Postgres
- analytics and event-scale paths in ClickHouse
- warehouse-native and governance paths in Snowflake

## What comes out

The same normalized model powers multiple purpose-built views.

| Surface | Primary job |
|---|---|
| Findings | evidence-first review |
| Remediation | fix-first queue |
| Security Graph | path and blast-radius context |
| Agent Mesh | agent-centered shared infrastructure view |
| Compliance | framework and evidence mapping |
| Governance / Activity / Traces | operational review surfaces |

## Supported surfaces

### Assets and evidence

- AI agent configs
- MCP servers and tools
- packages and lockfiles
- container images
- IaC: Terraform, Kubernetes, Helm, CloudFormation, Dockerfile
- cloud AI and infrastructure surfaces
- skills and instruction files
- model files and provenance
- runtime traces and correlated events
- SBOMs and external scanner exports

### Clouds and platforms

- AWS
- Azure
- GCP
- Databricks
- Snowflake
- additional AI/model ecosystem discovery surfaces where supported

### Formats

- JSON
- HTML
- SARIF
- CycloneDX
- SPDX
- Prometheus
- Mermaid and graph exports
- optional OCSF projection at the SIEM boundary

## Deployment models

| Deployment model | How it is used | Typical backend |
|---|---|---|
| Local CLI | developer audit, CI gate, one-off review | filesystem + optional SQLite |
| API + UI | central review, remediation, governance, fleet visibility | SQLite or Postgres, optional ClickHouse |
| MCP server | expose scanning and governance tools to MCP-capable clients | same backend as API or local install |
| Proxy / gateway | inspect and enforce runtime MCP traffic | runtime policy + audit path |
| Analytics / warehouse | central event and trend analysis | ClickHouse or Snowflake |

## Security and trust boundaries

Mode matters.

| Mode | Execution posture |
|---|---|
| Scanner mode | read-only discovery and analysis |
| MCP server mode | read-only tool surface |
| Proxy mode | live execution and enforcement boundary |

Guardrails include:

- policy and gateway enforcement
- undeclared tool blocking
- secret and credential redaction
- audit and HMAC integrity chain
- replay and rate-limit controls
- signed releases, provenance, and published self-SBOMs

## Short answer for coworkers

If someone asks “how does it get the data?”, the answer is:

`agent-bom` either scans the target directly, reads from a connected source,
accepts pushed telemetry, or ingests exported artifacts. All of those paths are
normalized into one canonical graph and findings model, then exposed through
CLI, API/UI, MCP, proxy, and export surfaces.

## Related docs

- [Architecture Overview](overview.md)
- [Data Ingestion and Security](data-ingestion-and-security.md)
- [Canonical Model vs OCSF](canonical-vs-ocsf.md)
- [Backend Parity](../deployment/backend-parity.md)
- [Security Policy](../security.md)
