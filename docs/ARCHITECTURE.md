# Architecture

One `agent-bom` product, multiple operational surfaces. The package exposes
CLI entry points, API/UI, MCP server mode, runtime proxy/gateway, cloud posture,
IaC scanning, fleet, graph, reporting, and compliance workflows over the same
core evidence model.

> **Product overview lives in [`HOW_IT_WORKS.md`](HOW_IT_WORKS.md)** — the
> canonical five-stage flow (intake → scan → evidence → control → artifacts) and
> the symbol-level CVE reachability differentiator. This document is the deeper
> surface and module architecture: it leads with the product mental model, then
> the implementation stack.

---

## 1. System Overview — Product Surfaces

```
pip install agent-bom    → shared core engine plus focused CLI entry points
```

Read the architecture in one direction: collect evidence, normalize it into one
AI-BOM/security model, then use that same model for local scans, the
self-hosted control plane, runtime enforcement, and audit/compliance outputs.
This diagram is intentionally a product map, not a full module graph.

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="images/architecture-dark.svg">
  <img alt="agent-bom architecture: sources to scan/ingest to unified Finding and ContextGraph to control plane to consumers" src="images/architecture-light.svg">
</picture>

```mermaid
flowchart TB
    Sources["1. Evidence sources\nRepos, lockfiles, SBOMs\nAgents, MCP servers, tools\nCloud, IaC, containers, GPUs\nRuntime proxy and gateway events"]
    Model["2. Shared evidence model\nInventory\nFindings + enrichment\nSecurity graph\nAudit + provenance"]
    Surfaces["3. Product surfaces\nLocal scan: CLI, Docker, GitHub Action\nControl plane: REST API, UI, fleet, Helm\nRuntime enforcement: MCP server, proxy, gateway, Shield"]
    Outputs["4. Decisions and artifacts\nDeveloper gates: terminal, SARIF, HTML\nSecurity triage: blast radius, graph paths\nGovernance: compliance evidence, audit trail\nOperations: fleet state, runtime blocks"]

    Sources --> Model --> Surfaces --> Outputs
```

| Surface | First command | Primary artifact | Production move |
|---|---|---|---|
| Local scan | `agent-bom agents -p .` | findings, SBOM, SARIF, HTML, graph export | GitHub Action or Docker scan in CI |
| Control plane | `agent-bom agents -p . --push-url ...` | fleet inventory, scan jobs, graph state | Helm/EKS with Postgres and tenant auth |
| Runtime enforcement | `agent-bom proxy ...` or `agent-bom mcp server` | audit JSONL, policy decisions, blocks | gateway/proxy sidecars and Shield SDK |

For a repo-level map of where each layer lives in `src/agent_bom/`, see
[`PROJECT_STRUCTURE.md`](../PROJECT_STRUCTURE.md). For role-based entry paths,
see [`START_HERE.md`](START_HERE.md).

---

## 1a. Layered Stack

The product reads top to bottom: inputs are normalized into one `Finding` and
one `ContextGraph`, the control plane serves and enforces over that evidence,
and outputs flow to both humans and headless agents. Each layer carries a single
**value** line — what it buys you, not just what it is.

```mermaid
flowchart TB
    subgraph L1["Inputs - meet teams where their evidence already lives"]
        IN["Repos · lockfiles · SBOMs\nContainer images · IaC\nMCP configs · repo URLs\nCloud accounts · runtime events"]
    end
    subgraph L2["Scanners - breadth without standing up agents"]
        SC["Discovery · parsers (15 ecosystems)\nOSV/advisory scanners · cloud · IaC · SAST · secrets"]
    end
    subgraph L3["Unified Finding - one model, so triage never forks per source"]
        FD["Finding + enrichment\nNVD CVSS · EPSS · KEV · GHSA · compliance tags"]
    end
    subgraph L4["ContextGraph - turn a CVE row into a reachable blast radius"]
        GR["UnifiedGraph\nattack-path fusion · blast reach · exposure scoring"]
    end
    subgraph L5["Control plane - same evidence, multi-tenant + audited"]
        direction TB
        MW["Middleware: auth · RBAC · tenant scope · rate-limit · audit"]
        API["REST API (300 ops)"]
        GW["Gateway / MCP server / proxy"]
        MW --> API
        MW --> GW
    end
    subgraph L6["Outputs - decisions in the format each consumer already trusts"]
        OUT["SARIF · CycloneDX · SPDX · OCSF\nHTML · PDF · JSON · CSV · webhooks"]
    end
    subgraph L7["Consumers - one model, two audiences"]
        HUM["Humans: CLI · UI cockpit"]
        AG["Headless: MCP tools · REST API"]
    end

    L1 --> L2 --> L3 --> L4 --> L5 --> L6 --> L7
```

---

## 1b. Implementation stack — hermetic and single-language

With the product mental model in place, the implementation detail: agent-bom is
pure Python (3.11+) end to end — CLI, FastAPI surface, MCP server, parsers,
OSV/NVD/EPSS/KEV/GHSA enrichment, blast-radius scoring, IaC engine, and CIS
benchmarks all live in the same interpreter. There is no Rust/Go/CGo extension
on the scan path. Disk-image scans use native `dpkg` / RPM parsers
(`src/agent_bom/filesystem.py`); the `syft` Go binary is opt-in only as a
tar-archive fallback for VM-style images.

Operational consequences:

- One language, one dep tree, one pip-audit/SBOM surface to audit and reproduce.
- Wheels build cleanly on `linux/amd64` and `linux/arm64` — no per-arch native toolchain.
- Slower than Rust/Go scanners on huge fanouts; per-package memory is higher. For VM disk-image scanning at scale, install `syft` alongside agent-bom and let the fallback path take over.

---

## 1c. Data Flow - one scan request

A single scan request walks discovery → extraction → scan → finding → graph →
outputs. The same lower libraries serve the CLI and the API.

```mermaid
flowchart LR
    REQ["Scan request\n(repo / path / image /\nSBOM / MCP config / URL / cloud)"]
    DISC["Discovery\nfind agents, MCP servers, targets"]
    EXT["Extraction\nparse packages, manifests, configs"]
    SCAN["Scan\nOSV batch + advisories"]
    ENR["Enrichment\nCVSS · EPSS · KEV · GHSA · compliance"]
    FIND["Unified Finding\nnormalized, deduped, scored"]
    GRAPH["ContextGraph\npackage → finding → server → tool → cred → agent"]
    OUT["Outputs\nconsole · SARIF · SBOM · HTML · graph export · webhooks"]

    REQ --> DISC --> EXT --> SCAN --> ENR --> FIND --> GRAPH --> OUT
```

**Value at each hop:** discovery finds shadow AI you did not know to ask about ·
extraction reads 15 ecosystems with one command · enrichment ranks by real-world
exploitability, not just CVSS · the graph makes "which agent does this reach?"
answerable · outputs land in the gate, ticket, or SIEM you already run.

---

## 1d. Frontend · Backend · Middleware

The dashboard is one door into the product, not the only one. The Next.js UI and
every headless caller hit the same FastAPI surface, behind the same middleware,
over the same stores.

```mermaid
flowchart TB
    subgraph FE["Frontend - human cockpit"]
        UI["Next.js 16 · React 19 · Tailwind 4\ninventory · findings · graph · compliance · runtime"]
    end
    subgraph MW["Middleware - one enforcement seam for every caller"]
        M1["TrustHeaders"]
        M2["API key · auth · RBAC · tenant scope"]
        M3["Rate limit"]
        M4["Max body size"]
    end
    subgraph BE["Backend - FastAPI"]
        R["365 REST operations across 43 route modules
plus 2 WebSocket routes"]
    end
    subgraph ST["Stores - start on SQLite, scale to a cluster without rewrites"]
        S1["SQLite (default / single node)"]
        S2["Postgres (multi-replica)"]
        S3["Graph store · optional Snowflake / ClickHouse"]
    end

    EXTAGENT["Headless: MCP server · REST API · SDK clients"]

    UI -->|HTTPS| MW
    EXTAGENT -->|HTTPS| MW
    MW --> BE --> ST
```

**Value:** the middleware seam means auth, tenant isolation, and audit are
enforced once for the UI, agents, and SDKs alike — there is no privileged
"UI-only" backdoor.

---

## 1e. Auth & Connections

The identity and connection model is **connect once, act through the stored
connection** — no surface ever prompts for a per-action credential.

- **Humans** sign in via OAuth / OIDC / SAML SSO (standard providers plus a
  Snowflake OAuth authorization-code + PKCE flow), with SCIM provisioning —
  `src/agent_bom/api/{oidc,saml,scim}.py`, `src/agent_bom/api/snowflake_oauth.py`.
- **Agents / CI** use scoped API keys / tokens.
- **Sources** (AWS, Azure, GCP, Snowflake) are onboarded once via read-only,
  agentless, brokered connectors — one least-privilege managed role per source,
  short-lived brokered credentials (e.g. AWS `sts:AssumeRole`), and write-only
  secrets (encrypted at rest, never read back). Every scan then runs through that
  stored connection.

Auth mode, tenant scope, RBAC, and audit are enforced in the shared middleware
(`src/agent_bom/api/middleware.py`) for every caller. Provider grants and setup
are in [`CLOUD_CONNECT.md`](CLOUD_CONNECT.md); the enterprise auth surface and
environment knobs are in [`ENTERPRISE.md`](ENTERPRISE.md).

---

## 1f. Input / Output Formats

agent-bom is format-agnostic on both ends: ingest whatever evidence exists,
emit whatever the next tool consumes.

```mermaid
flowchart LR
    subgraph INPUTS["Inputs - no pre-instrumentation required"]
        I1["Repo / path"]
        I2["Container image"]
        I3["SBOM"]
        I4["MCP config"]
        I5["Repo URL"]
        I6["Cloud account"]
        I7["IaC files"]
    end
    CORE["Unified Finding\nplus ContextGraph"]
    subgraph OUTPUTS["Outputs - drop into the tool you already run"]
        O1["SARIF - code scanning"]
        O2["CycloneDX - SBOM"]
        O3["SPDX - SBOM"]
        O4["OCSF - SIEM"]
        O5["HTML / PDF - review"]
        O6["JSON / CSV - automation"]
        O7["Webhooks - alerting"]
    end

    I1 & I2 & I3 & I4 & I5 & I6 & I7 --> CORE
    CORE --> O1 & O2 & O3 & O4 & O5 & O6 & O7
```

| Input | Value | Output | Value |
|---|---|---|---|
| Repo / path | scan source where it lives | SARIF | native code-scanning ingest |
| Container image | catch base-image + layer risk | CycloneDX / SPDX | portable SBOM for downstream tooling |
| SBOM | re-score an existing inventory | OCSF | normalized SIEM events |
| MCP config | map the agent ↔ server ↔ tool mesh | HTML / PDF | human-reviewable evidence |
| Repo URL | scan code you have not cloned | JSON / CSV | machine-readable for pipelines |
| Cloud account | read-only estate + CIS posture | Webhooks | push to alerting / ticketing |
| IaC files | block unsafe infra pre-deploy | | |

---

## 2. Scan Pipeline

Sequence of operations from invocation to report.

```mermaid
sequenceDiagram
    participant User
    participant CLI
    participant Discovery
    participant Scanner
    participant Enrichment
    participant BlastRadius
    participant Reporter

    User->>CLI: agent-bom agents [options]
    CLI->>Discovery: Detect MCP configs, images, clouds
    Discovery-->>CLI: Agents, servers, packages, tools

    CLI->>Scanner: Package list
    Scanner->>Scanner: OSV batch query
    Scanner-->>CLI: Raw CVE results

    CLI->>Enrichment: CVE IDs
    Enrichment->>Enrichment: NVD CVSS · EPSS · CISA KEV · GHSA
    Enrichment-->>CLI: Enriched vulnerabilities

    CLI->>BlastRadius: Vulns + topology
    BlastRadius->>BlastRadius: package → finding → server → agent → creds → tools
    BlastRadius->>BlastRadius: Tag 15 frameworks + attach AISVS benchmark
    BlastRadius-->>CLI: Scored + tagged findings

    CLI->>Reporter: Full results
    Reporter-->>User: Console / JSON / SARIF / HTML / SBOM
```

### Component model and extensibility direction

The pipeline is built from four component roles: **scanners** (discover and
produce raw findings), **enrichers** (add CVSS/EPSS/KEV/GHSA, compliance, cloud
and cost context), **matchers/correlators** (`correlate.py`,
`cross_env_correlation.py`, graph overlays), and a **reporter**. Scanner drivers
are already registered through `scanners/registry.py` with capability metadata
(surfaced by `agent-bom capabilities`), and `api/pipeline.py` (`ScanPipeline`,
`_run_scan_sync`) runs the stages and emits per-step DAG events.

Two seams are being formalized so new sources and detections plug in without
editing core orchestration:

- a **router** that resolves an input or connected source (path, image ref,
  cloud credential, MCP config, ingested SARIF) to the scanner and provider
  drivers that handle it, consolidating selection logic currently split across
  the CLI, the pipeline, and `scanners/__init__.py`; and
- an **orchestrator** that runs registered `scan → enrich → correlate → graph →
  findings` stages, with enrichers and matchers registered through the same
  capability-metadata pattern scanners already use.

This keeps detection-as-code rule packs and additional providers additive at the
registry boundary rather than as edits to the scan path.

---

## 3. Blast Radius Propagation

How one CVE propagates through the AI agent stack.

```mermaid
graph LR
    CVE["CVE-2025-XXXX\nCRITICAL · CVSS 9.8"]
    PKG["Vulnerable Package\nnpm / PyPI / Go"]
    SRV["MCP Server\nunverified · root"]

    AGT1["Cursor IDE\n4 servers · 12 tools"]
    AGT2["Claude Desktop\n3 servers · 8 tools"]

    CRED["ANTHROPIC_KEY\nAWS_SECRET · DB_URL"]
    TOOL["query_db · read_file\nwrite_file · run_shell"]

    CVE -->|affects| PKG
    SRV -->|depends_on| PKG
    SRV -->|vulnerable_to| CVE
    AGT1 & AGT2 -->|uses| SRV
    SRV -->|exposes_cred| CRED
    SRV -->|provides_tool| TOOL
    CRED -->|reaches_tool| TOOL

    style CVE fill:#dc2626,color:#fff
    style PKG fill:#ea580c,color:#fff
    style SRV fill:#d97706,color:#fff
    style AGT1 fill:#2563eb,color:#fff
    style AGT2 fill:#2563eb,color:#fff
    style CRED fill:#7c3aed,color:#fff
    style TOOL fill:#059669,color:#fff
```

**Color key:** Red = CVE · Orange = Package · Amber = Server · Blue = Agent · Purple = Credentials · Green = Tools

The full contract for what the graph promises and what it does not — entity types, edge kinds, scaling tiers, re-baseline procedure, and known coverage gaps — is in [docs/graph/CONTRACT.md](graph/CONTRACT.md).

### Estate-scale roll-up

Past a few hundred nodes a flat topology graph is unreadable. The estate is
organized as a `CONTAINS` containment tree (org → account/folder/project → app
→ resource), and `src/agent_bom/graph/rollup.py` collapses the graph along that
tree to a handful of top-level container nodes — each carrying aggregate
descendant counts, a by-type breakdown, worst-severity, a per-severity
histogram, and internet-exposed / toxic-combination flags propagated from every
descendant. The UI (and `GET /v1/graph/rollup`) drills down one level at a time
instead of loading the whole estate, with an attack-path-first view that returns
the nodes on materialized attack paths first. The roll-up is a pure read over
the existing `UnifiedGraph` — no new collection. Two further overlays enrich the
same graph: an ASPM layer (`aspm_overlay.py`) that organizes AppSec findings
around `APPLICATION` nodes, and a FinOps layer (`cost_overlay.py`) that fuses
LLM spend onto nodes and rolls it up along `CONTAINS` into `subtree_cost_usd`.

---

## 4. Compliance Tagging

Every finding is tagged against curated compliance frameworks, grouped into four families. OWASP AISVS is exposed as a separate benchmark result with per-check evidence. The bundled mappings are a curated subset of each framework focused on AI/MCP/agent risk-relevant controls — they are not a complete catalog. See [Coverage per framework](#coverage-per-framework) below for the generated control counts.

```mermaid
graph LR
    F["Finding\nCVE + severity + context"]

    subgraph OWASP["OWASP"]
        O1["LLM Top 10"]
        O2["MCP Top 10"]
        O3["Agentic Top 10"]
        O4["AISVS v1.0"]
    end

    subgraph NIST["NIST / FedRAMP"]
        N1["AI RMF 1.0"]
        N2["CSF 2.0"]
        N3["800-53 Rev 5"]
        N4["FedRAMP"]
    end

    subgraph INTL["Regulatory"]
        I1["EU AI Act"]
        I2["ISO 27001"]
        I3["SOC 2"]
        I4["CIS Controls v8"]
        I5["CMMC 2.0"]
    end

    ATL["MITRE ATLAS"]

    F --> OWASP & NIST & INTL & ATL

    T["Tagged Finding\n14 controls attached"]
    OWASP & NIST & INTL & ATL --> T

    style F fill:#dc2626,color:#fff
    style T fill:#059669,color:#fff
```

### Coverage per framework

agent-bom ships a curated control set per framework, sized to the AI/MCP/agent threat surface rather than a generic compliance scanner's full catalog. Numbers below count the controls that are **bundled and actively mapped** by the canonical metadata in `src/agent_bom/compliance_coverage.py`; AISVS is counted from the benchmark check registry. They are intentionally a subset; consult each framework's source standard for full coverage.

<!-- compliance-coverage:start -->
| Family | Framework | Bundled controls | Source-standard size (approx.) | What's covered |
|---|---|---|---|---|
| OWASP | LLM Top 10 (2025) | 10 / 10 | 10 | Full Top-10 |
| OWASP | MCP Top 10 (2025) | 10 / 10 | 10 | Full Top-10 |
| OWASP | Agentic Top 10 (2026) | 10 / 10 | 10 | Full Top-10 |
| OWASP | AISVS v1.0 | 9 checks | ~50 verification reqs | Programmatically verifiable subset (AI-4/5/6/7/8 categories) |
| NIST / FedRAMP | AI RMF 1.0 | 14 subcategories | ~70 | Govern / Map / Measure / Manage controls relevant to AI supply chain + MCP |
| NIST / FedRAMP | CSF 2.0 | 14 categories | ~108 | Supply-chain, identity, asset, monitoring categories |
| NIST / FedRAMP | 800-53 Rev 5 | 29 controls | ~1,006 | Vulnerability-driven mapping (RA-5, SI-2, etc.); not a complete catalog |
| NIST / FedRAMP | FedRAMP Moderate | 25 controls | ~325 | Subset of 800-53 controls in the Moderate baseline |
| MITRE | ATLAS | 65 techniques | ~90 | LLM/AI techniques: prompt injection, jailbreak, supply-chain, exfiltration, agent tool abuse |
| MITRE | ATT&CK Enterprise | 691 techniques | ~700 | Adversary techniques tagged via CWE → CAPEC → ATT&CK on every blast-radius finding |
| Regulatory | EU AI Act | 6 articles | ~113 | Articles 5/6/9/10/15/17 (prohibited practices, high-risk classification, risk mgmt, data governance, accuracy/cybersecurity, QMS) |
| Regulatory | ISO/IEC 27001:2022 | 9 Annex A controls | 93 | Supplier, vulnerability, cryptography, secure-dev, evidence collection |
| Regulatory | SOC 2 TSC | 9 criteria | ~64 | Common Criteria 6.x / 7.x / 8.x / 9.x (access, monitoring, change mgmt, vendor risk) |
| Regulatory | CIS Controls v8 | 10 safeguards | 153 | Software inventory, vulnerability mgmt, secure-dev (CIS 02 / 07 / 16) |
| Regulatory | CMMC 2.0 Level 2 | 17 practices | 110 | RA / SI / SC / CM / AC / IA practices most relevant to vulnerable-package risk |
| Regulatory | PCI DSS v4.0 | 12 requirements | 12 | Requirements 2/3/4/5/6/7/8/10/11/12 for vulnerable-package and evidence risk |
<!-- compliance-coverage:end -->

The bundled list is editable: see `src/agent_bom/compliance_coverage.py` for the framework metadata and `src/agent_bom/compliance_utils.py` for the `BlastRadius` field map. The UI consumes the same API response shape, so product coverage and dashboard controls should stay aligned with these catalogs.

---

## 5. Integration

How agent-bom fits into CI/CD, runtime, cloud, and enterprise tooling.

```mermaid
graph TB
    AB["agent-bom\nCore Engine"]

    CI["CI/CD\nGitHub Actions · Policy Gate · SARIF Upload · JS supply-chain guard"]
    RT["Runtime\nMCP Proxy · Docker Sidecar · OpenTelemetry"]
    HOSTS["MCP Hosts\n30 client types"]
    CLOUD["Cloud Providers\nAWS · Azure · GCP · Snowflake"]
    ENT["Enterprise\nSIEM · Slack · Jira · Webhooks · Prometheus"]

    CI -->|scan step| AB
    RT -->|intercept / monitor| AB
    HOSTS -->|config discovery| AB
    CLOUD -->|API discovery| AB
    AB -->|alerts / tickets / metrics| ENT

    style AB fill:#2563eb,color:#fff
```

---

## Key modules

| Module | Path | Responsibility |
|--------|------|----------------|
| CLI | `src/agent_bom/cli/` | Click entry point, command dispatch |
| Discovery | `src/agent_bom/discovery/__init__.py` | MCP client config discovery (29 first-class client types plus dynamic/project surfaces) |
| Parsers | `src/agent_bom/parsers/__init__.py` | Package extraction + MCP registry lookup |
| Scanners | `src/agent_bom/scanners/__init__.py` | OSV batch scan + CVSS + compliance tagging |
| Enrichment | `src/agent_bom/enrichment.py` | NVD + EPSS + CISA KEV enrichment |
| Models | `src/agent_bom/models.py` | Core data models (Package, Vulnerability, Agent, BlastRadius) |
| Output | `src/agent_bom/output/__init__.py` | JSON, CycloneDX, SARIF, SPDX, console |
| Policy | `src/agent_bom/policy.py` | Policy-as-code engine (17 conditions) |
| Proxy | `src/agent_bom/proxy.py` | Runtime MCP proxy (7 inline detectors) |
| MCP Server | `src/agent_bom/mcp_server*.py` | FastMCP server (75 tools across core, operator, runtime-catalog, and specialized modules) |
| Cloud | `src/agent_bom/cloud/` | AWS, Azure, GCP, Snowflake, Databricks, ClickHouse estate inventory; CIS posture where published and Databricks security best practices |
| Cloud side-scan | `src/agent_bom/cloud/side_scan.py`, `src/agent_bom/cloud/side_scan_targets.py`, `src/agent_bom/cloud/side_scan_lifecycle.py`, `src/agent_bom/cloud/side_scan_provider_adapters.py` | Agentless workload side-scan (CWPP) — AWS EBS CLI executor; injected-SDK Azure Managed Disk and GCP Persistent Disk lifecycle adapters with durable ownership/cleanup state; Azure/GCP scheduler/CLI wiring and live credentialed proof are not shipped |
| Registry sweep | `src/agent_bom/cloud/registry_sweep.py` | Registry-wide image enumeration + scan (ECR/ACR/GAR), digest-deduped, capped |
| Audit trail | `src/agent_bom/cloud/audit_trail.py` | Read-only CloudTrail/Activity Log/Cloud Audit ingest → behavioral `ACCESSED`/`INVOKED` graph edges (counts only) |
| Asset Tracker | `src/agent_bom/asset_tracker.py` | Persistent vuln tracking — first_seen, resolved, MTTR |
| Context Graph | `src/agent_bom/context_graph.py` | Lateral movement analysis — see [Graph Contract](graph/CONTRACT.md) for entity/edge coverage, accuracy guarantees, and scaling boundaries |
| Graph overlays | `src/agent_bom/graph/` | `rollup.py` (estate-scale `CONTAINS` roll-up + drill-down), `aspm_overlay.py` (application correlation), `cost_overlay.py` (LLM-spend fusion) |
| Remediation | `src/agent_bom/remediation.py` | Advisory-only fixes with least-privilege-to-apply (`applied`/`auto_remediation` always false) |
| Guard | `src/agent_bom/guard.py` | Pre-install CVE scan for pip/npm packages |
