# Architecture

Five products, one package. System overview, scan pipeline, blast radius, compliance, and integration.

---

## 0. Hermetic single-language stack

agent-bom is pure Python (3.11+) end to end — CLI, FastAPI surface, MCP server, parsers, OSV/NVD/EPSS/KEV/GHSA enrichment, blast-radius scoring, IaC engine, and CIS benchmarks all live in the same interpreter. There is no Rust/Go/CGo extension on the scan path. Disk-image scans use native `dpkg` / RPM parsers (`src/agent_bom/filesystem.py`); the `syft` Go binary is opt-in only as a tar-archive fallback for VM-style images.

Operational consequences:

- One language, one dep tree, one pip-audit/SBOM surface to audit and reproduce.
- Wheels build cleanly on `linux/amd64` and `linux/arm64` — no per-arch native toolchain.
- Slower than Rust/Go scanners on huge fanouts; per-package memory is higher. For VM disk-image scanning at scale, install `syft` alongside agent-bom and let the fallback path take over.

---

## 1. System Overview — 5 Products

```
pip install agent-bom    → 5 CLI entry points, shared core engine
```

```mermaid
graph TB
    subgraph BOM["agent-bom — BOM + Scanning"]
        Scan["scan\nFull 12-step pipeline"]
        Check_Cmd["check\nPre-install CVE gate"]
        Image_Cmd["image / fs / sbom\nContainer + filesystem"]
        Graph_Cmd["graph\nGraphML / Neo4j / DOT"]
        MCP_Cmd["mcp\ninventory / introspect / registry"]
    end

    subgraph Shield["agent-shield — Runtime Protection"]
        Proxy["proxy\nMCP proxy + audit"]
        Protect["protect --shield\n8 detectors + deep defense"]
        Run_Cmd["run\nZero-config proxy"]
    end

    subgraph Cloud["agent-cloud — Cloud Posture"]
        AWS["aws / azure / gcp\nCIS benchmarks"]
        Platforms["snowflake / databricks\nhuggingface / ollama"]
        Posture["posture\nCross-cloud summary"]
    end

    subgraph IAC["agent-iac — IaC Security"]
        IaCScan["scan\n138 rules × 5 formats"]
        Policy["policy\ntemplate / apply"]
    end

    subgraph Claw["agent-claw — Fleet Governance"]
        Fleet["fleet\nsync / list / stats"]
        Serve["serve / api\nDashboard + REST"]
        Report["report\nhistory / analytics"]
    end

    subgraph Core["Core Engine"]
        Discovery["Discovery\n29 first-class clients"]
        Parser["Package Parser\n15 ecosystems"]
        Scanner["CVE Scanner\nOSV + NVD + GHSA"]
        Blast["Blast Radius\nCVE → agent → credentials → tools"]
        IaC["IaC Engine\n138 rules"]
        CIS["CIS Benchmarks\nAWS / Azure / GCP"]
    end

    subgraph Output["Output"]
        Console["Console\nTable / verbose"]
        Formats["Formats\nJSON / SARIF / HTML / CycloneDX"]
        API["REST API + MCP\n36 tools"]
        Proxy["Runtime Proxy\n7 inline detectors"]
    end

    Scan & MCP_Cmd --> Discovery
    Image_Cmd & FS_Cmd & SBOM_Cmd --> Parser
    IAC_Cmd --> IaC
    Cloud_Cmd --> CIS
    Check_Cmd --> Scanner
    Run_Cmd --> Proxy

    Discovery --> Parser --> Scanner --> Blast
    Blast --> Console & Formats & API
    IaC & CIS --> Console
```

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
    BlastRadius->>BlastRadius: CVE → package → server → agent → creds → tools
    BlastRadius->>BlastRadius: Tag 14 frameworks + attach AISVS benchmark
    BlastRadius-->>CLI: Scored + tagged findings

    CLI->>Reporter: Full results
    Reporter-->>User: Console / JSON / SARIF / HTML / SBOM
```

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
    PKG -->|dependency of| SRV
    SRV -->|used by| AGT1 & AGT2
    AGT1 & AGT2 -->|exposes| CRED
    AGT1 & AGT2 -->|reaches| TOOL

    style CVE fill:#dc2626,color:#fff
    style PKG fill:#ea580c,color:#fff
    style SRV fill:#d97706,color:#fff
    style AGT1 fill:#2563eb,color:#fff
    style AGT2 fill:#2563eb,color:#fff
    style CRED fill:#7c3aed,color:#fff
    style TOOL fill:#059669,color:#fff
```

**Color key:** Red = CVE · Orange = Package · Amber = Server · Blue = Agent · Purple = Credentials · Green = Tools

---

## 4. Compliance Tagging

Every finding is tagged against 14 tag-mapped frameworks, grouped into four families. OWASP AISVS is exposed as a separate benchmark result with per-check evidence. The bundled mappings are a curated subset of each framework focused on AI/MCP/agent risk-relevant controls — they are not a complete catalog. See [Coverage per framework](#coverage-per-framework) below for the honest control counts.

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
| MCP Server | `src/agent_bom/mcp_server.py` | FastMCP server (36 tools) |
| Cloud | `src/agent_bom/cloud/` | AWS, Azure, GCP, Snowflake, Databricks, ClickHouse |
| Asset Tracker | `src/agent_bom/asset_tracker.py` | Persistent vuln tracking — first_seen, resolved, MTTR |
| Context Graph | `src/agent_bom/context_graph.py` | Lateral movement analysis |
| Guard | `src/agent_bom/guard.py` | Pre-install CVE scan for pip/npm packages |
