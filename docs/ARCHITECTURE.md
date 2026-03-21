# Architecture

Five products, one package. System overview, scan pipeline, blast radius, compliance, and integration.

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
        Protect["protect --shield\n7 detectors + deep defense"]
        Run_Cmd["run\nZero-config proxy"]
    end

    subgraph Cloud["agent-cloud — Cloud Posture"]
        AWS["aws / azure / gcp\nCIS benchmarks"]
        Platforms["snowflake / databricks\nhuggingface / ollama"]
        Posture["posture\nCross-cloud summary"]
    end

    subgraph IAC["agent-iac — IaC Security"]
        IaCScan["scan\n89 rules × 5 formats"]
        Policy["policy\ntemplate / apply"]
    end

    subgraph Claw["agent-claw — Fleet Governance"]
        Fleet["fleet\nsync / list / stats"]
        Serve["serve / api\nDashboard + REST"]
        Report["report\nhistory / analytics"]
    end

    subgraph Core["Core Engine"]
        Discovery["Discovery\n30 MCP clients"]
        Parser["Package Parser\n11 ecosystems"]
        Scanner["CVE Scanner\nOSV + NVD + GHSA"]
        Blast["Blast Radius\nCVE → agent → credentials → tools"]
        IaC["IaC Engine\n89 rules"]
        CIS["CIS Benchmarks\nAWS / Azure / GCP"]
    end

    subgraph Output["Output"]
        Console["Console\nTable / verbose"]
        Formats["Formats\nJSON / SARIF / HTML / CycloneDX"]
        API["REST API + MCP\n33 tools"]
        Proxy["Runtime Proxy\n7 detectors"]
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
    BlastRadius->>BlastRadius: Tag 14 compliance frameworks
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

Every finding is tagged against 14 frameworks, grouped into four families.

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

---

## 5. Integration

How agent-bom fits into CI/CD, runtime, cloud, and enterprise tooling.

```mermaid
graph TB
    AB["agent-bom\nCore Engine"]

    CI["CI/CD\nGitHub Actions · Policy Gate · SARIF Upload"]
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
| Discovery | `src/agent_bom/discovery/__init__.py` | MCP client config discovery (30 clients) |
| Parsers | `src/agent_bom/parsers/__init__.py` | Package extraction + MCP registry lookup |
| Scanners | `src/agent_bom/scanners/__init__.py` | OSV batch scan + CVSS + compliance tagging |
| Enrichment | `src/agent_bom/enrichment.py` | NVD + EPSS + CISA KEV enrichment |
| Models | `src/agent_bom/models.py` | Core data models (Package, Vulnerability, Agent, BlastRadius) |
| Output | `src/agent_bom/output/__init__.py` | JSON, CycloneDX, SARIF, SPDX, console |
| Policy | `src/agent_bom/policy.py` | Policy-as-code engine (17 conditions) |
| Proxy | `src/agent_bom/proxy.py` | Runtime MCP proxy (7 behavioral detectors) |
| MCP Server | `src/agent_bom/mcp_server.py` | FastMCP server (33 tools) |
| Cloud | `src/agent_bom/cloud/` | AWS, Azure, GCP, Snowflake, Databricks, ClickHouse |
| Asset Tracker | `src/agent_bom/asset_tracker.py` | Persistent vuln tracking — first_seen, resolved, MTTR |
| Context Graph | `src/agent_bom/context_graph.py` | Lateral movement analysis |
| Guard | `src/agent_bom/guard.py` | Pre-install CVE scan for pip/npm packages |
