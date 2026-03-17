# Architecture

This document describes the architecture of agent-bom through five diagrams covering the system overview, data flow pipeline, blast radius propagation, compliance framework mapping, and integration architecture.

---

## 1. System Architecture Overview

High-level view of CLI commands, the core processing engine, and output channels.

```mermaid
graph TB
    subgraph Commands["CLI Commands"]
        Scan["agent-bom scan\nAuto-detect everything"]
        MCP_Cmd["agent-bom mcp\nMCP agents + servers"]
        Image_Cmd["agent-bom image\nContainer images"]
        FS_Cmd["agent-bom fs\nFilesystem / VM"]
        IAC_Cmd["agent-bom iac\nDockerfile / K8s / TF / CFN"]
        SBOM_Cmd["agent-bom sbom\nIngest CycloneDX / SPDX"]
        Cloud_Cmd["agent-bom cloud\nAWS / Azure / GCP"]
        Check_Cmd["agent-bom check\nPre-install CVE gate"]
        Run_Cmd["agent-bom run\nRuntime MCP proxy"]
    end

    subgraph Core["Core Engine"]
        Discovery["Discovery\n22 MCP clients + auto-detect"]
        Parser["Package Parser\n11 ecosystems"]
        Scanner["CVE Scanner\nOSV + NVD + GHSA + local DB"]
        Blast["Blast Radius\nAgent → CVE → credential chain"]
        Enrichment["Enrichment\nEPSS + KEV + NVD CVSS"]
        IaC_Engine["IaC Engine\n82 rules, 4 formats"]
        CIS["CIS Benchmarks\nAWS 60 + Azure 95 + GCP 59"]
    end

    subgraph Output["Output"]
        Console["Console\nCompact / verbose"]
        Formats["17 formats\nJSON / SARIF / HTML / CycloneDX"]
        API["REST API\n+ 32 MCP tools"]
        Proxy["Runtime Proxy\n7 detectors"]
    end

    Scan --> Discovery
    MCP_Cmd --> Discovery
    Image_Cmd --> Parser
    FS_Cmd --> Parser
    SBOM_Cmd --> Parser
    IAC_Cmd --> IaC_Engine
    Cloud_Cmd --> CIS
    Check_Cmd --> Scanner
    Run_Cmd --> Proxy

    Discovery --> Parser
    Parser --> Scanner
    Scanner --> Blast
    Scanner --> Enrichment
    Blast --> Console
    Blast --> Formats
    Blast --> API
    IaC_Engine --> Console
    CIS --> Console
```

---

## 2. Data Flow Pipeline

Sequence of operations from user invocation through enrichment to final report generation.

```mermaid
sequenceDiagram
    participant User
    participant CLI
    participant Discovery
    participant Scanner
    participant Enrichment
    participant BlastRadius
    participant ComplianceTagger
    participant Reporter

    User->>CLI: agent-bom scan [options]
    CLI->>Discovery: Detect MCP configs, images, clouds
    Discovery-->>CLI: Agents, servers, packages, tools

    CLI->>Scanner: Package list
    Scanner->>Scanner: OSV batch query
    Scanner-->>CLI: Raw CVE results

    CLI->>Enrichment: CVE IDs
    Enrichment->>Enrichment: NVD CVSS v4
    Enrichment->>Enrichment: EPSS exploit probability
    Enrichment->>Enrichment: CISA KEV check
    Enrichment->>Enrichment: GHSA + NVIDIA CSAF
    Enrichment-->>CLI: Enriched vulnerabilities

    CLI->>BlastRadius: Vulns + topology
    BlastRadius->>BlastRadius: Map CVE to package to server
    BlastRadius->>BlastRadius: Map server to agents + credentials + tools
    BlastRadius-->>CLI: Blast radius chains

    CLI->>ComplianceTagger: Findings
    ComplianceTagger->>ComplianceTagger: Tag 14 frameworks
    ComplianceTagger-->>CLI: Tagged findings

    CLI->>CLI: Asset tracking (first_seen / resolved / MTTR)

    CLI->>Reporter: Full results
    Reporter-->>User: Console / JSON / HTML / SBOM / SARIF
```

---

## 3. Blast Radius Propagation

How a single CVE propagates through the AI agent stack, exposing credentials and tools.

```mermaid
graph LR
    CVE["CVE-2025-XXXX\nCRITICAL CVSS 9.8"]
    PKG["Vulnerable Package\nnpm / PyPI / Go"]
    SRV["MCP Server\nunverified / root"]

    AGT1["Agent: Cursor IDE\n4 servers / 12 tools"]
    AGT2["Agent: Claude Desktop\n3 servers / 8 tools"]

    CRED1["ANTHROPIC_KEY"]
    CRED2["AWS_SECRET"]
    CRED3["DB_URL"]

    TOOL1["query_db"]
    TOOL2["read_file"]
    TOOL3["write_file"]
    TOOL4["run_shell"]

    CVE -->|"affects"| PKG
    PKG -->|"dependency of"| SRV

    SRV -->|"used by"| AGT1
    SRV -->|"used by"| AGT2

    AGT1 -->|"exposes"| CRED1
    AGT1 -->|"exposes"| CRED2
    AGT2 -->|"exposes"| CRED3

    AGT1 -->|"reaches"| TOOL1
    AGT1 -->|"reaches"| TOOL2
    AGT2 -->|"reaches"| TOOL3
    AGT2 -->|"reaches"| TOOL4

    style CVE fill:#dc2626,color:#fff
    style PKG fill:#ea580c,color:#fff
    style SRV fill:#d97706,color:#fff
    style AGT1 fill:#2563eb,color:#fff
    style AGT2 fill:#2563eb,color:#fff
    style CRED1 fill:#7c3aed,color:#fff
    style CRED2 fill:#7c3aed,color:#fff
    style CRED3 fill:#7c3aed,color:#fff
    style TOOL1 fill:#059669,color:#fff
    style TOOL2 fill:#059669,color:#fff
    style TOOL3 fill:#059669,color:#fff
    style TOOL4 fill:#059669,color:#fff
```

**Color key:** Red = CVE, Orange = Package, Amber = Server, Blue = Agent, Purple = Credential, Green = Tool

---

## 4. Compliance Framework Mapping

Every blast radius finding is tagged against 14 compliance frameworks simultaneously.

```mermaid
graph TD
    Finding["Blast Radius Finding\nCVE + severity + context"]

    OWASP_LLM["OWASP LLM Top 10\nLLM01 - LLM10"]
    OWASP_MCP["OWASP MCP Top 10\nMCP01 - MCP10"]
    OWASP_AGT["OWASP Agentic Top 10\nASI01 - ASI10"]
    OWASP_AISVS["OWASP AISVS v1.0\nAI Supply Chain / Runtime Controls"]
    ATLAS["MITRE ATLAS\nAML.T0010 / T0043 / T0051"]
    NIST_AI["NIST AI RMF 1.0\nGovern / Map / Measure / Manage"]
    NIST_CSF["NIST CSF 2.0\nIdentify / Protect / Detect / Respond"]
    NIST_53["NIST 800-53 Rev 5\nCM-8 / RA-5 / SI-2 / SR-3"]
    FEDRAMP["FedRAMP Moderate\nDerived from 800-53 controls"]
    EU_AI["EU AI Act\nART-5 through ART-17"]
    ISO["ISO 27001\nAnnex A controls"]
    SOC2["SOC 2\nTrust Services Criteria"]
    CIS["CIS Controls v8\nIG1 / IG2 / IG3"]
    CMMC["CMMC 2.0\nLevel 1-3 practices"]

    Finding --> OWASP_LLM
    Finding --> OWASP_MCP
    Finding --> OWASP_AGT
    Finding --> OWASP_AISVS
    Finding --> ATLAS
    Finding --> NIST_AI
    Finding --> NIST_CSF
    Finding --> NIST_53
    Finding --> FEDRAMP
    Finding --> EU_AI
    Finding --> ISO
    Finding --> SOC2
    Finding --> CIS
    Finding --> CMMC

    Tagged["Tagged Finding\nAll framework controls attached"]

    OWASP_LLM --> Tagged
    OWASP_MCP --> Tagged
    OWASP_AGT --> Tagged
    OWASP_AISVS --> Tagged
    ATLAS --> Tagged
    NIST_AI --> Tagged
    NIST_CSF --> Tagged
    NIST_53 --> Tagged
    FEDRAMP --> Tagged
    EU_AI --> Tagged
    ISO --> Tagged
    SOC2 --> Tagged
    CIS --> Tagged
    CMMC --> Tagged

    style Finding fill:#dc2626,color:#fff
    style Tagged fill:#059669,color:#fff
```

---

## 5. Integration Architecture

How agent-bom integrates with CI/CD pipelines, runtime environments, cloud providers, and enterprise systems.

```mermaid
graph TB
    subgraph CICD["CI/CD Pipeline"]
        GHA["GitHub Actions"]
        Policy["Policy Gate\n--fail-on-severity"]
        SARIF["SARIF Upload\nGitHub Security Tab"]
    end

    subgraph Runtime["Runtime"]
        Proxy["MCP Proxy\nPayload Integrity"]
        Sidecar["Runtime Sidecar\nDocker Container"]
        OTel["OpenTelemetry\nTrace Ingestion"]
    end

    subgraph Hosts["MCP Hosts"]
        Claude["Claude Desktop / Code"]
        Cursor["Cursor IDE"]
        Codex["Codex CLI"]
        Gemini["Gemini CLI"]
        Others["14 more clients"]
    end

    subgraph CloudProv["Cloud Providers"]
        AWS["AWS\nBedrock / Lambda / EKS"]
        Azure["Azure\nAI Foundry / Functions"]
        GCP["GCP\nVertex AI / GKE"]
        Snow["Snowflake\nCortex / MCP / Snowpark"]
    end

    subgraph Export["Enterprise Export"]
        SIEM["SIEM / Splunk"]
        Slack["Slack Alerts"]
        Jira["Jira Tickets"]
        Webhook["Webhooks"]
        Prom["Prometheus / Grafana"]
    end

    AB["agent-bom\nCore Engine"]

    GHA -->|"scan step"| AB
    AB -->|"pass/fail"| Policy
    AB -->|"upload"| SARIF

    Proxy -->|"intercept"| AB
    Sidecar -->|"monitor"| AB
    OTel -->|"traces"| AB

    Hosts -->|"config discovery"| AB
    CloudProv -->|"API discovery"| AB

    AB -->|"alerts"| Slack
    AB -->|"tickets"| Jira
    AB -->|"events"| Webhook
    AB -->|"metrics"| Prom
    AB -->|"logs"| SIEM

    style AB fill:#2563eb,color:#fff
```

---

## Key modules

| Module | Path | Responsibility |
|--------|------|----------------|
| CLI | `src/agent_bom/cli.py` | Click entry point, flag parsing |
| Discovery | `src/agent_bom/discovery/__init__.py` | MCP client config discovery (22 clients) |
| Parsers | `src/agent_bom/parsers/__init__.py` | Package extraction + MCP registry lookup |
| Skill Parsers | `src/agent_bom/parsers/skills.py` + `skill_audit.py` | SKILL.md/CLAUDE.md behavioral audit, typosquat, Sigstore trust |
| Browser Extensions | `src/agent_bom/parsers/browser_extensions.py` | Chrome/Edge/Brave/Firefox manifest.json permission auditor |
| Scanners | `src/agent_bom/scanners/__init__.py` | OSV batch scan + CVSS + AI risk tagging |
| Output | `src/agent_bom/output/__init__.py` | JSON, CycloneDX, SARIF, SPDX, console output |
| Policy | `src/agent_bom/policy.py` | Policy-as-code engine |
| SBOM | `src/agent_bom/sbom.py` | SBOM ingestion (CycloneDX, SPDX) |
| Image | `src/agent_bom/image.py` | Docker image scanning |
| MCP Server | `src/agent_bom/mcp_server.py` | FastMCP server (32 tools) |
| Asset Tracker | `src/agent_bom/asset_tracker.py` | Persistent vuln tracking — first_seen, resolved, MTTR |
| Context Graph | `src/agent_bom/context_graph.py` | Lateral movement analysis |
| Cloud | `src/agent_bom/cloud/` | AWS, Azure, GCP, Snowflake, Databricks, Nebius |
| Logging | `src/agent_bom/logging_config.py` | Structured JSON/console logging, env var config |
| Guard | `src/agent_bom/guard.py` | Pre-install CVE scan for pip/npm packages |
| Glama | `src/agent_bom/glama.py` | Glama.ai registry sync (18,000+ MCP servers) |
