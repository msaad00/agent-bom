# AI-BOM Generator

> Full AI asset discovery, vulnerability scanning, threat mapping, and AI Bill of Materials generation.

## Goal

Produce a complete **AI Bill of Materials (AI-BOM)** — a structured inventory of every AI agent, MCP server, package, credential, and tool in the target environment, enriched with CVE data, blast radius analysis, OWASP LLM Top 10, and MITRE ATLAS threat mappings.

## Prerequisites

```bash
pip install agent-bom
# For cloud providers (install only what you need):
pip install 'agent-bom[aws]'       # AWS Bedrock, Lambda, EKS, SageMaker
pip install 'agent-bom[snowflake]'  # Cortex Agents, MCP Servers, Snowpark
pip install 'agent-bom[cloud]'      # All providers
```

## Steps

### 1. Environment Assessment

Determine what's in scope. Run dry-run to see what agent-bom will access:

```bash
agent-bom scan --dry-run
```

Check for:
- Local MCP client configs (Claude Desktop, Cursor, Windsurf, VS Code, etc.)
- Docker images running AI workloads
- Kubernetes clusters with AI pods
- Cloud provider accounts (AWS, Azure, GCP, Databricks, Snowflake, Nebius)
- Terraform IaC defining AI resources
- GitHub Actions using AI SDKs
- Python projects using agent frameworks

### 2. Local Discovery + Scan

Start with local agents and MCP configs:

```bash
# Auto-discover local MCP clients + scan + enrich with NVD/EPSS/KEV
agent-bom scan --enrich -f json -o ai-bom-local.json
```

**Decision point**: If vulnerabilities are found, note severity counts before proceeding to cloud scanning.

### 3. Container Image Scanning

If Docker images exist in the environment:

```bash
# Scan specific images (repeat --image for each)
agent-bom scan --image <image1>:<tag> --image <image2>:<tag> --enrich -f json -o ai-bom-images.json
```

If running in Kubernetes:

```bash
# Discover all pod images across namespaces
agent-bom scan --k8s --all-namespaces --enrich -f json -o ai-bom-k8s.json
```

### 4. Cloud Provider Discovery

Run discovery for each cloud in scope. Combine flags for a single unified scan:

```bash
# AWS — full depth
agent-bom scan --aws --aws-region us-east-1 \
  --aws-include-lambda --aws-include-eks --aws-include-step-functions \
  --enrich -f json -o ai-bom-aws.json

# Snowflake — Cortex Agents, MCP Servers, Search, Snowpark, Streamlit
agent-bom scan --snowflake --enrich -f json -o ai-bom-snowflake.json

# Azure AI Foundry + Container Apps
agent-bom scan --azure --enrich -f json -o ai-bom-azure.json

# GCP Vertex AI + Cloud Run
agent-bom scan --gcp --gcp-project <project-id> --enrich -f json -o ai-bom-gcp.json

# Databricks clusters + model serving
agent-bom scan --databricks --enrich -f json -o ai-bom-databricks.json

# Nebius GPU cloud
agent-bom scan --nebius --nebius-project-id <project> --enrich -f json -o ai-bom-nebius.json
```

For **CoreWeave** (K8s-native):

```bash
agent-bom scan --k8s --context=coreweave-cluster --all-namespaces --enrich -f json -o ai-bom-coreweave.json
```

**Decision point**: If specific EC2 instances run AI workloads, add tag-filtered EC2:

```bash
agent-bom scan --aws --aws-include-ec2 --aws-ec2-tag "Environment=ai-prod" --enrich
```

### 5. Infrastructure-as-Code Scanning

Scan Terraform for AI resource definitions and hardcoded secrets:

```bash
agent-bom scan --tf-dir ./infrastructure --enrich -f json -o ai-bom-terraform.json
```

Scan GitHub Actions for AI SDK usage and credential exposure:

```bash
agent-bom scan --gha . --enrich -f json -o ai-bom-gha.json
```

### 6. Python Agent Framework Scanning

Detect agent framework usage (LangChain, AutoGen, CrewAI, LlamaIndex, OpenAI Agents SDK, etc.):

```bash
agent-bom scan --agent-project ./my-agent-app --enrich -f json -o ai-bom-agent.json
```

### 7. Unified AI-BOM Generation

Combine everything into one comprehensive scan:

```bash
agent-bom scan \
  --aws --aws-region us-east-1 --aws-include-lambda --aws-include-eks \
  --snowflake --databricks \
  --k8s --all-namespaces \
  --image myapp:latest \
  --tf-dir ./infrastructure \
  --gha . \
  --agent-project ./my-agent \
  --enrich \
  -f json -o ai-bom-complete.json
```

### 8. Export in Standard Formats

Generate compliance-ready exports:

```bash
# CycloneDX 1.6 (machine-readable, SBOM standard)
agent-bom scan [your flags] -f cyclonedx -o ai-bom.cdx.json

# SPDX 3.0 (ISO standard)
agent-bom scan [your flags] -f spdx -o ai-bom.spdx.json

# SARIF (GitHub Security tab)
agent-bom scan [your flags] -f sarif -o results.sarif

# HTML dashboard (interactive, human-readable)
agent-bom scan [your flags] -f html -o ai-bom-report.html
```

### 9. Graph Visualization

Generate the dependency graph (provider -> agent -> server -> package -> CVE):

```bash
agent-bom scan [your flags] -f graph -o ai-bom-graph.json
```

Open the HTML dashboard to see the interactive Cytoscape.js graph:

```bash
agent-bom scan [your flags] -f html -o report.html && open report.html
```

### 10. Review and Remediate

The AI-BOM JSON output includes:
- `document_type: "AI-BOM"` and `spec_version: "1.0"`
- Full agent/server/package inventory
- Vulnerability list with CVSS scores, EPSS probabilities, KEV status
- Blast radius: which agents, credentials, and tools each CVE can reach
- Remediation plan with named assets and impact percentages
- `threat_framework_summary` with OWASP LLM Top 10 + MITRE ATLAS coverage

**Decision point**: If critical/high CVEs exist, prioritize by:
1. CISA KEV (actively exploited) — fix immediately
2. EPSS > 0.5 (high exploitation probability) — fix within 48h
3. Blast radius: CVEs that reach credentials or shell-exec tools — fix first
4. Everything else — schedule in next sprint

## Outputs

| Artifact | Format | Purpose |
|----------|--------|---------|
| `ai-bom-complete.json` | AI-BOM JSON | Machine-readable full inventory |
| `ai-bom.cdx.json` | CycloneDX 1.6 | SBOM standard for compliance |
| `ai-bom.spdx.json` | SPDX 3.0 | ISO standard for auditors |
| `results.sarif` | SARIF | GitHub Security tab integration |
| `report.html` | HTML | Interactive dashboard + graph |
| `ai-bom-graph.json` | Graph JSON | Dependency graph for Cytoscape/Sigma.js |

## Architecture

```
                    ┌─────────────────────────────────────┐
                    │         AI-BOM Generator             │
                    └──────────────┬──────────────────────┘
                                   │
            ┌──────────────────────┼──────────────────────┐
            │                      │                      │
     ┌──────▼──────┐     ┌────────▼────────┐     ┌──────▼──────┐
     │ Local Agents │     │  Cloud Providers │     │  Container  │
     │ MCP Configs  │     │  AWS/Azure/GCP   │     │  Images     │
     │ Python Agents│     │  Snowflake/DB    │     │  K8s Pods   │
     └──────┬──────┘     │  Nebius          │     └──────┬──────┘
            │             └────────┬────────┘            │
            └──────────────────────┼─────────────────────┘
                                   │
                    ┌──────────────▼──────────────────────┐
                    │     CVE Scanning + Enrichment        │
                    │  OSV → NVD CVSS → EPSS → CISA KEV   │
                    └──────────────┬──────────────────────┘
                                   │
                    ┌──────────────▼──────────────────────┐
                    │     Threat Framework Mapping          │
                    │  OWASP LLM Top 10 + MITRE ATLAS      │
                    └──────────────┬──────────────────────┘
                                   │
                    ┌──────────────▼──────────────────────┐
                    │     AI-BOM Document Generation        │
                    │  JSON / CycloneDX / SPDX / SARIF     │
                    └─────────────────────────────────────┘
```
