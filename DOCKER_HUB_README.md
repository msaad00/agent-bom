# agent-bom

Security scanner for AI infrastructure — from agent to runtime.

5 products in 1 package: **agent-bom** (BOM + scanning), **agent-shield** (runtime protection), **agent-cloud** (cloud posture), **agent-iac** (IaC security), **agent-claw** (fleet governance).

Discovers AI agents and MCP servers, scans all dependencies against OSV/NVD/GHSA, maps blast radius (which credentials and tools each CVE reaches), enforces policy in real time, and generates compliance evidence for 14 frameworks.

## Quick start

```bash
# Scan your AI agent environment
docker run --rm agentbom/agent-bom:latest agents

# Pre-install CVE gate
docker run --rm agentbom/agent-bom:latest check flask@2.0.0

# Scan a project directory
docker run --rm -v "$(pwd):/workspace" agentbom/agent-bom:latest agents -p /workspace

# Export CycloneDX ML BOM (with modelCard, dataset, training metadata)
docker run --rm -v "$(pwd):/workspace" agentbom/agent-bom:latest agents -p /workspace -f cyclonedx -o /workspace/sbom.json

# Export dependency graph for Neo4j
docker run --rm -v "$(pwd):/workspace" agentbom/agent-bom:latest graph /workspace/report.json -f cypher -o /workspace/import.cypher

# IaC misconfiguration scan
docker run --rm -v "$(pwd):/workspace" agentbom/agent-bom:latest iac /workspace

# Secret detection
docker run --rm -v "$(pwd):/workspace" agentbom/agent-bom:latest secrets /workspace

# Source code analysis
docker run --rm -v "$(pwd):/workspace" agentbom/agent-bom:latest code /workspace
```

## What it scans

- **30 MCP client types** — Claude Desktop, Cursor, Windsurf, VS Code Copilot, Cline, Continue, Zed, Cortex Code, Codex CLI, Gemini CLI, Sourcegraph Cody, Aider, Trae, Aide, and more
- **Packages** — npm, pip, cargo, go modules, OS packages (dpkg/rpm/apk) via OSV, NVD, EPSS, CISA KEV
- **Containers** — Docker images via Grype + Syft
- **Cloud AI** — AWS Bedrock, Azure OpenAI, GCP Vertex AI, Snowflake Cortex, Databricks, HuggingFace, Ollama, and more (12 total)
- **MCP servers** — tool poisoning, description injection, credential exposure
- **IaC** — Dockerfile, Kubernetes, Terraform, CloudFormation, Helm (89 rules)
- **Source code** — AST analysis of Python AI frameworks (LangChain, CrewAI, OpenAI Agents SDK, and 7 more)
- **Secrets** — 31 credential patterns + 11 PII patterns across source, config, and .env files

## Key features

- **Blast radius mapping** — traces CVE impact: package → server → agent → credentials → tools
- **Runtime MCP proxy** — 7 behavioral detectors: rug pull, tool drift, injection, credential leak, exfil, response cloaking, vector DB injection
- **14 compliance frameworks** — OWASP LLM Top 10, OWASP Agentic Top 10, MITRE ATLAS, MITRE ATT&CK, NIST AI RMF, EU AI Act, NIST CSF, ISO 27001, SOC 2, CMMC, FedRAMP, CIS Benchmarks, AISVS, and more
- **Policy-as-code** — 17 conditions with AND/OR/NOT expression engine
- **33 MCP server tools** — available to any MCP-compatible AI assistant
- **18 output formats** — JSON, SARIF, CycloneDX 1.6, SPDX, HTML, GraphML, Neo4j Cypher, JUnit, CSV, Markdown, Mermaid, Prometheus, OCSF, and more
- **18-page Next.js dashboard** — sidebar navigation, interactive topology graphs, compliance heatmaps, fleet management

## Tags

| Tag | Description |
|-----|-------------|
| `latest` | Most recent stable release |
| `v0.74.1` | Current stable version (pinned) |

## Links

- [GitHub](https://github.com/msaad00/agent-bom)
- [Documentation](https://github.com/msaad00/agent-bom/blob/main/README.md)
- [PyPI](https://pypi.org/project/agent-bom/)
- [MCP Server (GHCR)](https://github.com/msaad00/agent-bom/pkgs/container/agent-bom)
- [GitHub Action](https://github.com/marketplace/actions/agent-bom-security-scan)
