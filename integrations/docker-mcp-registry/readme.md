# agent-bom

Open security scanner and graph for agentic infrastructure — discover agents and MCP, map blast radius, and inspect runtime.

Discovers AI agents and MCP servers, scans packages, images, filesystems, IaC, and cloud AI infrastructure, maps blast radius showing which credentials and tools each CVE reaches, enforces policy in real time, and generates compliance evidence.

Package risk is only the start. agent-bom maps what it can reach across MCP servers, agents, credentials, tools, and runtime context.

## Quick start

```bash
# Scan your AI agent environment
docker run --rm agentbom/agent-bom scan

# Pre-install CVE gate
docker run --rm agentbom/agent-bom check flask@2.0.0

# Generate CycloneDX SBOM
docker run --rm -v "$(pwd):/workspace" agentbom/agent-bom scan -p /workspace -f cyclonedx -o /workspace/sbom.json
```

## What it scans

- **30 MCP client types** — Claude Desktop, Cursor, Windsurf, VS Code Copilot, and more
- **Packages** — npm, pip, cargo, go modules, OS packages via OSV, NVD, EPSS, CISA KEV
- **Containers** — Docker images with native OCI package discovery
- **IaC** — Dockerfile, Kubernetes, Terraform, CloudFormation, Helm (89 rules)
- **Cloud AI** — 12 providers including AWS Bedrock, Azure OpenAI, GCP Vertex AI

## Key features

- **Blast radius mapping** — package → server → agent → credentials → tools
- **Runtime MCP proxy** — 7 inline detectors for drift, injection, credential leak, cloaking, rate limiting, vector DB injection, and cross-agent correlation
- **Framework-aware evidence** — OWASP, MITRE, NIST, EU AI Act, ISO 27001, SOC 2, CIS, CMMC, and more
- **MCP tools** — available to any MCP-compatible AI assistant

## Source

- GitHub: https://github.com/msaad00/agent-bom
- PyPI: https://pypi.org/project/agent-bom/
- License: Apache 2.0
