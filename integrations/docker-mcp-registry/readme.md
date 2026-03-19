# agent-bom

Security scanner for AI infrastructure — from agent to runtime.

Discovers AI agents and MCP servers, scans all dependencies against OSV/NVD/GHSA, maps blast radius showing which credentials and tools each CVE reaches, enforces policy in real time, and generates compliance evidence for 14 frameworks.

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
- **Containers** — Docker images via Grype + Syft
- **IaC** — Dockerfile, Kubernetes, Terraform, CloudFormation, Helm (89 rules)
- **Cloud AI** — 12 providers including AWS Bedrock, Azure OpenAI, GCP Vertex AI

## Key features

- **Blast radius mapping** — package → server → agent → credentials → tools
- **Runtime MCP proxy** — 7 behavioral detectors (rug pull, injection, credential leak, exfil, cloaking, rate limiting, vector DB injection)
- **14 compliance frameworks** — OWASP LLM Top 10, OWASP Agentic Top 10, MITRE ATLAS, MITRE ATT&CK, NIST AI RMF, EU AI Act, NIST CSF, ISO 27001, SOC 2, CMMC, FedRAMP, CIS Benchmarks, AISVS
- **32 MCP tools** — available to any MCP-compatible AI assistant

## Source

- GitHub: https://github.com/msaad00/agent-bom
- PyPI: https://pypi.org/project/agent-bom/
- License: Apache 2.0
