# agent-bom

Security scanner for AI infrastructure — from agent to runtime.

Discovers AI agents and MCP servers, scans all dependencies against OSV/NVD/GHSA, maps blast radius (which credentials and tools each CVE reaches), enforces policy in real time, and generates compliance evidence for 14 frameworks.

## Quick start

```bash
# Scan your AI agent environment
docker run --rm agentbom/agent-bom:latest scan

# Pre-install CVE gate — check before you install
docker run --rm agentbom/agent-bom:latest check flask@2.0.0

# Scan a specific project directory
docker run --rm -v "$(pwd):/workspace" agentbom/agent-bom:latest scan -p /workspace

# Export SBOM (CycloneDX / SPDX) or SARIF for GitHub Security tab
docker run --rm -v "$(pwd):/workspace" agentbom/agent-bom:latest scan -p /workspace -f cyclonedx -o /workspace/sbom.json

# IaC misconfiguration scan
docker run --rm -v "$(pwd):/workspace" agentbom/agent-bom:latest iac /workspace
```

## What it scans

- **22 MCP client types** — Claude Desktop, Cursor, Windsurf, VS Code Copilot, Cline, Continue, Zed, Cortex Code, Codex CLI, Gemini CLI, and more
- **Packages** — npm, pip, cargo, go modules, os packages (dpkg/rpm/apk) via OSV, NVD, EPSS, CISA KEV
- **Containers** — Docker images via Grype + Syft
- **Cloud AI** — AWS Bedrock, Azure OpenAI, GCP Vertex AI, Snowflake Cortex, and 8 more providers (12 total)
- **MCP servers** — tool poisoning, description injection, credential exposure
- **IaC** — Dockerfile, Kubernetes, Terraform, CloudFormation, Helm (82 + 7 Helm rules)

## Key features

- **Blast radius mapping** — traces CVE impact: package → server → agent → credentials → tools
- **Runtime MCP proxy** — 7 behavioral detectors: rug pull, tool drift, injection, credential leak, exfil, response cloaking, vector DB injection
- **14 compliance frameworks** — OWASP LLM Top 10, OWASP Agentic Top 10, MITRE ATLAS, MITRE ATT&CK, NIST AI RMF, EU AI Act, NIST CSF, ISO 27001, SOC 2, CMMC, FedRAMP, CIS Benchmarks, AISVS, and more
- **Policy-as-code** — 17 conditions with AND/OR/NOT expression engine
- **32 MCP server tools** — available to any MCP-compatible AI assistant

## Tags

| Tag | Description |
|-----|-------------|
| `latest` | Most recent stable release |
| `v0.71.3` | Current stable version (pinned) |

## Links

- [GitHub](https://github.com/msaad00/agent-bom)
- [Documentation](https://github.com/msaad00/agent-bom/blob/main/README.md)
- [PyPI](https://pypi.org/project/agent-bom/)
- [MCP Server (GHCR)](https://github.com/msaad00/agent-bom/pkgs/container/agent-bom)
- [GitHub Action](https://github.com/marketplace/actions/agent-bom-security-scan)
