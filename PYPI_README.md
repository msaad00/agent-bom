# agent-bom

<!-- mcp-name: io.github.msaad00/agent-bom -->

**Security scanner for AI agents, MCP servers, containers, cloud, and runtime.**

Your AI agent's dependencies have a CVE. Which credentials leak? agent-bom maps the full blast radius: CVE → package → MCP server → AI agent → credentials → tools — with CWE-aware impact classification.

![agent-bom demo](https://raw.githubusercontent.com/msaad00/agent-bom/main/docs/images/demo-latest.gif)

## Quick start

```bash
pip install agent-bom

agent-bom agents                      # Discover + scan AI agents
agent-bom check flask@2.0.0           # Pre-install CVE gate
agent-bom image nginx:latest          # Container image scan
agent-bom iac Dockerfile k8s/         # IaC misconfigurations
```

## What it scans

- **30 MCP client types** — Claude Desktop, Cursor, Windsurf, VS Code, Codex CLI, and more
- **15 package ecosystems** — OSV + NVD + GHSA + EPSS + CISA KEV
- **Container images** — native OCI parser, no external tools needed
- **IaC** — Dockerfile, Terraform, CloudFormation, Helm, K8s (138 rules)
- **Cloud AI** — AWS, Azure, GCP, Databricks, Snowflake, HuggingFace, Ollama
- **Secrets** — 34 credential patterns + 11 PII patterns
- **Runtime** — MCP proxy with 112 detection patterns, PII redaction, Shield SDK
- **14 compliance frameworks** — OWASP, MITRE, NIST, EU AI Act, ISO 27001, SOC 2, CIS, CMMC, FedRAMP

## Key features

- **Blast radius mapping** — CVE → package → MCP server → agent → credentials
- **CWE-aware impact** — RCE shows credential exposure, DoS does not
- **19 output formats** — SARIF, CycloneDX 1.6, SPDX 3.0, HTML, Prometheus, and more
- **MCP server** — 33 security tools for Claude, Cursor, Windsurf
- **Dependency confusion detection** — flags internal naming patterns
- **VEX generation** — auto-triage with CWE-aware reachability

Read-only. Agentless. No secrets leave your machine.

## Links

- [GitHub](https://github.com/msaad00/agent-bom)
- [Docker Hub](https://hub.docker.com/r/agentbom/agent-bom)
- [Documentation](https://github.com/msaad00/agent-bom#readme)
