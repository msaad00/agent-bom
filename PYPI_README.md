# agent-bom

<!-- mcp-name: io.github.msaad00/agent-bom -->

**Open security platform for agentic infrastructure. Broad scanning, blast radius, runtime, and trust.**

Your AI agent's dependencies have a CVE. Which credentials leak?

```text
CVE-2025-1234  (CRITICAL · CVSS 9.8 · CISA KEV)
  |── better-sqlite3@9.0.0  (npm)
       |── sqlite-mcp  (MCP Server · unverified · root)
            |── Cursor IDE  (Agent · 4 servers · 12 tools)
            |── ANTHROPIC_KEY, DB_URL, AWS_SECRET  (Credentials exposed)
            |── query_db, read_file, write_file, run_shell  (Tools at risk)

 Fix: upgrade better-sqlite3 → 11.7.0
```

agent-bom maps the blast radius: CVE → package → MCP server → AI agent → credentials → tools.

Traditional scanners often stop at `CVE → package`. agent-bom shows which credentials and tools are actually at risk — with CWE-aware impact classification so a DoS vuln doesn't falsely claim credential exposure.

![agent-bom demo](https://raw.githubusercontent.com/msaad00/agent-bom/main/docs/images/demo-latest.gif)

## Quick start

```bash
pip install agent-bom

agent-bom agents                              # Discover + scan local AI agents and MCP servers
agent-bom agents -p .                         # Scan project manifests plus agent/MCP context
agent-bom check flask@2.0.0 --ecosystem pypi  # Pre-install CVE gate
agent-bom image nginx:latest                  # Container image scan
agent-bom iac Dockerfile k8s/ infra/main.tf   # IaC misconfigurations
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

- **Blast radius mapping** — CVE → package → MCP server → agent → credentials → tools
- **CWE-aware impact** — RCE shows credential exposure, DoS does not
- **19 output formats** — SARIF, CycloneDX 1.6, SPDX 3.0, HTML, Prometheus, and more
- **MCP server** — 36 security tools for Claude, Cursor, Windsurf
- **Dependency confusion detection** — flags internal naming patterns
- **VEX generation** — auto-triage with CWE-aware reachability

Read-only. Agentless. No secrets leave your machine.

## How it works

![How agent-bom works](https://raw.githubusercontent.com/msaad00/agent-bom/main/docs/images/scan-pipeline-light.svg)

## Blast radius

![Blast radius](https://raw.githubusercontent.com/msaad00/agent-bom/main/docs/images/blast-radius-light.svg)

## Links

- [GitHub](https://github.com/msaad00/agent-bom)
- [Docker Hub](https://hub.docker.com/r/agentbom/agent-bom)
- [Documentation](https://github.com/msaad00/agent-bom#readme)
