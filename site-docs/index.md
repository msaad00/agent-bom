# agent-bom

**Open security scanner and graph for AI supply chain and infrastructure — discover agents and MCP, map blast radius, and inspect runtime.**

Scan agents, MCP, packages, containers, Kubernetes, cloud, and GPU workloads with blast-radius context.

## What it does

```
CVE-2025-1234  (CRITICAL · CVSS 9.8 · CISA KEV)
  └─ better-sqlite3@9.0.0  (npm)
       └─ sqlite-mcp  (MCP Server · unverified)
            ├─ Cursor IDE  (Agent · 4 servers · 12 tools)
            ├─ ANTHROPIC_KEY, DB_URL, AWS_SECRET  (Credentials exposed)
            └─ query_db, read_file, write_file  (Tools at risk)

 Fix: upgrade better-sqlite3 → 11.7.0
```

Package risk is only the start. agent-bom maps what it can reach across MCP servers, agents, credentials, tools, and runtime context.

## Quick start

```bash
pip install agent-bom
agent-bom agents                         # auto-discover local AI agents + MCP servers
agent-bom skills scan .                 # scan skills / instruction files
agent-bom check flask@2.0.0 --ecosystem pypi   # check a specific package
```

[Get started](getting-started/install.md){ .md-button .md-button--primary }
[View on GitHub](https://github.com/msaad00/agent-bom){ .md-button }

## Key capabilities

| Capability | Description |
|---|---|
| **Discovery** | Auto-detect 29 first-class MCP client types plus dynamic/project surfaces |
| **CVE scanning** | OSV + NVD CVSS v4 + EPSS + CISA KEV + GHSA |
| **Blast radius** | Map CVE impact: package → server → agent → credentials → tools |
| **Registry** | 427+ MCP server security metadata entries |
| **Compliance** | OWASP LLM/Agentic/MCP Top 10, MITRE ATLAS, EU AI Act, NIST AI RMF, CIS |
| **Runtime proxy** | Policy enforcement, credential leak detection, audit logging |
| **SBOM** | CycloneDX 1.6, SPDX 3.0 output |
| **Cloud** | AWS, Snowflake, Azure, GCP CIS benchmarks |

## Deploy In Your Infra

`agent-bom` is not limited to one hosting model. The clean self-hosted story is:

- **control plane**: API + UI + Postgres
- **scan**: CI jobs, scheduled CronJobs, or one-off discovery runs
- **fleet**: endpoint and collector inventory pushed into one control plane
- **runtime**: selected `agent-bom proxy` sidecars or local proxy wrappers
- **gateway**: central policy management for those proxy paths

| Need | Recommended path |
|---|---|
| local scan or CI gate | CLI or GitHub Action |
| self-hosted operator plane | API + UI + Postgres |
| your own AWS / EKS rollout | Helm control plane + scheduled scan jobs + selected proxy sidecars |
| developer workstation inventory | fleet sync |
| live MCP enforcement | proxy + gateway |
| assistant-facing tool server | `agent-bom mcp server` |

[Deployment Overview](deployment/overview.md){ .md-button .md-button--primary }
[Your Own AWS / EKS](deployment/own-infra-eks.md){ .md-button }
