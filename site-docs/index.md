# agent-bom

**Open security platform for agentic infrastructure. Broad scanning, blast radius, runtime, and trust.**

Find CVEs, map blast radius, detect credential exposure across MCP agents, containers, Kubernetes, cloud, and GPU workloads.

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

Traditional scanners often stop at CVE -> package. agent-bom shows which MCP servers, AI agents, credentials, and tools are actually at risk.

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
| **Discovery** | Auto-detect 30 MCP clients (Claude, Cursor, Windsurf, VS Code, etc.) |
| **CVE scanning** | OSV + NVD CVSS v4 + EPSS + CISA KEV + GHSA |
| **Blast radius** | Map CVE impact: package → server → agent → credentials → tools |
| **Registry** | 427+ MCP server security metadata entries |
| **Compliance** | OWASP LLM/Agentic/MCP Top 10, MITRE ATLAS, EU AI Act, NIST AI RMF, CIS |
| **Runtime proxy** | Policy enforcement, credential leak detection, audit logging |
| **SBOM** | CycloneDX 1.6, SPDX 3.0 output |
| **Cloud** | AWS, Snowflake, Azure, GCP CIS benchmarks |

## Deployment options

| Mode | Command |
|---|---|
| CLI | `pip install agent-bom` |
| MCP server | `agent-bom mcp server` |
| Docker | `docker run ghcr.io/msaad00/agent-bom agents` |
| GitHub Action | `uses: msaad00/agent-bom@v0.75.11` |
| Kubernetes | Helm chart + CronJob + DaemonSet |
| Remote SSE | Self-host or use hosted endpoint |
