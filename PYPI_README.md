# agent-bom

<!-- mcp-name: io.github.msaad00/agent-bom -->

**Open security scanner for agentic infrastructure — agents, MCP, packages, containers, cloud, and runtime.**

Package risk is only the start. What matters is what it can reach.

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

Package risk is only the start. agent-bom maps what it can reach across MCP servers, agents, credentials, tools, and runtime context. CWE-aware impact classification keeps a DoS from being reported like credential compromise.

Canonical references:

- Product brief: https://github.com/msaad00/agent-bom/blob/main/docs/PRODUCT_BRIEF.md
- Verified metrics: https://github.com/msaad00/agent-bom/blob/main/docs/PRODUCT_METRICS.md
- Enterprise controls map: https://github.com/msaad00/agent-bom/blob/main/docs/ENTERPRISE.md
- Community: https://discord.gg/3YmYPqKZh5

![agent-bom demo](https://raw.githubusercontent.com/msaad00/agent-bom/main/docs/images/demo-latest.gif)

## Quick start

```bash
pip install agent-bom

agent-bom agents                              # Discover + scan local AI agents and MCP servers
agent-bom agents -p .                         # Scan project manifests plus agent/MCP context
agent-bom mesh --project .                    # Show the live agent / MCP topology
agent-bom check flask@2.0.0 --ecosystem pypi  # Pre-install CVE gate
agent-bom image nginx:latest                  # Container image scan
agent-bom iac Dockerfile k8s/ infra/main.tf   # IaC misconfigurations
```

## What it scans

- **Agents + MCP** — MCP clients, servers, tools, transports, trust posture
- **Skills + instructions** — `CLAUDE.md`, `AGENTS.md`, `.cursorrules`, `.windsurfrules`, `skills/*`
- **Package risk** — software supply chain scanning with enrichment and blast radius
- **Container images + IaC** — native OCI parsing plus Dockerfile, Terraform, CloudFormation, Helm, and Kubernetes coverage
- **Cloud AI** — cloud and AI infrastructure posture across major supported providers
- **Secrets + runtime** — MCP proxy, Shield SDK, secrets, and redaction surfaces
- **Compliance + evidence** — mapped governance and evidence-generation views

## Key features

- **Blast radius mapping** — CVE → package → MCP server → agent → credentials → tools
- **CWE-aware impact** — RCE shows credential exposure, DoS does not
- **Portable outputs** — SARIF, CycloneDX, SPDX, HTML, graph, JSON, and more
- **MCP server mode** — expose `agent-bom` capabilities directly to MCP clients like Claude, Cursor, Windsurf, and Cortex CoCo / Cortex Code
- **Skill bundle identity** — stable bundle hashes for skill and instruction file review
- **Dependency confusion detection** — flags internal naming patterns
- **VEX generation** — auto-triage with CWE-aware reachability

## Proof points

- `9` threat-intel sources
- `16` lockfile formats
- `13` model formats
- `36` MCP tools
- `13` PostgreSQL RLS-backed tenant tables
- `8` runtime detector classes

Read-only. Agentless. No secrets leave your machine.

## How it works

![How agent-bom works](https://raw.githubusercontent.com/msaad00/agent-bom/main/docs/images/scan-pipeline-light.svg)

## Blast radius

![Blast radius](https://raw.githubusercontent.com/msaad00/agent-bom/main/docs/images/blast-radius-light.svg)

## Links

- [GitHub](https://github.com/msaad00/agent-bom)
- [Docker Hub](https://hub.docker.com/r/agentbom/agent-bom)
- [Documentation](https://github.com/msaad00/agent-bom#readme)
- [Product brief](https://github.com/msaad00/agent-bom/blob/main/docs/PRODUCT_BRIEF.md)
- [Verified metrics](https://github.com/msaad00/agent-bom/blob/main/docs/PRODUCT_METRICS.md)
- [Enterprise controls map](https://github.com/msaad00/agent-bom/blob/main/docs/ENTERPRISE.md)
- [Discord](https://discord.gg/3YmYPqKZh5)
