# agent-bom

<!-- mcp-name: io.github.msaad00/agent-bom -->

**Open security scanner for AI supply chain — agents, MCP servers, packages, containers, cloud, GPU, and runtime.**

Find what is installed, see what it can reach, and understand what a vulnerable package can actually touch.

```text
CVE-2025-1234  (CRITICAL · CVSS 9.8 · CISA KEV)
  |── better-sqlite3@9.0.0  (npm)
       |── sqlite-mcp  (MCP Server · unverified · root)
            |── Cursor IDE  (Agent · 4 servers · 12 tools)
            |── ANTHROPIC_KEY, DB_URL, AWS_SECRET  (Credentials exposed)
            |── query_db, read_file, write_file, run_shell  (Tools at risk)

 Fix: upgrade better-sqlite3 → 11.7.0
```

agent-bom maps blast radius: `CVE -> package -> MCP server -> agent -> credentials -> tools`.

Scan local agent configs, MCP servers, instruction files, lockfiles, containers, cloud posture, GPU surfaces, and runtime evidence.

Try the built-in demo first:

```bash
agent-bom agents --demo --offline
```

The GIF uses that same curated sample so the output stays reproducible across releases. For real scans, run `agent-bom agents`, or add `-p .` to fold project manifests and lockfiles into the same result.

![agent-bom demo](https://raw.githubusercontent.com/msaad00/agent-bom/main/docs/images/demo-latest.gif)

## Quick start

```bash
pip install agent-bom

agent-bom agents -p .                            # Discover + scan local AI agents, MCP, and project packages
agent-bom agents -p . --remediate remediation.md # Generate a fix-first remediation plan
pip install 'agent-bom[ui]'                      # once, if you want the dashboard
agent-bom serve                                  # API + dashboard + unified graph explorer
```

## What it scans

- **Agents + MCP** — MCP clients, servers, tools, transports, trust posture
- **Skills + instructions** — `CLAUDE.md`, `AGENTS.md`, `.cursorrules`, `.windsurfrules`, `skills/*`
- **Package risk** — software supply chain scanning with enrichment and blast radius
- **Container images + IaC** — native OCI parsing plus Dockerfile, Terraform, CloudFormation, Helm, and Kubernetes coverage
- **Cloud AI** — cloud and AI infrastructure posture across major supported providers
- **Secrets + runtime** — MCP proxy, Shield SDK, secrets, and redaction surfaces
- **Compliance + evidence** — mapped governance plus ZIP evidence bundles for auditors

## Key features

- **Blast radius mapping** — CVE → package → MCP server → agent → credentials → tools
- **CWE-aware impact** — RCE shows credential exposure, DoS does not
- **Portable outputs** — SARIF, CycloneDX, SPDX, HTML, graph, JSON, ZIP evidence bundles, and more
- **MCP server mode** — expose `agent-bom` capabilities directly to MCP clients like Claude, Cursor, Windsurf, and Cortex CoCo / Cortex Code
- **Skill bundle identity** — stable bundle hashes for skill and instruction file review
- **Dependency confusion detection** — flags internal naming patterns
- **VEX generation** — auto-triage with CWE-aware reachability

Read-only. Agentless. No secrets leave your machine unless you explicitly enable an outbound integration.

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
