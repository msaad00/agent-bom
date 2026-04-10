# agent-bom

**Open security scanner and graph for agentic infrastructure — discover agents and MCP, map blast radius, and inspect runtime.**

Package risk is only the start. What matters is what it can reach.

agent-bom helps developers, security teams, and enterprises discover AI agent and MCP environments,
map CVEs into real blast radius, scan packages, container images, Kubernetes, IaC, and cloud AI infrastructure, and protect MCP traffic at runtime.

Canonical references:

- Product brief: https://github.com/msaad00/agent-bom/blob/main/docs/PRODUCT_BRIEF.md
- Verified metrics: https://github.com/msaad00/agent-bom/blob/main/docs/PRODUCT_METRICS.md

## Who It Is For

- **Developers:** scan your workstation, repos, MCP servers, and AI tools
- **Security teams:** map package risk into agents, credentials, and reachable tools
- **Enterprises:** add runtime protection, policy, and compliance evidence

## Quick Start

**Discover and scan your AI agent environment**

```bash
docker run --rm agentbom/agent-bom:latest agents
```

**Workstation posture summary**

```bash
docker run --rm agentbom/agent-bom:latest agents --posture
```

**Pre-install CVE check**

```bash
docker run --rm agentbom/agent-bom:latest check flask@2.0.0
```

**Scan a project directory**

```bash
docker run --rm -v "$(pwd):/workspace" agentbom/agent-bom:latest agents -p /workspace
```

**Export AI BOM (CycloneDX 1.6 / SPDX 3.0)**

```bash
docker run --rm -v "$(pwd):/workspace" agentbom/agent-bom:latest agents -p /workspace -f cyclonedx -o /workspace/ai-bom.json
```

**IaC misconfiguration scan**

```bash
docker run --rm -v "$(pwd):/workspace" agentbom/agent-bom:latest iac /workspace
```

**Cloud AI and infra inventory**

```bash
docker run --rm agentbom/agent-bom:latest cloud aws
```

**Preflight health check**

```bash
docker run --rm agentbom/agent-bom:latest doctor
```

## Why Teams Use It

Package risk is only the start.

agent-bom maps what it can reach across MCP servers, agents, credentials, tools, and runtime context.

It answers the higher-value questions:

- Which AI agents are affected?
- Which MCP servers load the vulnerable package?
- Which credentials are exposed?
- Which tools are reachable?
- What should be fixed first?
- Which local AI infrastructure should be scanned next?

It covers:

- MCP client discovery across Claude Desktop, Claude Code, Cursor, Windsurf, VS Code Copilot, Cline, Continue, Zed, Cortex CoCo / Cortex Code, and more
- Packages, container images, IaC, secrets, AI source code, and cloud AI environments
- Blast radius from package to server to agent to credentials and tools
- Runtime MCP proxy plus the broader runtime protection engine
- API + dashboard for fleet-wide visibility

## Coverage At A Glance

- **Agents + MCP** — clients, servers, tools, transports, trust posture
- **Skills + instructions** — `CLAUDE.md`, `AGENTS.md`, `.cursorrules`, `skills/*`
- **Supply chain** — package ecosystems, blast radius, dependency confusion, SBOM formats
- **Containers + IaC + cloud** — OCI images, Docker, Kubernetes, Terraform, Helm, cloud AI posture
- **Runtime + trust** — MCP proxy, runtime protection engine, capability risk, compliance mapping

## Deployment Guidance

| Environment | Recommendation |
|-------------|----------------|
| Developer laptop | `pip install agent-bom` is fine; read-only and no listener by default |
| CI/CD | `docker run --rm agentbom/agent-bom` for isolated scans and easy gating |
| Enterprise fleet | run `agent-bom serve` in a dedicated container or namespace with RBAC |
| Air-gapped | pre-sync the DB and run with `--offline` |

## Tags

| Tag | Description |
|-----|-------------|
| `latest` | Most recent stable release |
| `0.76.2` | Current stable version (pinned) |

## Links

- [GitHub](https://github.com/msaad00/agent-bom)
- [PyPI](https://pypi.org/project/agent-bom/)
- [GitHub Action](https://github.com/marketplace/actions/agent-bom)
- [Discord](https://discord.gg/3YmYPqKZh5)
- [Discussions](https://github.com/msaad00/agent-bom/discussions)
