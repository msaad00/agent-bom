# agent-bom

**Open security platform for agentic infrastructure. Broad scanning, blast radius, runtime, and trust.**

Your AI agent's dependencies have a CVE. Which credentials leak?

agent-bom helps developers, security teams, and enterprises discover AI agent and MCP environments,
map CVEs into real blast radius, scan packages, container images, Kubernetes, IaC, and cloud AI infrastructure, and protect MCP traffic at runtime.

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

Traditional scanners often stop at `CVE -> package`.

agent-bom answers the higher-value questions:

- Which AI agents are affected?
- Which MCP servers load the vulnerable package?
- Which credentials are exposed?
- Which tools are reachable?
- What should be fixed first?
- Which local AI infrastructure should be scanned next?

It covers:

- **30 MCP client types** — Claude Desktop, Cursor, Windsurf, VS Code Copilot, Cline, Continue, Zed, Cortex Code, and more
- Packages, container images, IaC, secrets, AI source code, and cloud AI environments
- Blast radius from package to server to agent to credentials and tools
- Runtime MCP proxy with 8 behavioral detectors
- 14 compliance frameworks
- 36 MCP server tools
- API + dashboard for fleet-wide visibility

## Coverage At A Glance

- **Agents + MCP** — 30 client types, MCP servers, tools, transports, trust posture
- **Skills + instructions** — `CLAUDE.md`, `AGENTS.md`, `.cursorrules`, `skills/*`
- **Supply chain** — 15 ecosystems, blast radius, dependency confusion, SBOM formats
- **Containers + IaC + cloud** — OCI images, Docker, Kubernetes, Terraform, Helm, cloud AI posture
- **Runtime + trust** — MCP proxy, 8 detectors, capability risk, compliance mapping

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
| `v0.75.12` | Current stable version (pinned) |

## Links

- [GitHub](https://github.com/msaad00/agent-bom)
- [PyPI](https://pypi.org/project/agent-bom/)
- [GitHub Action](https://github.com/marketplace/actions/agent-bom)
- [Discussions](https://github.com/msaad00/agent-bom/discussions)
