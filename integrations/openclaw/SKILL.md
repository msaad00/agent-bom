---
name: agent-bom
description: >-
  AI supply chain security scanner — check packages for CVEs, look up MCP servers
  in the 427+ server threat registry, assess blast radius, generate SBOMs, enforce
  compliance (OWASP, MITRE ATLAS, EU AI Act, NIST AI RMF). Use when the user
  mentions vulnerability scanning, dependency security, SBOM generation, MCP server
  trust, or AI supply chain risk.
version: 0.38.1
license: Apache-2.0
compatibility: >-
  Requires Python 3.11+. Install via pipx or pip. Optional: Docker for container
  scanning (Grype/Syft). No external API keys required for basic operation.
metadata:
  author: msaad00
  homepage: https://github.com/msaad00/agent-bom
  source: https://github.com/msaad00/agent-bom
  pypi: https://pypi.org/project/agent-bom/
  smithery: https://smithery.ai/server/agent-bom/agent-bom
  scorecard: https://securityscorecards.dev/viewer/?uri=github.com/msaad00/agent-bom
  tests: 2099
  install:
    pipx: agent-bom
    pip: agent-bom
    docker: ghcr.io/msaad00/agent-bom:0.38.1
  openclaw:
    requires:
      bins: []
      env: []
    optional_env: []
    emoji: "\U0001F6E1"
    homepage: https://github.com/msaad00/agent-bom
    source: https://github.com/msaad00/agent-bom
    license: Apache-2.0
    os:
      - darwin
      - linux
      - windows
    file_reads: []
    file_writes: []
    network_endpoints:
      - url: "https://trustworthy-solace-production-14a6.up.railway.app/sse"
        purpose: "Optional remote MCP endpoint — queries public vulnerability databases (OSV, NVD, EPSS, KEV) and the bundled registry. Local-first scanning recommended."
        auth: false
    telemetry: false
    persistence: false
    privilege_escalation: false
    always: false
    autonomous_invocation: restricted
---

# agent-bom — AI Supply Chain Security Scanner

Scans AI infrastructure for vulnerabilities, generates SBOMs, and enforces
compliance. Discovers MCP clients, servers, and packages across 18+ AI platforms.

## Install (Recommended: Local-First)

Local scanning eliminates all third-party trust concerns. All vulnerability
databases (OSV, NVD, EPSS, KEV) are queried directly from your machine.

```bash
pipx install agent-bom
agent-bom scan              # auto-discover 18 MCP clients + scan
agent-bom check langchain   # check a specific package
agent-bom where             # show all discovery paths
```

### As an MCP Server (Local)

```json
{
  "mcpServers": {
    "agent-bom": {
      "command": "uvx",
      "args": ["agent-bom", "mcp"]
    }
  }
}
```

### As a Docker Container

```bash
docker run --rm ghcr.io/msaad00/agent-bom:0.38.1 scan
```

### Self-Hosted SSE Server

```bash
docker build -f Dockerfile.sse -t agent-bom-sse .
docker run -p 8080:8080 agent-bom-sse
# Connect: { "type": "sse", "url": "http://localhost:8080/sse" }
```

## Available MCP Tools (14 tools)

| Tool | Description |
|------|-------------|
| `scan` | Full discovery + vulnerability scan pipeline |
| `check` | Check a package for CVEs (OSV, NVD, EPSS, KEV) |
| `blast_radius` | Map CVE impact chain across agents, servers, credentials |
| `registry_lookup` | Look up MCP server in 427+ server threat registry |
| `compliance` | OWASP LLM/Agentic Top 10, EU AI Act, MITRE ATLAS, NIST AI RMF |
| `remediate` | Prioritized remediation plan for vulnerabilities |
| `verify` | Package integrity + SLSA provenance check |
| `skill_trust` | Assess skill file trust level (5-category analysis) |
| `generate_sbom` | Generate SBOM (CycloneDX or SPDX format) |
| `policy_check` | Evaluate results against security policy |
| `diff` | Compare two scan reports (new/resolved/persistent) |
| `marketplace_check` | Pre-install trust check with registry cross-reference |
| `where` | Show MCP client config discovery paths |
| `inventory` | List discovered agents, servers, packages |

## MCP Resources

| Resource | Description |
|----------|-------------|
| `registry://servers` | Browse 427+ MCP server threat intelligence registry |
| `policy://template` | Default security policy template |

## Example Workflows

```
# Check a package before installing
check(package="@modelcontextprotocol/server-filesystem", ecosystem="npm")

# Map blast radius of a CVE
blast_radius(cve_id="CVE-2024-21538")

# Look up a server in the threat registry
registry_lookup(server_name="brave-search")

# Generate an SBOM
generate_sbom(format="cyclonedx")

# Assess trust of a skill file
skill_trust(skill_content="<paste SKILL.md content>")
```

## Remote SSE Endpoint (Optional)

For MCP clients that only support remote servers (e.g., some Claude Desktop
configurations), a convenience endpoint is available:

```json
{
  "mcpServers": {
    "agent-bom": {
      "type": "sse",
      "url": "https://trustworthy-solace-production-14a6.up.railway.app/sse"
    }
  }
}
```

**Important:** This endpoint queries the same public vulnerability databases
as local scanning. It receives only the arguments you provide in tool calls
(package names, CVE IDs, server names). For sensitive environments, use local
installation or self-host your own instance.

## Security Boundaries

### Safe to send (public data only)

- Public package names + versions (`langchain`, `express@4.18.2`)
- Public CVE IDs (`CVE-2024-21538`)
- Public MCP server names (`brave-search`)
- Ecosystem identifiers (`pypi`, `npm`, `go`)

### Never send

- API keys, tokens, passwords, or `.env` contents
- Full config files (may contain credentials)
- Internal URLs, hostnames, or proprietary package names
- Use `${env:VAR}` references, never literal credential values

## Verification

- **Source**: [github.com/msaad00/agent-bom](https://github.com/msaad00/agent-bom) (Apache-2.0)
- **PyPI**: [pypi.org/project/agent-bom](https://pypi.org/project/agent-bom/)
- **Smithery**: 99/100 quality score
- **Sigstore signed**: `agent-bom verify agent-bom@0.38.1`
- **2,099 tests** with automated security scanning (CodeQL + OpenSSF Scorecard)
- **OpenSSF Scorecard**: [securityscorecards.dev](https://securityscorecards.dev/viewer/?uri=github.com/msaad00/agent-bom)
- **No telemetry**: Zero tracking, zero analytics
