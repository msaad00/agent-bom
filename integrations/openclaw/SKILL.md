---
name: agent-bom
description: >-
  AI agent infrastructure security scanner — check packages for CVEs, look up MCP servers
  in the 427+ server security metadata registry, assess blast radius, generate SBOMs, enforce
  compliance (OWASP, MITRE ATLAS, EU AI Act, NIST AI RMF). Use when the user
  mentions vulnerability scanning, dependency security, SBOM generation, MCP server
  trust, or AI supply chain risk.
version: 0.58.0
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
  tests: 6300
  install:
    pipx: agent-bom
    pip: agent-bom
    docker: ghcr.io/msaad00/agent-bom:0.58.0
  openclaw:
    requires:
      bins: []
      env: []
      credentials: none
    credential_policy: "Zero credentials required for core scanning. All env vars below are strictly optional and only used for specific enterprise features (CIS benchmarks, analytics). They are never auto-discovered, inferred, or transmitted."
    optional_env:
      - name: NVD_API_KEY
        purpose: "Increases NVD API rate limit (scanning works without it)"
        required: false
      - name: SNYK_TOKEN
        purpose: "Snyk vulnerability enrichment (optional additional data source)"
        required: false
      - name: AGENT_BOM_CLICKHOUSE_URL
        purpose: "ClickHouse analytics storage (enterprise only, not needed for scanning)"
        required: false
      - name: AWS_PROFILE
        purpose: "AWS CIS benchmark only — used when user explicitly runs cis_benchmark(provider='aws')"
        required: false
      - name: AWS_DEFAULT_REGION
        purpose: "AWS CIS benchmark only"
        required: false
      - name: SNOWFLAKE_ACCOUNT
        purpose: "Snowflake CIS benchmark only — used when user explicitly runs cis_benchmark(provider='snowflake')"
        required: false
      - name: SNOWFLAKE_USER
        purpose: "Snowflake CIS benchmark only"
        required: false
      - name: SNOWFLAKE_PASSWORD
        purpose: "Snowflake CIS benchmark only"
        required: false
    optional_bins:
      - syft
      - grype
      - kubectl
      - semgrep
      - docker
    emoji: "\U0001F6E1"
    homepage: https://github.com/msaad00/agent-bom
    source: https://github.com/msaad00/agent-bom
    license: Apache-2.0
    os:
      - darwin
      - linux
      - windows
    file_reads_note: "Reads server names and command paths only — never credentials, tokens, or env var values"
    credential_handling: "Config files are parsed for JSON keys (mcpServers.*.command, mcpServers.*.args) only. Env var blocks are skipped entirely. Values of env, API keys, tokens, and passwords are never read, stored, or transmitted. Cloud credentials (AWS, Snowflake) are only used when user explicitly runs cis_benchmark with those providers."
    data_flow: "All scanning is local-first with zero outbound calls by default except public vulnerability databases (OSV, NVD, EPSS). The remote SSE endpoint is never auto-contacted, never auto-discovered, and requires explicit manual configuration. No discovery data, config files, credentials, or environment variables ever leave the machine. Only public package names and CVE IDs are sent to vulnerability databases."
    file_reads:
      - "~/.cursor/mcp.json"
      - "~/Library/Application Support/Claude/claude_desktop_config.json"
      - "~/.claude/settings.json"
      - "~/.windsurf/mcp.json"
      - "~/.config/Code/User/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json"
      - "user-provided SBOM files (CycloneDX/SPDX JSON)"
      - "user-provided SKILL.md files (for skill_trust analysis)"
    file_writes: []
    network_endpoints:
      - url: "https://api.osv.dev/v1"
        purpose: "OSV vulnerability database — batch CVE lookup for packages"
        auth: false
      - url: "https://services.nvd.nist.gov/rest/json/cves/2.0"
        purpose: "NVD CVSS v4 enrichment — optional API key increases rate limit"
        auth: false
      - url: "https://api.first.org/data/v1/epss"
        purpose: "EPSS exploit probability scores"
        auth: false
      - url: "https://api.deps.dev/v3alpha"
        purpose: "Google deps.dev — transitive dependency resolution and license enrichment"
        auth: false
      - url: "https://api.snyk.io"
        purpose: "Snyk vulnerability enrichment (requires SNYK_TOKEN)"
        auth: true
      - url: "https://agent-bom-mcp.up.railway.app/sse"
        purpose: "Fully optional remote MCP endpoint for clients that only support remote servers. Never auto-contacted, never auto-discovered. Requires explicit manual configuration by the user. Only receives tool call arguments (public package names, CVE IDs). Never receives config files, credentials, env vars, or discovery data."
        auth: false
        opt_in: true
        auto_contacted: false
        receives_credentials: false
        receives_discovery_data: false
    telemetry: false
    persistence: false
    privilege_escalation: false
    always: false
    autonomous_invocation: restricted
---

# agent-bom — AI Supply Chain Security Scanner

Scans AI infrastructure for vulnerabilities, generates SBOMs, and enforces
compliance. Discovers MCP clients, servers, and packages across 20 MCP clients.

## Install (Recommended: Local-First)

Local scanning eliminates all third-party trust concerns. All vulnerability
databases (OSV, NVD, EPSS, KEV) are queried directly from your machine.

```bash
pipx install agent-bom
agent-bom scan              # auto-discover 20 MCP clients + scan
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
docker run --rm ghcr.io/msaad00/agent-bom:0.58.0 scan
```

### Self-Hosted SSE Server

```bash
docker build -f Dockerfile.sse -t agent-bom-sse .
docker run -p 8080:8080 agent-bom-sse
# Connect: { "type": "sse", "url": "http://localhost:8080/sse" }
```

## Available MCP Tools (20 tools)

| Tool | Description |
|------|-------------|
| `scan` | Full discovery + vulnerability scan pipeline |
| `check` | Check a package for CVEs (OSV, NVD, EPSS, KEV) |
| `blast_radius` | Map CVE impact chain across agents, servers, credentials |
| `registry_lookup` | Look up MCP server in 427+ server security metadata registry |
| `compliance` | OWASP LLM/Agentic Top 10, EU AI Act, MITRE ATLAS, NIST AI RMF |
| `remediate` | Prioritized remediation plan for vulnerabilities |
| `verify` | Package integrity + SLSA provenance check |
| `skill_trust` | Assess skill file trust level (5-category analysis) |
| `generate_sbom` | Generate SBOM (CycloneDX or SPDX format) |
| `policy_check` | Evaluate results against security policy |
| `diff` | Compare two scan reports (new/resolved/persistent) |
| `marketplace_check` | Pre-install trust check with registry cross-reference |
| `code_scan` | SAST scanning via Semgrep with CWE-based compliance mapping |
| `where` | Show MCP client config discovery paths |
| `inventory` | List discovered agents, servers, packages |
| `context_graph` | Agent context graph with lateral movement analysis |
| `analytics_query` | Query vulnerability trends, posture history, and runtime events from ClickHouse |
| `cis_benchmark` | Run CIS benchmark checks against AWS or Snowflake accounts |
| `fleet_scan` | Batch registry lookup + risk scoring for MCP server inventories |
| `runtime_correlate` | Cross-reference runtime audit logs with CVE findings |

## MCP Resources

| Resource | Description |
|----------|-------------|
| `registry://servers` | Browse 427+ MCP server security metadata registry |
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

## Remote SSE Endpoint (Fully Optional, Opt-In Only)

For MCP clients that only support remote servers, a convenience endpoint exists.
**This is never auto-contacted.** You must manually add it to your config to use it.
Local-first scanning is the recommended and default mode.

```json
{
  "mcpServers": {
    "agent-bom": {
      "type": "sse",
      "url": "https://agent-bom-mcp.up.railway.app/sse"
    }
  }
}
```

**Data sent to this endpoint:** Only the arguments you provide in tool calls
(public package names, CVE IDs, server names). **Never sent:** config files,
credentials, API keys, environment variables, file contents, or discovery data.
For sensitive environments, use local installation or self-host your own instance.

## Privacy & Data Handling

### Config file reads

Discovery reads local MCP client config files to extract **server names and
command paths only**. It never reads, parses, or transmits credential values,
API keys, or environment variable contents from those files. The extracted data
(e.g., "brave-search is configured in Claude Desktop") stays in local memory
and is only included in scan output you explicitly request.

### Network behavior

All scanning runs **locally by default** with no outbound connections except
public vulnerability databases (OSV, NVD, EPSS). The remote SSE endpoint
(`railway.app`) is **opt-in only** — you must explicitly add it to your MCP
client config. It is never contacted during normal local operation.

Optional tokens (NVD_API_KEY, SNYK_TOKEN, AGENT_BOM_CLICKHOUSE_URL) are only
used when you explicitly set them. They are never auto-discovered or inferred.

### Cloud credentials (CIS benchmarks)

The `cis_benchmark` tool for AWS uses standard AWS SDK credential chain
(AWS_PROFILE, AWS_DEFAULT_REGION) and for Snowflake uses SNOWFLAKE_ACCOUNT,
SNOWFLAKE_USER, SNOWFLAKE_PASSWORD. These are **only used when you explicitly
invoke `cis_benchmark`** with those providers — they are never read during
normal scanning, discovery, or any other tool call. If not set, the tool
returns an error asking you to configure them.

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
- **Smithery**: [smithery.ai/server/agent-bom](https://smithery.ai/server/agent-bom/agent-bom)
- **Sigstore signed**: `agent-bom verify agent-bom@0.58.0`
- **6,300+ tests** with automated security scanning (CodeQL + OpenSSF Scorecard)
- **OpenSSF Scorecard**: [securityscorecards.dev](https://securityscorecards.dev/viewer/?uri=github.com/msaad00/agent-bom)
- **No telemetry**: Zero tracking, zero analytics
