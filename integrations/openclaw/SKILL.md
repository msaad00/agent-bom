---
name: agent-bom
description: Scan AI agents and MCP servers for CVEs, generate SBOMs, map blast radius, enforce security policies
version: 0.31.0
metadata:
  openclaw:
    requires:
      bins:
        - agent-bom
      optional_bins:
        - docker
        - grype
    emoji: "\U0001F6E1"
    homepage: https://github.com/msaad00/agent-bom
    source: https://github.com/msaad00/agent-bom
    pypi: https://pypi.org/project/agent-bom/
    license: Apache-2.0
    os:
      - darwin
      - linux
    install:
      - kind: uv
        package: agent-bom
        bins:
          - agent-bom
      - kind: pip
        package: agent-bom
        bins:
          - agent-bom
      - kind: pipx
        package: agent-bom
        bins:
          - agent-bom
---

# agent-bom — AI Supply Chain Security Scanner

## What it does

agent-bom is a **read-only** security scanner for AI agent and MCP server configurations.
It discovers MCP client configs on your system, extracts package dependencies, and queries
public vulnerability databases for known CVEs. It then maps blast radius (which credentials
and tools are exposed if a package is compromised), generates SBOMs, and evaluates security policies.

**Key capabilities:**
- CVE scanning via OSV.dev (no API key required)
- NVD CVSS v4 enrichment, EPSS exploit probability, CISA KEV status
- Blast radius mapping: CVE → package → server → agent → credentials/tools
- SBOM generation: CycloneDX 1.6, SPDX 3.0, SARIF 2.1.0
- Policy-as-code engine for CI/CD security gates
- Threat intelligence registry of 427+ known MCP servers with risk metadata
- Docker image scanning (requires `docker` binary, optional)

## Installation

### Recommended: uv (fastest)
```bash
uv tool install agent-bom
```

### Alternative: pip
```bash
pip install agent-bom
```

### Alternative: pipx (isolated environment)
```bash
pipx install agent-bom
```

### Verify installation
```bash
agent-bom --version
# Should print: agent-bom 0.31.0
```

### Verify source
- **PyPI**: https://pypi.org/project/agent-bom/
- **Source**: https://github.com/msaad00/agent-bom
- **Sigstore signatures**: Each release wheel and sdist is signed with Sigstore OIDC.
  Verify with: `cosign verify-blob dist/agent_bom-*.whl --bundle dist/agent_bom-*.whl.bundle`

## When to use

- Before installing a new MCP server — run a pre-install check
- To audit your current agent setup for vulnerabilities
- To generate compliance documentation (SBOM)
- To understand blast radius of a specific CVE
- To enforce security policy gates in CI/CD

## Workflows

### 1. Quick scan (auto-discover local MCP configs)

```bash
agent-bom scan --format json
```

Discovers all configured MCP clients on your system, extracts package dependencies,
and queries OSV.dev for known CVEs. No API keys required.

### 2. Scan with enrichment (NVD CVSS + EPSS + CISA KEV)

```bash
agent-bom scan --enrich --format json
```

Adds CVSS v4 scores from NVD, exploit probability from EPSS, and CISA Known Exploited
Vulnerability status to each finding. Set `NVD_API_KEY` for higher NVD rate limits (optional).

### 3. Check a specific MCP server before installing

```bash
agent-bom check <package-name>@<version> -e <ecosystem>
```

Example:
```bash
agent-bom check @modelcontextprotocol/server-filesystem@2025.1.14 -e npm
```

### 4. Generate SBOM

```bash
agent-bom scan --format cyclonedx --output sbom.json
```

Supported formats: `cyclonedx` (CycloneDX 1.6), `spdx` (SPDX 3.0), `sarif` (SARIF 2.1.0)

### 5. Scan Docker image (requires `docker` binary)

```bash
agent-bom scan --image nginx:1.25 --format json
```

Uses Grype/Syft if available, otherwise falls back to Docker CLI for package extraction.
**This workflow requires the `docker` binary to be installed.**

### 6. Evaluate security policy

```bash
agent-bom scan --policy policy.json --enrich
```

### 7. Generate remediation plan

```bash
agent-bom scan --enrich --remediate remediation.md
```

## Output interpretation

- **critical/high severity**: Immediate action required — upgrade or remove package
- **blast_radii**: Shows CVE → package → server → agent → credentials/tools chain
- **exposed_credentials**: Env var **names** at risk if CVE is exploited (values are never shown)
- **risk_score**: 0-10 contextual score based on severity + reach + credential exposure
- **owasp_tags/atlas_tags/nist_ai_rmf_tags**: OWASP LLM Top 10, MITRE ATLAS, NIST AI RMF mappings

## Transparency: what agent-bom reads

### Config files read (per MCP client)

agent-bom reads the following JSON/YAML config files to discover MCP server entries.
It only reads server names, commands, arguments, and environment variable **names** (never values).

| Client | macOS path | Linux path |
|--------|-----------|------------|
| Claude Desktop | `~/Library/Application Support/Claude/claude_desktop_config.json` | `~/.config/Claude/claude_desktop_config.json` |
| Claude Code | `~/.claude/settings.json`, `~/.claude.json` | same |
| Cursor | `~/Library/Application Support/Cursor/User/globalStorage/cursor.mcp/mcp.json`, `~/.cursor/mcp.json` | `~/.config/Cursor/User/globalStorage/cursor.mcp/mcp.json`, `~/.cursor/mcp.json` |
| Windsurf | `~/.windsurf/mcp.json`, `~/Library/Application Support/Windsurf/User/globalStorage/windsurf.mcp/mcp.json` | `~/.windsurf/mcp.json` |
| Cline (VS Code) | `~/Library/Application Support/Code/User/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json` | `~/.config/Code/User/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json` |
| VS Code Copilot | `~/Library/Application Support/Code/User/mcp.json` | `~/.config/Code/User/mcp.json` |
| Continue.dev | `~/.continue/config.json` | same |
| Zed | `~/.config/zed/settings.json` | same |
| OpenClaw | `~/.openclaw/openclaw.json` | same |
| Cortex Code | `~/.snowflake/cortex/mcp.json` | same |
| Docker MCP Toolkit | `~/.docker/mcp/registry.yaml`, `~/.docker/mcp/catalogs/docker-mcp.yaml` | same |

**Project-level configs** (in current working directory): `.mcp.json`, `mcp.json`, `.cursor/mcp.json`, `.vscode/mcp.json`

**Docker Compose files**: `docker-compose.yml`, `docker-compose.yaml`, `compose.yml`, `compose.yaml`

### Network endpoints called (all read-only GET/POST queries)

| API | URL | Purpose | Auth required |
|-----|-----|---------|---------------|
| OSV.dev | `https://api.osv.dev/v1/querybatch` | CVE lookup by package | No |
| NVD | `https://services.nvd.nist.gov/rest/json/cves/2.0` | CVSS scores | No (API key optional for rate limits) |
| EPSS | `https://api.first.org/data/v1/epss` | Exploit probability | No |
| CISA KEV | `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json` | Known exploited vulns | No |
| npm registry | `https://registry.npmjs.org/{pkg}/{version}` | Package metadata | No |
| PyPI | `https://pypi.org/pypi/{pkg}/{version}/json` | Package metadata | No |

**No data is sent to any endpoint except package names and versions for vulnerability lookup.**
**No scan results, config contents, or credential values are transmitted anywhere.**

### Environment variables

agent-bom reads these env var **names only** from MCP server configs (to map blast radius):
- It pattern-matches for credential-like names: `*KEY*`, `*TOKEN*`, `*SECRET*`, `*PASSWORD*`, `*CREDENTIAL*`, `*AUTH*`
- Standard system vars (`PATH`, `HOME`, `LANG`) are excluded
- **Values are never read, stored, logged, or transmitted** — only the variable name appears in reports

agent-bom itself optionally uses:
- `NVD_API_KEY` — higher NVD rate limits (optional, never logged or transmitted beyond NVD)

## Guardrails

- **Read-only**: agent-bom never writes, modifies, or deletes any file on your system
- **No execution**: It never runs MCP servers, spawns processes, or executes discovered commands
- **No credential access**: Only env var **names** appear in reports — values are never read
- **No data exfiltration**: Scan results stay local. Only package names/versions are sent to public APIs
- **No persistence**: No background processes, daemons, cron jobs, or system modifications
- **No privilege escalation**: Runs as current user, no sudo/root required
- **Auditable**: Full source code at https://github.com/msaad00/agent-bom (Apache-2.0 license)
- **Signed releases**: Every PyPI release is signed with Sigstore OIDC

## Runtime dependencies

| Feature | Required binary | Notes |
|---------|----------------|-------|
| Core scanning | `agent-bom` only | No external tools needed |
| Docker image scanning | `docker` | Optional — only for `--image` flag |
| Enhanced image scanning | `grype`, `syft` | Optional — richer results if available |
