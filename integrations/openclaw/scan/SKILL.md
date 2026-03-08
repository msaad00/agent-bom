---
name: agent-bom-scan
description: >-
  AI agent infrastructure vulnerability scanner — discovers MCP clients and servers,
  checks packages for CVEs (OSV, NVD, EPSS, KEV), maps blast radius, and generates
  remediation plans. Use when the user mentions vulnerability scanning, dependency
  security, CVE lookup, blast radius analysis, or AI supply chain risk.
version: 0.61.0
license: Apache-2.0
compatibility: >-
  Requires Python 3.11+. Install via pipx or pip. Optional: Grype/Syft for
  container image scanning. No API keys required for basic operation.
metadata:
  author: msaad00
  homepage: https://github.com/msaad00/agent-bom
  source: https://github.com/msaad00/agent-bom
  pypi: https://pypi.org/project/agent-bom/
  scorecard: https://securityscorecards.dev/viewer/?uri=github.com/msaad00/agent-bom
  tests: 3480
  install:
    pipx: agent-bom
    pip: agent-bom
    docker: ghcr.io/msaad00/agent-bom:0.61.0
  openclaw:
    requires:
      bins: []
      env: []
      credentials: none
    credential_policy: "Zero credentials required. Optional env vars below increase rate limits. They are never auto-discovered, inferred, or transmitted."
    optional_env:
      - name: NVD_API_KEY
        purpose: "Increases NVD API rate limit (scanning works without it)"
        required: false
    optional_bins:
      - syft
      - grype
    emoji: "\U0001F6E1"
    homepage: https://github.com/msaad00/agent-bom
    source: https://github.com/msaad00/agent-bom
    license: Apache-2.0
    os:
      - darwin
      - linux
      - windows
    file_reads_note: "Parses MCP client config files to extract server names, commands, args, and URLs only. Env var values are handled by sanitize_env_vars() in the installed package — verify at https://github.com/msaad00/agent-bom/blob/main/src/agent_bom/security.py#L159"
    credential_handling: "Config files are parsed as JSON/TOML/YAML. Only server names, commands, args, and URLs are extracted. Env var value redaction is implemented by sanitize_env_vars() in the installed code — inspect before running with sensitive data: https://github.com/msaad00/agent-bom/blob/main/src/agent_bom/security.py#L159"
    data_flow: "All scanning is local-first. Only public package names and CVE IDs are sent to vulnerability databases (OSV, NVD, EPSS, GitHub Advisories). Verify no-exfiltration behavior by reviewing the installed code before providing production credentials."
    install_verification: "Before running with sensitive data: (1) pip install agent-bom; (2) agent-bom verify agent-bom; (3) review security.py#L159 (sanitize_env_vars) and discovery/__init__.py to confirm redaction behavior."
    file_reads:
      # Claude Desktop
      - "~/Library/Application Support/Claude/claude_desktop_config.json"
      - "~/.config/Claude/claude_desktop_config.json"
      # Claude Code
      - "~/.claude/settings.json"
      - "~/.claude.json"
      # Cursor
      - "~/.cursor/mcp.json"
      - "~/Library/Application Support/Cursor/User/globalStorage/cursor.mcp/mcp.json"
      # Windsurf
      - "~/.windsurf/mcp.json"
      # Cline
      - "~/Library/Application Support/Code/User/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json"
      # VS Code Copilot
      - "~/Library/Application Support/Code/User/mcp.json"
      # Codex CLI
      - "~/.codex/config.toml"
      # Gemini CLI
      - "~/.gemini/settings.json"
      # Goose
      - "~/.config/goose/config.yaml"
      # Continue
      - "~/.continue/config.json"
      # Zed
      - "~/.config/zed/settings.json"
      # OpenClaw
      - "~/.openclaw/openclaw.json"
      # Roo Code
      - "~/Library/Application Support/Code/User/globalStorage/rooveterinaryinc.roo-cline/settings/cline_mcp_settings.json"
      # Amazon Q
      - "~/Library/Application Support/Code/User/globalStorage/amazonwebservices.amazon-q-vscode/mcp.json"
      # JetBrains AI
      - "~/Library/Application Support/JetBrains/*/mcp.json"
      - "~/.config/github-copilot/intellij/mcp.json"
      # Junie
      - "~/.junie/mcp/mcp.json"
      # Project-level configs
      - ".mcp.json"
      - ".vscode/mcp.json"
      - ".cursor/mcp.json"
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
      - url: "https://api.github.com/advisories"
        purpose: "GitHub Security Advisories — supplemental CVE lookup"
        auth: false
    telemetry: false
    persistence: false
    privilege_escalation: false
    always: false
    autonomous_invocation: restricted
---

# agent-bom-scan — AI Supply Chain Vulnerability Scanner

Discovers MCP clients and servers across 20 AI tools, checks packages for CVEs,
maps blast radius, and generates remediation plans.

## Install

```bash
pipx install agent-bom
agent-bom scan              # auto-discover + scan
agent-bom check langchain   # check a specific package
agent-bom where             # show all discovery paths
```

### As an MCP Server

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

## Tools (8)

| Tool | Description |
|------|-------------|
| `scan` | Full discovery + vulnerability scan pipeline |
| `check` | Check a package for CVEs (OSV, NVD, EPSS, KEV) |
| `blast_radius` | Map CVE impact chain across agents, servers, credentials |
| `remediate` | Prioritized remediation plan for vulnerabilities |
| `verify` | Package integrity + SLSA provenance check |
| `diff` | Compare two scan reports (new/resolved/persistent) |
| `where` | Show MCP client config discovery paths |
| `inventory` | List discovered agents, servers, packages |

## Example Workflows

```
# Check a package before installing
check(package="@modelcontextprotocol/server-filesystem", ecosystem="npm")

# Map blast radius of a CVE
blast_radius(cve_id="CVE-2024-21538")

# Full scan
scan()
```

## Privacy & Data Handling

This skill installs agent-bom from PyPI. The redaction behavior described here
is implemented in the installed package — **verify before running with
sensitive data**:

```bash
# 1. Verify package integrity (Sigstore)
agent-bom verify agent-bom

# 2. Review the redaction code directly
# security.py L159: sanitize_env_vars() — replaces env values with ***REDACTED***
# https://github.com/msaad00/agent-bom/blob/main/src/agent_bom/security.py#L159

# 3. Review config parsing
# https://github.com/msaad00/agent-bom/blob/main/src/agent_bom/discovery/__init__.py
```

Discovery reads local MCP client config files. Only server names, commands,
args, and URLs are extracted. Env var values are replaced with `***REDACTED***`
by `sanitize_env_vars()` in the installed code. Only public package names and
CVE IDs are sent to vulnerability databases.

## Verification

- **Source**: [github.com/msaad00/agent-bom](https://github.com/msaad00/agent-bom) (Apache-2.0)
- **Sigstore signed**: `agent-bom verify agent-bom@0.61.0
- **3,400+ tests** with CodeQL + OpenSSF Scorecard
- **No telemetry**: Zero tracking, zero analytics
