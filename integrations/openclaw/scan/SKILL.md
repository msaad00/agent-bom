---
name: agent-bom-scan
description: >-
  Check vulnerabilities in a specified package/version, repository, container
  image, or SBOM, or inspect a specified CVE. Discover local MCP clients only
  when the user explicitly requests that discovery. Ask for the target when
  a request such as "verify" or "is this safe" does not identify one.
version: 0.108.4
license: Apache-2.0
compatibility: >-
  Requires Python 3.11+. Install via pipx or pip. Native container image
  scanning — no external scanner required. No API keys required for basic
  operation.
metadata:
  author: msaad00
  homepage: https://github.com/msaad00/agent-bom
  source: https://github.com/msaad00/agent-bom
  pypi: https://pypi.org/project/agent-bom/
  scorecard: https://securityscorecards.dev/viewer/?uri=github.com/msaad00/agent-bom
  install:
    pipx: agent-bom
    pip: agent-bom
    docker: ghcr.io/msaad00/agent-bom:0.108.4
  openclaw:
    requires:
      bins: []
      env: []
      credentials: none
    credential_policy: "No credentials required for basic scanning. Do not discover or use cloud credentials through this skill. Use optional vulnerability-provider authentication only when configured for the requested scan."
    optional_env: []
    optional_bins:
      - semgrep
      - kubectl
    emoji: "\U0001F6E1"
    homepage: https://github.com/msaad00/agent-bom
    source: https://github.com/msaad00/agent-bom
    license: Apache-2.0
    os:
      - darwin
      - linux
      - windows
    credential_handling: "sanitize_env_vars() redacts credential-like and sensitive environment values before reporting; benign configuration values may remain in the in-memory model. Source: https://github.com/msaad00/agent-bom/blob/main/src/agent_bom/security.py"
    data_flow: "Online vulnerability lookups send package identifiers, versions and advisory IDs to providers. Confirm permission before querying private package identifiers. Image/repository inputs also contact the requested registry/host. Use offline mode when network queries are not authorized; report resulting coverage gaps. Do not upload configuration contents or scan reports through this skill."
    file_reads:
      # Possible discovery inputs, not permission to read every listed source.
      # Read only explicitly requested targets or authorized client discovery.
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
      # Roo Code
      - "~/Library/Application Support/Code/User/globalStorage/rooveterinaryinc.roo-cline/settings/cline_mcp_settings.json"
      # Amazon Q
      - "~/Library/Application Support/Code/User/globalStorage/amazonwebservices.amazon-q-vscode/mcp.json"
      # JetBrains AI
      - "~/Library/Application Support/JetBrains/*/mcp.json"
      - "~/.config/github-copilot/intellij/mcp.json"
      # Junie
      - "~/.junie/mcp/mcp.json"
      # GitHub Copilot CLI
      - "~/.copilot/mcp-config.json"
      # Tabnine
      - "~/.tabnine/mcp_servers.json"
      # Cortex Code (Snowflake)
      - "~/.snowflake/cortex/mcp.json"
      - "~/.snowflake/cortex/settings.json"
      - "~/.snowflake/cortex/permissions.json"
      - "~/.snowflake/cortex/hooks.json"
      # Snowflake CLI
      - "~/.snowflake/connections.toml"
      - "~/.snowflake/config.toml"
      # Project-level configs
      - ".mcp.json"
      - ".vscode/mcp.json"
      - ".cursor/mcp.json"
      # User-provided files
      - "user-provided SBOM files (CycloneDX/SPDX JSON)"
    file_writes:
      - "configured local scanner state and vulnerability caches"
      - "user-requested report or SBOM output paths"
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
    persistence: true
    privilege_escalation: false
    always: false
    autonomous_invocation: restricted
---

# agent-bom-scan — AI Supply Chain Vulnerability Scanner

Checks packages for CVEs, scans container images natively, verifies package
provenance via Sigstore, scans filesystems, and generates SBOMs.

## Install

```bash
pipx install agent-bom
agent-bom check langchain==0.1.0  # check a specific package with version
agent-bom scan --project . --no-discover  # scan the requested project
agent-bom scan --image nginx:1.25 --no-discover  # scan the requested image
agent-bom scan --sbom sbom.json --no-discover  # scan a supplied SBOM
agent-bom scan --project . --no-discover -f cyclonedx -o sbom.json  # requested output
agent-bom verify agent-bom   # verify Sigstore provenance
```

## Choose the Target First

Use the narrowest input that satisfies the request. If the package/version,
repository, image or SBOM is missing, ask for it. Do not interpret a generic
"verify" or "is this safe" as permission to scan the host.

For explicit CLI targets, pass `--no-discover`; for the MCP `scan` tool, pass
`no_discover=True`. An invalid, empty or unreadable target is a collection gap,
not permission to fall back to home-directory or MCP-client discovery. Report
the gap and ask for a valid target.

Home-directory configuration and MCP-client discovery require an explicit user
request for those sources. The `file_reads` list discloses possible inputs; it
does not authorize reading them. Do not use discovered cloud credentials.
Cloud inventory requires the separately authorized cloud discovery skill.

Scans can write local state and vulnerability caches. Write reports or SBOMs
only to requested output paths. Offline scans may have incomplete advisory
coverage; preserve that qualification in the result.

### As an MCP Server

```json
{
  "mcpServers": {
    "agent-bom": {
      "command": "uvx",
      "args": ["agent-bom", "mcp", "server"]
    }
  }
}
```

## When to Use

- Check a named package and version for vulnerabilities.
- Scan a specified image, repository or SBOM.
- Look up a named CVE or advisory.
- Generate an SBOM for a specified project.
- Discover local MCP clients when the user explicitly requests that scope.

## Tools (8)

| Tool | Description |
|------|-------------|
| `check` | Check a package for CVEs (OSV, NVD, EPSS, KEV) |
| `scan` | Scan an explicit target; use `no_discover=True` to disable ambient discovery |
| `intel_lookup` | Look up an advisory in the local vulnerability database |
| `exposure_paths` | Inspect recorded exposure paths |
| `compliance` | Map findings to compliance frameworks |
| `remediate` | Prioritized remediation plan for vulnerabilities |
| `generate_sbom` | Generate an SBOM for an explicit configuration path |
| `policy_check` | Evaluate a policy against scan evidence |

These are the default `scan` MCP profile tools. Additional tools such as
`registry_lookup` require a profile that advertises them; inspect the connected
server's tool list before calling one. CLI commands such as `verify` and `diff`
are not default MCP tools. Supply explicit inputs to tools that can discover
clients when their target is omitted, including `compliance` and `generate_sbom`.

## Examples

```
# Check a package before installing
check(package="langchain", version="0.1.0", ecosystem="pypi")

# Look up an advisory in the local database
intel_lookup(advisory_id="CVE-2024-21538")

# Scan only the project the user requested
scan(config_path="/authorized/project", no_discover=True)
```

## Agentic Workflows

Use tool chains, not isolated calls, when the user asks for a decision:

| User intent | Recommended sequence | Output |
|-------------|----------------------|--------|
| "Check this MCP package before installing" | `check` with the supplied package, version and ecosystem | vulnerability evidence and any lookup gaps; no installation |
| "Gate this PR" | CLI `scan` of the requested project with `--no-discover`, SARIF output and fail on high/critical findings | SARIF for code scanning plus non-zero gate result |
| "Audit this fleet inventory" | validate the supplied inventory -> CLI `scan --inventory inventory.json --no-discover` with JSON output | findings for the supplied inventory |
| "What changed since last run?" | scoped current scan -> CLI `diff` against the supplied prior JSON | new/resolved/persistent findings |
| "What should I fix first?" | scoped `scan` -> `exposure_paths` -> `remediate` plan | prioritized plan; no automatic dependency edits |

Pick output by consumer: SARIF for CI, JSON for automation/graph, HTML or
Markdown for human review, CycloneDX/SPDX for SBOM consumers.

For CLI gates, prefer:

```bash
agent-bom scan --project . --no-discover --format sarif --output agent-bom.sarif --fail-on-severity high
```

## Guardrails

- Show CVEs even when NVD analysis is pending or severity is `unknown` — a CVE ID is still a real finding.
- Treat `UNKNOWN` severity as unresolved, not benign — it means data is not yet available.
- Do not install packages, execute discovered commands, edit dependencies or change system configuration as part of a scan. Installation in the setup example is a separate user action.
- Allow only the scanner's local state/cache writes and explicitly requested reports; do not overwrite unrelated files.
- Online lookups transmit package identifiers and versions. Confirm permission before querying private identifiers, or use offline mode and report its coverage gaps.
- Read only the authorized targets, whether inside or outside the user's home directory. Never print raw credentials or upload configuration contents.

## Privacy & Data Handling

```bash
# Step 1: Install
pip install agent-bom

# Step 2: Review redaction logic BEFORE scanning
# sanitize_env_vars() redacts credential-like and sensitive env values before
# reporting; benign configuration values may remain in the in-memory model:
# https://github.com/msaad00/agent-bom/blob/main/src/agent_bom/security.py

# Step 3: Verify package provenance (Sigstore)
agent-bom verify agent-bom

# Step 4: Scan only the requested project
agent-bom scan --project . --no-discover
```

## Verification

- **Source**: [github.com/msaad00/agent-bom](https://github.com/msaad00/agent-bom) (Apache-2.0)
- **Sigstore signed**: `agent-bom verify agent-bom@0.108.4`
- **Contracts**: `tests/test_bundled_skill_contract.py` checks skill metadata and the default MCP tool list.
- **Network boundary**: Online scans use vulnerability providers and the explicitly requested repository or image host; use offline mode when those requests are not authorized.
