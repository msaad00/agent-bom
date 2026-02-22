---
name: agent-bom
description: Scan AI agents and MCP servers for CVEs, generate SBOMs, map blast radius, enforce security policies
version: 0.28.0
metadata:
  openclaw:
    requires:
      bins:
        - agent-bom
    emoji: "\U0001F6E1"
    homepage: https://github.com/msaad00/agent-bom
    os:
      - darwin
      - linux
    install:
      - kind: uv
        package: agent-bom
        bins:
          - agent-bom
---

# agent-bom — AI Supply Chain Security Scanner

## What it does

Scans your AI agent and MCP server configurations for known vulnerabilities (CVEs),
maps blast radius (which credentials and tools are exposed if a package is compromised),
generates SBOMs (CycloneDX, SPDX, SARIF), and enforces security policies.

Covers 10+ MCP clients (Claude Desktop, Cursor, Windsurf, VS Code Copilot, OpenClaw, etc.)
and a threat intelligence registry of 112+ MCP servers with risk levels and tool metadata.

## When to use

- Before installing a new MCP server — run a pre-install check
- To audit your current agent setup for vulnerabilities
- To generate compliance documentation (SBOM)
- To understand blast radius of a specific CVE
- To enforce security policy gates in CI/CD

## Workflows

### Quick scan (auto-discover local MCP configs)

Run: `agent-bom scan --format json`

This discovers all configured MCP clients on your system, extracts package dependencies,
and queries OSV.dev for known CVEs.

### Scan with enrichment (NVD CVSS + EPSS + CISA KEV)

Run: `agent-bom scan --enrich --format json`

Adds CVSS v4 scores from NVD, exploit probability from EPSS, and CISA Known Exploited
Vulnerability status to each finding.

### Check a specific MCP server before installing

Run: `agent-bom check <package-name>@<version> -e <ecosystem>`

Example: `agent-bom check @modelcontextprotocol/server-filesystem@2025.1.14 -e npm`

### Generate SBOM

Run: `agent-bom scan --format cyclonedx --output sbom.json`

Supported formats: cyclonedx (CycloneDX 1.6), spdx (SPDX 3.0), sarif (SARIF 2.1.0)

### Scan Docker image

Run: `agent-bom scan --image nginx:1.25 --format json`

### Evaluate security policy

Run: `agent-bom scan --policy policy.json --enrich`

### Generate remediation plan

Run: `agent-bom scan --enrich --remediate remediation.md`

## Output interpretation

- **critical/high severity**: Immediate action required — upgrade or remove package
- **blast_radii**: Shows CVE → package → server → agent → credentials/tools chain
- **exposed_credentials**: Env var names at risk if CVE is exploited
- **risk_score**: 0-10 contextual score based on severity + reach + credential exposure
- **owasp_tags/atlas_tags/nist_ai_rmf_tags**: OWASP LLM Top 10, MITRE ATLAS, NIST AI RMF mappings

## Guardrails

- agent-bom is **read-only** — it never modifies files, runs servers, or accesses credential values
- Only env var **names** appear in reports (values are always redacted)
- All API calls (OSV, NVD, EPSS) are read-only queries
