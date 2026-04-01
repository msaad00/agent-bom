---
name: agent-bom
description: >-
  Open security scanner for agentic infrastructure — agents, MCP, packages,
  blast radius, runtime, and trust across MCP servers, skills, packages,
  and agents in Cortex Code.
tools:
  - bash
---

# agent-bom — Security Platform for Agentic Infrastructure

Scan your MCP servers, packages, and AI agent configurations for CVEs,
credential exposure, and supply chain risks. Maps blast radius from
vulnerable packages to the credentials and tools they can reach.

## When to Use

- Before installing a new MCP server or skill
- To audit your Cortex Code MCP configuration for vulnerabilities
- To check if a specific package has known CVEs
- To map the blast radius of a vulnerability across your agent setup
- To generate an SBOM for compliance (CycloneDX, SPDX)
- To verify package integrity via Sigstore provenance

## What This Skill Provides

- **CVE scanning** with enrichment from OSV, NVD, EPSS, CISA KEV
- **MCP server discovery** across real AI developer tools, including Cortex Code
- **Blast radius mapping** — which agents, credentials, and tools are exposed
- **Compliance mapping** across OWASP, NIST, MITRE, EU AI Act, and related frameworks
- **Runtime proxy** for MCP traffic interception and policy enforcement
- **SKILL.md trust assessment** with 17 behavioral risk patterns

## Install

```bash
# Install via pip or pipx
pipx install agent-bom

# Or run directly with uvx (no install needed)
uvx agent-bom scan
```

## Instructions

### Scan the current MCP setup

```bash
agent-bom scan
```

Auto-discovers all configured MCP clients (Cortex Code, Claude Desktop, Cursor, etc.),
resolves their server packages, and scans for CVEs.

### Check a package before installing

```bash
agent-bom check <package>@<version> --ecosystem <npm|pypi|go|maven|cargo|nuget|gem>
```

### Map blast radius of a CVE

```bash
agent-bom scan --enrich
# Then review the blast radius section in the output
```

### Generate SBOM

```bash
agent-bom scan -f cyclonedx -o sbom.json
agent-bom scan -f spdx -o sbom.spdx.json
```

### Scan with GPU infrastructure detection

```bash
agent-bom scan --gpu-scan
```

### Run as MCP server (for other AI tools)

```bash
agent-bom mcp server
```

### Proxy MCP traffic with policy enforcement

```bash
agent-bom proxy "npx @modelcontextprotocol/server-filesystem /workspace" --policy policy.yml
```

## Common Patterns

### Pre-install security check
When a user asks to install a new MCP server or package:
1. Run `agent-bom check <package> --ecosystem <ecosystem>`
2. If vulnerabilities found, show severity and suggest fixed versions
3. If clean, confirm safe to proceed

### Full security audit
When a user asks for a security review:
1. Run `agent-bom scan --enrich`
2. Summarize findings by severity
3. Highlight any credential exposure
4. Show blast radius for critical/high findings

### Compliance report
When compliance documentation is needed:
1. Run `agent-bom scan -f cyclonedx -o sbom.json`
2. Run `agent-bom scan --enrich` for compliance framework mapping
3. Report maps to OWASP, NIST, EU AI Act, ISO 27001, SOC 2

## Best Practices

- Always run `agent-bom check` before adding new MCP servers to your `mcp.json`
- Use `--enrich` for full NVD/EPSS/KEV enrichment (slower but more complete)
- Review blast radius for any CRITICAL or HIGH findings
- Use `agent-bom scan -f sarif` for CI/CD integration with GitHub Security tab
- No API keys required for basic scanning (NVD_API_KEY optional for higher rate limits)

## Privacy

- Only public package names and versions are sent to vulnerability databases
- Credentials in MCP configs are redacted by `sanitize_env_vars()`
- No telemetry, no tracking, no analytics
- Apache 2.0 licensed, fully open source
