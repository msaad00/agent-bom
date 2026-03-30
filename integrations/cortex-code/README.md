# agent-bom + Cortex CoCo / Cortex Code Integration

## Add agent-bom as an MCP Server

Add to `~/.snowflake/cortex/mcp.json`:

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

Or if installed via pip/pipx:

```json
{
  "mcpServers": {
    "agent-bom": {
      "command": "agent-bom",
      "args": ["mcp", "server"]
    }
  }
}
```

This gives Cortex CoCo access to agent-bom's MCP security and analysis tools via natural language.

## Install as a Cortex Code Skill

Copy the skill to your Cortex Code skills directory:

```bash
cp integrations/cortex-code/SKILL.md ~/.snowflake/cortex/skills/agent-bom/SKILL.md
```

Or for project-level:

```bash
mkdir -p .cortex/skills/agent-bom
cp integrations/cortex-code/SKILL.md .cortex/skills/agent-bom/SKILL.md
```

## What You Get

### As MCP Server

All agent-bom MCP tools become available in Cortex Code:

| Tool | What it does |
|------|-------------|
| `scan` | Full discovery + vulnerability scan |
| `check` | Pre-install CVE check for a package |
| `blast_radius` | Map CVE impact across agents and credentials |
| `policy_check` | Evaluate security policy against findings |
| `registry_lookup` | Query 427+ MCP server security metadata |
| `generate_sbom` | Generate CycloneDX or SPDX SBOM |
| `compliance` | Map findings to OWASP, NIST, MITRE, EU AI Act, and related frameworks |
| `remediate` | Prioritized remediation plan |
| `skill_scan` | Scan CLAUDE.md, AGENTS.md, and other instruction files |
| `skill_verify` | Verify Sigstore provenance for instruction files |
| `skill_trust` | Trust assessment for SKILL.md files |
| `code_scan` | SAST scanning with CWE mapping |
| `context_graph` | Lateral movement analysis |
| `cis_benchmark` | CIS benchmark for AWS/Azure/GCP/Snowflake |
| `gpu_infra_scan` | GPU/AI compute infrastructure scanning |
| ... and more | See `agent-bom mcp server --help` |

### As Skill

Cortex Code can use agent-bom CLI commands directly:
- "Scan my MCP setup for vulnerabilities"
- "Check if langchain has any CVEs"
- "Generate an SBOM for compliance"
- "What's the blast radius of CVE-2024-21538?"

## Cortex CoCo Security Coverage

agent-bom fills these security gaps in Cortex CoCo:

| Cortex Code guidance | agent-bom automation |
|---------------------|---------------------|
| "Verify MCP server integrity" | Automated scanning of all configured MCP servers |
| "Only install from trusted sources" | Trust assessment with 17 behavioral risk patterns |
| Manual permission review | Blast radius analysis showing credential exposure |
| No CVE scanning | Full enrichment: OSV + NVD + EPSS + CISA KEV |
| No compliance mapping | Framework-aware evidence across OWASP, NIST, EU AI Act, ISO 27001, SOC 2, CIS, and more |
| No runtime enforcement | Runtime proxy with 7 inline detectors, plus the broader 8-detector protection engine |

## Runtime proxy and config audit

Wrap third-party MCP servers when you want live traffic inspection:

```bash
agent-bom proxy "npx @modelcontextprotocol/server-filesystem /workspace"
```

Or auto-wrap eligible JSON MCP configs:

```bash
agent-bom proxy-configure --log-dir ~/.agent-bom/logs --detect-credentials --apply
```

For Cortex, agent-bom also audits:

- `~/.snowflake/cortex/permissions.json` for overly broad cached approvals
- `~/.snowflake/cortex/hooks.json` for risky shell hooks or unrestricted triggers
- `~/.snowflake/cortex/settings.json` for auxiliary config context

## Auto-Discovery

agent-bom already discovers Cortex CoCo's MCP configuration at
`~/.snowflake/cortex/mcp.json`. Running `agent-bom agents` will
automatically find and scan your Cortex Code MCP servers plus the associated
settings, permissions, and hooks files.
