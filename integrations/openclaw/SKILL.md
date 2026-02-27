---
name: agent-bom
description: AI supply chain security scanner — check packages for CVEs, look up MCP servers in the threat registry, assess blast radius, generate SBOMs, enforce compliance
version: 0.35.0
metadata:
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
      - url: "https://agent-bom-mcp.up.railway.app/sse"
        purpose: "Remote MCP server — tools query public vulnerability databases (OSV, NVD, EPSS, KEV) and the bundled 427-server registry. No local file access."
        auth: false
    telemetry: false
    persistence: false
    privilege_escalation: false
---

# agent-bom — AI Supply Chain Security Scanner

An MCP server that provides security scanning tools for AI infrastructure:
- **CVE lookup** — check any package against OSV.dev, NVD, EPSS, CISA KEV
- **MCP registry** — look up any MCP server in the 427+ server threat intelligence registry
- **Blast radius** — map how a CVE reaches credentials and tools
- **Compliance** — OWASP LLM Top 10, MITRE ATLAS, NIST AI RMF

## Security Boundaries

### What is safe to send to the remote server

| Safe to send | Examples |
|-------------|----------|
| Package names + versions | `langchain`, `express@4.18.2` |
| Ecosystem identifiers | `pypi`, `npm`, `go` |
| CVE IDs | `CVE-2024-21538` |
| MCP server names | `brave-search`, `filesystem` |
| Non-sensitive skill text | SKILL.md content for trust assessment |

### What you must NOT send

| Never send | Why |
|-----------|-----|
| API keys, tokens, passwords | The remote server does not need them and cannot use them securely |
| Full config files | May contain credential values or internal hostnames |
| `.env` file contents | Contains secrets |
| Internal URLs or hostnames | Reveals infrastructure |

### How the remote server works

This skill connects to a remote MCP server hosted on Railway over **HTTPS/TLS**. The server:

1. **Does NOT read your local files.** The server runs on Railway, not your machine. `file_reads: []` is accurate — this skill never accesses your filesystem.
2. **Tools that need local data require you to provide it.** For example, `check(package="langchain", ecosystem="pypi")` sends only the package name you provide. The server queries public vulnerability databases and returns results.
3. **Tools that query bundled data work immediately.** `registry_lookup`, `compliance`, `skill_trust` query data bundled inside the server (the 427-server registry, OWASP/ATLAS/NIST mappings).
4. **The `scan()` tool on this remote server** scans the server's own environment — it does NOT reach into your machine. For local MCP config discovery, use the CLI: `pipx install agent-bom && agent-bom scan`.

**What the server receives:** Only the arguments you provide in tool calls (package names, CVE IDs, server names). Nothing else.

**What the server sends outbound:** Package names + versions to OSV.dev, NVD, EPSS, and CISA KEV APIs. No credentials, hostnames, or config contents.

### If using autonomous agent invocation

If your MCP client allows the agent to call tools autonomously (without your confirmation per call), limit the agent's scope to only send package names, CVE IDs, and server names. Do not allow the agent to pass config file contents, environment variables, or credential values to any tool.

## Setup

Add the agent-bom MCP server to your client config:

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

For OpenClaw, add this to `~/.openclaw/openclaw.json`. For other MCP clients
(Claude Desktop, Cursor, VS Code, etc.), add to the appropriate config file.

## Available MCP Tools

Once connected, the agent-bom MCP server provides **13 tools**:

### Tools that work fully via remote server (no local access needed)

| Tool | Description |
|------|-------------|
| `check` | Check a specific package for known vulnerabilities (you provide package name + ecosystem) |
| `blast_radius` | Map the impact chain of a CVE across agents, servers, credentials, and tools |
| `registry_lookup` | Look up an MCP server in the 427+ server threat intelligence registry |
| `compliance` | Check OWASP LLM Top 10, MITRE ATLAS, and NIST AI RMF compliance |
| `remediate` | Generate a prioritized remediation plan for discovered vulnerabilities |
| `verify` | Check package integrity and SLSA provenance |
| `skill_trust` | Assess trust level of a skill file (5-category analysis with verdict) |
| `generate_sbom` | Generate a Software Bill of Materials (CycloneDX or SPDX) |
| `policy_check` | Evaluate scan results against a security policy |
| `diff` | Compare two scan reports to see what changed |

### Tools that scan the server's own environment (not your machine)

| Tool | Description |
|------|-------------|
| `scan` | Run the full discovery → scan pipeline on the server's environment. For local scanning, use the CLI. |
| `where` | Show MCP client config discovery paths on the server. For your machine, use the CLI. |
| `inventory` | List agents and servers found on the server. For local inventory, use the CLI. |

## Available MCP Resources

| Resource | Description |
|----------|-------------|
| `registry://servers` | Browse the 427+ MCP server threat intelligence registry |
| `policy://template` | Default security policy template |

## Example Workflows

### Check a package before installing
```
check(package="@modelcontextprotocol/server-filesystem", ecosystem="npm")
```

### Map blast radius of a CVE
```
blast_radius(cve_id="CVE-2024-21538")
```

### Look up a server in the threat registry
```
registry_lookup(server_name="brave-search")
```

### Check compliance
```
compliance()
```

### Generate an SBOM
```
generate_sbom(format="cyclonedx")
```

### Assess trust of a skill file
```
skill_trust(skill_content="<paste SKILL.md content>")
```

## For Local Scanning (Auto-Discovery of Your MCP Configs)

To scan your own machine's MCP client configs with full auto-discovery across
18 clients (Claude Desktop, Cursor, Codex CLI, Gemini CLI, etc.), install the
CLI locally:

```bash
pipx install agent-bom
agent-bom scan                    # auto-discover + scan local configs
agent-bom scan --dry-run          # preview what would be read (nothing accessed)
agent-bom scan --enforce          # + tool poisoning detection
agent-bom where                   # show all 18 client discovery paths
```

The CLI reads 27 specific config paths (enumerated in [PERMISSIONS.md](https://github.com/msaad00/agent-bom/blob/main/PERMISSIONS.md)).
It extracts server names, package names, and env var **names** only — never values, credentials, or secrets.

## Source & Verification

- **Source code**: https://github.com/msaad00/agent-bom (Apache-2.0)
- **PyPI**: https://pypi.org/project/agent-bom/
- **Smithery**: https://smithery.ai/server/agent-bom/agent-bom (99/100 quality score)
- **Sigstore signed**: Every release is signed with Sigstore OIDC
- **1,430+ tests**: Every commit passes automated security scanning
- **OpenSSF Scorecard**: https://securityscorecards.dev/viewer/?uri=github.com/msaad00/agent-bom
